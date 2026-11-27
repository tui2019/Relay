//! `relay-cli`: Local cross-device protocol engine.
//!
//! Reads user-supplied Nearby Presence `SharedCredential`s from a local JSON file,
//! decodes BLE `0xFCF1` Service Data advertisements streamed over stdin (e.g. from the
//! macOS CoreBluetooth bridge), establishes UKEY2-encrypted Nearby Connections sessions
//! over Wi-Fi LAN TCP (or BLE L2CAP bridge), and handles:
//! - Instant Hotspot (`nearby.sharedconnectivity`) credential requests
//! - Notification Sync + Quick Reply (`DeviceLink` -> `NotificationSyncRpcService`)
//! - Universal Clipboard & Task Handoff (`DeviceLink` -> `CompanionTransportService` / `TaskContinuityMessage`)

use relay_core::continuity::{
    encode_clipboard_transfer, ClipboardTransferReassembler, EncodedClipData, EncodedClipDataItem,
    TaskContinuityMessage,
};
use relay_core::devicelink::{
    CompanionTransportBoolMsg, CompanionTransportCapabilityMsg, DeviceLinkChunkReassembler,
    DeviceLinkEvent, DeviceLinkSession, SERVICE_COMPANION_TRANSPORT, SERVICE_NOTIFICATION_SYNC,
    SERVICE_QUICK_ACCESS,
};
use relay_core::dtdi::{
    build_app_channel_message, build_devicelink_wakeup_message, decode_dtdi_message,
    decode_wakeup_envelope, dtdi_message, unwrap_channel_payload, CHANNEL_WAKEUP,
    PACKAGE_AMBIENT_STREAMING, PACKAGE_DTDI,
};
use relay_core::hotspot::{
    availability_response_code_name, build_availability_request, build_connect_tethering_request,
    connect_response_code_name, decode_tether_envelope, DecodedTetherMessage, DeviceStatus,
};
use relay_core::nearby_connections::{
    build_authentication_message, build_authentication_result, build_bwu_client_introduction,
    build_bwu_event, build_bytes_payload_frames, build_connection_request,
    build_connection_response, build_keep_alive, build_presence_connection_request,
    decode_length_prefixed, encode_length_prefixed, OfflineFrame, SERVICE_ID_SHARED_CONNECTIVITY,
};
use relay_core::notifications::{build_dismiss, build_quick_reply, NotificationSyncEvent};
use relay_core::presence::{
    build_one_way_presence_auth_message, decode_presence_auth_message,
    decrypt_presence_advertisement, DerivedPresenceKey, SharedCredential,
};
use relay_core::quickaccess::{
    build_path_request, GetDocumentResponse, OpenDocumentChunk, QuickAccessDocument,
};
use relay_core::ukey2::Ukey2Initiator;
use relay_core::weave::{
    build_ble_v2_ack, build_ble_v2_data, build_ble_v2_introduction, service_id_hash,
    SocketControlFrame, WeaveFramer, WeaveRxEvent, SERVICE_ID_DTDI,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct CredentialsFile {
    device_id: String,
    device_name: String,
    shared_credentials: Vec<SharedCredential>,
}

/// JSON command received on stdin (from macOS Swift bridge or interactive user).
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum BridgeCommand {
    /// Decrypt a raw `0xFCF1` BLE Service Data packet (hex-encoded) captured by CoreBluetooth.
    BlePresenceAdv {
        peripheral_id: String,
        rssi: i32,
        service_data_hex: String,
    },
    /// Connect to a Nearby Connections Wi-Fi LAN TCP endpoint (`host:port`) with UKEY2 handshake.
    ConnectLan {
        host: String,
        port: u16,
        service_id: Option<String>,
    },
    /// Connect to a nearby Android device over Weave BLE GATT (`0xFEF3`) via `RelayBridge weave`
    /// and perform Nearby Connections BLE v2 + UKEY2 + PresenceConnectionAuthenticator handshake.
    ConnectBleWeave {
        peripheral_id: String,
        service_id: Option<String>,
        mac_bridge_path: Option<String>,
        peer_device_id: Option<String>,
        request_hotspot: Option<bool>,
    },
    /// Encode a Universal Clipboard text clip as Android 17 `TaskContinuityMessage` frames (hex).
    EncodeClipboard { text: String },
    /// Encode a Notification Sync Quick Reply RPC packet (hex).
    EncodeQuickReply {
        notification_key: String,
        action_index: i32,
        reply_text: String,
    },
    /// Encode a Notification Dismiss RPC packet (hex).
    EncodeDismiss { notification_key: String },
    /// Encode an Instant Hotspot tether request frame (hex).
    EncodeHotspotRequest,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum BridgeEvent {
    Ready {
        device_id: String,
        loaded_credentials: usize,
    },
    PresenceMatched {
        peripheral_id: String,
        rssi: i32,
        device_name: String,
        device_id: String,
        action_bits_hex: String,
        instant_hotspot_available: bool,
        cross_device_available: bool,
    },
    PresenceUnmatched {
        peripheral_id: String,
        reason: String,
    },
    Ukey2Connected {
        host: String,
        port: u16,
        short_auth_token: String,
    },
    BleWeaveEvent {
        stage: String,
        detail: String,
    },
    HotspotCredentials {
        ssid: String,
        password: String,
        security_type: i32,
        bssid: Option<String>,
    },
    NotificationSynced {
        key: String,
        package_name: String,
        app_name: String,
        title: String,
        text: String,
    },
    ClipboardReceived {
        text: String,
        timestamp_ms: i64,
    },
    EncodedFrames {
        kind: String,
        frames_hex: Vec<String>,
    },
    Error {
        message: String,
    },
}

fn emit(ev: &BridgeEvent) {
    if let Ok(line) = serde_json::to_string(ev) {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

async fn read_framed(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_framed(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_all(&encode_length_prefixed(data)).await?;
    stream.flush().await
}

async fn run_lan_session(
    host: &str,
    port: u16,
    device_id: &str,
    device_name: &str,
    service_id: &str,
) -> Result<(), String> {
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("TCP connect {host}:{port} failed: {e}"))?;

    // 1. Send Nearby Connections CONNECTION_REQUEST
    let req = build_connection_request(device_id, device_name.as_bytes().to_vec(), rand::random());
    write_framed(&mut stream, &req.encode_to_vec())
        .await
        .map_err(|e| e.to_string())?;

    // 2. Run UKEY2 P256_SHA512 handshake
    let (initiator, client_init) = Ukey2Initiator::start();
    write_framed(&mut stream, &client_init)
        .await
        .map_err(|e| e.to_string())?;

    let server_init = read_framed(&mut stream).await.map_err(|e| e.to_string())?;
    let (client_finish, mut d2d) = initiator
        .handle_server_init(&server_init)
        .map_err(|e| format!("UKEY2 failed: {e}"))?;
    write_framed(&mut stream, &client_finish)
        .await
        .map_err(|e| e.to_string())?;

    emit(&BridgeEvent::Ukey2Connected {
        host: host.to_string(),
        port,
        short_auth_token: d2d.short_auth_token(),
    });

    // 3. Exchange encrypted CONNECTION_RESPONSE
    let accept_wire = d2d.encrypt_message(&build_connection_response(true).encode_to_vec());
    write_framed(&mut stream, &accept_wire)
        .await
        .map_err(|e| e.to_string())?;

    // 4. Send initial protocol payload depending on service_id
    let mut dl_session = DeviceLinkSession::new();
    let mut clip_reassembler = ClipboardTransferReassembler::default();
    let mut next_payload_id = 1i64;

    if service_id == SERVICE_ID_SHARED_CONNECTIVITY {
        let tether_req = build_connect_tethering_request();
        for frame in build_bytes_payload_frames(next_payload_id, &tether_req) {
            let enc = d2d.encrypt_message(&frame.encode_to_vec());
            write_framed(&mut stream, &enc)
                .await
                .map_err(|e| e.to_string())?;
        }
    } else {
        for pkt in DeviceLinkSession::build_desktop_handshake(device_id, "macOS") {
            next_payload_id += 1;
            for frame in build_bytes_payload_frames(next_payload_id, &pkt.encode_to_vec()) {
                let enc = d2d.encrypt_message(&frame.encode_to_vec());
                write_framed(&mut stream, &enc)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }

    // 5. Receive & demux encrypted OfflineFrames
    loop {
        let enc_wire = match read_framed(&mut stream).await {
            Ok(b) => b,
            Err(_) => break,
        };
        let plain = d2d
            .decrypt_message(&enc_wire)
            .map_err(|e| format!("D2D decrypt failed: {e}"))?;
        let frame = OfflineFrame::decode(plain.as_slice()).map_err(|e| e.to_string())?;
        let Some(v1) = frame.v1 else { continue };
        let Some(pt) = v1.payload_transfer else {
            continue;
        };
        let Some(chunk) = pt.payload_chunk else {
            continue;
        };
        let body = chunk.body.unwrap_or_default();
        if body.is_empty() {
            continue;
        }

        if service_id == SERVICE_ID_SHARED_CONNECTIVITY {
            if let Ok(DecodedTetherMessage::ConnectResponse(resp)) = decode_tether_envelope(&body) {
                if let Some((ssid, password, security_type)) = resp.credentials() {
                    emit(&BridgeEvent::HotspotCredentials {
                        ssid,
                        password,
                        security_type,
                        bssid: resp.instant_hotspot_status.and_then(|s| s.bssid),
                    });
                }
            }
        } else if let Ok(Some(ev)) = dl_session.handle_incoming(&body) {
            if let DeviceLinkEvent::IncomingStreamData {
                service, data, ..
            } = ev
            {
                if service == SERVICE_NOTIFICATION_SYNC {
                    if let Ok(ns) = NotificationSyncEvent::decode(data.as_slice()) {
                        if let Some(
                            relay_core::notifications::notification_sync_event::Event::Posted(p),
                        ) = ns.event
                        {
                            for n in p.notifications {
                                let basic = n.basic_content.unwrap_or_default();
                                emit(&BridgeEvent::NotificationSynced {
                                    key: n.key.unwrap_or_default(),
                                    package_name: n.package_name.unwrap_or_default(),
                                    app_name: n.app_name.unwrap_or_default(),
                                    title: basic.title.unwrap_or_default(),
                                    text: basic.text.unwrap_or_default(),
                                });
                            }
                        }
                    }
                } else if service == SERVICE_COMPANION_TRANSPORT {
                    if let Ok(tc) = TaskContinuityMessage::decode(data.as_slice()) {
                        if let Some(payload) = tc.payload {
                            match payload {
                                relay_core::continuity::task_continuity_message::Payload::ClipboardTransferStart(s) => {
                                    clip_reassembler.start_transfer(&s);
                                }
                                relay_core::continuity::task_continuity_message::Payload::ClipboardTransferChunk(c) => {
                                    if let Ok(Some(clip)) = clip_reassembler.push_chunk(&c) {
                                        if let Some(item) = clip.items.first() {
                                            if let Some(text) = &item.text {
                                                emit(&BridgeEvent::ClipboardReceived {
                                                    text: text.clone(),
                                                    timestamp_ms: clip.timestamp_ms,
                                                });
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = decode_length_prefixed(&[]);
    Ok(())
}

async fn run_ble_weave_session(
    peripheral_id: &str,
    service_id: &str,
    mac_bridge_path: &str,
    device_id: &str,
    device_name: &str,
    peer_key_seed: Option<[u8; 32]>,
    request_hotspot: bool,
) -> Result<(), String> {
    let shash = service_id_hash(service_id);
    let mut child = Command::new(mac_bridge_path)
        .args(["weave", peripheral_id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn {mac_bridge_path}: {e}"))?;

    let mut child_stdin = child.stdin.take().ok_or("no child stdin")?;
    let child_stdout = child.stdout.take().ok_or("no child stdout")?;
    let mut lines = BufReader::new(child_stdout).lines();

    let mut framer = WeaveFramer::new(20);
    let mut rx_ble_buf: Vec<u8> = Vec::new();
    let mut pending_rx_messages: std::collections::VecDeque<Vec<u8>> =
        std::collections::VecDeque::new();

    // Helper: wait for a single JSON event from RelayBridge
    async fn next_mac_event(
        lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    ) -> Result<serde_json::Value, String> {
        loop {
            let line = tokio::time::timeout(std::time::Duration::from_secs(20), lines.next_line())
                .await
                .map_err(|_| "BLE Weave timeout waiting for RelayBridge".to_string())?
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "RelayBridge exited unexpectedly".to_string())?;
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if v.get("cmd").and_then(|c| c.as_str()) == Some("ble_presence_adv") {
                    continue;
                }
                return Ok(v);
            }
        }
    }

    // Write a single GATT packet and wait for `weave_tx_ack`, queueing any concurrent `weave_rx`.
    async fn send_gatt_packet(
        child_stdin: &mut tokio::process::ChildStdin,
        lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        framer: &mut WeaveFramer,
        pending_rx: &mut std::collections::VecDeque<Vec<u8>>,
        pkt: &[u8],
    ) -> Result<(), String> {
        let cmd = format!("write {}\n", hex::encode(pkt));
        child_stdin
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        child_stdin.flush().await.map_err(|e| e.to_string())?;
        loop {
            let ev = next_mac_event(lines).await?;
            match ev.get("event").and_then(|e| e.as_str()) {
                Some("weave_tx_ack") => {
                    let err = ev.get("error").and_then(|e| e.as_str()).unwrap_or("");
                    if !err.is_empty() {
                        return Err(format!("GATT write error: {err}"));
                    }
                    return Ok(());
                }
                Some("weave_rx") => {
                    if let Some(hx) = ev.get("value_hex").and_then(|v| v.as_str()) {
                        emit(&BridgeEvent::BleWeaveEvent {
                            stage: "weave_rx_raw".into(),
                            detail: hx.to_string(),
                        });
                        if let Ok(raw) = hex::decode(hx) {
                            match framer.feed_rx(&raw) {
                                Ok(WeaveRxEvent::DataMessage(msg)) => {
                                    emit(&BridgeEvent::BleWeaveEvent {
                                        stage: "weave_rx_msg".into(),
                                        detail: hex::encode(&msg),
                                    });
                                    pending_rx.push_back(msg);
                                }
                                Ok(WeaveRxEvent::Incomplete) => {}
                                Ok(WeaveRxEvent::ConnectionConfirm { .. }) => {}
                                Err(e) => return Err(format!("Weave rx error: {e}")),
                            }
                        }
                    }
                }
                Some("ble_disconnected") => return Err("BLE disconnected during TX".into()),
                _ => {}
            }
        }
    }

    async fn send_weave_msg(
        child_stdin: &mut tokio::process::ChildStdin,
        lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        framer: &mut WeaveFramer,
        pending_rx: &mut std::collections::VecDeque<Vec<u8>>,
        msg: &[u8],
    ) -> Result<(), String> {
        let pkts = framer.packetize_data(msg);
        for pkt in pkts {
            send_gatt_packet(child_stdin, lines, framer, pending_rx, &pkt).await?;
        }
        Ok(())
    }

    async fn recv_ble_frame(
        child_stdin: &mut tokio::process::ChildStdin,
        lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        framer: &mut WeaveFramer,
        pending_rx: &mut std::collections::VecDeque<Vec<u8>>,
        rx_ble_buf: &mut Vec<u8>,
        shash: [u8; 3],
    ) -> Result<Vec<u8>, String> {
        loop {
            // Check if rx_ble_buf already contains a full length-prefixed Nearby frame
            if rx_ble_buf.len() >= 4 {
                let len = u32::from_be_bytes([
                    rx_ble_buf[0],
                    rx_ble_buf[1],
                    rx_ble_buf[2],
                    rx_ble_buf[3],
                ]) as usize;
                if rx_ble_buf.len() >= 4 + len {
                    let frame = rx_ble_buf[4..4 + len].to_vec();
                    rx_ble_buf.drain(..4 + len);
                    return Ok(frame);
                }
            }

            let raw_weave = if let Some(m) = pending_rx.pop_front() {
                m
            } else {
                loop {
                    let ev = next_mac_event(lines).await?;
                    match ev.get("event").and_then(|e| e.as_str()) {
                        Some("weave_rx") => {
                            let hx = ev.get("value_hex").and_then(|v| v.as_str()).unwrap_or("");
                            let raw = hex::decode(hx).map_err(|e| e.to_string())?;
                            match framer.feed_rx(&raw).map_err(|e| e.to_string())? {
                                WeaveRxEvent::DataMessage(msg) => break msg,
                                WeaveRxEvent::Incomplete => continue,
                                WeaveRxEvent::ConnectionConfirm { .. } => continue,
                            }
                        }
                        Some("ble_disconnected") => return Err("BLE disconnected while reading".into()),
                        _ => continue,
                    }
                }
            };

            if raw_weave.len() < 3 {
                continue;
            }
            if &raw_weave[..3] == b"\x00\x00\x00" {
                if let Ok(ctrl) = SocketControlFrame::decode(&raw_weave[3..]) {
                    emit(&BridgeEvent::BleWeaveEvent {
                        stage: "ble_control_frame".into(),
                        detail: format!("type={:?}", ctrl.r#type),
                    });
                    if ctrl.r#type == Some(2) {
                        return Err(format!("Peer sent BLE DISCONNECTION for {}", hex::encode(shash)));
                    }
                }
                continue;
            }
            if raw_weave[..3] == shash {
                let data_chunk = &raw_weave[3..];
                rx_ble_buf.extend_from_slice(data_chunk);
                // Send BlePacket PACKET_ACKNOWLEDGEMENT so Android BLE v2 continues streaming
                let ack = build_ble_v2_ack(shash, data_chunk.len() as i32);
                let _ = send_weave_msg(child_stdin, lines, framer, pending_rx, &ack).await;
            }
        }
    }

    // 1. Wait for `weave_ready`
    let max_write_len: u16;
    loop {
        let ev = next_mac_event(&mut lines).await?;
        match ev.get("event").and_then(|e| e.as_str()) {
            Some("weave_ready") => {
                max_write_len = ev
                    .get("max_write_len")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(512)
                    .min(512) as u16;
                break;
            }
            Some("ble_connect_failed") | Some("weave_subscribe_error") => {
                let _ = child.kill().await;
                return Err(format!("BLE connect failed: {ev}"));
            }
            _ => {}
        }
    }

    // 2. Weave Connection Request -> Connection Confirm
    let conn_req = framer.build_connection_request(max_write_len);
    send_gatt_packet(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &conn_req,
    )
    .await?;

    loop {
        let ev = next_mac_event(&mut lines).await?;
        if ev.get("event").and_then(|e| e.as_str()) == Some("weave_rx") {
            let hx = ev.get("value_hex").and_then(|v| v.as_str()).unwrap_or("");
            let raw = hex::decode(hx).map_err(|e| e.to_string())?;
            if let WeaveRxEvent::ConnectionConfirm {
                selected_version,
                selected_mtu,
                ..
            } = framer.feed_rx(&raw).map_err(|e| e.to_string())?
            {
                emit(&BridgeEvent::BleWeaveEvent {
                    stage: "weave_connected".into(),
                    detail: format!("version={selected_version} mtu={selected_mtu}"),
                });
                break;
            }
        }
    }

    // 3. Send Nearby Connections BLE v2 SocketControlFrame::INTRODUCTION
    let intro = build_ble_v2_introduction(shash);
    send_weave_msg(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &intro,
    )
    .await?;
    emit(&BridgeEvent::BleWeaveEvent {
        stage: "ble_intro_sent".into(),
        detail: format!("service_id={service_id} hash={}", hex::encode(shash)),
    });

    // 4. Send OfflineFrame::CONNECTION_REQUEST (as PresenceDevice for Instant Hotspot & DTDI)
    let ep_id = &device_id[..device_id.len().min(4)];
    let is_presence_service =
        service_id == SERVICE_ID_SHARED_CONNECTIVITY || service_id == SERVICE_ID_DTDI;
    let nc_req = if is_presence_service {
        let numeric_id: i64 = device_id.parse().unwrap_or(1_234_567_890);
        build_presence_connection_request(ep_id, numeric_id, device_name, rand::random())
    } else {
        build_connection_request(ep_id, device_name.as_bytes().to_vec(), rand::random())
    };
    let nc_req_ble = build_ble_v2_data(shash, &nc_req.encode_to_vec());
    send_weave_msg(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &nc_req_ble,
    )
    .await?;
    emit(&BridgeEvent::BleWeaveEvent {
        stage: "connection_request_sent".into(),
        detail: format!("bytes={}", nc_req_ble.len()),
    });

    // 5. Send UKEY2 CLIENT_INIT
    let (initiator, client_init) = Ukey2Initiator::start();
    let ci_ble = build_ble_v2_data(shash, &client_init);
    send_weave_msg(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &ci_ble,
    )
    .await?;
    emit(&BridgeEvent::BleWeaveEvent {
        stage: "ukey2_client_init_sent".into(),
        detail: format!("bytes={}", client_init.len()),
    });

    // 6. Receive UKEY2 SERVER_INIT from the Pixel 9 Pro!
    let server_init = recv_ble_frame(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &mut rx_ble_buf,
        shash,
    )
    .await?;
    let (client_finish, mut d2d) = initiator
        .handle_server_init(&server_init)
        .map_err(|e| format!("UKEY2 SERVER_INIT failed (raw={}): {e}", hex::encode(&server_init)))?;

    // 7. Send UKEY2 CLIENT_FINISH!
    let cf_ble = build_ble_v2_data(shash, &client_finish);
    send_weave_msg(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &cf_ble,
    )
    .await?;

    emit(&BridgeEvent::Ukey2Connected {
        host: format!("ble://{peripheral_id}"),
        port: 0xFEF3,
        short_auth_token: d2d.short_auth_token(),
    });

    // 8a. Nearby Presence one-way authentication (PLAINTEXT, before CONNECTION_RESPONSE & encryption!)
    // Verified in GMS `dmzt.java:7324,9326-9393` & `dsui.java:218-305`.
    if is_presence_service {
        if let Some(key_seed) = peer_key_seed {
            let auth_payload = build_one_way_presence_auth_message(&d2d.auth_string, &key_seed);
            let auth_msg_frame = build_authentication_message(auth_payload).encode_to_vec();
            let auth_msg_ble = build_ble_v2_data(shash, &auth_msg_frame);
            send_weave_msg(
                &mut child_stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx_messages,
                &auth_msg_ble,
            )
            .await?;
            emit(&BridgeEvent::BleWeaveEvent {
                stage: "presence_auth_sent".into(),
                detail: format!("one-way auth_message bytes={}", auth_msg_frame.len()),
            });

            // Read peer's plaintext AUTHENTICATION_MESSAGE (broadcaster signature) or early AUTHENTICATION_RESULT
            let peer_auth_raw = recv_ble_frame(
                &mut child_stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx_messages,
                &mut rx_ble_buf,
                shash,
            )
            .await?;
            let peer_auth_frame = OfflineFrame::decode(peer_auth_raw.as_slice()).map_err(|e| {
                format!(
                    "Failed to decode peer auth OfflineFrame (raw={}): {e}",
                    hex::encode(&peer_auth_raw)
                )
            })?;
            let v1 = peer_auth_frame.v1.as_ref();
            match v1.and_then(|v| v.r#type) {
                Some(8) => {
                    let msg_bytes = v1
                        .and_then(|v| v.authentication_message.as_ref())
                        .and_then(|m| m.auth_message.as_deref())
                        .unwrap_or_default();
                    let decoded_sig_len = decode_presence_auth_message(msg_bytes)
                        .ok()
                        .and_then(|f| f.signature)
                        .map(|s| s.len())
                        .unwrap_or(0);
                    emit(&BridgeEvent::BleWeaveEvent {
                        stage: "presence_auth_peer_msg".into(),
                        detail: format!(
                            "received broadcaster AUTHENTICATION_MESSAGE (sig_len={decoded_sig_len})"
                        ),
                    });

                    // Exchange plaintext AUTHENTICATION_RESULT (1 = SUCCESS)
                    let res_frame = build_authentication_result(1).encode_to_vec();
                    let res_ble = build_ble_v2_data(shash, &res_frame);
                    send_weave_msg(
                        &mut child_stdin,
                        &mut lines,
                        &mut framer,
                        &mut pending_rx_messages,
                        &res_ble,
                    )
                    .await?;

                    let peer_res_raw = recv_ble_frame(
                        &mut child_stdin,
                        &mut lines,
                        &mut framer,
                        &mut pending_rx_messages,
                        &mut rx_ble_buf,
                        shash,
                    )
                    .await?;
                    let peer_res_frame = OfflineFrame::decode(peer_res_raw.as_slice())
                        .map_err(|e| format!("decode peer AUTHENTICATION_RESULT failed: {e}"))?;
                    let peer_status = peer_res_frame
                        .v1
                        .as_ref()
                        .and_then(|v| v.authentication_result.as_ref())
                        .and_then(|r| r.result)
                        .unwrap_or(-1);
                    emit(&BridgeEvent::BleWeaveEvent {
                        stage: "presence_auth_result".into(),
                        detail: format!("peer AUTHENTICATION_RESULT={peer_status}"),
                    });
                    if peer_status != 1 && peer_status != 0 {
                        let _ = child.kill().await;
                        return Err(format!("Peer rejected Presence auth: result={peer_status}"));
                    }
                }
                Some(9) => {
                    let peer_status = v1
                        .and_then(|v| v.authentication_result.as_ref())
                        .and_then(|r| r.result)
                        .unwrap_or(-1);
                    let _ = child.kill().await;
                    return Err(format!(
                        "Peer returned early AUTHENTICATION_RESULT={peer_status} (raw={})",
                        hex::encode(&peer_auth_raw)
                    ));
                }
                other => {
                    let _ = child.kill().await;
                    return Err(format!(
                        "Unexpected frame during Presence auth: type={other:?} frame={peer_auth_frame:?}"
                    ));
                }
            }
        } else {
            emit(&BridgeEvent::BleWeaveEvent {
                stage: "presence_auth_skipped".into(),
                detail: "no peer_key_seed available".into(),
            });
        }
    }

    // 8b. Exchange PLAINTEXT CONNECTION_RESPONSE(ACCEPT)!
    // Per GMS `dmzt.java:2885-2893`, UKEY2 encryption is enabled ONLY AFTER both sides exchange CONNECTION_RESPONSE.
    let accept_plain = build_connection_response(true).encode_to_vec();
    let accept_ble = build_ble_v2_data(shash, &accept_plain);
    send_weave_msg(
        &mut child_stdin,
        &mut lines,
        &mut framer,
        &mut pending_rx_messages,
        &accept_ble,
    )
    .await?;
    emit(&BridgeEvent::BleWeaveEvent {
        stage: "connection_response_sent".into(),
        detail: "plaintext ACCEPT".into(),
    });

    // Wait for peer's plaintext CONNECTION_RESPONSE(ACCEPT)
    loop {
        let peer_raw = recv_ble_frame(
            &mut child_stdin,
            &mut lines,
            &mut framer,
            &mut pending_rx_messages,
            &mut rx_ble_buf,
            shash,
        )
        .await?;
        let peer_frame = OfflineFrame::decode(peer_raw.as_slice()).map_err(|e| {
            format!(
                "Failed to decode plaintext peer frame before encryption (raw={}): {e}",
                hex::encode(&peer_raw)
            )
        })?;
        let v1_type = peer_frame.v1.as_ref().and_then(|v| v.r#type);
        emit(&BridgeEvent::BleWeaveEvent {
            stage: "plaintext_peer_frame".into(),
            detail: format!("type={v1_type:?} frame={peer_frame:?}"),
        });
        match v1_type {
            Some(2) => {
                let resp_code = peer_frame
                    .v1
                    .as_ref()
                    .and_then(|v| v.connection_response.as_ref())
                    .and_then(|r| r.response)
                    .unwrap_or(0);
                let status = peer_frame
                    .v1
                    .as_ref()
                    .and_then(|v| v.connection_response.as_ref())
                    .and_then(|r| r.status)
                    .unwrap_or(-1);
                if resp_code == 2 || (status != 0 && status != -1) {
                    let _ = child.kill().await;
                    return Err(format!(
                        "Peer rejected CONNECTION_RESPONSE: status={status} response={resp_code}"
                    ));
                }
                break;
            }
            Some(5) => {
                // Plaintext KEEP_ALIVE
                let seq = peer_frame
                    .v1
                    .as_ref()
                    .and_then(|v| v.keep_alive.as_ref())
                    .and_then(|k| k.seq_num);
                let is_ack = peer_frame
                    .v1
                    .as_ref()
                    .and_then(|v| v.keep_alive.as_ref())
                    .and_then(|k| k.ack)
                    .unwrap_or(false);
                if !is_ack {
                    let ka = build_keep_alive(true, seq).encode_to_vec();
                    let ka_ble = build_ble_v2_data(shash, &ka);
                    send_weave_msg(
                        &mut child_stdin,
                        &mut lines,
                        &mut framer,
                        &mut pending_rx_messages,
                        &ka_ble,
                    )
                    .await?;
                }
            }
            Some(6) => {
                let _ = child.kill().await;
                return Err("Peer sent DISCONNECTION before CONNECTION_RESPONSE".into());
            }
            _ => {}
        }
    }

    emit(&BridgeEvent::BleWeaveEvent {
        stage: "encryption_enabled".into(),
        detail: "UKEY2 AES-256-CBC-HMAC-SHA256 active".into(),
    });

    // 9. Send encrypted protocol requests depending on service_id
    let mut connect_tethering_sent = false;
    let mut next_ble_payload_id: i64 = 100;
    let dtdi_channel_uuid = uuid::Uuid::new_v4().to_string();
    let mut dl_session = DeviceLinkSession::new();
    let mut dl_reassembler = DeviceLinkChunkReassembler::default();
    let mut clip_reassembler = ClipboardTransferReassembler::default();
    let mut dl_handshake_sent = false;
    let mut notif_stream_req_id: Option<i64> = None;
    let mut qa_list_req_id: Option<i64> = None;
    let mut qa_stat_req_id: Option<i64> = None;
    let mut qa_open_req_id: Option<i64> = None;
    let mut ct_can_form_req_id: Option<i64> = None;
    let mut ct_caps_req_id: Option<i64> = None;
    let mut ct_data_req_id: Option<i64> = None;

    if service_id == SERVICE_ID_SHARED_CONNECTIVITY {
        let avail_req = build_availability_request();
        for frame in build_bytes_payload_frames(1, &avail_req) {
            let enc = d2d.encrypt_message(&frame.encode_to_vec());
            let ble = build_ble_v2_data(shash, &enc);
            send_weave_msg(
                &mut child_stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx_messages,
                &ble,
            )
            .await?;
        }
        emit(&BridgeEvent::BleWeaveEvent {
            stage: "instant_hotspot_request_sent".into(),
            detail: r#"sent {"type":1,"data":""} (TetherAvailabilityRequest)"#.into(),
        });
    } else if service_id == SERVICE_ID_DTDI {
        let req_id = uuid::Uuid::new_v4().to_string();
        let wakeup_bytes = build_devicelink_wakeup_message(&dtdi_channel_uuid, &req_id, false);
        next_ble_payload_id += 1;
        for frame in build_bytes_payload_frames(next_ble_payload_id, &wakeup_bytes) {
            let enc = d2d.encrypt_message(&frame.encode_to_vec());
            let ble = build_ble_v2_data(shash, &enc);
            send_weave_msg(
                &mut child_stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx_messages,
                &ble,
            )
            .await?;
        }
        emit(&BridgeEvent::BleWeaveEvent {
            stage: "dtdi_wakeup_sent".into(),
            detail: format!("channel={dtdi_channel_uuid} req_id={req_id}"),
        });
    }

    // 10. Read encrypted frames from peer (supporting seamless BLE -> Wi-Fi LAN TCP bandwidth upgrade!)
    let mut payload_buffers: std::collections::HashMap<i64, Vec<u8>> =
        std::collections::HashMap::new();
    let mut upgraded_tcp: Option<TcpStream> = None;

    for _ in 0..400 {
        let next_enc = if let Some(ref mut tcp) = upgraded_tcp {
            match tokio::time::timeout(std::time::Duration::from_secs(20), read_framed(tcp)).await {
                Ok(Ok(b)) => Ok(b),
                Ok(Err(e)) => Err(format!("TCP read error: {e}")),
                Err(_) => Err("TCP read timeout".to_string()),
            }
        } else {
            recv_ble_frame(
                &mut child_stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx_messages,
                &mut rx_ble_buf,
                shash,
            )
            .await
        };

        match next_enc {
            Ok(enc) => match d2d.decrypt_message(&enc) {
                Ok(plain) => {
                    if let Ok(frame) = OfflineFrame::decode(plain.as_slice()) {
                        emit(&BridgeEvent::BleWeaveEvent {
                            stage: "decrypted_peer_frame".into(),
                            detail: format!("{frame:?}"),
                        });
                        if let Some(v1) = &frame.v1 {
                            // Handle BANDWIDTH_UPGRADE_NEGOTIATION (BLE -> Wi-Fi LAN TCP)
                            if v1.r#type == Some(4) {
                                if let Some(bwu) = &v1.bandwidth_upgrade_negotiation {
                                    if bwu.event_type == Some(1) && upgraded_tcp.is_none() {
                                        if let Some(info) = &bwu.upgrade_path_info {
                                            if info.medium == Some(5) {
                                                if let Some(sock) = &info.wifi_lan_socket {
                                                    let ip_opt: Option<std::net::IpAddr> =
                                                        match sock.ip_address.as_deref() {
                                                            Some(b) if b.len() == 4 => {
                                                                Some(std::net::IpAddr::V4(
                                                                    std::net::Ipv4Addr::new(
                                                                        b[0], b[1], b[2], b[3],
                                                                    ),
                                                                ))
                                                            }
                                                            Some(b) if b.len() == 16 => {
                                                                let arr: [u8; 16] =
                                                                    b.try_into().unwrap();
                                                                Some(std::net::IpAddr::V6(
                                                                    std::net::Ipv6Addr::from(arr),
                                                                ))
                                                            }
                                                            _ => None,
                                                        };
                                                    let port =
                                                        sock.wifi_port.unwrap_or(0) as u16;
                                                    if let (Some(ip), true) = (ip_opt, port > 0) {
                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                            stage: "bwu_connecting_tcp".into(),
                                                            detail: format!("{ip}:{port}"),
                                                        });
                                                        match TcpStream::connect((ip, port)).await {
                                                            Ok(mut tcp) => {
                                                                // 1. Plaintext CLIENT_INTRODUCTION on TCP
                                                                let intro_wire =
                                                                    build_bwu_client_introduction(
                                                                        ep_id,
                                                                    )
                                                                    .encode_to_vec();
                                                                if let Err(e) =
                                                                    write_framed(&mut tcp, &intro_wire)
                                                                        .await
                                                                {
                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                        stage: "bwu_error".into(),
                                                                        detail: format!("CLIENT_INTRODUCTION write failed: {e}"),
                                                                    });
                                                                    continue;
                                                                }
                                                                // 2. Read plaintext CLIENT_INTRODUCTION_ACK (event_type=6) on TCP
                                                                match tokio::time::timeout(
                                                                    std::time::Duration::from_secs(5),
                                                                    read_framed(&mut tcp),
                                                                )
                                                                .await
                                                                {
                                                                    Ok(Ok(ack_raw)) => {
                                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                                            stage: "bwu_client_intro_ack".into(),
                                                                            detail: format!("bytes={} hex={}", ack_raw.len(), hex::encode(&ack_raw)),
                                                                        });
                                                                    }
                                                                    other => {
                                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                                            stage: "bwu_error".into(),
                                                                            detail: format!("CLIENT_INTRODUCTION_ACK failed: {other:?}"),
                                                                        });
                                                                        continue;
                                                                    }
                                                                }
                                                                // 3. Encrypted LAST_WRITE_TO_PRIOR_CHANNEL on BLE
                                                                let last_enc = d2d.encrypt_message(
                                                                    &build_bwu_event(2)
                                                                        .encode_to_vec(),
                                                                );
                                                                let last_ble =
                                                                    build_ble_v2_data(shash, &last_enc);
                                                                send_weave_msg(
                                                                    &mut child_stdin,
                                                                    &mut lines,
                                                                    &mut framer,
                                                                    &mut pending_rx_messages,
                                                                    &last_ble,
                                                                )
                                                                .await?;
                                                                // 4. Per GMS `dmoj.java:166-237, 1572-1605`, BOTH `LAST_WRITE_TO_PRIOR_CHANNEL`
                                                                //    AND `SAFE_TO_CLOSE_PRIOR_CHANNEL` are exchanged encrypted on the PRIOR channel (BLE)!
                                                                //    Wait for peer's LAST_WRITE_TO_PRIOR_CHANNEL (2), reply SAFE_TO_CLOSE_PRIOR_CHANNEL (3)
                                                                //    on BLE, and wait for peer's SAFE_TO_CLOSE_PRIOR_CHANNEL (3) on BLE so our D2D
                                                                //    sequence numbers stay in lockstep before switching to TCP.
                                                                let mut saw_peer_last_write = false;
                                                                let mut saw_peer_safe_to_close = false;
                                                                let mut sent_safe_to_close = false;
                                                                while !(saw_peer_last_write && saw_peer_safe_to_close) {
                                                                    let b_enc = recv_ble_frame(
                                                                        &mut child_stdin,
                                                                        &mut lines,
                                                                        &mut framer,
                                                                        &mut pending_rx_messages,
                                                                        &mut rx_ble_buf,
                                                                        shash,
                                                                    )
                                                                    .await?;
                                                                    let b_plain = d2d
                                                                        .decrypt_message(&b_enc)
                                                                        .map_err(|e| format!("BLE drain decrypt: {e}"))?;
                                                                    if let Ok(bf) =
                                                                        OfflineFrame::decode(
                                                                            b_plain.as_slice(),
                                                                        )
                                                                    {
                                                                        let bwu_ev = bf
                                                                            .v1
                                                                            .as_ref()
                                                                            .and_then(|v| {
                                                                                v.bandwidth_upgrade_negotiation
                                                                                    .as_ref()
                                                                            })
                                                                            .and_then(|b| b.event_type);
                                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                                            stage: "bwu_ble_drain".into(),
                                                                            detail: format!("bwu_event={bwu_ev:?} frame={bf:?}"),
                                                                        });
                                                                        if bwu_ev == Some(2) {
                                                                            saw_peer_last_write = true;
                                                                            if !sent_safe_to_close {
                                                                                sent_safe_to_close = true;
                                                                                let safe_enc = d2d.encrypt_message(
                                                                                    &build_bwu_event(3)
                                                                                        .encode_to_vec(),
                                                                                );
                                                                                let safe_ble = build_ble_v2_data(shash, &safe_enc);
                                                                                send_weave_msg(
                                                                                    &mut child_stdin,
                                                                                    &mut lines,
                                                                                    &mut framer,
                                                                                    &mut pending_rx_messages,
                                                                                    &safe_ble,
                                                                                )
                                                                                .await?;
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "bwu_safe_to_close_sent_ble".into(),
                                                                                    detail: "sent encrypted SAFE_TO_CLOSE_PRIOR_CHANNEL on BLE".into(),
                                                                                });
                                                                            }
                                                                        } else if bwu_ev == Some(3) {
                                                                            saw_peer_safe_to_close = true;
                                                                        }
                                                                    }
                                                                }
                                                                // 5. Close prior BLE channel cleanly so Pixel's `priorChannel.F()` returns
                                                                //    immediately, resumes TCP (`newChannel.v()`), and fires `onBandwidthChanged(HIGH)`.
                                                                //    Wait briefly for Pixel's plaintext DISCONNECTION/EOF before killing RelayBridge
                                                                //    so our BLE GATT writes (SAFE_TO_CLOSE + DISCONNECTION) flush completely.
                                                                let disc_frame = OfflineFrame {
                                                                    version: Some(1),
                                                                    v1: Some(relay_core::nearby_connections::V1Frame {
                                                                        r#type: Some(6),
                                                                        disconnection: Some(relay_core::nearby_connections::DisconnectionFrame {
                                                                            request_safe_to_disconnect: Some(false),
                                                                        }),
                                                                        ..Default::default()
                                                                    }),
                                                                };
                                                                let disc_ble = build_ble_v2_data(
                                                                    shash,
                                                                    &disc_frame.encode_to_vec(),
                                                                );
                                                                let _ = send_weave_msg(
                                                                    &mut child_stdin,
                                                                    &mut lines,
                                                                    &mut framer,
                                                                    &mut pending_rx_messages,
                                                                    &disc_ble,
                                                                )
                                                                .await;
                                                                let _ = tokio::time::timeout(
                                                                    std::time::Duration::from_millis(1500),
                                                                    recv_ble_frame(
                                                                        &mut child_stdin,
                                                                        &mut lines,
                                                                        &mut framer,
                                                                        &mut pending_rx_messages,
                                                                        &mut rx_ble_buf,
                                                                        shash,
                                                                    ),
                                                                )
                                                                .await;
                                                                let _ = child.kill().await;
                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                    stage: "bwu_upgraded".into(),
                                                                    detail: format!("WIFI_LAN tcp://{ip}:{port} (prior BLE closed)"),
                                                                });
                                                                // 6. Send DeviceLink desktop handshake over fast Wi-Fi LAN TCP!
                                                                if service_id == SERVICE_ID_DTDI && !dl_handshake_sent {
                                                                    dl_handshake_sent = true;
                                                                    for pkt in DeviceLinkSession::build_desktop_handshake(device_id, "macOS 15") {
                                                                        let wrapped = build_app_channel_message(
                                                                            PACKAGE_AMBIENT_STREAMING,
                                                                            &dtdi_channel_uuid,
                                                                            2, // SENDER_INCOMING_CHANNEL (peer's incoming wakeup channel)
                                                                            pkt.encode_to_vec(),
                                                                        );
                                                                        next_ble_payload_id += 1;
                                                                        for cframe in build_bytes_payload_frames(next_ble_payload_id, &wrapped) {
                                                                            let cenc = d2d.encrypt_message(&cframe.encode_to_vec());
                                                                            write_framed(&mut tcp, &cenc).await.map_err(|e| e.to_string())?;
                                                                        }
                                                                    }
                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                        stage: "devicelink_handshake_sent".into(),
                                                                        detail: format!("over WIFI_LAN channel={dtdi_channel_uuid}"),
                                                                    });
                                                                }
                                                                upgraded_tcp = Some(tcp);
                                                            }
                                                            Err(e) => {
                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                    stage: "bwu_error".into(),
                                                                    detail: format!("TCP connect {ip}:{port} failed: {e}"),
                                                                });
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            // Reply to encrypted KEEP_ALIVE pings
                            if v1.r#type == Some(5) {
                                if let Some(ka) = &v1.keep_alive {
                                    if !ka.ack.unwrap_or(false) {
                                        let ack = build_keep_alive(true, ka.seq_num).encode_to_vec();
                                        let ack_enc = d2d.encrypt_message(&ack);
                                        if let Some(ref mut tcp) = upgraded_tcp {
                                            let _ = write_framed(tcp, &ack_enc).await;
                                        } else {
                                            let ack_ble = build_ble_v2_data(shash, &ack_enc);
                                            let _ = send_weave_msg(
                                                &mut child_stdin,
                                                &mut lines,
                                                &mut framer,
                                                &mut pending_rx_messages,
                                                &ack_ble,
                                            )
                                            .await;
                                        }
                                    }
                                }
                            }
                            if v1.r#type == Some(6) {
                                break;
                            }
                            if let Some(pt) = &v1.payload_transfer {
                                let pid = pt
                                    .payload_header
                                    .as_ref()
                                    .and_then(|h| h.id)
                                    .unwrap_or(0);
                                if let Some(chunk) = &pt.payload_chunk {
                                    let entry = payload_buffers.entry(pid).or_default();
                                    if let Some(body) = &chunk.body {
                                        entry.extend_from_slice(body);
                                    }
                                    let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;
                                    if is_last && !entry.is_empty() {
                                        let full_body = std::mem::take(entry);
                                        if service_id == SERVICE_ID_DTDI {
                                            match decode_dtdi_message(&full_body) {
                                                Ok(dmsg) => {
                                                    let ch = dmsg.channel_id.unwrap_or_default();
                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                        stage: "dtdi_rx".into(),
                                                        detail: format!(
                                                            "pkg={} ch={} content={:?}",
                                                            ch.app_package_name,
                                                            ch.channel_name,
                                                            dmsg.content
                                                        ),
                                                    });
                                                    if let Some(dtdi_message::Content::Payload(
                                                        payload,
                                                    )) = dmsg.content
                                                    {
                                                        if ch.app_package_name == PACKAGE_DTDI
                                                            && ch.channel_name == CHANNEL_WAKEUP
                                                        {
                                                            if let Ok(wm) =
                                                                decode_wakeup_envelope(&payload)
                                                            {
                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                    stage: "dtdi_wakeup_response"
                                                                        .into(),
                                                                    detail: format!("{wm:?}"),
                                                                });
                                                            }
                                                        } else if ch.app_package_name
                                                            == PACKAGE_AMBIENT_STREAMING
                                                        {
                                                            let inner_dl = match dl_reassembler.push(&payload) {
                                                                Ok((Some(full), chunk_meta)) => {
                                                                    if let Some((cid, clen, is_last)) = chunk_meta {
                                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                                            stage: "devicelink_chunk_complete".into(),
                                                                            detail: format!("msg_id={cid} last_chunk_len={clen} total_len={} is_last={is_last}", full.len()),
                                                                        });
                                                                    }
                                                                    full
                                                                }
                                                                Ok((None, chunk_meta)) => {
                                                                    if let Some((cid, clen, is_last)) = chunk_meta {
                                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                                            stage: "devicelink_chunk_rx".into(),
                                                                            detail: format!("msg_id={cid} chunk_len={clen} is_last={is_last}"),
                                                                        });
                                                                    }
                                                                    continue;
                                                                }
                                                                Err(_) => match unwrap_channel_payload(&payload) {
                                                                    Ok(b) => b,
                                                                    Err(_) => payload.clone(),
                                                                },
                                                            };
                                                            match dl_session
                                                                .handle_incoming(&inner_dl)
                                                            {
                                                                Ok(Some(ev)) => {
                                                                    // Avoid dumping huge icon/cert byte arrays into stdout logs
                                                                    let ev_summary = match &ev {
                                                                        DeviceLinkEvent::ResponsePayload { request_id, data, is_stream_end } => {
                                                                            format!("ResponsePayload {{ request_id: {request_id}, len: {}, is_stream_end: {is_stream_end} }}", data.len())
                                                                        }
                                                                        other => format!("{other:?}"),
                                                                    };
                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                        stage: "devicelink_event".into(),
                                                                        detail: ev_summary,
                                                                    });
                                                                    let mut outgoing_dl: Vec<relay_core::devicelink::DeviceLinkPacket> = Vec::new();
                                                                    match ev {
                                                                        DeviceLinkEvent::RemoteServices(svcs) => {
                                                                            if svcs.iter().any(|s| s == SERVICE_NOTIFICATION_SYNC)
                                                                                && notif_stream_req_id.is_none()
                                                                            {
                                                                                let (rid, pkt) = dl_session.build_unary_request(
                                                                                    SERVICE_NOTIFICATION_SYNC,
                                                                                    "ReadNotificationShadeEvents",
                                                                                    Vec::new(),
                                                                                );
                                                                                notif_stream_req_id = Some(rid);
                                                                                outgoing_dl.push(pkt);
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "notif_sync_subscribed".into(),
                                                                                    detail: format!("req_id={rid} ReadNotificationShadeEvents"),
                                                                                });
                                                                            }
                                                                            if svcs.iter().any(|s| s == SERVICE_QUICK_ACCESS)
                                                                                && qa_list_req_id.is_none()
                                                                            {
                                                                                let (srid, spkt) = dl_session.build_unary_request(
                                                                                    SERVICE_QUICK_ACCESS,
                                                                                    "GetDocument",
                                                                                    build_path_request("/"),
                                                                                );
                                                                                qa_stat_req_id = Some(srid);
                                                                                outgoing_dl.push(spkt);
                                                                                let (lrid, lpkt) = dl_session.build_unary_request(
                                                                                    SERVICE_QUICK_ACCESS,
                                                                                    "GetChildDocuments",
                                                                                    build_path_request("/"),
                                                                                );
                                                                                qa_list_req_id = Some(lrid);
                                                                                outgoing_dl.push(lpkt);
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "quick_access_probed".into(),
                                                                                    detail: format!("stat_id={srid} list_id={lrid} path=/"),
                                                                                });
                                                                            }
                                                                            if svcs.iter().any(|s| s == SERVICE_COMPANION_TRANSPORT)
                                                                                && ct_can_form_req_id.is_none()
                                                                            {
                                                                                let (rid, pkt) = dl_session.build_unary_request(
                                                                                    SERVICE_COMPANION_TRANSPORT,
                                                                                    "CanFormCompanionTransportWithDevice",
                                                                                    CompanionTransportBoolMsg { value: Some(false) }.encode_to_vec(),
                                                                                );
                                                                                ct_can_form_req_id = Some(rid);
                                                                                outgoing_dl.push(pkt);
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "companion_transport_probed".into(),
                                                                                    detail: format!("req_id={rid} CanFormCompanionTransportWithDevice"),
                                                                                });
                                                                            }
                                                                        }
                                                                        DeviceLinkEvent::ResponsePayload {
                                                                            request_id,
                                                                            data,
                                                                            is_stream_end,
                                                                        } => {
                                                                            if Some(request_id) == notif_stream_req_id && !data.is_empty() {
                                                                                match NotificationSyncEvent::decode(data.as_slice()) {
                                                                                    Ok(ns) => match ns.event {
                                                                                        Some(relay_core::notifications::notification_sync_event::Event::Initial(p))
                                                                                        | Some(relay_core::notifications::notification_sync_event::Event::Posted(p)) => {
                                                                                            emit(&BridgeEvent::BleWeaveEvent {
                                                                                                stage: "notification_batch".into(),
                                                                                                detail: format!("count={}", p.notifications.len()),
                                                                                            });
                                                                                            for n in p.notifications {
                                                                                                let mut title = n
                                                                                                    .basic_content
                                                                                                    .as_ref()
                                                                                                    .and_then(|b| b.title.clone())
                                                                                                    .unwrap_or_default();
                                                                                                let mut text = n
                                                                                                    .basic_content
                                                                                                    .as_ref()
                                                                                                    .and_then(|b| b.text.clone())
                                                                                                    .unwrap_or_default();
                                                                                                if let Some(bt) = &n.big_text_content {
                                                                                                    if let Some(t) = &bt.big_title {
                                                                                                        if !t.is_empty() {
                                                                                                            title = t.clone();
                                                                                                        }
                                                                                                    }
                                                                                                    if let Some(b) = &bt.big_text {
                                                                                                        if !b.is_empty() {
                                                                                                            text = b.clone();
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                                if let Some(m) = &n.messaging_content {
                                                                                                    if let Some(last) = m.messages.last() {
                                                                                                        let sender = last.sender.as_ref().and_then(|p| p.name.clone()).unwrap_or_default();
                                                                                                        let body = last.text.clone().unwrap_or_default();
                                                                                                        let conv = m.conversation_title.clone().unwrap_or_default();
                                                                                                        if !conv.is_empty() {
                                                                                                            title = conv;
                                                                                                        } else if !sender.is_empty() {
                                                                                                            title = sender.clone();
                                                                                                        }
                                                                                                        if !body.is_empty() {
                                                                                                            text = if !sender.is_empty() && sender != title {
                                                                                                                format!("{sender}: {body}")
                                                                                                            } else {
                                                                                                                body
                                                                                                            };
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                                emit(&BridgeEvent::NotificationSynced {
                                                                                                    key: n.key.unwrap_or_default(),
                                                                                                    package_name: n.package_name.unwrap_or_default(),
                                                                                                    app_name: n.app_name.unwrap_or_default(),
                                                                                                    title,
                                                                                                    text,
                                                                                                });
                                                                                            }
                                                                                        }
                                                                                        Some(relay_core::notifications::notification_sync_event::Event::Removed(r)) => {
                                                                                            emit(&BridgeEvent::BleWeaveEvent {
                                                                                                stage: "notification_removed".into(),
                                                                                                detail: format!("{:?}", r.keys),
                                                                                            });
                                                                                        }
                                                                                        other => {
                                                                                            emit(&BridgeEvent::BleWeaveEvent {
                                                                                                stage: "notification_state".into(),
                                                                                                detail: format!("{other:?}"),
                                                                                            });
                                                                                        }
                                                                                    },
                                                                                    Err(e) => {
                                                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                                                            stage: "notification_decode_err".into(),
                                                                                            detail: format!("{e} hex={}", hex::encode(&data[..data.len().min(96)])),
                                                                                        });
                                                                                    }
                                                                                }
                                                                            } else if Some(request_id) == qa_stat_req_id {
                                                                                match GetDocumentResponse::decode(data.as_slice()) {
                                                                                    Ok(resp) => emit(&BridgeEvent::BleWeaveEvent {
                                                                                        stage: "quick_access_stat".into(),
                                                                                        detail: format!("{resp:?}"),
                                                                                    }),
                                                                                    Err(e) => emit(&BridgeEvent::BleWeaveEvent {
                                                                                        stage: "quick_access_stat_err".into(),
                                                                                        detail: format!("{e} hex={}", hex::encode(&data[..data.len().min(64)])),
                                                                                    }),
                                                                                }
                                                                            } else if Some(request_id) == qa_list_req_id {
                                                                                if !data.is_empty() {
                                                                                    match QuickAccessDocument::decode(data.as_slice()) {
                                                                                        Ok(doc) => {
                                                                                            let path = doc.document_id.clone().unwrap_or_default();
                                                                                            let mime = doc.mime_type.clone().unwrap_or_default();
                                                                                            let size = doc.size.unwrap_or(0);
                                                                                            emit(&BridgeEvent::BleWeaveEvent {
                                                                                                stage: "quick_access_entry".into(),
                                                                                                detail: format!("{path} ({mime}, {size} B)"),
                                                                                            });
                                                                                            // Test live OpenDocument file read on the first regular file
                                                                                            if qa_open_req_id.is_none()
                                                                                                && mime != "vnd.android.document/directory"
                                                                                                && !path.is_empty()
                                                                                            {
                                                                                                let (orid, opkt) = dl_session.build_unary_request(
                                                                                                    SERVICE_QUICK_ACCESS,
                                                                                                    "OpenDocument",
                                                                                                    build_path_request(&path),
                                                                                                );
                                                                                                qa_open_req_id = Some(orid);
                                                                                                outgoing_dl.push(opkt);
                                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                                    stage: "quick_access_open_sent".into(),
                                                                                                    detail: format!("req_id={orid} path={path}"),
                                                                                                });
                                                                                            }
                                                                                        }
                                                                                        Err(e) => emit(&BridgeEvent::BleWeaveEvent {
                                                                                            stage: "quick_access_list_raw".into(),
                                                                                            detail: format!("err={e} len={} hex={}", data.len(), hex::encode(&data[..data.len().min(96)])),
                                                                                        }),
                                                                                    }
                                                                                }
                                                                            } else if Some(request_id) == qa_open_req_id {
                                                                                if let Ok(ch) = OpenDocumentChunk::decode(data.as_slice()) {
                                                                                    let chunk_bytes = ch
                                                                                        .chunk
                                                                                        .as_ref()
                                                                                        .and_then(|c| c.data.as_ref())
                                                                                        .map(|b| b.len())
                                                                                        .unwrap_or(0);
                                                                                    let meta_bytes = ch.metadata.as_ref().map(|b| b.len()).unwrap_or(0);
                                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                                        stage: "quick_access_open_rx".into(),
                                                                                        detail: format!("end={is_stream_end} meta_bytes={meta_bytes} chunk_bytes={chunk_bytes}"),
                                                                                    });
                                                                                }
                                                                            } else if Some(request_id) == ct_can_form_req_id {
                                                                                let can_form = CompanionTransportBoolMsg::decode(data.as_slice())
                                                                                    .ok()
                                                                                    .and_then(|m| m.value)
                                                                                    .unwrap_or(false);
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "companion_transport_can_form".into(),
                                                                                    detail: format!("can_form={can_form} raw={}", hex::encode(&data)),
                                                                                });
                                                                                if can_form && ct_caps_req_id.is_none() {
                                                                                    let (caps_id, caps_start) = dl_session.build_stream_start(
                                                                                        SERVICE_COMPANION_TRANSPORT,
                                                                                        "ExchangeCapabilities",
                                                                                    );
                                                                                    ct_caps_req_id = Some(caps_id);
                                                                                    outgoing_dl.push(caps_start);
                                                                                    outgoing_dl.push(DeviceLinkSession::build_stream_data(
                                                                                        caps_id,
                                                                                        SERVICE_COMPANION_TRANSPORT,
                                                                                        CompanionTransportCapabilityMsg { capability: Some(1) }.encode_to_vec(),
                                                                                    ));
                                                                                    let (data_id, data_start) = dl_session.build_stream_start(
                                                                                        SERVICE_COMPANION_TRANSPORT,
                                                                                        "StartDataTransfer",
                                                                                    );
                                                                                    ct_data_req_id = Some(data_id);
                                                                                    outgoing_dl.push(data_start);
                                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                                        stage: "companion_transport_streams_started".into(),
                                                                                        detail: format!("caps_id={caps_id} data_id={data_id}"),
                                                                                    });
                                                                                }
                                                                            } else if Some(request_id) == ct_caps_req_id {
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "companion_transport_caps_rx".into(),
                                                                                    detail: format!("end={is_stream_end} hex={}", hex::encode(&data)),
                                                                                });
                                                                            } else if Some(request_id) == ct_data_req_id {
                                                                                emit(&BridgeEvent::BleWeaveEvent {
                                                                                    stage: "companion_transport_data_rx".into(),
                                                                                    detail: format!("end={is_stream_end} len={} hex={}", data.len(), hex::encode(&data[..data.len().min(128)])),
                                                                                });
                                                                            }
                                                                        }
                                                                        DeviceLinkEvent::IncomingUnaryCall {
                                                                            request_id,
                                                                            service,
                                                                            method,
                                                                            ..
                                                                        } if service == SERVICE_COMPANION_TRANSPORT
                                                                            && method == "CanFormCompanionTransportWithDevice" =>
                                                                        {
                                                                            outgoing_dl.push(DeviceLinkSession::build_unary_response(
                                                                                request_id,
                                                                                CompanionTransportBoolMsg { value: Some(true) }.encode_to_vec(),
                                                                            ));
                                                                        }
                                                                        DeviceLinkEvent::IncomingStreamData {
                                                                            service,
                                                                            data,
                                                                            ..
                                                                        } => {
                                                                            if service == SERVICE_NOTIFICATION_SYNC {
                                                                                if let Ok(ns) = NotificationSyncEvent::decode(data.as_slice()) {
                                                                                    if let Some(relay_core::notifications::notification_sync_event::Event::Posted(p)) = ns.event {
                                                                                        for n in p.notifications {
                                                                                            let basic = n.basic_content.unwrap_or_default();
                                                                                            emit(&BridgeEvent::NotificationSynced {
                                                                                                key: n.key.unwrap_or_default(),
                                                                                                package_name: n.package_name.unwrap_or_default(),
                                                                                                app_name: n.app_name.unwrap_or_default(),
                                                                                                title: basic.title.unwrap_or_default(),
                                                                                                text: basic.text.unwrap_or_default(),
                                                                                            });
                                                                                        }
                                                                                    }
                                                                                }
                                                                            } else if service == SERVICE_COMPANION_TRANSPORT {
                                                                                if let Ok(tc) = TaskContinuityMessage::decode(data.as_slice()) {
                                                                                    if let Some(p) = tc.payload {
                                                                                        match p {
                                                                                            relay_core::continuity::task_continuity_message::Payload::ClipboardTransferStart(s) => {
                                                                                                clip_reassembler.start_transfer(&s);
                                                                                            }
                                                                                            relay_core::continuity::task_continuity_message::Payload::ClipboardTransferChunk(c) => {
                                                                                                if let Ok(Some(clip)) = clip_reassembler.push_chunk(&c) {
                                                                                                    if let Some(item) = clip.items.first() {
                                                                                                        if let Some(text) = &item.text {
                                                                                                            emit(&BridgeEvent::ClipboardReceived {
                                                                                                                text: text.clone(),
                                                                                                                timestamp_ms: clip.timestamp_ms,
                                                                                                            });
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            _ => {}
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        _ => {}
                                                                    }
                                                                    for pkt in outgoing_dl {
                                                                        let wrapped = build_app_channel_message(
                                                                            PACKAGE_AMBIENT_STREAMING,
                                                                            &ch.channel_name,
                                                                            2, // SENDER_INCOMING_CHANNEL
                                                                            pkt.encode_to_vec(),
                                                                        );
                                                                        next_ble_payload_id += 1;
                                                                        for cframe in build_bytes_payload_frames(next_ble_payload_id, &wrapped) {
                                                                            let cenc = d2d.encrypt_message(&cframe.encode_to_vec());
                                                                            if let Some(ref mut tcp) = upgraded_tcp {
                                                                                write_framed(tcp, &cenc).await.map_err(|e| e.to_string())?;
                                                                            } else {
                                                                                let cble = build_ble_v2_data(shash, &cenc);
                                                                                send_weave_msg(
                                                                                    &mut child_stdin,
                                                                                    &mut lines,
                                                                                    &mut framer,
                                                                                    &mut pending_rx_messages,
                                                                                    &cble,
                                                                                )
                                                                                .await?;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                Ok(None) => {
                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                        stage: "devicelink_none".into(),
                                                                        detail: format!("len={} hex={}", inner_dl.len(), hex::encode(&inner_dl[..inner_dl.len().min(64)])),
                                                                    });
                                                                }
                                                                Err(e) => {
                                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                                        stage: "devicelink_decode_err".into(),
                                                                        detail: format!("{e} raw={}", hex::encode(&payload)),
                                                                    });
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                        stage: "dtdi_decode_err".into(),
                                                        detail: format!(
                                                            "{e} raw={}",
                                                            hex::encode(&full_body)
                                                        ),
                                                    });
                                                }
                                            }
                                        } else if let Ok(decoded) =
                                            decode_tether_envelope(&full_body)
                                        {
                                            emit(&BridgeEvent::BleWeaveEvent {
                                                stage: "tether_message".into(),
                                                detail: format!("{decoded:?}"),
                                            });
                                            match decoded {
                                                DecodedTetherMessage::AvailabilityResponse(av) => {
                                                    let code = av.response_code.unwrap_or(0);
                                                    let dev = av
                                                        .device_status_raw
                                                        .as_deref()
                                                        .and_then(|b| DeviceStatus::decode(b).ok());
                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                        stage: "hotspot_availability".into(),
                                                        detail: format!(
                                                            "code={} ({}) device={:?} battery={:?}% carrier={:?} bars={:?} wifi_conn={:?} cell_data={:?}",
                                                            code,
                                                            availability_response_code_name(code),
                                                            dev.as_ref().and_then(|d| d.device_name.as_deref()),
                                                            dev.as_ref().and_then(|d| d.battery_percentage),
                                                            dev.as_ref().and_then(|d| d.cell_provider.as_deref()),
                                                            dev.as_ref().and_then(|d| d.connection_strength),
                                                            dev.as_ref().and_then(|d| d.is_wifi_connected),
                                                            dev.as_ref().and_then(|d| d.is_cell_data_available),
                                                        ),
                                                    });
                                                    if let Some(wifi) = &av.nearby_wifi_status {
                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                            stage: "nearby_wifi_share".into(),
                                                            detail: format!(
                                                                "status_code={:?} ssid={:?} has_password={} password_len={} security_types={:?} hidden={:?}",
                                                                wifi.status_code,
                                                                wifi.ssid.as_deref().map(|s| s.trim_matches('"')),
                                                                wifi.password.as_deref().map(|p| !p.is_empty()).unwrap_or(false),
                                                                wifi.password.as_deref().map(|p| p.trim_matches('"').len()).unwrap_or(0),
                                                                wifi.security_types,
                                                                wifi.is_hidden_ssid,
                                                            ),
                                                        });
                                                    }
                                                    if request_hotspot && !connect_tethering_sent {
                                                        connect_tethering_sent = true;
                                                        let connect_req =
                                                            build_connect_tethering_request();
                                                        for cframe in build_bytes_payload_frames(
                                                            2,
                                                            &connect_req,
                                                        ) {
                                                            let cenc = d2d.encrypt_message(
                                                                &cframe.encode_to_vec(),
                                                            );
                                                            let cble =
                                                                build_ble_v2_data(shash, &cenc);
                                                            send_weave_msg(
                                                                &mut child_stdin,
                                                                &mut lines,
                                                                &mut framer,
                                                                &mut pending_rx_messages,
                                                                &cble,
                                                            )
                                                            .await?;
                                                        }
                                                        emit(&BridgeEvent::BleWeaveEvent {
                                                            stage: "instant_hotspot_connect_sent"
                                                                .into(),
                                                            detail: r#"sent {"type":3,"data":""} (ConnectTetheringRequest)"#.into(),
                                                        });
                                                    }
                                                }
                                                DecodedTetherMessage::ConnectResponse(resp) => {
                                                    let code = resp.response_code.unwrap_or(0);
                                                    if let Some((ssid, password, security_type)) =
                                                        resp.credentials()
                                                    {
                                                        emit(&BridgeEvent::HotspotCredentials {
                                                            ssid,
                                                            password,
                                                            security_type,
                                                            bssid: resp
                                                                .instant_hotspot_status
                                                                .and_then(|s| s.bssid),
                                                        });
                                                        break;
                                                    }
                                                    emit(&BridgeEvent::BleWeaveEvent {
                                                        stage: "hotspot_connect_failed".into(),
                                                        detail: format!(
                                                            "response_code={} ({})",
                                                            code,
                                                            connect_response_code_name(code)
                                                        ),
                                                    });
                                                    break;
                                                }
                                                _ => {}
                                            }
                                        } else {
                                            emit(&BridgeEvent::BleWeaveEvent {
                                                stage: "tether_payload_raw".into(),
                                                detail: String::from_utf8_lossy(&full_body)
                                                    .to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        emit(&BridgeEvent::BleWeaveEvent {
                            stage: "decrypted_peer_raw".into(),
                            detail: hex::encode(&plain),
                        });
                    }
                }
                Err(e) => {
                    emit(&BridgeEvent::BleWeaveEvent {
                        stage: "raw_peer_frame".into(),
                        detail: format!("decrypt err={e}, raw_hex={}", hex::encode(&enc)),
                    });
                }
            },
            Err(e) => {
                emit(&BridgeEvent::BleWeaveEvent {
                    stage: "rx_ended".into(),
                    detail: e,
                });
                break;
            }
        }
    }

    let _ = child.kill().await;
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let creds_path: Option<PathBuf> = args
        .windows(2)
        .find(|w| w[0] == "--credentials")
        .map(|w| PathBuf::from(&w[1]));

    let (device_id, device_name, derived_keys): (String, String, Vec<DerivedPresenceKey>) =
        if let Some(path) = creds_path {
            match fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str::<CredentialsFile>(&s).map_err(|e| e.to_string()))
            {
                Ok(cfg) => {
                    let mut keys = Vec::new();
                    for c in cfg.shared_credentials {
                        match c.derive_keys() {
                            Ok(k) => keys.push(k),
                            Err(e) => emit(&BridgeEvent::Error {
                                message: format!("Invalid credential {}: {e}", c.device_name),
                            }),
                        }
                    }
                    (cfg.device_id, cfg.device_name, keys)
                }
                Err(e) => {
                    emit(&BridgeEvent::Error {
                        message: format!("Failed to load credentials {}: {e}", path.display()),
                    });
                    return;
                }
            }
        } else {
            ("relay-mac".to_string(), "Mac".to_string(), Vec::new())
        };

    emit(&BridgeEvent::Ready {
        device_id: device_id.clone(),
        loaded_credentials: derived_keys.len(),
    });

    let mut dl = DeviceLinkSession::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cmd: BridgeCommand = match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                emit(&BridgeEvent::Error {
                    message: format!("Invalid JSON command: {e}"),
                });
                continue;
            }
        };

        match cmd {
            BridgeCommand::BlePresenceAdv {
                peripheral_id,
                rssi,
                service_data_hex,
            } => match hex::decode(service_data_hex.trim()) {
                Ok(raw) => match decrypt_presence_advertisement(&raw, &derived_keys) {
                    Ok(adv) => {
                        let action_bits_hex = adv
                            .data_elements
                            .iter()
                            .find_map(|de| match de {
                                relay_core::presence::DataElement::ActionBits(b) => {
                                    Some(hex::encode(b))
                                }
                                _ => None,
                            })
                            .unwrap_or_default();
                        emit(&BridgeEvent::PresenceMatched {
                            peripheral_id,
                            rssi,
                            device_name: adv.device_name,
                            device_id: adv.device_id,
                            action_bits_hex,
                            instant_hotspot_available: adv.instant_hotspot_available,
                            cross_device_available: adv.cross_device_available,
                        });
                    }
                    Err(e) => emit(&BridgeEvent::PresenceUnmatched {
                        peripheral_id,
                        reason: e.to_string(),
                    }),
                },
                Err(e) => emit(&BridgeEvent::Error {
                    message: format!("Invalid hex: {e}"),
                }),
            },
            BridgeCommand::ConnectLan {
                host,
                port,
                service_id,
            } => {
                let svc = service_id.unwrap_or_else(|| SERVICE_ID_SHARED_CONNECTIVITY.to_string());
                if let Err(e) = run_lan_session(&host, port, &device_id, &device_name, &svc).await {
                    emit(&BridgeEvent::Error { message: e });
                }
            }
            BridgeCommand::ConnectBleWeave {
                peripheral_id,
                service_id,
                mac_bridge_path,
                peer_device_id,
                request_hotspot,
            } => {
                let svc = service_id.unwrap_or_else(|| SERVICE_ID_DTDI.to_string());
                let bridge = mac_bridge_path.unwrap_or_else(|| "./bridge/RelayBridge".to_string());
                let peer_key_seed = if let Some(ref pid) = peer_device_id {
                    derived_keys
                        .iter()
                        .find(|k| k.device_id == *pid || k.device_name == *pid)
                        .map(|k| k.authenticity_key)
                } else {
                    derived_keys.first().map(|k| k.authenticity_key)
                };
                if let Err(e) = run_ble_weave_session(
                    &peripheral_id,
                    &svc,
                    &bridge,
                    &device_id,
                    &device_name,
                    peer_key_seed,
                    request_hotspot.unwrap_or(true),
                )
                .await
                {
                    emit(&BridgeEvent::Error { message: e });
                }
            }
            BridgeCommand::EncodeClipboard { text } => {
                let clip = EncodedClipData {
                    label: Some("macOS Clipboard".into()),
                    is_sensitive: false,
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0),
                    items: vec![EncodedClipDataItem {
                        text: Some(text),
                        html_text: None,
                        uri: None,
                    }],
                };
                let msgs = encode_clipboard_transfer(&device_id, &device_name, &clip, 16 * 1024);
                let frames_hex = msgs
                    .into_iter()
                    .map(|m| hex::encode(m.encode_to_vec()))
                    .collect();
                emit(&BridgeEvent::EncodedFrames {
                    kind: "task_continuity_clipboard".into(),
                    frames_hex,
                });
            }
            BridgeCommand::EncodeQuickReply {
                notification_key,
                action_index,
                reply_text,
            } => {
                let inner = build_quick_reply(&notification_key, action_index, &reply_text);
                let (_, pkt) =
                    dl.build_unary_request(SERVICE_NOTIFICATION_SYNC, "ExecuteRemoteAction", inner);
                emit(&BridgeEvent::EncodedFrames {
                    kind: "notification_quick_reply".into(),
                    frames_hex: vec![hex::encode(pkt.encode_to_vec())],
                });
            }
            BridgeCommand::EncodeDismiss { notification_key } => {
                let inner = build_dismiss(&notification_key);
                let (_, pkt) =
                    dl.build_unary_request(SERVICE_NOTIFICATION_SYNC, "ExecuteRemoteAction", inner);
                emit(&BridgeEvent::EncodedFrames {
                    kind: "notification_dismiss".into(),
                    frames_hex: vec![hex::encode(pkt.encode_to_vec())],
                });
            }
            BridgeCommand::EncodeHotspotRequest => {
                let req = build_connect_tethering_request();
                emit(&BridgeEvent::EncodedFrames {
                    kind: "instant_hotspot_request".into(),
                    frames_hex: vec![hex::encode(req)],
                });
            }
        }
    }
}
