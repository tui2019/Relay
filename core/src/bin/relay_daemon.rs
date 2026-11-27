//! `relay-daemon`: Persistent cross-device daemon for `Relay.app`.
//!
//! Coordinates:
//! 1. BLE Nearby Presence (`0xFCF1`) scanning via `RelayBridge scan`
//! 2. Instant Hotspot & Instant Wi-Fi (`nearby.sharedconnectivity`) probe + trigger + `CoreWLAN` join
//! 3. Persistent Wi-Fi LAN `DeviceLink` (`com.google.android.gms.dtdi`) for:
//!    - Live Notification Sync (`NotificationSyncRpcService`: stream + Dismiss + Quick Reply)
//!    - Live `/sdcard` WebDAV Finder mount (`QuickAccessService` -> `http://127.0.0.1:<port>/`)

use relay_core::devicelink::{
    DeviceLinkChunkReassembler, DeviceLinkEvent, DeviceLinkSession, SERVICE_NOTIFICATION_SYNC,
    SERVICE_QUICK_ACCESS,
};
use relay_core::dtdi::{
    build_app_channel_message, build_devicelink_wakeup_message, decode_dtdi_message, dtdi_message,
    unwrap_channel_payload, PACKAGE_AMBIENT_STREAMING,
};
use relay_core::google_auth::{
    exchange_oauth_token, generate_android_id, sync_nearby_presence, write_secret_file,
    GoogleAccountSession,
};
use relay_core::hotspot::{
    build_availability_request, build_connect_tethering_request, build_disconnect_tethering_request,
    connect_response_code_name, decode_tether_envelope, DecodedTetherMessage, DeviceStatus,
    InstantHotspotStatusCode,
};
use relay_core::nearby_connections::{
    build_authentication_message, build_authentication_result, build_bwu_client_introduction,
    build_bwu_event, build_bytes_payload_frames, build_connection_response, build_keep_alive,
    build_presence_connection_request, OfflineFrame, SERVICE_ID_SHARED_CONNECTIVITY,
};
use relay_core::notifications::{build_dismiss, build_quick_reply, NotificationSyncEvent};
use relay_core::presence::{
    build_one_way_presence_auth_message, decrypt_presence_advertisement, DerivedPresenceKey,
    SharedCredential,
};
use relay_core::quickaccess::{
    build_create_request, build_move_request, build_path_request, build_rename_request,
    build_write_stream_messages, DocumentMutationResponse, GetDocumentResponse, OpenDocumentChunk,
    QuickAccessDocument, SimpleBoolResponse,
};
use relay_core::ukey2::{D2DConnectionContext, Ukey2Initiator};
use relay_core::weave::{
    build_ble_v2_ack, build_ble_v2_data, build_ble_v2_introduction, service_id_hash,
    SocketControlFrame, WeaveFramer, WeaveRxEvent, SERVICE_ID_DTDI,
};
use relay_core::webdav::{serve_webdav, QuickAccessClient, QuickAccessRpc};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

#[derive(Debug, Serialize, Deserialize)]
struct CredentialsFile {
    device_id: String,
    device_name: String,
    shared_credentials: Vec<SharedCredential>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum DaemonCommand {
    StartHotspot,
    StopHotspot,
    ConnectPhoneWifi,
    ProbeTether,
    DismissNotification {
        key: String,
    },
    ReplyNotification {
        key: String,
        action_index: Option<i32>,
        text: String,
    },
    Reconnect,
    GoogleLogin {
        oauth_token: String,
    },
    SyncCredentials,
    GoogleSignOut,
}

#[derive(Debug, Clone, Serialize)]
struct StatusSnapshot {
    event: &'static str,
    device_name: String,
    ble_nearby: bool,
    devicelink_connected: bool,
    rssi: Option<i32>,
    battery_percent: Option<i32>,
    cell_provider: Option<String>,
    hotspot_available: bool,
    hotspot_active: bool,
    hotspot_ssid: Option<String>,
    wifi_share_available: bool,
    wifi_share_ssid: Option<String>,
    webdav_url: String,
    busy_action: Option<String>,
    signed_in: bool,
    account_email: Option<String>,
    credential_count: usize,
    last_sync_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum DaemonEvent {
    NotificationPosted {
        key: String,
        package_name: String,
        app_name: String,
        title: String,
        text: String,
        can_reply: bool,
        reply_action_index: i32,
        is_initial: bool,
    },
    NotificationRemoved {
        keys: Vec<String>,
    },
    ActionResult {
        action: String,
        ok: bool,
        message: String,
    },
    Log {
        message: String,
    },
}

fn emit_json<T: Serialize>(v: &T) {
    if let Ok(s) = serde_json::to_string(v) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{s}");
        let _ = out.flush();
    }
}

fn log_msg(msg: impl Into<String>) {
    emit_json(&DaemonEvent::Log {
        message: msg.into(),
    });
}

#[derive(Default)]
struct SharedState {
    device_name: String,
    peer_device_id: String,
    peer_key_seed: Option<[u8; 32]>,
    peripheral_id: Option<String>,
    ble_nearby: bool,
    devicelink_connected: bool,
    rssi: Option<i32>,
    instant_hotspot_flag: bool,
    battery_percent: Option<i32>,
    cell_provider: Option<String>,
    hotspot_available: bool,
    hotspot_active: bool,
    hotspot_ssid: Option<String>,
    wifi_share_available: bool,
    wifi_share_ssid: Option<String>,
    wifi_share_password: Option<String>,
    webdav_url: String,
    busy_action: Option<String>,
    signed_in: bool,
    account_email: Option<String>,
    credential_count: usize,
    last_sync_unix: Option<u64>,
}

impl SharedState {
    fn emit_status(&self) {
        emit_json(&StatusSnapshot {
            event: "status",
            device_name: if self.device_name.is_empty() {
                "Android Phone".into()
            } else {
                self.device_name.clone()
            },
            ble_nearby: self.ble_nearby,
            devicelink_connected: self.devicelink_connected,
            rssi: self.rssi,
            battery_percent: self.battery_percent,
            cell_provider: self.cell_provider.clone(),
            hotspot_available: self.hotspot_available || self.instant_hotspot_flag,
            hotspot_active: self.hotspot_active,
            hotspot_ssid: self.hotspot_ssid.clone(),
            wifi_share_available: self.wifi_share_available,
            wifi_share_ssid: self.wifi_share_ssid.clone(),
            webdav_url: self.webdav_url.clone(),
            busy_action: self.busy_action.clone(),
            signed_in: self.signed_in,
            account_email: self.account_email.clone(),
            credential_count: self.credential_count,
            last_sync_unix: self.last_sync_unix,
        });
    }
}

enum NotifAction {
    Dismiss {
        key: String,
    },
    Reply {
        key: String,
        action_index: i32,
        text: String,
    },
}

enum PendingQaRpc {
    GetDoc(oneshot::Sender<Result<QuickAccessDocument, String>>),
    GetChildren(
        Vec<QuickAccessDocument>,
        oneshot::Sender<Result<Vec<QuickAccessDocument>, String>>,
    ),
    OpenDoc(Vec<u8>, oneshot::Sender<Result<Vec<u8>, String>>),
    DocMutation(oneshot::Sender<Result<QuickAccessDocument, String>>),
    BoolMutation(oneshot::Sender<Result<(), String>>),
}

// ---------------------------------------------------------------------------
// Low-level framed TCP & BLE Weave helpers
// ---------------------------------------------------------------------------

async fn write_framed_half(stream: &mut OwnedWriteHalf, payload: &[u8]) -> Result<(), String> {
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| format!("TCP write len: {e}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("TCP write body: {e}"))?;
    stream.flush().await.map_err(|e| format!("TCP flush: {e}"))
}

async fn read_framed_half(stream: &mut OwnedReadHalf) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("TCP read len: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 8 * 1024 * 1024 {
        return Err(format!("TCP frame too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("TCP read body: {e}"))?;
    Ok(buf)
}

async fn write_framed(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| format!("TCP write len: {e}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("TCP write body: {e}"))?;
    stream.flush().await.map_err(|e| format!("TCP flush: {e}"))
}

async fn read_framed(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("TCP read len: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 8 * 1024 * 1024 {
        return Err(format!("TCP frame too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("TCP read body: {e}"))?;
    Ok(buf)
}

struct BleWeaveConn {
    child: Child,
    stdin: ChildStdin,
    lines: tokio::io::Lines<BufReader<ChildStdout>>,
    framer: WeaveFramer,
    pending_rx: VecDeque<Vec<u8>>,
    rx_ble_buf: Vec<u8>,
    shash: [u8; 3],
    d2d: D2DConnectionContext,
    ep_id: String,
}

impl BleWeaveConn {
    async fn next_mac_event(
        lines: &mut tokio::io::Lines<BufReader<ChildStdout>>,
    ) -> Result<serde_json::Value, String> {
        match tokio::time::timeout(Duration::from_secs(22), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                serde_json::from_str(&line).map_err(|e| format!("bad mac JSON: {e}"))
            }
            Ok(Ok(None)) => Err("RelayBridge closed stdout".into()),
            Ok(Err(e)) => Err(format!("RelayBridge read error: {e}")),
            Err(_) => Err("BLE Weave timeout".into()),
        }
    }

    async fn send_gatt_packet(
        stdin: &mut ChildStdin,
        lines: &mut tokio::io::Lines<BufReader<ChildStdout>>,
        framer: &mut WeaveFramer,
        pending_rx: &mut VecDeque<Vec<u8>>,
        got_confirm: &mut bool,
        pkt: &[u8],
    ) -> Result<(), String> {
        let cmd = format!("write {}\n", hex::encode(pkt));
        stdin
            .write_all(cmd.as_bytes())
            .await
            .map_err(|e| format!("weave_tx write: {e}"))?;
        stdin.flush().await.map_err(|e| e.to_string())?;
        loop {
            let ev = Self::next_mac_event(lines).await?;
            match ev.get("event").and_then(|v| v.as_str()) {
                Some("weave_tx_ack") => {
                    let err = ev.get("error").and_then(|e| e.as_str()).unwrap_or("");
                    if !err.is_empty() {
                        return Err(format!("GATT write error: {err}"));
                    }
                    return Ok(());
                }
                Some("weave_tx_error") => return Err(format!("weave_tx_error: {ev}")),
                Some("weave_rx") => {
                    let hx = ev.get("value_hex").and_then(|v| v.as_str()).unwrap_or("");
                    if let Ok(raw) = hex::decode(hx) {
                        match framer.feed_rx(&raw) {
                            Ok(WeaveRxEvent::DataMessage(msg)) => pending_rx.push_back(msg),
                            Ok(WeaveRxEvent::ConnectionConfirm { .. }) => *got_confirm = true,
                            _ => {}
                        }
                    }
                }
                Some("ble_disconnected") => return Err("BLE disconnected during TX".into()),
                _ => {}
            }
        }
    }

    async fn send_weave_msg(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut dummy_confirm = true;
        for pkt in self.framer.packetize_data(payload) {
            Self::send_gatt_packet(
                &mut self.stdin,
                &mut self.lines,
                &mut self.framer,
                &mut self.pending_rx,
                &mut dummy_confirm,
                &pkt,
            )
            .await?;
        }
        Ok(())
    }

    async fn recv_ble_frame(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if self.rx_ble_buf.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.rx_ble_buf[0],
                    self.rx_ble_buf[1],
                    self.rx_ble_buf[2],
                    self.rx_ble_buf[3],
                ]) as usize;
                if self.rx_ble_buf.len() >= 4 + len {
                    let frame = self.rx_ble_buf[4..4 + len].to_vec();
                    self.rx_ble_buf.drain(..4 + len);
                    return Ok(frame);
                }
            }
            let raw_weave = if let Some(m) = self.pending_rx.pop_front() {
                m
            } else {
                loop {
                    let ev = Self::next_mac_event(&mut self.lines).await?;
                    match ev.get("event").and_then(|e| e.as_str()) {
                        Some("weave_rx") => {
                            let hx = ev.get("value_hex").and_then(|v| v.as_str()).unwrap_or("");
                            let raw = hex::decode(hx).map_err(|e| e.to_string())?;
                            match self.framer.feed_rx(&raw).map_err(|e| e.to_string())? {
                                WeaveRxEvent::DataMessage(msg) => break msg,
                                WeaveRxEvent::Incomplete
                                | WeaveRxEvent::ConnectionConfirm { .. } => continue,
                            }
                        }
                        Some("ble_disconnected") => return Err("BLE disconnected".into()),
                        _ => continue,
                    }
                }
            };
            if raw_weave.len() < 3 {
                continue;
            }
            if &raw_weave[..3] == b"\x00\x00\x00" {
                if let Ok(ctrl) = SocketControlFrame::decode(&raw_weave[3..]) {
                    if ctrl.r#type == Some(2) {
                        return Err(format!(
                            "Peer disconnected BLE service {}",
                            hex::encode(self.shash)
                        ));
                    }
                }
                continue;
            }
            if raw_weave[..3] == self.shash {
                let chunk = &raw_weave[3..];
                self.rx_ble_buf.extend_from_slice(chunk);
                let ack = build_ble_v2_ack(self.shash, chunk.len() as i32);
                let _ = self.send_weave_msg(&ack).await;
            }
        }
    }

    async fn connect(
        mac_bridge: &str,
        peripheral_id: &str,
        service_id: &str,
        device_id: &str,
        device_name: &str,
        peer_key_seed: [u8; 32],
    ) -> Result<Self, String> {
        let mut child = Command::new(mac_bridge)
            .arg("weave")
            .arg(peripheral_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to spawn RelayBridge weave: {e}"))?;

        let mut stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let mut lines = BufReader::new(stdout).lines();
        let mut framer = WeaveFramer::new(20);
        let mut pending_rx = VecDeque::new();
        let rx_ble_buf = Vec::new();
        let shash = service_id_hash(service_id);

        let max_write_len: u16;
        loop {
            let ev = Self::next_mac_event(&mut lines).await?;
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

        let mut got_confirm = false;
        let conn_req = framer.build_connection_request(max_write_len);
        Self::send_gatt_packet(
            &mut stdin,
            &mut lines,
            &mut framer,
            &mut pending_rx,
            &mut got_confirm,
            &conn_req,
        )
        .await?;

        while !got_confirm {
            let ev = Self::next_mac_event(&mut lines).await?;
            if ev.get("event").and_then(|e| e.as_str()) == Some("weave_rx") {
                let hx = ev.get("value_hex").and_then(|v| v.as_str()).unwrap_or("");
                let raw = hex::decode(hx).map_err(|e| e.to_string())?;
                if let WeaveRxEvent::ConnectionConfirm { .. } =
                    framer.feed_rx(&raw).map_err(|e| e.to_string())?
                {
                    got_confirm = true;
                }
            }
        }

        // BLE v2 introduction
        let intro = build_ble_v2_introduction(shash);
        for pkt in framer.packetize_data(&intro) {
            Self::send_gatt_packet(
                &mut stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx,
                &mut got_confirm,
                &pkt,
            )
            .await?;
        }

        // Presence CONNECTION_REQUEST (use a fresh random 4-char endpoint_id per session so
        // rapid reconnects never collide with a stale NearbyConnections endpoint slot!)
        let ep_id: String = (0..4)
            .map(|_| {
                let idx = (rand::random::<u8>() % 36) as usize;
                b"abcdefghijklmnopqrstuvwxyz0123456789"[idx] as char
            })
            .collect();
        let numeric_id: i64 = device_id.parse().unwrap_or(1_234_567_890);
        let nc_req =
            build_presence_connection_request(&ep_id, numeric_id, device_name, rand::random());
        let nc_req_ble = build_ble_v2_data(shash, &nc_req.encode_to_vec());
        for pkt in framer.packetize_data(&nc_req_ble) {
            Self::send_gatt_packet(
                &mut stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx,
                &mut got_confirm,
                &pkt,
            )
            .await?;
        }

        // UKEY2 CLIENT_INIT
        let (initiator, client_init) = Ukey2Initiator::start();
        let ci_ble = build_ble_v2_data(shash, &client_init);
        for pkt in framer.packetize_data(&ci_ble) {
            Self::send_gatt_packet(
                &mut stdin,
                &mut lines,
                &mut framer,
                &mut pending_rx,
                &mut got_confirm,
                &pkt,
            )
            .await?;
        }

        // Temporary struct for clean recv_ble_frame during UKEY2/Presence auth
        let dummy_d2d = {
            // Read SERVER_INIT
            let mut conn_pre = BlePreAuth {
                stdin,
                lines,
                framer,
                pending_rx,
                rx_ble_buf,
                shash,
            };
            let server_init = conn_pre.recv_ble_frame().await?;
            let (client_finish, d2d) = initiator
                .handle_server_init(&server_init)
                .map_err(|e| format!("UKEY2 SERVER_INIT: {e}"))?;
            let cf_ble = build_ble_v2_data(shash, &client_finish);
            conn_pre.send_weave_msg(&cf_ble).await?;

            // Presence one-way authentication (plaintext before encryption)
            let auth_payload = build_one_way_presence_auth_message(&d2d.auth_string, &peer_key_seed);
            let auth_ble = build_ble_v2_data(shash, &build_authentication_message(auth_payload).encode_to_vec());
            conn_pre.send_weave_msg(&auth_ble).await?;

            let peer_auth_raw = conn_pre.recv_ble_frame().await?;
            let peer_auth = OfflineFrame::decode(peer_auth_raw.as_slice())
                .map_err(|e| format!("decode peer auth: {e}"))?;
            if peer_auth.v1.as_ref().and_then(|v| v.r#type) != Some(8) {
                let _ = child.kill().await;
                return Err(format!("Peer rejected Presence auth: {peer_auth:?}"));
            }
            let res_ble = build_ble_v2_data(shash, &build_authentication_result(1).encode_to_vec());
            conn_pre.send_weave_msg(&res_ble).await?;
            let peer_res_raw = conn_pre.recv_ble_frame().await?;
            let peer_res = OfflineFrame::decode(peer_res_raw.as_slice())
                .map_err(|e| format!("decode peer auth result: {e}"))?;
            let st = peer_res
                .v1
                .as_ref()
                .and_then(|v| v.authentication_result.as_ref())
                .and_then(|r| r.result)
                .unwrap_or(-1);
            if st != 1 && st != 0 {
                let _ = child.kill().await;
                return Err(format!("Peer Presence auth status={st}"));
            }

            // Plaintext CONNECTION_RESPONSE(ACCEPT)
            let acc_ble = build_ble_v2_data(shash, &build_connection_response(true).encode_to_vec());
            conn_pre.send_weave_msg(&acc_ble).await?;
            loop {
                let pr = conn_pre.recv_ble_frame().await?;
                let pf = OfflineFrame::decode(pr.as_slice()).map_err(|e| e.to_string())?;
                match pf.v1.as_ref().and_then(|v| v.r#type) {
                    Some(2) => break,
                    Some(5) => {
                        let ka = pf.v1.as_ref().and_then(|v| v.keep_alive.as_ref());
                        if !ka.and_then(|k| k.ack).unwrap_or(false) {
                            let ack = build_keep_alive(true, ka.and_then(|k| k.seq_num));
                            conn_pre
                                .send_weave_msg(&build_ble_v2_data(shash, &ack.encode_to_vec()))
                                .await?;
                        }
                    }
                    Some(6) => {
                        let _ = child.kill().await;
                        return Err("Peer disconnected before CONNECTION_RESPONSE".into());
                    }
                    _ => {}
                }
            }
            (conn_pre, d2d)
        };

        let (pre, d2d) = dummy_d2d;
        Ok(Self {
            child,
            stdin: pre.stdin,
            lines: pre.lines,
            framer: pre.framer,
            pending_rx: pre.pending_rx,
            rx_ble_buf: pre.rx_ble_buf,
            shash: pre.shash,
            d2d,
            ep_id,
        })
    }

    async fn close(mut self) {
        // Send encrypted DISCONNECTION frame so GMS NearbyHostWrapper releases the peer cleanly!
        let disc = OfflineFrame {
            version: Some(1),
            v1: Some(relay_core::nearby_connections::V1Frame {
                r#type: Some(6),
                disconnection: Some(relay_core::nearby_connections::DisconnectionFrame {
                    request_safe_to_disconnect: Some(false),
                }),
                ..Default::default()
            }),
        };
        let disc_enc = self.d2d.encrypt_message(&disc.encode_to_vec());
        let _ = tokio::time::timeout(
            Duration::from_millis(800),
            self.send_weave_msg(&build_ble_v2_data(self.shash, &disc_enc)),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = self.child.kill().await;
    }
}

struct BlePreAuth {
    stdin: ChildStdin,
    lines: tokio::io::Lines<BufReader<ChildStdout>>,
    framer: WeaveFramer,
    pending_rx: VecDeque<Vec<u8>>,
    rx_ble_buf: Vec<u8>,
    shash: [u8; 3],
}

impl BlePreAuth {
    async fn send_weave_msg(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut dummy_confirm = true;
        for pkt in self.framer.packetize_data(payload) {
            BleWeaveConn::send_gatt_packet(
                &mut self.stdin,
                &mut self.lines,
                &mut self.framer,
                &mut self.pending_rx,
                &mut dummy_confirm,
                &pkt,
            )
            .await?;
        }
        Ok(())
    }

    async fn recv_ble_frame(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if self.rx_ble_buf.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.rx_ble_buf[0],
                    self.rx_ble_buf[1],
                    self.rx_ble_buf[2],
                    self.rx_ble_buf[3],
                ]) as usize;
                if self.rx_ble_buf.len() >= 4 + len {
                    let frame = self.rx_ble_buf[4..4 + len].to_vec();
                    self.rx_ble_buf.drain(..4 + len);
                    return Ok(frame);
                }
            }
            let raw_weave = if let Some(m) = self.pending_rx.pop_front() {
                m
            } else {
                loop {
                    let ev = BleWeaveConn::next_mac_event(&mut self.lines).await?;
                    match ev.get("event").and_then(|e| e.as_str()) {
                        Some("weave_rx") => {
                            let hx = ev.get("value_hex").and_then(|v| v.as_str()).unwrap_or("");
                            let raw = hex::decode(hx).map_err(|e| e.to_string())?;
                            match self.framer.feed_rx(&raw).map_err(|e| e.to_string())? {
                                WeaveRxEvent::DataMessage(msg) => break msg,
                                WeaveRxEvent::Incomplete
                                | WeaveRxEvent::ConnectionConfirm { .. } => continue,
                            }
                        }
                        Some("ble_disconnected") => return Err("BLE disconnected".into()),
                        _ => continue,
                    }
                }
            };
            if raw_weave.len() < 3 {
                continue;
            }
            if &raw_weave[..3] == b"\x00\x00\x00" {
                if let Ok(ctrl) = SocketControlFrame::decode(&raw_weave[3..]) {
                    if ctrl.r#type == Some(2) {
                        return Err(format!(
                            "Peer disconnected BLE service {}",
                            hex::encode(self.shash)
                        ));
                    }
                }
                continue;
            }
            if raw_weave[..3] == self.shash {
                let chunk = &raw_weave[3..];
                self.rx_ble_buf.extend_from_slice(chunk);
                let ack = build_ble_v2_ack(self.shash, chunk.len() as i32);
                let _ = self.send_weave_msg(&ack).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BLE Scan once to find Android phone
// ---------------------------------------------------------------------------

struct FoundPeer {
    peripheral_id: String,
    device_name: String,
    device_id: String,
    key_seed: [u8; 32],
    rssi: i32,
    instant_hotspot_available: bool,
}

async fn scan_for_phone(
    mac_bridge: &str,
    keys: &[DerivedPresenceKey],
    timeout_secs: u64,
) -> Option<FoundPeer> {
    let mut child = Command::new(mac_bridge)
        .arg("scan")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let mut lines = BufReader::new(stdout).lines();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut found = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(600), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                    if v.get("event").and_then(|e| e.as_str()) == Some("bluetooth_state") {
                        let st = v.get("state").and_then(|s| s.as_i64()).unwrap_or(-1);
                        if st == 3 {
                            log_msg("macOS Bluetooth permission denied (CBManagerStateUnauthorized): allow Relay in System Settings -> Privacy & Security -> Bluetooth");
                            break;
                        }
                    }
                    if v.get("cmd").and_then(|c| c.as_str()) == Some("ble_presence_adv") {
                        let pid = v
                            .get("peripheral_id")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string();
                        let rssi = v.get("rssi").and_then(|r| r.as_i64()).unwrap_or(-65) as i32;
                        let hx = v
                            .get("service_data_hex")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        if let Ok(raw) = hex::decode(hx) {
                            if let Ok(m) = decrypt_presence_advertisement(&raw, keys) {
                                if let Some(dk) = keys.iter().find(|k| k.device_id == m.device_id) {
                                    found = Some(FoundPeer {
                                        peripheral_id: pid,
                                        device_name: m.device_name,
                                        device_id: m.device_id,
                                        key_seed: dk.authenticity_key,
                                        rssi,
                                        instant_hotspot_available: m.instant_hotspot_available,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Ok(Ok(None)) | Ok(Err(_)) => break,
            Err(_) => continue,
        }
    }
    let _ = child.kill().await;
    found
}

// ---------------------------------------------------------------------------
// Instant Hotspot & Instant Wi-Fi over BLE (`nearby.sharedconnectivity`)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum TetherMode {
    Probe,
    StartHotspot,
    StopHotspot,
}

struct TetherResult {
    battery_percent: Option<i32>,
    cell_provider: Option<String>,
    is_wifi_connected: Option<bool>,
    hotspot_available: bool,
    hotspot_active: bool,
    hotspot_ssid: Option<String>,
    hotspot_password: Option<String>,
    wifi_share_available: bool,
    wifi_share_ssid: Option<String>,
    wifi_share_password: Option<String>,
    error: Option<String>,
}

async fn run_tether_ble(
    mac_bridge: &str,
    peripheral_id: &str,
    device_id: &str,
    device_name: &str,
    peer_key_seed: [u8; 32],
    mode: TetherMode,
) -> Result<TetherResult, String> {
    let mut conn = BleWeaveConn::connect(
        mac_bridge,
        peripheral_id,
        SERVICE_ID_SHARED_CONNECTIVITY,
        device_id,
        device_name,
        peer_key_seed,
    )
    .await?;

    let mut res = TetherResult {
        battery_percent: None,
        cell_provider: None,
        is_wifi_connected: None,
        hotspot_available: false,
        hotspot_active: false,
        hotspot_ssid: None,
        hotspot_password: None,
        wifi_share_available: false,
        wifi_share_ssid: None,
        wifi_share_password: None,
        error: None,
    };

    // Send the target magictether message directly:
    // - Probe: TetherAvailabilityRequest (type=1)
    // - StartHotspot: ConnectTetheringRequest (type=3) directly — skips type=1 roundtrip (~1.5s faster!)
    // - StopHotspot: DisconnectTetheringRequest (type=5, one-way — dhah.java removes client & calls dham.b())
    let first_req = match mode {
        TetherMode::Probe => build_availability_request(),
        TetherMode::StartHotspot => build_connect_tethering_request(),
        TetherMode::StopHotspot => build_disconnect_tethering_request(),
    };
    for f in build_bytes_payload_frames(1, &first_req) {
        let enc = conn.d2d.encrypt_message(&f.encode_to_vec());
        conn.send_weave_msg(&build_ble_v2_data(conn.shash, &enc))
            .await?;
    }

    if mode == TetherMode::StopHotspot {
        // DisconnectTetheringRequest is one-way (`dhah.java:83-98`); allow time for delivery & processing.
        tokio::time::sleep(Duration::from_millis(700)).await;
        conn.close().await;
        return Ok(res);
    }

    let mut payload_bufs: HashMap<i64, Vec<u8>> = HashMap::new();

    for _ in 0..40 {
        let enc = match conn.recv_ble_frame().await {
            Ok(b) => b,
            Err(e) => {
                if res.hotspot_ssid.is_some()
                    || (mode == TetherMode::Probe && res.battery_percent.is_some())
                {
                    break;
                }
                conn.close().await;
                return Err(e);
            }
        };
        let plain = conn
            .d2d
            .decrypt_message(&enc)
            .map_err(|e| format!("tether decrypt: {e}"))?;
        let Ok(frame) = OfflineFrame::decode(plain.as_slice()) else {
            continue;
        };
        let Some(v1) = frame.v1 else { continue };
        if v1.r#type == Some(5) {
            if let Some(ka) = v1.keep_alive {
                if !ka.ack.unwrap_or(false) {
                    let ack_enc = conn
                        .d2d
                        .encrypt_message(&build_keep_alive(true, ka.seq_num).encode_to_vec());
                    let _ = conn
                        .send_weave_msg(&build_ble_v2_data(conn.shash, &ack_enc))
                        .await;
                }
            }
            continue;
        }
        if v1.r#type == Some(6) {
            break;
        }
        if let Some(pt) = v1.payload_transfer {
            let pid = pt.payload_header.and_then(|h| h.id).unwrap_or(0);
            if let Some(ch) = pt.payload_chunk {
                let entry = payload_bufs.entry(pid).or_default();
                if let Some(body) = ch.body {
                    entry.extend_from_slice(&body);
                }
                if (ch.flags.unwrap_or(0) & 1) != 0 && !entry.is_empty() {
                    let full = std::mem::take(entry);
                    if let Ok(decoded) = decode_tether_envelope(&full) {
                        match decoded {
                            DecodedTetherMessage::AvailabilityResponse(resp) => {
                                let code = resp.response_code.unwrap_or(0);
                                res.hotspot_available = code == 1 || code == 7 || code == 9;
                                if let Some(ds_raw) = resp.device_status_raw {
                                    if let Ok(ds) = DeviceStatus::decode(ds_raw.as_slice()) {
                                        res.battery_percent = ds.battery_percentage;
                                        res.cell_provider = ds.cell_provider;
                                        res.is_wifi_connected = ds.is_wifi_connected;
                                    }
                                }
                                if let Some(ihs) = resp.instant_hotspot_status {
                                    if ihs.status_code
                                        == Some(InstantHotspotStatusCode::HotspotActive as i32)
                                    {
                                        res.hotspot_active = true;
                                        res.hotspot_available = true;
                                        res.hotspot_ssid = ihs
                                            .ssid
                                            .map(|s| s.trim_matches('"').to_string())
                                            .filter(|s| !s.is_empty());
                                    }
                                }
                                if let Some(ws) = resp.nearby_wifi_status {
                                    if ws.status_code == Some(4) {
                                        res.wifi_share_available = true;
                                        res.wifi_share_ssid = ws
                                            .ssid
                                            .map(|s| s.trim_matches('"').to_string())
                                            .filter(|s| !s.is_empty());
                                        res.wifi_share_password =
                                            ws.password.map(|s| s.trim_matches('"').to_string());
                                    }
                                }
                                break;
                            }
                            DecodedTetherMessage::ConnectResponse(resp) => {
                                if let Some(ds_raw) = resp.device_status_raw {
                                    if let Ok(ds) = DeviceStatus::decode(ds_raw.as_slice()) {
                                        res.battery_percent = ds.battery_percentage;
                                        res.cell_provider = ds.cell_provider;
                                        res.is_wifi_connected = ds.is_wifi_connected;
                                    }
                                }
                                let code = resp.response_code.unwrap_or(0);
                                if code == 1 {
                                    res.hotspot_available = true;
                                    res.hotspot_active = true;
                                    res.hotspot_ssid = resp
                                        .instant_hotspot_status
                                        .as_ref()
                                        .and_then(|h| h.ssid.clone())
                                        .or(resp.legacy_ssid)
                                        .map(|s| s.trim_matches('"').to_string());
                                    res.hotspot_password = resp
                                        .instant_hotspot_status
                                        .as_ref()
                                        .and_then(|h| h.password.clone())
                                        .or(resp.legacy_password)
                                        .map(|s| s.trim_matches('"').to_string());
                                } else {
                                    res.error = Some(format!(
                                        "ConnectTethering failed: {}",
                                        connect_response_code_name(code)
                                    ));
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    conn.close().await;
    Ok(res)
}

async fn detect_wifi_device() -> String {
    if let Ok(out) = Command::new("/usr/sbin/networksetup")
        .arg("-listallhardwareports")
        .output()
        .await
    {
        let s = String::from_utf8_lossy(&out.stdout);
        let mut saw_wifi = false;
        for line in s.lines() {
            if line.contains("Wi-Fi") || line.contains("AirPort") {
                saw_wifi = true;
            } else if saw_wifi && line.trim_start().starts_with("Device:") {
                if let Some(dev) = line.split(':').nth(1) {
                    let dev = dev.trim();
                    if !dev.is_empty() {
                        return dev.to_string();
                    }
                }
            }
        }
    }
    "en0".to_string()
}

async fn join_wifi_via_corewlan(
    mac_bridge: &str,
    ssid: &str,
    password: &str,
) -> Result<(), String> {
    let iface = detect_wifi_device().await;
    // Start trying almost immediately (500ms) once ConnectTetheringResponse arrives — the SoftAP
    // is usually already beaconing by the time the phone sends SUCCESS — with fast 1s retries.
    for attempt in 0..6 {
        tokio::time::sleep(Duration::from_millis(if attempt == 0 { 500 } else { 1000 })).await;
        let ns = Command::new("/usr/sbin/networksetup")
            .arg("-setairportnetwork")
            .arg(&iface)
            .arg(ssid)
            .arg(password)
            .output()
            .await;
        if let Ok(out) = ns {
            let combined = format!(
                "{} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if out.status.success()
                && !combined.to_ascii_lowercase().contains("error")
                && !combined.contains("Could not find")
            {
                return Ok(());
            }
            log_msg(format!(
                "networksetup attempt {} for {ssid}: {}",
                attempt + 1,
                combined.trim()
            ));
        }
        if attempt >= 2 {
            if let Ok(out) = Command::new(mac_bridge)
                .arg("join-wifi")
                .arg(ssid)
                .arg(password)
                .output()
                .await
            {
                if out.status.success() {
                    return Ok(());
                }
            }
        }
    }
    Err(format!(
        "Failed to join Wi-Fi {ssid} via networksetup/CoreWLAN"
    ))
}

// ---------------------------------------------------------------------------
// Persistent DTDI -> Wi-Fi LAN TCP -> DeviceLink (Notifications + QuickAccess)
// ---------------------------------------------------------------------------

async fn run_devicelink_session(
    mac_bridge: &str,
    peripheral_id: &str,
    device_id: &str,
    device_name: &str,
    peer_key_seed: [u8; 32],
    state: Arc<Mutex<SharedState>>,
    dl_connected: Arc<AtomicBool>,
    ble_lock: Arc<Mutex<()>>,
    qa_rx: &mut mpsc::Receiver<QuickAccessRpc>,
    notif_rx: &mut mpsc::Receiver<NotifAction>,
    cancel_rx: &mut mpsc::Receiver<()>,
    did_connect_tcp: &mut bool,
) -> Result<(), String> {
    let ble_guard = ble_lock.lock().await;
    log_msg(format!("Connecting DTDI over BLE ({peripheral_id})..."));
    let mut conn = BleWeaveConn::connect(
        mac_bridge,
        peripheral_id,
        SERVICE_ID_DTDI,
        device_id,
        device_name,
        peer_key_seed,
    )
    .await?;
    log_msg("DTDI BLE UKEY2 + PresenceAuth connected; sending wakeup...");

    let dtdi_channel_uuid = uuid::Uuid::new_v4().to_string();
    let req_id = uuid::Uuid::new_v4().to_string();
    let wakeup = build_devicelink_wakeup_message(&dtdi_channel_uuid, &req_id, false);
    let mut next_payload_id: i64 = 100;
    for f in build_bytes_payload_frames(next_payload_id, &wakeup) {
        let enc = conn.d2d.encrypt_message(&f.encode_to_vec());
        conn.send_weave_msg(&build_ble_v2_data(conn.shash, &enc))
            .await?;
    }
    log_msg("DTDI wakeup sent; waiting for Wi-Fi LAN upgrade...");

    // Wait for BLE -> Wi-Fi LAN TCP bandwidth upgrade (medium = 5) with bounded 10s deadline
    // so ble_lock is never held hostage if the phone is on a different network.
    let mut tcp: Option<TcpStream> = None;
    let bwu_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    for _ in 0..30 {
        let now = tokio::time::Instant::now();
        if now >= bwu_deadline {
            break;
        }
        let rem = bwu_deadline - now;
        let enc = tokio::select! {
            _ = cancel_rx.recv() => {
                conn.close().await;
                drop(ble_guard);
                return Ok(());
            }
            r = tokio::time::timeout(rem, conn.recv_ble_frame()) => {
                match r {
                    Ok(Ok(b)) => b,
                    Ok(Err(e)) => {
                        conn.close().await;
                        drop(ble_guard);
                        return Err(e);
                    }
                    Err(_) => break,
                }
            }
        };
        let plain = conn
            .d2d
            .decrypt_message(&enc)
            .map_err(|e| format!("dtdi ble decrypt: {e}"))?;
        let Ok(frame) = OfflineFrame::decode(plain.as_slice()) else {
            continue;
        };
        let Some(v1) = frame.v1 else { continue };
        if v1.r#type == Some(5) {
            if let Some(ka) = v1.keep_alive {
                if !ka.ack.unwrap_or(false) {
                    let ack_enc = conn
                        .d2d
                        .encrypt_message(&build_keep_alive(true, ka.seq_num).encode_to_vec());
                    let _ = conn
                        .send_weave_msg(&build_ble_v2_data(conn.shash, &ack_enc))
                        .await;
                }
            }
            continue;
        }
        if v1.r#type == Some(6) {
            conn.close().await;
            return Err("Peer disconnected during DTDI BWU".into());
        }
        if v1.r#type == Some(4) {
            if let Some(bwu) = v1.bandwidth_upgrade_negotiation {
                if bwu.event_type == Some(1) {
                    if let Some(info) = bwu.upgrade_path_info {
                        log_msg(format!("Received BWU UPGRADE_PATH_AVAILABLE: medium={:?}", info.medium));
                        let target_addr: Option<(std::net::IpAddr, u16)> = if info.medium == Some(5)
                        {
                            info.wifi_lan_socket.and_then(|sock| {
                                let ip = match sock.ip_address.as_deref() {
                                    Some(b) if b.len() == 4 => Some(std::net::IpAddr::V4(
                                        std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                                    )),
                                    Some(b) if b.len() == 16 => {
                                        let arr: [u8; 16] = b.try_into().unwrap();
                                        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr)))
                                    }
                                    _ => None,
                                };
                                let port = sock.wifi_port.unwrap_or(0) as u16;
                                ip.filter(|_| port > 0).map(|i| (i, port))
                            })
                        } else if info.medium == Some(3) {
                            // WIFI_HOTSPOT upgrade (e.g. Pixel SoftAP ap_br_wlan2 gateway:port!)
                            info.wifi_hotspot_credentials.and_then(|hc| {
                                log_msg(format!(
                                    "WIFI_HOTSPOT upgrade creds: ssid={:?} gateway={:?} port={:?}",
                                    hc.ssid, hc.gateway, hc.port
                                ));
                                let ip = hc
                                    .gateway
                                    .as_deref()
                                    .and_then(|g| g.parse::<std::net::IpAddr>().ok());
                                let port = hc.port.unwrap_or(0) as u16;
                                ip.filter(|_| port > 0).map(|i| (i, port))
                            })
                        } else {
                            None
                        };

                        if let Some((ip, port)) = target_addr {
                            let mut stream = tokio::time::timeout(
                                Duration::from_secs(6),
                                TcpStream::connect((ip, port)),
                            )
                            .await
                            .map_err(|_| format!("TCP connect {ip}:{port} timeout"))?
                            .map_err(|e| format!("TCP connect {ip}:{port}: {e}"))?;

                            // 1. Plaintext CLIENT_INTRODUCTION -> CLIENT_INTRODUCTION_ACK on TCP
                            write_framed(
                                &mut stream,
                                &build_bwu_client_introduction(&conn.ep_id).encode_to_vec(),
                            )
                            .await?;
                            let _ack = tokio::time::timeout(
                                Duration::from_secs(5),
                                read_framed(&mut stream),
                            )
                            .await
                            .map_err(|_| "CLIENT_INTRODUCTION_ACK timeout")??;

                            // 2. Encrypted LAST_WRITE + SAFE_TO_CLOSE on BLE (keeps D2D seq in lockstep)
                            let last_enc = conn
                                .d2d
                                .encrypt_message(&build_bwu_event(2).encode_to_vec());
                            conn.send_weave_msg(&build_ble_v2_data(conn.shash, &last_enc))
                                .await?;
                            let mut saw_last = false;
                            let mut saw_safe = false;
                            let mut sent_safe = false;
                            while !(saw_last && saw_safe) {
                                let benc = conn.recv_ble_frame().await?;
                                let bplain = conn
                                    .d2d
                                    .decrypt_message(&benc)
                                    .map_err(|e| format!("bwu drain decrypt: {e}"))?;
                                if let Ok(bf) = OfflineFrame::decode(bplain.as_slice()) {
                                    let ev = bf
                                        .v1
                                        .and_then(|v| v.bandwidth_upgrade_negotiation)
                                        .and_then(|b| b.event_type);
                                    if ev == Some(2) {
                                        saw_last = true;
                                        if !sent_safe {
                                            sent_safe = true;
                                            let safe_enc = conn
                                                .d2d
                                                .encrypt_message(&build_bwu_event(3).encode_to_vec());
                                            conn.send_weave_msg(&build_ble_v2_data(
                                                conn.shash, &safe_enc,
                                            ))
                                            .await?;
                                        }
                                    } else if ev == Some(3) {
                                        saw_safe = true;
                                    }
                                }
                            }
                            // 3. Plaintext DISCONNECTION on BLE & close BLE child!
                            let disc = OfflineFrame {
                                version: Some(1),
                                v1: Some(relay_core::nearby_connections::V1Frame {
                                    r#type: Some(6),
                                    disconnection: Some(
                                        relay_core::nearby_connections::DisconnectionFrame {
                                            request_safe_to_disconnect: Some(false),
                                        },
                                    ),
                                    ..Default::default()
                                }),
                            };
                            let _ = conn
                                .send_weave_msg(&build_ble_v2_data(
                                    conn.shash,
                                    &disc.encode_to_vec(),
                                ))
                                .await;
                            let _ = tokio::time::timeout(
                                Duration::from_millis(1200),
                                conn.recv_ble_frame(),
                            )
                            .await;
                            tcp = Some(stream);
                            break;
                        }
                    }
                }
            }
        }
    }

    let mut d2d = conn.d2d;
    let _ = conn.child.kill().await; // BLE is now 100% free!
    drop(ble_guard);
    let tcp = tcp.ok_or("No WIFI_LAN upgrade received (phone not on same Wi-Fi LAN?)")?;
    *did_connect_tcp = true;

    // Split TCP into dedicated cancel-safe reader task + writer half!
    // (Calling `read_exact` directly inside `tokio::select!` is NOT cancel-safe and corrupts framing.)
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let (tcp_frame_tx, mut tcp_frame_rx) = mpsc::channel::<Result<Vec<u8>, String>>(128);
    let reader_task = tokio::spawn(async move {
        loop {
            match read_framed_half(&mut tcp_read).await {
                Ok(frame) => {
                    if tcp_frame_tx.send(Ok(frame)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tcp_frame_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Send DeviceLink desktop handshake over fast Wi-Fi LAN TCP
    let mut dl_session = DeviceLinkSession::new();
    let mut dl_reassembler = DeviceLinkChunkReassembler::default();
    let send_dl = |d2d: &mut D2DConnectionContext,
                   next_pid: &mut i64,
                   pkt: relay_core::devicelink::DeviceLinkPacket|
     -> Vec<Vec<u8>> {
        let wrapped = build_app_channel_message(
            PACKAGE_AMBIENT_STREAMING,
            &dtdi_channel_uuid,
            2, // SENDER_INCOMING_CHANNEL
            pkt.encode_to_vec(),
        );
        *next_pid += 1;
        build_bytes_payload_frames(*next_pid, &wrapped)
            .into_iter()
            .map(|cf| d2d.encrypt_message(&cf.encode_to_vec()))
            .collect()
    };

    for pkt in DeviceLinkSession::build_desktop_handshake(device_id, "macOS") {
        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
            write_framed_half(&mut tcp_write, &enc).await?;
        }
    }

    {
        let mut st = state.lock().await;
        st.devicelink_connected = true;
        st.emit_status();
    }
    log_msg("DeviceLink connected over Wi-Fi LAN TCP; waiting for remote services...");

    let mut payload_bufs: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut notif_req_id: Option<i64> = None;
    let mut qa_pending: HashMap<i64, PendingQaRpc> = HashMap::new();
    let mut keepalive_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    let mut ka_seq: u32 = 1;

    let result: Result<(), String> = loop {
        tokio::select! {
            _ = cancel_rx.recv() => {
                break Ok(());
            }
            _ = keepalive_tick.tick() => {
                ka_seq = ka_seq.wrapping_add(1);
                let ka_enc = d2d.encrypt_message(&build_keep_alive(false, Some(ka_seq)).encode_to_vec());
                if let Err(e) = write_framed_half(&mut tcp_write, &ka_enc).await {
                    break Err(format!("TCP keepalive failed: {e}"));
                }
            }
            Some(qa_cmd) = qa_rx.recv() => {
                match qa_cmd {
                    QuickAccessRpc::GetDocument { path, reply } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "GetDocument",
                            build_path_request(&path),
                        );
                        qa_pending.insert(rid, PendingQaRpc::GetDoc(reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                    QuickAccessRpc::GetChildDocuments { path, reply } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "GetChildDocuments",
                            build_path_request(&path),
                        );
                        qa_pending.insert(rid, PendingQaRpc::GetChildren(Vec::new(), reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                    QuickAccessRpc::OpenDocument { path, reply } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "OpenDocument",
                            build_path_request(&path),
                        );
                        qa_pending.insert(rid, PendingQaRpc::OpenDoc(Vec::new(), reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                    QuickAccessRpc::CreateDocument {
                        parent_path,
                        display_name,
                        mime_type,
                        reply,
                    } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "CreateDocument",
                            build_create_request(&parent_path, &display_name, &mime_type),
                        );
                        qa_pending.insert(rid, PendingQaRpc::DocMutation(reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                    QuickAccessRpc::WriteDocument { path, data, reply } => {
                        let (rid, start_pkt) =
                            dl_session.build_stream_start(SERVICE_QUICK_ACCESS, "WriteDocument");
                        qa_pending.insert(rid, PendingQaRpc::BoolMutation(reply));
                        let mut ok = true;
                        for enc in send_dl(&mut d2d, &mut next_payload_id, start_pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            for msg in build_write_stream_messages(&path, &data) {
                                let dpkt = DeviceLinkSession::build_stream_data(
                                    rid,
                                    SERVICE_QUICK_ACCESS,
                                    msg,
                                );
                                for enc in send_dl(&mut d2d, &mut next_payload_id, dpkt) {
                                    if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                        ok = false;
                                        break;
                                    }
                                }
                                if !ok {
                                    break;
                                }
                            }
                        }
                        if ok {
                            let end_pkt =
                                DeviceLinkSession::build_stream_end(rid, SERVICE_QUICK_ACCESS);
                            for enc in send_dl(&mut d2d, &mut next_payload_id, end_pkt) {
                                if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    QuickAccessRpc::DeleteDocument { path, reply } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "DeleteDocument",
                            build_path_request(&path),
                        );
                        qa_pending.insert(rid, PendingQaRpc::BoolMutation(reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                    QuickAccessRpc::RenameDocument {
                        path,
                        new_name,
                        reply,
                    } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "RenameDocument",
                            build_rename_request(&path, &new_name),
                        );
                        qa_pending.insert(rid, PendingQaRpc::DocMutation(reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                    QuickAccessRpc::MoveDocument {
                        path,
                        dest_parent_path,
                        reply,
                    } => {
                        let (rid, pkt) = dl_session.build_unary_request(
                            SERVICE_QUICK_ACCESS,
                            "MoveDocument",
                            build_move_request(&path, &dest_parent_path),
                        );
                        qa_pending.insert(rid, PendingQaRpc::BoolMutation(reply));
                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                            if write_framed_half(&mut tcp_write, &enc).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            Some(act) = notif_rx.recv() => {
                let inner = match act {
                    NotifAction::Dismiss { key } => build_dismiss(&key),
                    NotifAction::Reply { key, action_index, text } => build_quick_reply(&key, action_index, &text),
                };
                let (_, pkt) = dl_session.build_unary_request(
                    SERVICE_NOTIFICATION_SYNC,
                    "ExecuteRemoteAction",
                    inner,
                );
                for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                    if let Err(e) = write_framed_half(&mut tcp_write, &enc).await {
                        log_msg(format!("Failed sending notification action: {e}"));
                        break;
                    }
                }
            }
            maybe_frame = tcp_frame_rx.recv() => {
                let enc = match maybe_frame {
                    Some(Ok(b)) => b,
                    Some(Err(e)) => break Err(e),
                    None => break Err("TCP reader closed".into()),
                };
                let plain = match d2d.decrypt_message(&enc) {
                    Ok(p) => p,
                    Err(e) => break Err(format!("TCP decrypt error: {e}")),
                };
                let Ok(frame) = OfflineFrame::decode(plain.as_slice()) else { continue };
                let Some(v1) = frame.v1 else { continue };
                if v1.r#type == Some(5) {
                    if let Some(ka) = v1.keep_alive {
                        if !ka.ack.unwrap_or(false) {
                            let ack_enc = d2d.encrypt_message(&build_keep_alive(true, ka.seq_num).encode_to_vec());
                            let _ = write_framed_half(&mut tcp_write, &ack_enc).await;
                        }
                    }
                    continue;
                }
                if v1.r#type == Some(6) {
                    break Err("Peer disconnected DeviceLink TCP".into());
                }
                if let Some(pt) = v1.payload_transfer {
                    let pid = pt.payload_header.and_then(|h| h.id).unwrap_or(0);
                    if let Some(ch) = pt.payload_chunk {
                        let entry = payload_bufs.entry(pid).or_default();
                        if let Some(body) = ch.body {
                            entry.extend_from_slice(&body);
                        }
                        if (ch.flags.unwrap_or(0) & 1) != 0 && !entry.is_empty() {
                            let full = std::mem::take(entry);
                            let Ok(dmsg) = decode_dtdi_message(&full) else { continue };
                            let cid = dmsg.channel_id.unwrap_or_default();
                            if cid.app_package_name != PACKAGE_AMBIENT_STREAMING {
                                continue;
                            }
                            let Some(dtdi_message::Content::Payload(payload)) = dmsg.content else {
                                continue;
                            };
                            let inner_dl = match dl_reassembler.push(&payload) {
                                Ok((Some(full_dl), _)) => full_dl,
                                Ok((None, _)) => continue,
                                Err(_) => unwrap_channel_payload(&payload).unwrap_or(payload),
                            };
                            let Ok(Some(ev)) = dl_session.handle_incoming(&inner_dl) else {
                                continue;
                            };
                            match ev {
                                DeviceLinkEvent::RemoteServices(svcs) => {
                                    let has_qa = svcs.iter().any(|s| s == SERVICE_QUICK_ACCESS);
                                    dl_connected.store(has_qa, Ordering::Relaxed);
                                    log_msg(format!("Remote DeviceLink services: {:?} (quick_access={has_qa})", svcs));
                                    if svcs.iter().any(|s| s == SERVICE_NOTIFICATION_SYNC) && notif_req_id.is_none() {
                                        let (rid, pkt) = dl_session.build_unary_request(
                                            SERVICE_NOTIFICATION_SYNC,
                                            "ReadNotificationShadeEvents",
                                            Vec::new(),
                                        );
                                        notif_req_id = Some(rid);
                                        for enc in send_dl(&mut d2d, &mut next_payload_id, pkt) {
                                            let _ = write_framed_half(&mut tcp_write, &enc).await;
                                        }
                                        log_msg("Subscribed to live Notification Sync");
                                    }
                                }
                                DeviceLinkEvent::Cancelled { request_id, reason } => {
                                    log_msg(format!("DeviceLink RPC {request_id} cancelled: {reason}"));
                                    if let Some(pending) = qa_pending.remove(&request_id) {
                                        let err = format!("DeviceLink cancelled: {reason}");
                                        match pending {
                                            PendingQaRpc::GetDoc(tx)
                                            | PendingQaRpc::DocMutation(tx) => {
                                                let _ = tx.send(Err(err));
                                            }
                                            PendingQaRpc::GetChildren(_, tx) => {
                                                let _ = tx.send(Err(err));
                                            }
                                            PendingQaRpc::OpenDoc(_, tx) => {
                                                let _ = tx.send(Err(err));
                                            }
                                            PendingQaRpc::BoolMutation(tx) => {
                                                let _ = tx.send(Err(err));
                                            }
                                        }
                                    }
                                }
                                DeviceLinkEvent::ResponsePayload { request_id, data, is_stream_end } => {
                                    if Some(request_id) == notif_req_id && !data.is_empty() {
                                        if let Ok(ns) = NotificationSyncEvent::decode(data.as_slice()) {
                                            match ns.event {
                                                Some(relay_core::notifications::notification_sync_event::Event::Initial(p)) => {
                                                    emit_notifications(p.notifications, true);
                                                }
                                                Some(relay_core::notifications::notification_sync_event::Event::Posted(p)) => {
                                                    emit_notifications(p.notifications, false);
                                                }
                                                Some(relay_core::notifications::notification_sync_event::Event::Removed(r)) => {
                                                    emit_json(&DaemonEvent::NotificationRemoved { keys: r.keys });
                                                }
                                                _ => {}
                                            }
                                        }
                                    } else if let Some(pending) = qa_pending.remove(&request_id) {
                                        match pending {
                                            PendingQaRpc::GetDoc(tx) => {
                                                if data.is_empty() && !is_stream_end {
                                                    qa_pending.insert(request_id, PendingQaRpc::GetDoc(tx));
                                                } else {
                                                    match GetDocumentResponse::decode(data.as_slice()) {
                                                        Ok(resp) => {
                                                            if let Some(doc) = resp.document {
                                                                let _ = tx.send(Ok(doc));
                                                            } else {
                                                                let _ = tx.send(Err("Not found".into()));
                                                            }
                                                        }
                                                        Err(e) => {
                                                            let _ = tx.send(Err(format!("GetDocument decode: {e}")));
                                                        }
                                                    }
                                                }
                                            }
                                            PendingQaRpc::GetChildren(mut list, tx) => {
                                                if !data.is_empty() {
                                                    if let Ok(doc) = QuickAccessDocument::decode(data.as_slice()) {
                                                        list.push(doc);
                                                    }
                                                }
                                                if is_stream_end {
                                                    let _ = tx.send(Ok(list));
                                                } else {
                                                    qa_pending.insert(request_id, PendingQaRpc::GetChildren(list, tx));
                                                }
                                            }
                                            PendingQaRpc::OpenDoc(mut buf, tx) => {
                                                if !data.is_empty() {
                                                    if let Ok(ch) = OpenDocumentChunk::decode(data.as_slice()) {
                                                        if let Some(c) = ch.chunk.and_then(|c| c.data) {
                                                            buf.extend_from_slice(&c);
                                                        }
                                                    }
                                                }
                                                if is_stream_end {
                                                    let _ = tx.send(Ok(buf));
                                                } else {
                                                    qa_pending.insert(request_id, PendingQaRpc::OpenDoc(buf, tx));
                                                }
                                            }
                                            PendingQaRpc::DocMutation(tx) => {
                                                match DocumentMutationResponse::decode(data.as_slice()) {
                                                    Ok(resp) if resp.success == Some(true) => {
                                                        if let Some(doc) = resp.document {
                                                            let _ = tx.send(Ok(doc));
                                                        } else {
                                                            let _ = tx.send(Err("Missing document in response".into()));
                                                        }
                                                    }
                                                    Ok(_) => {
                                                        let _ = tx.send(Err("Operation failed on phone".into()));
                                                    }
                                                    Err(e) => {
                                                        let _ = tx.send(Err(format!("DocMutation decode: {e}")));
                                                    }
                                                }
                                            }
                                            PendingQaRpc::BoolMutation(tx) => {
                                                match SimpleBoolResponse::decode(data.as_slice()) {
                                                    Ok(resp) if resp.success == Some(true) => {
                                                        let _ = tx.send(Ok(()));
                                                    }
                                                    Ok(_) => {
                                                        let _ = tx.send(Err("Operation failed on phone".into()));
                                                    }
                                                    Err(e) => {
                                                        let _ = tx.send(Err(format!("BoolMutation decode: {e}")));
                                                    }
                                                }
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
    };

    reader_task.abort();
    dl_connected.store(false, Ordering::Relaxed);
    // Fail any in-flight WebDAV/FileProvider RPCs cleanly
    for (_, pending) in qa_pending {
        match pending {
            PendingQaRpc::GetDoc(tx) | PendingQaRpc::DocMutation(tx) => {
                let _ = tx.send(Err("DeviceLink disconnected".into()));
            }
            PendingQaRpc::GetChildren(_, tx) => {
                let _ = tx.send(Err("DeviceLink disconnected".into()));
            }
            PendingQaRpc::OpenDoc(_, tx) => {
                let _ = tx.send(Err("DeviceLink disconnected".into()));
            }
            PendingQaRpc::BoolMutation(tx) => {
                let _ = tx.send(Err("DeviceLink disconnected".into()));
            }
        }
    }

    {
        let mut st = state.lock().await;
        st.devicelink_connected = false;
        st.emit_status();
    }
    result
}

fn emit_notifications(
    notifications: Vec<relay_core::notifications::SyncedNotification>,
    is_initial: bool,
) {
    for n in notifications {
        // Filter out ongoing system banners (e.g. "USB debugging", "Hotspot active") & group summaries
        if n.is_ongoing == Some(true) || n.is_group_summary == Some(true) {
            continue;
        }
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
        let can_reply = n.messaging_content.is_some();
        if text.is_empty() {
            if let Some(msg) = &n.messaging_content {
                if let Some(ct) = &msg.conversation_title {
                    if !ct.is_empty() {
                        title = ct.clone();
                    }
                }
                if let Some(last) = msg.messages.last() {
                    let sender = last
                        .sender
                        .as_ref()
                        .and_then(|s| s.name.as_deref())
                        .unwrap_or("");
                    let body = last.text.as_deref().unwrap_or("");
                    text = if sender.is_empty() {
                        body.to_string()
                    } else {
                        format!("{sender}: {body}")
                    };
                }
            }
        }
        if title.is_empty() && text.is_empty() {
            continue;
        }
        emit_json(&DaemonEvent::NotificationPosted {
            key: n.key.unwrap_or_default(),
            package_name: n.package_name.unwrap_or_default(),
            app_name: n.app_name.unwrap_or_default(),
            title,
            text,
            can_reply,
            reply_action_index: 0,
            is_initial,
        });
    }
}

// ---------------------------------------------------------------------------
// Main daemon orchestration
// ---------------------------------------------------------------------------

fn default_data_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Relay")
    } else {
        PathBuf::from(".")
    }
}

fn local_mac_display_name() -> String {
    if let Ok(out) = std::process::Command::new("/usr/sbin/scutil")
        .args(["--get", "ComputerName"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    if let Ok(out) = std::process::Command::new("/bin/hostname").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout)
                .trim()
                .trim_end_matches(".local")
                .to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    "Mac".to_string()
}

async fn perform_cloud_sync_and_reload(
    acct_slot: &Arc<Mutex<Option<GoogleAccountSession>>>,
    account_path: &PathBuf,
    synced_creds_path: &PathBuf,
    derived_keys: &Arc<RwLock<Vec<DerivedPresenceKey>>>,
    local_identity: &Arc<RwLock<(String, String)>>,
    state: &Arc<Mutex<SharedState>>,
) -> Result<(String, usize), String> {
    let mut acct = {
        let guard = acct_slot.lock().await;
        guard
            .clone()
            .ok_or_else(|| "Not signed in to a Google Account".to_string())?
    };

    let mac_name = local_mac_display_name();
    let synced = sync_nearby_presence(&mut acct, &mac_name).await?;

    // Save updated account session (`0600`)
    let acct_json = serde_json::to_vec_pretty(&acct).map_err(|e| e.to_string())?;
    write_secret_file(account_path, &acct_json)?;

    // Save synced Nearby Presence credentials (`0600`)
    let local_id = acct
        .dusi
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| acct.android_id.clone());
    let creds_file = CredentialsFile {
        device_id: local_id.clone(),
        device_name: mac_name.clone(),
        shared_credentials: synced.shared_credentials.clone(),
    };
    let creds_json = serde_json::to_vec_pretty(&creds_file).map_err(|e| e.to_string())?;
    write_secret_file(synced_creds_path, &creds_json)?;

    // Hot-reload derived presence keys & local identity in memory!
    let new_derived: Vec<DerivedPresenceKey> = synced
        .shared_credentials
        .iter()
        .filter_map(|c| c.derive_keys().ok())
        .collect();
    let count = new_derived.len();
    {
        let mut dk = derived_keys.write().await;
        *dk = new_derived;
    }
    {
        let mut id = local_identity.write().await;
        *id = (local_id, mac_name);
    }
    {
        let mut guard = acct_slot.lock().await;
        *guard = Some(acct.clone());
    }
    {
        let mut st = state.lock().await;
        st.signed_in = true;
        st.account_email = Some(acct.email.clone());
        st.credential_count = count;
        st.last_sync_unix = Some(synced.synced_at_unix_secs);
        if let Some(phone_name) = synced.primary_phone_name {
            if st.device_name.is_empty() || st.device_name == "Android Phone" || !st.ble_nearby {
                st.device_name = phone_name;
            }
        }
        st.emit_status();
    }

    log_msg(format!(
        "Google cloud sync ok for {}: {} credentials loaded (registered as laptop in Cross-Device Services)",
        acct.email, count
    ));
    Ok((acct.email, count))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fallback_creds_path = args
        .windows(2)
        .find(|w| w[0] == "--credentials")
        .map(|w| PathBuf::from(&w[1]));
    let data_dir = args
        .windows(2)
        .find(|w| w[0] == "--data-dir")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(default_data_dir);
    let mac_bridge = args
        .windows(2)
        .find(|w| w[0] == "--mac-bridge")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "./RelayBridge".to_string());
    let webdav_port: u16 = args
        .windows(2)
        .find(|w| w[0] == "--webdav-port")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(48921);

    let account_path = data_dir.join("account.json");
    let synced_creds_path = data_dir.join("credentials.json");

    let initial_account: Option<GoogleAccountSession> = fs::read_to_string(&account_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    // Load initial credentials from synced data_dir first, then optional --credentials fallback
    let load_creds = |p: &PathBuf| -> Option<CredentialsFile> {
        fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str::<CredentialsFile>(&s).ok())
    };
    let initial_cfg = load_creds(&synced_creds_path).or_else(|| {
        fallback_creds_path
            .as_ref()
            .and_then(load_creds)
    });

    let mac_name = local_mac_display_name();
    let (init_device_id, init_device_name, init_keys): (String, String, Vec<DerivedPresenceKey>) =
        if let Some(cfg) = initial_cfg {
            let keys: Vec<DerivedPresenceKey> = cfg
                .shared_credentials
                .iter()
                .filter_map(|c| c.derive_keys().ok())
                .collect();
            (cfg.device_id, cfg.device_name, keys)
        } else {
            let fallback_id = initial_account
                .as_ref()
                .and_then(|a| a.dusi.clone().or_else(|| Some(a.android_id.clone())))
                .unwrap_or_else(generate_android_id);
            (fallback_id, mac_name, Vec::new())
        };

    let init_key_count = init_keys.len();
    let derived_keys = Arc::new(RwLock::new(init_keys));
    let local_identity = Arc::new(RwLock::new((init_device_id, init_device_name)));
    let account_slot = Arc::new(Mutex::new(initial_account.clone()));

    let state = Arc::new(Mutex::new(SharedState {
        device_name: "Android Phone".into(),
        webdav_url: format!("http://127.0.0.1:{webdav_port}/"),
        signed_in: initial_account.is_some(),
        account_email: initial_account.as_ref().map(|a| a.email.clone()),
        credential_count: init_key_count,
        last_sync_unix: initial_account.as_ref().and_then(|a| a.last_sync_unix_secs),
        ..Default::default()
    }));
    state.lock().await.emit_status();

    // Start loopback FileProvider API + WebDAV server immediately on 127.0.0.1:<webdav_port>
    let dl_connected = Arc::new(AtomicBool::new(false));
    let just_joined_hotspot = Arc::new(AtomicBool::new(false));
    let (qa_tx, mut qa_rx) = mpsc::channel::<QuickAccessRpc>(64);
    let webdav_client = QuickAccessClient::new(qa_tx, dl_connected.clone());
    tokio::spawn(async move {
        if let Err(e) = serve_webdav(webdav_port, webdav_client).await {
            log_msg(format!("WebDAV server error: {e}"));
        }
    });
    log_msg(format!("FileProvider/WebDAV API listening on http://127.0.0.1:{webdav_port}/"));

    // Channels for UI commands
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<DaemonCommand>(32);
    let (notif_tx, mut notif_rx) = mpsc::channel::<NotifAction>(32);
    let (cancel_dl_tx, mut cancel_dl_rx) = mpsc::channel::<()>(4);

    // Periodic Google Cloud credential auto-refresh task (immediately on startup if signed in,
    // then whenever wall-clock age >= 12h — resilient across MacBook lid-closed sleep and well
    // before Google's 5-day SharedCredential expiration!)
    {
        let acct_slot = account_slot.clone();
        let account_path = account_path.clone();
        let synced_creds_path = synced_creds_path.clone();
        let derived_keys = derived_keys.clone();
        let local_identity = local_identity.clone();
        let state = state.clone();
        let cancel_dl_tx = cancel_dl_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let mut first_run = true;
            loop {
                let acct_opt = acct_slot.lock().await.clone();
                if let Some(acct) = acct_opt {
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let last_sync = acct.last_sync_unix_secs.unwrap_or(0);
                    let due = first_run || now_secs.saturating_sub(last_sync) >= 12 * 3600;
                    if due {
                        first_run = false;
                        let had_keys = !derived_keys.read().await.is_empty();
                        match perform_cloud_sync_and_reload(
                            &acct_slot,
                            &account_path,
                            &synced_creds_path,
                            &derived_keys,
                            &local_identity,
                            &state,
                        )
                        .await
                        {
                            Ok(_) => {
                                if !had_keys {
                                    let _ = cancel_dl_tx.try_send(());
                                }
                            }
                            Err(e) => {
                                log_msg(format!("Background Google credential sync failed: {e}"));
                                tokio::time::sleep(Duration::from_secs(30 * 60)).await;
                                continue;
                            }
                        }
                    }
                    // Poll wall-clock every 10 min so waking from long sleep triggers sync promptly
                    tokio::time::sleep(Duration::from_secs(10 * 60)).await;
                } else {
                    first_run = true;
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });
    }

    // Stdin JSON command reader
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(cmd) = serde_json::from_str::<DaemonCommand>(trimmed) {
                let _ = cmd_tx.send(cmd).await;
            }
        }
        std::process::exit(0);
    });

    // BLE mutex so only one RelayBridge BLE session runs at a time
    let ble_lock = Arc::new(Mutex::new(()));

    // Spawn command handler (GoogleLogin, SyncCredentials, GoogleSignOut, Hotspot, Wi-Fi, Probe, Notif, Reconnect)
    {
        let state = state.clone();
        let ble_lock = ble_lock.clone();
        let mac_bridge = mac_bridge.clone();
        let local_identity = local_identity.clone();
        let keys_lock = derived_keys.clone();
        let acct_slot = account_slot.clone();
        let account_path = account_path.clone();
        let synced_creds_path = synced_creds_path.clone();
        let notif_tx = notif_tx.clone();
        let cancel_dl_tx = cancel_dl_tx.clone();
        let just_joined_hotspot = just_joined_hotspot.clone();
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    DaemonCommand::GoogleLogin { oauth_token } => {
                        {
                            let mut st = state.lock().await;
                            st.busy_action = Some("Signing in to Google...".into());
                            st.emit_status();
                        }
                        let android_id = generate_android_id();
                        let res = match exchange_oauth_token(&oauth_token, &android_id).await {
                            Ok(acct) => {
                                {
                                    let mut guard = acct_slot.lock().await;
                                    *guard = Some(acct);
                                }
                                perform_cloud_sync_and_reload(
                                    &acct_slot,
                                    &account_path,
                                    &synced_creds_path,
                                    &keys_lock,
                                    &local_identity,
                                    &state,
                                )
                                .await
                            }
                            Err(e) => Err(e),
                        };
                        {
                            let mut st = state.lock().await;
                            st.busy_action = None;
                            st.emit_status();
                        }
                        match res {
                            Ok((email, count)) => {
                                let _ = cancel_dl_tx.try_send(());
                                emit_json(&DaemonEvent::ActionResult {
                                    action: "google_login".into(),
                                    ok: true,
                                    message: format!("Signed in as {email} ({count} keys synced)"),
                                });
                            }
                            Err(e) => {
                                log_msg(format!("Google Sign-In failed: {e}"));
                                emit_json(&DaemonEvent::ActionResult {
                                    action: "google_login".into(),
                                    ok: false,
                                    message: e,
                                });
                            }
                        }
                    }
                    DaemonCommand::SyncCredentials => {
                        {
                            let mut st = state.lock().await;
                            st.busy_action = Some("Syncing Google credentials...".into());
                            st.emit_status();
                        }
                        let res = perform_cloud_sync_and_reload(
                            &acct_slot,
                            &account_path,
                            &synced_creds_path,
                            &keys_lock,
                            &local_identity,
                            &state,
                        )
                        .await;
                        {
                            let mut st = state.lock().await;
                            st.busy_action = None;
                            st.emit_status();
                        }
                        match res {
                            Ok((email, count)) => {
                                let _ = cancel_dl_tx.try_send(());
                                emit_json(&DaemonEvent::ActionResult {
                                    action: "sync_credentials".into(),
                                    ok: true,
                                    message: format!("Synced {count} keys for {email}"),
                                });
                            }
                            Err(e) => {
                                emit_json(&DaemonEvent::ActionResult {
                                    action: "sync_credentials".into(),
                                    ok: false,
                                    message: e,
                                });
                            }
                        }
                    }
                    DaemonCommand::GoogleSignOut => {
                        {
                            let mut guard = acct_slot.lock().await;
                            *guard = None;
                        }
                        let _ = fs::remove_file(&account_path);
                        let _ = fs::remove_file(&synced_creds_path);
                        {
                            let mut dk = keys_lock.write().await;
                            dk.clear();
                        }
                        {
                            let mut st = state.lock().await;
                            st.signed_in = false;
                            st.account_email = None;
                            st.credential_count = 0;
                            st.last_sync_unix = None;
                            st.ble_nearby = false;
                            st.devicelink_connected = false;
                            st.rssi = None;
                            st.battery_percent = None;
                            st.cell_provider = None;
                            st.hotspot_available = false;
                            st.hotspot_active = false;
                            st.hotspot_ssid = None;
                            st.wifi_share_available = false;
                            st.wifi_share_ssid = None;
                            st.wifi_share_password = None;
                            st.peripheral_id = None;
                            st.peer_key_seed = None;
                            st.emit_status();
                        }
                        let _ = cancel_dl_tx.try_send(());
                        log_msg("Signed out of Google Account and cleared local credentials");
                        emit_json(&DaemonEvent::ActionResult {
                            action: "google_sign_out".into(),
                            ok: true,
                            message: "Signed out of Google Account".into(),
                        });
                    }
                    DaemonCommand::DismissNotification { key } => {
                        let _ = notif_tx.send(NotifAction::Dismiss { key }).await;
                    }
                    DaemonCommand::ReplyNotification {
                        key,
                        action_index,
                        text,
                    } => {
                        let _ = notif_tx
                            .send(NotifAction::Reply {
                                key,
                                action_index: action_index.unwrap_or(0),
                                text,
                            })
                            .await;
                    }
                    DaemonCommand::Reconnect => {
                        let _ = cancel_dl_tx.try_send(());
                    }
                    DaemonCommand::ConnectPhoneWifi => {
                        let (ssid_opt, pass_opt) = {
                            let mut st = state.lock().await;
                            st.busy_action = Some("Connecting to phone Wi-Fi...".into());
                            st.emit_status();
                            (st.wifi_share_ssid.clone(), st.wifi_share_password.clone())
                        };
                        let res = match (ssid_opt, pass_opt) {
                            (Some(ssid), Some(pass)) => {
                                join_wifi_via_corewlan(&mac_bridge, &ssid, &pass)
                                    .await
                                    .map(|()| format!("Connected to {ssid}"))
                            }
                            _ => Err("No shared Wi-Fi credentials cached".into()),
                        };
                        {
                            let mut st = state.lock().await;
                            st.busy_action = None;
                            st.emit_status();
                        }
                        match res {
                            Ok(m) => emit_json(&DaemonEvent::ActionResult {
                                action: "connect_phone_wifi".into(),
                                ok: true,
                                message: m,
                            }),
                            Err(e) => emit_json(&DaemonEvent::ActionResult {
                                action: "connect_phone_wifi".into(),
                                ok: false,
                                message: e,
                            }),
                        }
                    }
                    DaemonCommand::ProbeTether
                    | DaemonCommand::StartHotspot
                    | DaemonCommand::StopHotspot => {
                        let mode = match cmd {
                            DaemonCommand::StartHotspot => TetherMode::StartHotspot,
                            DaemonCommand::StopHotspot => TetherMode::StopHotspot,
                            _ => TetherMode::Probe,
                        };
                        let keys = keys_lock.read().await.clone();
                        let (device_id, device_name) = local_identity.read().await.clone();
                        let _guard = ble_lock.lock().await;
                        {
                            let mut st = state.lock().await;
                            st.busy_action = Some(match mode {
                                TetherMode::StartHotspot => "Starting Instant Hotspot...".into(),
                                TetherMode::StopHotspot => "Stopping Instant Hotspot...".into(),
                                TetherMode::Probe => "Refreshing phone status...".into(),
                            });
                            st.emit_status();
                        }

                        // For StartHotspot / StopHotspot, try the cached BLE peripheral first to
                        // skip the ~1.5-2s BLE scan! Fall back to a fresh scan if RPA rotated.
                        let cached_target = if mode != TetherMode::Probe {
                            let st = state.lock().await;
                            match (&st.peripheral_id, st.peer_key_seed) {
                                (Some(pid), Some(ks)) => Some((pid.clone(), ks)),
                                _ => None,
                            }
                        } else {
                            None
                        };

                        let tether_outcome: Result<TetherResult, String> =
                            if let Some((pid, ks)) = cached_target {
                                match run_tether_ble(
                                    &mac_bridge,
                                    &pid,
                                    &device_id,
                                    &device_name,
                                    ks,
                                    mode,
                                )
                                .await
                                {
                                    Ok(tr) => Ok(tr),
                                    Err(first_err) => {
                                        log_msg(format!(
                                            "Cached BLE tether failed ({first_err}); rescanning..."
                                        ));
                                        if let Some(peer) =
                                            scan_for_phone(&mac_bridge, &keys, 5).await
                                        {
                                            {
                                                let mut st = state.lock().await;
                                                st.peripheral_id =
                                                    Some(peer.peripheral_id.clone());
                                                st.device_name = peer.device_name.clone();
                                                st.peer_device_id = peer.device_id.clone();
                                                st.peer_key_seed = Some(peer.key_seed);
                                                st.ble_nearby = true;
                                                st.rssi = Some(peer.rssi);
                                                st.instant_hotspot_flag =
                                                    peer.instant_hotspot_available;
                                            }
                                            run_tether_ble(
                                                &mac_bridge,
                                                &peer.peripheral_id,
                                                &device_id,
                                                &device_name,
                                                peer.key_seed,
                                                mode,
                                            )
                                            .await
                                        } else {
                                            Err("Phone not found over BLE".into())
                                        }
                                    }
                                }
                            } else if let Some(peer) = scan_for_phone(&mac_bridge, &keys, 5).await {
                                {
                                    let mut st = state.lock().await;
                                    st.peripheral_id = Some(peer.peripheral_id.clone());
                                    st.device_name = peer.device_name.clone();
                                    st.peer_device_id = peer.device_id.clone();
                                    st.peer_key_seed = Some(peer.key_seed);
                                    st.ble_nearby = true;
                                    st.rssi = Some(peer.rssi);
                                    st.instant_hotspot_flag = peer.instant_hotspot_available;
                                }
                                if mode == TetherMode::Probe && !peer.instant_hotspot_available {
                                    let mut st = state.lock().await;
                                    st.hotspot_available = false;
                                    st.hotspot_active = false;
                                    st.hotspot_ssid = None;
                                    st.wifi_share_available = false;
                                    st.wifi_share_ssid = None;
                                    st.wifi_share_password = None;
                                    log_msg("Phone not advertising Instant Hotspot/Wi-Fi right now");
                                    Err("__SKIP_PROBE__".into())
                                } else {
                                    run_tether_ble(
                                        &mac_bridge,
                                        &peer.peripheral_id,
                                        &device_id,
                                        &device_name,
                                        peer.key_seed,
                                        mode,
                                    )
                                    .await
                                }
                            } else {
                                Err("Phone not found over BLE".into())
                            };

                        let action_res = match tether_outcome {
                            Err(e) if e == "__SKIP_PROBE__" => {
                                Ok("Status updated".into())
                            }
                            Ok(tr) => {
                                if mode == TetherMode::StopHotspot {
                                    {
                                        let mut st = state.lock().await;
                                        st.hotspot_active = false;
                                        st.hotspot_ssid = None;
                                    }
                                    log_msg("Sent DisconnectTetheringRequest (type=5) to phone");
                                    Ok("Instant Hotspot stopped".into())
                                } else {
                                    {
                                        let mut st = state.lock().await;
                                        if tr.battery_percent.is_some() {
                                            st.battery_percent = tr.battery_percent;
                                        }
                                        if tr.cell_provider.is_some() {
                                            st.cell_provider = tr.cell_provider.clone();
                                        }
                                        st.hotspot_available = tr.hotspot_available;
                                        st.hotspot_active = tr.hotspot_active;
                                        if tr.hotspot_ssid.is_some() {
                                            st.hotspot_ssid = tr.hotspot_ssid.clone();
                                        } else if !tr.hotspot_active {
                                            st.hotspot_ssid = None;
                                        }
                                        st.wifi_share_available = tr.wifi_share_available;
                                        st.wifi_share_ssid = tr.wifi_share_ssid.clone();
                                        st.wifi_share_password = tr.wifi_share_password.clone();
                                    }
                                    if mode == TetherMode::StartHotspot {
                                        if let (Some(ssid), Some(pass)) =
                                            (tr.hotspot_ssid, tr.hotspot_password)
                                        {
                                            log_msg(format!(
                                                "Instant Hotspot enabled ({ssid}); joining Wi-Fi..."
                                            ));
                                            match join_wifi_via_corewlan(&mac_bridge, &ssid, &pass)
                                                .await
                                            {
                                                Ok(()) => {
                                                    {
                                                        let mut st = state.lock().await;
                                                        st.hotspot_active = true;
                                                        st.hotspot_ssid = Some(ssid.clone());
                                                    }
                                                    just_joined_hotspot
                                                        .store(true, Ordering::Relaxed);
                                                    let _ = cancel_dl_tx.try_send(());
                                                    Ok(format!(
                                                        "Connected to Instant Hotspot {ssid}"
                                                    ))
                                                }
                                                Err(e) => Err(format!(
                                                    "Hotspot {ssid} enabled, but Wi-Fi join failed: {e}"
                                                )),
                                            }
                                        } else {
                                            Err(tr.error.unwrap_or_else(|| {
                                                "Hotspot did not return credentials".into()
                                            }))
                                        }
                                    } else {
                                        Ok("Phone status updated".into())
                                    }
                                }
                            }
                            Err(e) => Err(e),
                        };

                        {
                            let mut st = state.lock().await;
                            st.busy_action = None;
                            st.emit_status();
                        }
                        if mode == TetherMode::StartHotspot || mode == TetherMode::StopHotspot {
                            let action_name = if mode == TetherMode::StartHotspot {
                                "start_hotspot"
                            } else {
                                "stop_hotspot"
                            };
                            match action_res {
                                Ok(m) => emit_json(&DaemonEvent::ActionResult {
                                    action: action_name.into(),
                                    ok: true,
                                    message: m,
                                }),
                                Err(e) => emit_json(&DaemonEvent::ActionResult {
                                    action: action_name.into(),
                                    ok: false,
                                    message: e,
                                }),
                            }
                        }
                    }
                }
            }
        });
    }

    // Main connection supervisor loop (wait for keys -> scan -> optional tether probe -> DeviceLink Wi-Fi LAN)
    let mut dl_fail_streak: u32 = 0;
    loop {
        let keys = derived_keys.read().await.clone();
        if keys.is_empty() {
            let _ = tokio::time::timeout(Duration::from_secs(5), cancel_dl_rx.recv()).await;
            continue;
        }
        let (device_id, device_name) = local_identity.read().await.clone();

        let peer_opt = {
            let _guard = ble_lock.lock().await;
            scan_for_phone(&mac_bridge, &keys, 10).await
        };

        let Some(peer) = peer_opt else {
            {
                let mut st = state.lock().await;
                st.ble_nearby = false;
                st.devicelink_connected = false;
                st.emit_status();
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        };

        {
            let mut st = state.lock().await;
            st.peripheral_id = Some(peer.peripheral_id.clone());
            st.device_name = peer.device_name.clone();
            st.peer_device_id = peer.device_id.clone();
            st.peer_key_seed = Some(peer.key_seed);
            st.ble_nearby = true;
            st.rssi = Some(peer.rssi);
            st.instant_hotspot_flag = peer.instant_hotspot_available;
            st.emit_status();
        }

        // If Pixel advertises Instant Hotspot / Instant Wi-Fi availability bit, quickly grab
        // battery percentage, carrier, hotspot active state, and shareable Wi-Fi over BLE!
        let mut phone_on_cellular_only = false;
        if peer.instant_hotspot_available {
            let _guard = ble_lock.lock().await;
            match run_tether_ble(
                &mac_bridge,
                &peer.peripheral_id,
                &device_id,
                &device_name,
                peer.key_seed,
                TetherMode::Probe,
            )
            .await
            {
                Ok(tr) => {
                    if tr.is_wifi_connected == Some(false) {
                        phone_on_cellular_only = true;
                    }
                    let mut st = state.lock().await;
                    if tr.battery_percent.is_some() {
                        st.battery_percent = tr.battery_percent;
                    }
                    if tr.cell_provider.is_some() {
                        st.cell_provider = tr.cell_provider;
                    }
                    st.hotspot_available = tr.hotspot_available;
                    st.hotspot_active = tr.hotspot_active;
                    if tr.hotspot_ssid.is_some() {
                        st.hotspot_ssid = tr.hotspot_ssid;
                    } else if !tr.hotspot_active {
                        st.hotspot_ssid = None;
                    }
                    st.wifi_share_available = tr.wifi_share_available;
                    st.wifi_share_ssid = tr.wifi_share_ssid;
                    st.wifi_share_password = tr.wifi_share_password;
                    st.emit_status();
                    log_msg(format!(
                        "Tether probe ok: battery={:?}% hotspot_avail={} hotspot_active={} wifi_connected={:?} wifi_share={}",
                        st.battery_percent, st.hotspot_available, st.hotspot_active, tr.is_wifi_connected, st.wifi_share_available
                    ));
                }
                Err(e) => {
                    log_msg(format!("Tether probe failed: {e}"));
                }
            }
            tokio::time::sleep(Duration::from_millis(600)).await;
        } else {
            {
                let mut st = state.lock().await;
                if st.hotspot_available || st.hotspot_active || st.wifi_share_available {
                    st.hotspot_available = false;
                    st.hotspot_active = false;
                    st.hotspot_ssid = None;
                    st.wifi_share_available = false;
                    st.wifi_share_ssid = None;
                    st.wifi_share_password = None;
                    st.emit_status();
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Verified on Android phone logcat: GMS DTDI only upgrades over STA Wi-Fi LAN (`wlan0`),
        // never over cellular or SoftAP (`ap_br_wlan2`). When phone has no Wi-Fi STA connection,
        // keep BLE 100% free so Start/Stop Instant Hotspot execute immediately!
        let _ = just_joined_hotspot.swap(false, Ordering::Relaxed);
        if phone_on_cellular_only {
            let _ = tokio::time::timeout(Duration::from_secs(15), cancel_dl_rx.recv()).await;
            continue;
        }

        // Now establish persistent DeviceLink over Wi-Fi LAN TCP (BLE is freed right after upgrade!)
        while cancel_dl_rx.try_recv().is_ok() {}
        let mut did_connect_tcp = false;
        let dl_res = run_devicelink_session(
            &mac_bridge,
            &peer.peripheral_id,
            &device_id,
            &device_name,
            peer.key_seed,
            state.clone(),
            dl_connected.clone(),
            ble_lock.clone(),
            &mut qa_rx,
            &mut notif_rx,
            &mut cancel_dl_rx,
            &mut did_connect_tcp,
        )
        .await;

        if did_connect_tcp {
            dl_fail_streak = 0;
        }
        let wait_secs: u64 = match dl_res {
            Ok(()) => {
                // Manual Reconnect requested
                dl_fail_streak = 0;
                1
            }
            Err(e) => {
                log_msg(format!("DeviceLink ended (tcp_ok={did_connect_tcp}): {e}"));
                if did_connect_tcp {
                    5
                } else {
                    // Exponential backoff when Wi-Fi LAN upgrade fails (e.g. different Wi-Fi
                    // networks) so we don't repeatedly trigger DtdiIncomingConnectionWakeupActivity!
                    dl_fail_streak = dl_fail_streak.saturating_add(1);
                    match dl_fail_streak {
                        1 => 10,
                        2 => 30,
                        3 => 60,
                        _ => 180,
                    }
                }
            }
        };
        if wait_secs > 1 {
            log_msg(format!("Next DeviceLink retry in {wait_secs}s (or immediately on Reconnect)"));
        }
        if tokio::time::timeout(Duration::from_secs(wait_secs), cancel_dl_rx.recv())
            .await
            .is_ok()
        {
            // Manual Reconnect woke us up early — reset backoff immediately
            dl_fail_streak = 0;
        }
    }
}
