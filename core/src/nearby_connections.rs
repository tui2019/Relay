//! Google Nearby Connections wire framing (`OfflineFrame` / `V1Frame`) and
//! BLE v2 (`0xFEF3`) / Wi-Fi LAN TCP length-prefixed framing.
//!
//! Wire-compatible with `google/nearby/connections/implementation/proto/offline_wire_formats.proto`.

use prost::Message;
use thiserror::Error;

/// Nearby Connections BLE v2 Service UUID (`0xFEF3`).
pub const NEARBY_BLE_V2_SERVICE_UUID: &str = "0000FEF3-0000-1000-8000-00805F9B34FB";

/// Nearby Connections BLE v2 L2CAP/GATT data packet magic (service_id hash = 3 bytes).
pub const BLE_V2_CONTROL_PACKET_SERVICE_ID_HASH: [u8; 3] = [0x00, 0x00, 0x00];

/// Instant Hotspot / SharedConnectivity Nearby Connections service ID (verified in `TetherChimeraService.java`).
pub const SERVICE_ID_SHARED_CONNECTIVITY: &str = "nearby.sharedconnectivity";

/// DTDI / DeviceLink channel name extra (verified in `lhx.java`).
pub const DEVICELINK_DTDI_WAKEUP: &str =
    "com.google.ambient.streaming.multidevicesync.devicelink.dtdi.WAKEUP";
pub const DEVICELINK_DTDI_CHANNEL_EXTRA: &str =
    "com.google.ambient.streaming.multidevicesync.devicelink.dtdi.CHANNEL_NAME";

#[derive(Debug, Error)]
pub enum NearbyError {
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("frame truncated or invalid length prefix")]
    TruncatedFrame,
    #[error("payload chunk out of order or unknown payload_id {0}")]
    InvalidPayload(i64),
}

// ---------------------------------------------------------------------------
// Wire-exact OfflineFrame protobufs (offline_wire_formats.proto)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct OfflineFrame {
    /// 1 = V1
    #[prost(int32, optional, tag = "1")]
    pub version: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub v1: Option<V1Frame>,
}

#[derive(Clone, PartialEq, Message)]
pub struct V1Frame {
    /// 1=CONNECTION_REQUEST, 2=CONNECTION_RESPONSE, 3=PAYLOAD_TRANSFER,
    /// 4=BANDWIDTH_UPGRADE_NEGOTIATION, 5=KEEP_ALIVE, 6=DISCONNECTION, 7=PAIRED_KEY_ENCRYPTION
    #[prost(int32, optional, tag = "1")]
    pub r#type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub connection_request: Option<ConnectionRequestFrame>,
    #[prost(message, optional, tag = "3")]
    pub connection_response: Option<ConnectionResponseFrame>,
    #[prost(message, optional, tag = "4")]
    pub payload_transfer: Option<PayloadTransferFrame>,
    #[prost(message, optional, tag = "5")]
    pub bandwidth_upgrade_negotiation: Option<BandwidthUpgradeNegotiationFrame>,
    #[prost(message, optional, tag = "6")]
    pub keep_alive: Option<KeepAliveFrame>,
    #[prost(message, optional, tag = "7")]
    pub disconnection: Option<DisconnectionFrame>,
    #[prost(message, optional, tag = "8")]
    pub paired_key_encryption: Option<PairedKeyEncryptionFrame>,
    #[prost(message, optional, tag = "9")]
    pub authentication_message: Option<AuthenticationMessageFrame>,
    #[prost(message, optional, tag = "10")]
    pub authentication_result: Option<AuthenticationResultFrame>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PairedKeyEncryptionFrame {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub signed_data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AuthenticationMessageFrame {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub auth_message: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AuthenticationResultFrame {
    #[prost(int32, optional, tag = "1")]
    pub result: Option<i32>,
}

/// Wire-exact `PresenceDevice` embedded in `ConnectionRequestFrame` (tag 13).
/// Required by `magictether` (`dgzp.java:43`: `if (!(dmhbVar instanceof PresenceDevice))`).
#[derive(Clone, PartialEq, Message)]
pub struct PresenceDeviceProto {
    #[prost(string, optional, tag = "1")]
    pub endpoint_id: Option<String>,
    /// 2 = PRESENCE_ENDPOINT
    #[prost(int32, optional, tag = "2")]
    pub endpoint_type: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub connectivity_info_list: Option<Vec<u8>>,
    #[prost(int64, optional, tag = "4")]
    pub device_id: Option<i64>,
    #[prost(string, optional, tag = "5")]
    pub device_name: Option<String>,
    /// 1=PHONE, 2=TABLET, 4=LAPTOP
    #[prost(int32, optional, tag = "6")]
    pub device_type: Option<i32>,
    #[prost(string, optional, tag = "7")]
    pub device_image_url: Option<String>,
    #[prost(int32, repeated, packed = "true", tag = "8")]
    pub discovery_medium: Vec<i32>,
    #[prost(int32, repeated, packed = "true", tag = "9")]
    pub actions: Vec<i32>,
    #[prost(int64, repeated, packed = "true", tag = "10")]
    pub identity_type: Vec<i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConnectionRequestFrame {
    #[prost(string, optional, tag = "1")]
    pub endpoint_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub endpoint_name: Option<String>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub handshake_data: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "4")]
    pub nonce: Option<i32>,
    /// Mediums supported: 1=MDNS, 2=BLUETOOTH, 3=WIFI_HOTSPOT, 4=BLE, 5=WIFI_LAN, 10=BLE_L2CAP
    #[prost(int32, repeated, packed = "false", tag = "5")]
    pub mediums: Vec<i32>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub endpoint_info: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "8")]
    pub keep_alive_interval_millis: Option<i32>,
    #[prost(int32, optional, tag = "9")]
    pub keep_alive_timeout_millis: Option<i32>,
    #[prost(message, optional, tag = "13")]
    pub presence_device: Option<PresenceDeviceProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ConnectionResponseFrame {
    /// 0 = OK (STATUS_OK), 8004 = REJECTED
    #[prost(int32, optional, tag = "1")]
    pub status: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub handshake_data: Option<Vec<u8>>,
    /// 1 = ACCEPT, 2 = REJECT
    #[prost(int32, optional, tag = "3")]
    pub response: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PayloadTransferFrame {
    /// 1 = DATA, 2 = CONTROL
    #[prost(int32, optional, tag = "1")]
    pub packet_type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub payload_header: Option<PayloadHeader>,
    #[prost(message, optional, tag = "3")]
    pub payload_chunk: Option<PayloadChunk>,
    #[prost(message, optional, tag = "4")]
    pub control_message: Option<PayloadControlMessage>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PayloadHeader {
    #[prost(int64, optional, tag = "1")]
    pub id: Option<i64>,
    /// 1 = BYTES, 2 = FILE, 3 = STREAM
    #[prost(int32, optional, tag = "2")]
    pub r#type: Option<i32>,
    #[prost(int64, optional, tag = "3")]
    pub total_size: Option<i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PayloadChunk {
    /// bit 0 (1) = LAST_CHUNK
    #[prost(int32, optional, tag = "1")]
    pub flags: Option<i32>,
    #[prost(int64, optional, tag = "2")]
    pub offset: Option<i64>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PayloadControlMessage {
    /// 1 = PAYLOAD_ERROR, 2 = PAYLOAD_CANCELED, 3 = PAYLOAD_RECEIVED_ACK
    #[prost(int32, optional, tag = "1")]
    pub event: Option<i32>,
    #[prost(int64, optional, tag = "2")]
    pub offset: Option<i64>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BandwidthUpgradeNegotiationFrame {
    /// 1=UPGRADE_PATH_AVAILABLE, 2=LAST_WRITE_TO_PRIOR_CHANNEL, 3=SAFE_TO_CLOSE_PRIOR_CHANNEL,
    /// 4=CLIENT_INTRODUCTION, 5=UPGRADE_FAILURE, 6=CLIENT_INTRODUCTION_ACK
    #[prost(int32, optional, tag = "1")]
    pub event_type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub upgrade_path_info: Option<UpgradePathInfo>,
    #[prost(message, optional, tag = "3")]
    pub client_introduction: Option<ClientIntroduction>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ClientIntroduction {
    #[prost(string, optional, tag = "1")]
    pub endpoint_id: Option<String>,
    #[prost(bool, optional, tag = "2")]
    pub supports_disabling_encryption: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub struct UpgradePathInfo {
    /// 3=WIFI_HOTSPOT, 5=WIFI_LAN, 8=WIFI_DIRECT, 9=WEB_RTC
    #[prost(int32, optional, tag = "1")]
    pub medium: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub wifi_hotspot_credentials: Option<WifiHotspotCredentials>,
    /// Verified tag 3 (`itck.e`) in GMS `dmti.java:276-286`
    #[prost(message, optional, tag = "3")]
    pub wifi_lan_socket: Option<WifiLanSocket>,
    /// Verified tag 11 (`itck.k`) in GMS `dmti.java:703-704`
    #[prost(bool, optional, tag = "11")]
    pub supports_client_introduction_ack: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WifiHotspotCredentials {
    #[prost(string, optional, tag = "1")]
    pub ssid: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub password: Option<String>,
    #[prost(int32, optional, tag = "3")]
    pub port: Option<i32>,
    #[prost(string, optional, tag = "4")]
    pub gateway: Option<String>,
    #[prost(int32, optional, tag = "5")]
    pub frequency: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct WifiLanSocket {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ip_address: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    pub wifi_port: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct KeepAliveFrame {
    #[prost(bool, optional, tag = "1")]
    pub ack: Option<bool>,
    #[prost(uint32, optional, tag = "2")]
    pub seq_num: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DisconnectionFrame {
    #[prost(bool, optional, tag = "1")]
    pub request_safe_to_disconnect: Option<bool>,
}

// ---------------------------------------------------------------------------
// Helpers: Builders & Length-Prefixed Framing (TCP / L2CAP / RFCOMM)
// ---------------------------------------------------------------------------

pub fn build_connection_request(endpoint_id: &str, endpoint_info: Vec<u8>, nonce: i32) -> OfflineFrame {
    let endpoint_name = String::from_utf8_lossy(&endpoint_info).to_string();
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(1),
            connection_request: Some(ConnectionRequestFrame {
                endpoint_id: Some(endpoint_id.to_string()),
                endpoint_name: Some(endpoint_name),
                handshake_data: None,
                nonce: Some(nonce),
                mediums: vec![3, 4, 5, 10], // WIFI_HOTSPOT, BLE, WIFI_LAN, BLE_L2CAP
                endpoint_info: Some(endpoint_info),
                keep_alive_interval_millis: Some(5000),
                keep_alive_timeout_millis: Some(30000),
                presence_device: None,
            }),
            ..Default::default()
        }),
    }
}

/// Build a `CONNECTION_REQUEST` presenting as a `PresenceDevice` (tag 13) for
/// `magictether` (`"nearby.sharedconnectivity"`) and Nearby Presence services.
pub fn build_presence_connection_request(
    endpoint_id: &str,
    device_id: i64,
    device_name: &str,
    nonce: i32,
) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(1),
            connection_request: Some(ConnectionRequestFrame {
                endpoint_id: Some(endpoint_id.to_string()),
                endpoint_name: Some(device_name.to_string()),
                handshake_data: None,
                nonce: Some(nonce),
                mediums: vec![3, 4, 5, 10], // WIFI_HOTSPOT, BLE, WIFI_LAN, BLE_L2CAP
                endpoint_info: Some(device_name.as_bytes().to_vec()),
                keep_alive_interval_millis: Some(5000),
                keep_alive_timeout_millis: Some(30000),
                presence_device: Some(PresenceDeviceProto {
                    endpoint_id: Some(endpoint_id.to_string()),
                    endpoint_type: Some(2), // PRESENCE_ENDPOINT
                    connectivity_info_list: None,
                    device_id: Some(device_id),
                    device_name: Some(device_name.to_string()),
                    device_type: Some(4), // LAPTOP
                    device_image_url: None,
                    discovery_medium: vec![4], // BLE
                    actions: vec![10],         // PresenceAction(10) = Instant Tethering
                    identity_type: vec![0],    // PRIVATE
                }),
            }),
            ..Default::default()
        }),
    }
}

pub fn build_connection_response(accept: bool) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(2),
            connection_response: Some(ConnectionResponseFrame {
                status: Some(if accept { 0 } else { 8004 }),
                handshake_data: None,
                response: Some(if accept { 1 } else { 2 }),
            }),
            ..Default::default()
        }),
    }
}

pub fn build_authentication_message(auth_message: Vec<u8>) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(8),
            authentication_message: Some(AuthenticationMessageFrame {
                auth_message: Some(auth_message),
            }),
            ..Default::default()
        }),
    }
}

pub fn build_authentication_result(result: i32) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(9),
            authentication_result: Some(AuthenticationResultFrame {
                result: Some(result),
            }),
            ..Default::default()
        }),
    }
}

pub fn build_keep_alive(ack: bool, seq_num: Option<u32>) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(5),
            keep_alive: Some(KeepAliveFrame {
                ack: Some(ack),
                seq_num,
            }),
            ..Default::default()
        }),
    }
}

pub fn build_bwu_client_introduction(endpoint_id: &str) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(4),
            bandwidth_upgrade_negotiation: Some(BandwidthUpgradeNegotiationFrame {
                event_type: Some(4), // CLIENT_INTRODUCTION
                upgrade_path_info: None,
                client_introduction: Some(ClientIntroduction {
                    endpoint_id: Some(endpoint_id.to_string()),
                    supports_disabling_encryption: Some(false),
                }),
            }),
            ..Default::default()
        }),
    }
}

pub fn build_bwu_event(event_type: i32) -> OfflineFrame {
    OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(4),
            bandwidth_upgrade_negotiation: Some(BandwidthUpgradeNegotiationFrame {
                event_type: Some(event_type),
                upgrade_path_info: None,
                client_introduction: None,
            }),
            ..Default::default()
        }),
    }
}

/// Build a complete BYTES payload transfer (data chunk + terminal LAST_CHUNK frame).
pub fn build_bytes_payload_frames(payload_id: i64, bytes: &[u8]) -> Vec<OfflineFrame> {
    let total = bytes.len() as i64;
    let data_frame = OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(3),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(1),
                payload_header: Some(PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(1), // BYTES
                    total_size: Some(total),
                }),
                payload_chunk: Some(PayloadChunk {
                    flags: Some(0),
                    offset: Some(0),
                    body: Some(bytes.to_vec()),
                }),
                control_message: None,
            }),
            ..Default::default()
        }),
    };
    let end_frame = OfflineFrame {
        version: Some(1),
        v1: Some(V1Frame {
            r#type: Some(3),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(1),
                payload_header: Some(PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(1),
                    total_size: Some(total),
                }),
                payload_chunk: Some(PayloadChunk {
                    flags: Some(1), // LAST_CHUNK
                    offset: Some(total),
                    body: Some(Vec::new()),
                }),
                control_message: None,
            }),
            ..Default::default()
        }),
    };
    vec![data_frame, end_frame]
}

/// Encode a 4-byte big-endian length-prefixed frame (used on Wi-Fi LAN TCP, RFCOMM, and BLE L2CAP).
pub fn encode_length_prefixed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a single 4-byte big-endian length-prefixed frame, returning `(frame_bytes, rest)`.
pub fn decode_length_prefixed(buf: &[u8]) -> Result<(&[u8], &[u8]), NearbyError> {
    if buf.len() < 4 {
        return Err(NearbyError::TruncatedFrame);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Err(NearbyError::TruncatedFrame);
    }
    Ok((&buf[4..4 + len], &buf[4 + len..]))
}

/// BLE v2 data packet wrapper (`3-byte service_id_hash || 4-byte BE length || payload`).
pub fn encode_ble_v2_data_packet(service_id_hash: [u8; 3], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len());
    out.extend_from_slice(&service_id_hash);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_frame_bytes_payload_roundtrip() {
        let frames = build_bytes_payload_frames(12345, b"hello devicelink");
        assert_eq!(frames.len(), 2);
        let wire = encode_length_prefixed(&frames[0].encode_to_vec());
        let (raw, rest) = decode_length_prefixed(&wire).unwrap();
        assert!(rest.is_empty());
        let decoded = OfflineFrame::decode(raw).unwrap();
        let pt = decoded.v1.unwrap().payload_transfer.unwrap();
        assert_eq!(pt.payload_header.unwrap().id, Some(12345));
        assert_eq!(pt.payload_chunk.unwrap().body.unwrap(), b"hello devicelink");
    }
}
