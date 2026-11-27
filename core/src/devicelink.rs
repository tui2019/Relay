//! Android 17 `DeviceLink` RPC wire protocol (`com.google.ambient.streaming`).
//!
//! Field numbers and message structures verified directly from Pixel 9 Pro Android 17
//! `base.apk` (`wmr`, `wms`, `wmu`, `wmp`, `wmi`, `wmk`, `wnc`, `wmg`, `wna`, `wmx`,
//! `wmw`, `wmv`, `wnb`, `wmz`, `wmy`, and `loj.java`).

use prost::Message;
use std::collections::HashMap;
use thiserror::Error;

pub const SERVICE_NOTIFICATION_SYNC: &str = "NotificationSyncRpcService";
pub const SERVICE_COMPANION_TRANSPORT: &str = "CompanionTransportService";
pub const SERVICE_QUICK_ACCESS: &str = "QuickAccessService";

#[derive(Debug, Error)]
pub enum DeviceLinkError {
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("remote cancelled request {request_id}: {reason}")]
    RemoteCancelled { request_id: i64, reason: String },
}

/// Device form factor enum (`wmk.d`, mapped in `loj.java:471-496`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DeviceType {
    Phone = 0,
    Tablet = 1,
    Desktop = 2,
    Xr = 3,
}

/// Outer DTDI framing envelope used by `com.google.ambient.streaming` on `DeviceLink` channels:
/// - `tag 1`: unchunked `DeviceLinkPacket` bytes (for packets <= 4096 bytes)
/// - `tag 2`: chunked `DeviceLinkPacket` fragment (`4096`-byte chunks for larger packets like
///   `NotificationSyncEvent` batches with PNG icons)
#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkWireEnvelope {
    #[prost(oneof = "device_link_wire_envelope::Payload", tags = "1, 2")]
    pub payload: Option<device_link_wire_envelope::Payload>,
}

pub mod device_link_wire_envelope {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Payload {
        #[prost(bytes = "vec", tag = "1")]
        Single(Vec<u8>),
        #[prost(message, tag = "2")]
        Chunk(DeviceLinkChunk),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkChunk {
    #[prost(int64, optional, tag = "1")]
    pub message_id: Option<i64>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub data: Option<Vec<u8>>,
    /// Tag 3: `is_last` (`0` = more chunks follow, `1` = final chunk; verified live on Pixel 9 Pro).
    #[prost(int32, optional, tag = "3")]
    pub is_last: Option<i32>,
}

/// Reassembles 4096-byte `DeviceLinkChunk` frames into full `DeviceLinkPacket` byte buffers.
#[derive(Default)]
pub struct DeviceLinkChunkReassembler {
    buffers: HashMap<i64, Vec<u8>>,
}

impl DeviceLinkChunkReassembler {
    /// Push a raw DTDI `com.google.ambient.streaming` channel payload (`DeviceLinkWireEnvelope`).
    /// Returns `Ok(Some(packet_bytes))` when a complete `DeviceLinkPacket` is ready,
    /// or `Ok(None)` when waiting for more chunks.
    pub fn push(
        &mut self,
        raw: &[u8],
    ) -> Result<(Option<Vec<u8>>, Option<(i64, usize, bool)>), DeviceLinkError> {
        let env = DeviceLinkWireEnvelope::decode(raw)?;
        match env.payload {
            Some(device_link_wire_envelope::Payload::Single(bytes)) => Ok((Some(bytes), None)),
            Some(device_link_wire_envelope::Payload::Chunk(chunk)) => {
                let id = chunk.message_id.unwrap_or(0);
                let data = chunk.data.unwrap_or_default();
                let chunk_len = data.len();
                let is_last = chunk.is_last == Some(1);
                let buf = self.buffers.entry(id).or_default();
                buf.extend_from_slice(&data);
                if is_last {
                    let full = self.buffers.remove(&id).unwrap_or_default();
                    Ok((Some(full), Some((id, chunk_len, true))))
                } else {
                    Ok((None, Some((id, chunk_len, false))))
                }
            }
            None => Ok((None, None)),
        }
    }
}

/// Top-level DeviceLink packet (`wmr.java`).
#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkPacket {
    #[prost(oneof = "device_link_packet::Body", tags = "1, 2, 3, 4")]
    pub body: Option<device_link_packet::Body>,
}

pub mod device_link_packet {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "1")]
        Request(DeviceLinkRequest),
        #[prost(message, tag = "2")]
        Response(DeviceLinkResponse),
        #[prost(message, tag = "3")]
        Cancel(DeviceLinkCancel),
        #[prost(message, tag = "4")]
        Control(DeviceLinkControl),
    }
}

/// `wms.java`: RPC request packet.
#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkRequest {
    #[prost(int64, optional, tag = "1")]
    pub request_id: Option<i64>,
    #[prost(string, optional, tag = "2")]
    pub service_name: Option<String>,
    #[prost(oneof = "device_link_request::Kind", tags = "3, 4, 5, 6")]
    pub kind: Option<device_link_request::Kind>,
}

pub mod device_link_request {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "3")]
        UnaryCall(UnaryCall),
        #[prost(message, tag = "4")]
        StreamStart(StreamStart),
        #[prost(message, tag = "5")]
        StreamPayload(StreamPayload),
        #[prost(message, tag = "6")]
        StreamEnd(StreamEnd),
    }
}

/// `wna`: unary method name + serialized request protobuf.
#[derive(Clone, PartialEq, Message)]
pub struct UnaryCall {
    #[prost(string, optional, tag = "1")]
    pub method_name: Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub payload: Option<Vec<u8>>,
}

/// `wmx`: start a streaming RPC call.
#[derive(Clone, PartialEq, Message)]
pub struct StreamStart {
    #[prost(string, optional, tag = "1")]
    pub method_name: Option<String>,
}

/// `wmw`: streaming request payload chunk.
#[derive(Clone, PartialEq, Message)]
pub struct StreamPayload {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data: Option<Vec<u8>>,
}

/// `wmv`: end of client stream.
#[derive(Clone, PartialEq, Message)]
pub struct StreamEnd {}

/// `wmu.java`: RPC response packet.
#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkResponse {
    #[prost(int64, optional, tag = "1")]
    pub request_id: Option<i64>,
    #[prost(oneof = "device_link_response::Kind", tags = "2, 3, 4")]
    pub kind: Option<device_link_response::Kind>,
}

pub mod device_link_response {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "2")]
        UnaryResponse(UnaryResponse),
        #[prost(message, tag = "3")]
        StreamChunk(StreamChunk),
        #[prost(message, tag = "4")]
        StreamEnd(ResponseStreamEnd),
    }
}

/// `wnb`: unary response payload bytes.
#[derive(Clone, PartialEq, Message)]
pub struct UnaryResponse {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub payload: Option<Vec<u8>>,
}

/// `wmz`: streaming response chunk bytes.
#[derive(Clone, PartialEq, Message)]
pub struct StreamChunk {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data: Option<Vec<u8>>,
}

/// `wmy`: end of response stream.
#[derive(Clone, PartialEq, Message)]
pub struct ResponseStreamEnd {}

/// `wmp`: cancel an active RPC request.
#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkCancel {
    #[prost(int64, optional, tag = "1")]
    pub request_id: Option<i64>,
    #[prost(string, optional, tag = "2")]
    pub error_message: Option<String>,
}

/// `wmi.java`: DeviceLink control message.
#[derive(Clone, PartialEq, Message)]
pub struct DeviceLinkControl {
    #[prost(oneof = "device_link_control::Kind", tags = "1, 2, 3")]
    pub kind: Option<device_link_control::Kind>,
}

pub mod device_link_control {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        DeviceMetadata(DeviceMetadata),
        #[prost(message, tag = "2")]
        ServiceList(ServiceList),
        #[prost(message, tag = "3")]
        AttestationInfo(AttestationInfo),
    }
}

/// `wmk.java`: peer metadata exchanged at session start.
#[derive(Clone, PartialEq, Message)]
pub struct DeviceMetadata {
    #[prost(string, optional, tag = "1")]
    pub device_id: Option<String>,
    /// 0=PHONE, 1=TABLET, 2=DESKTOP, 3=XR
    #[prost(int32, optional, tag = "2")]
    pub device_type: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub os_version: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub cds_version: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub gms_version: Option<String>,
    /// 16-byte attestation challenge nonce (unused for non-attested services like NotificationSync & CompanionTransport).
    #[prost(bytes = "vec", optional, tag = "6")]
    pub attestation_challenge: Option<Vec<u8>>,
}

/// `wnc`: list of exposed DeviceLink RPC service names.
#[derive(Clone, PartialEq, Message)]
pub struct ServiceList {
    #[prost(string, repeated, tag = "1")]
    pub services: Vec<String>,
}

/// `wmg`: DER-encoded X.509 attestation cert chain (only required by AppCast).
#[derive(Clone, PartialEq, Message)]
pub struct AttestationInfo {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub cert_chain: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// CompanionTransportService RPC protobufs (`kzc.java`, `kzn.java`, `lau.java`)
// ---------------------------------------------------------------------------

/// `kzn.java`: `CanFormCompanionTransportWithDevice` request/response (`isDebuggable` / `canForm`).
#[derive(Clone, PartialEq, Message)]
pub struct CompanionTransportBoolMsg {
    #[prost(bool, optional, tag = "1")]
    pub value: Option<bool>,
}

/// `kzc.java`: `ExchangeCapabilities` capability bitmask/enum.
#[derive(Clone, PartialEq, Message)]
pub struct CompanionTransportCapabilityMsg {
    #[prost(int32, optional, tag = "1")]
    pub capability: Option<i32>,
}

// ---------------------------------------------------------------------------
// DeviceLink Session Multiplexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum DeviceLinkEvent {
    RemoteMetadata(DeviceMetadata),
    RemoteServices(Vec<String>),
    IncomingUnaryCall {
        request_id: i64,
        service: String,
        method: String,
        payload: Vec<u8>,
    },
    IncomingStreamStart {
        request_id: i64,
        service: String,
        method: String,
    },
    IncomingStreamData {
        request_id: i64,
        service: String,
        method: String,
        data: Vec<u8>,
    },
    IncomingStreamEnd {
        request_id: i64,
    },
    ResponsePayload {
        request_id: i64,
        data: Vec<u8>,
        is_stream_end: bool,
    },
    Cancelled {
        request_id: i64,
        reason: String,
    },
}

pub struct DeviceLinkSession {
    next_request_id: i64,
    active_streams: HashMap<i64, (String, String)>,
}

impl Default for DeviceLinkSession {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceLinkSession {
    pub fn new() -> Self {
        Self {
            next_request_id: 1,
            active_streams: HashMap::new(),
        }
    }

    pub fn build_desktop_handshake(device_id: &str, os_version: &str) -> Vec<DeviceLinkPacket> {
        let mut challenge = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
        let meta = DeviceLinkPacket {
            body: Some(device_link_packet::Body::Control(DeviceLinkControl {
                kind: Some(device_link_control::Kind::DeviceMetadata(DeviceMetadata {
                    device_id: Some(device_id.to_string()),
                    device_type: Some(DeviceType::Desktop as i32),
                    os_version: Some(os_version.to_string()),
                    cds_version: Some("1.0".to_string()),
                    gms_version: Some("26.22.43".to_string()),
                    attestation_challenge: Some(challenge),
                })),
            })),
        };
        let services = DeviceLinkPacket {
            body: Some(device_link_packet::Body::Control(DeviceLinkControl {
                kind: Some(device_link_control::Kind::ServiceList(ServiceList {
                    services: vec![
                        SERVICE_NOTIFICATION_SYNC.to_string(),
                        SERVICE_COMPANION_TRANSPORT.to_string(),
                    ],
                })),
            })),
        };
        vec![meta, services]
    }

    pub fn build_unary_request(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> (i64, DeviceLinkPacket) {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let pkt = DeviceLinkPacket {
            body: Some(device_link_packet::Body::Request(DeviceLinkRequest {
                request_id: Some(id),
                service_name: Some(service.to_string()),
                kind: Some(device_link_request::Kind::UnaryCall(UnaryCall {
                    method_name: Some(method.to_string()),
                    payload: Some(payload),
                })),
            })),
        };
        (id, pkt)
    }

    pub fn build_unary_response(request_id: i64, payload: Vec<u8>) -> DeviceLinkPacket {
        DeviceLinkPacket {
            body: Some(device_link_packet::Body::Response(DeviceLinkResponse {
                request_id: Some(request_id),
                kind: Some(device_link_response::Kind::UnaryResponse(UnaryResponse {
                    payload: Some(payload),
                })),
            })),
        }
    }

    pub fn build_stream_start(&mut self, service: &str, method: &str) -> (i64, DeviceLinkPacket) {
        let id = self.next_request_id;
        self.next_request_id += 1;
        self.active_streams
            .insert(id, (service.to_string(), method.to_string()));
        let pkt = DeviceLinkPacket {
            body: Some(device_link_packet::Body::Request(DeviceLinkRequest {
                request_id: Some(id),
                service_name: Some(service.to_string()),
                kind: Some(device_link_request::Kind::StreamStart(StreamStart {
                    method_name: Some(method.to_string()),
                })),
            })),
        };
        (id, pkt)
    }

    pub fn build_stream_data(request_id: i64, service: &str, data: Vec<u8>) -> DeviceLinkPacket {
        DeviceLinkPacket {
            body: Some(device_link_packet::Body::Request(DeviceLinkRequest {
                request_id: Some(request_id),
                service_name: Some(service.to_string()),
                kind: Some(device_link_request::Kind::StreamPayload(StreamPayload {
                    data: Some(data),
                })),
            })),
        }
    }

    pub fn build_stream_end(request_id: i64, service: &str) -> DeviceLinkPacket {
        DeviceLinkPacket {
            body: Some(device_link_packet::Body::Request(DeviceLinkRequest {
                request_id: Some(request_id),
                service_name: Some(service.to_string()),
                kind: Some(device_link_request::Kind::StreamEnd(StreamEnd {})),
            })),
        }
    }

    pub fn handle_incoming(&mut self, wire: &[u8]) -> Result<Option<DeviceLinkEvent>, DeviceLinkError> {
        let pkt = DeviceLinkPacket::decode(wire)?;
        let Some(body) = pkt.body else {
            return Ok(None);
        };
        match body {
            device_link_packet::Body::Control(ctrl) => match ctrl.kind {
                Some(device_link_control::Kind::DeviceMetadata(m)) => {
                    Ok(Some(DeviceLinkEvent::RemoteMetadata(m)))
                }
                Some(device_link_control::Kind::ServiceList(s)) => {
                    Ok(Some(DeviceLinkEvent::RemoteServices(s.services)))
                }
                _ => Ok(None),
            },
            device_link_packet::Body::Request(req) => {
                let id = req.request_id.unwrap_or(0);
                let service = req.service_name.unwrap_or_default();
                match req.kind {
                    Some(device_link_request::Kind::UnaryCall(u)) => {
                        Ok(Some(DeviceLinkEvent::IncomingUnaryCall {
                            request_id: id,
                            service,
                            method: u.method_name.unwrap_or_default(),
                            payload: u.payload.unwrap_or_default(),
                        }))
                    }
                    Some(device_link_request::Kind::StreamStart(s)) => {
                        let method = s.method_name.unwrap_or_default();
                        self.active_streams
                            .insert(id, (service.clone(), method.clone()));
                        Ok(Some(DeviceLinkEvent::IncomingStreamStart {
                            request_id: id,
                            service,
                            method,
                        }))
                    }
                    Some(device_link_request::Kind::StreamPayload(p)) => {
                        let (svc, mth) = self
                            .active_streams
                            .get(&id)
                            .cloned()
                            .unwrap_or((service, String::new()));
                        Ok(Some(DeviceLinkEvent::IncomingStreamData {
                            request_id: id,
                            service: svc,
                            method: mth,
                            data: p.data.unwrap_or_default(),
                        }))
                    }
                    Some(device_link_request::Kind::StreamEnd(_)) => {
                        self.active_streams.remove(&id);
                        Ok(Some(DeviceLinkEvent::IncomingStreamEnd { request_id: id }))
                    }
                    None => Ok(None),
                }
            }
            device_link_packet::Body::Response(resp) => {
                let id = resp.request_id.unwrap_or(0);
                match resp.kind {
                    Some(device_link_response::Kind::UnaryResponse(u)) => {
                        Ok(Some(DeviceLinkEvent::ResponsePayload {
                            request_id: id,
                            data: u.payload.unwrap_or_default(),
                            is_stream_end: true,
                        }))
                    }
                    Some(device_link_response::Kind::StreamChunk(c)) => {
                        Ok(Some(DeviceLinkEvent::ResponsePayload {
                            request_id: id,
                            data: c.data.unwrap_or_default(),
                            is_stream_end: false,
                        }))
                    }
                    Some(device_link_response::Kind::StreamEnd(_)) => {
                        Ok(Some(DeviceLinkEvent::ResponsePayload {
                            request_id: id,
                            data: Vec::new(),
                            is_stream_end: true,
                        }))
                    }
                    None => Ok(None),
                }
            }
            device_link_packet::Body::Cancel(c) => Ok(Some(DeviceLinkEvent::Cancelled {
                request_id: c.request_id.unwrap_or(0),
                reason: c.error_message.unwrap_or_default(),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devicelink_handshake_and_unary_roundtrip() {
        let mut session = DeviceLinkSession::new();
        let hs = DeviceLinkSession::build_desktop_handshake("mac-1", "macOS 15");
        assert_eq!(hs.len(), 2);
        let ev0 = session.handle_incoming(&hs[0].encode_to_vec()).unwrap().unwrap();
        match ev0 {
            DeviceLinkEvent::RemoteMetadata(m) => {
                assert_eq!(m.device_type, Some(DeviceType::Desktop as i32));
                assert_eq!(m.device_id.as_deref(), Some("mac-1"));
            }
            _ => panic!("expected metadata"),
        }

        let (req_id, pkt) =
            session.build_unary_request(SERVICE_NOTIFICATION_SYNC, "ExecuteRemoteAction", vec![1, 2, 3]);
        assert_eq!(req_id, 1);
        let ev = session.handle_incoming(&pkt.encode_to_vec()).unwrap().unwrap();
        match ev {
            DeviceLinkEvent::IncomingUnaryCall {
                request_id,
                service,
                method,
                payload,
            } => {
                assert_eq!(request_id, 1);
                assert_eq!(service, SERVICE_NOTIFICATION_SYNC);
                assert_eq!(method, "ExecuteRemoteAction");
                assert_eq!(payload, vec![1, 2, 3]);
            }
            _ => panic!("expected unary call"),
        }
    }
}
