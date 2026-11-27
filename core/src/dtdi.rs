//! Wire-exact Google DTDI (`com.google.android.gms.dtdi`) channel framing and
//! `WakeUpChannel` protobufs.
//!
//! Verified directly from `PrebuiltGmsCoreVic.apk` (`classes.dex`, `classes4.dex`, `classes6.dex`):
//! - `brzs.java`: outer DTDI message over Nearby Connections `BYTES` payload
//! - `brzq.java`: `ChannelId` (`app_package_name`, `channel_name`, `channel_type`)
//! - `zwx.java` / `zwp.java`: `WakeUpChannel` envelope & union
//! - `zwu.java` / `zww.java` / `zwr.java` / `zwt.java`: `StartAndroidComponentRequest` / `Response`
//! - `btnm.java` / `btoh.java`: wakeup certificate verification & silent same-account launch

use prost::Message;
use thiserror::Error;

pub const PACKAGE_DTDI: &str = "com.google.android.gms.dtdi";
pub const CHANNEL_WAKEUP: &str = "com.google.android.gms.dtdi.WakeUpChannel";
pub const PACKAGE_AMBIENT_STREAMING: &str = "com.google.ambient.streaming";
pub const ACTION_DEVICELINK_WAKEUP: &str =
    "com.google.ambient.streaming.multidevicesync.devicelink.dtdi.WAKEUP";
pub const EXTRA_DEVICELINK_CHANNEL_NAME: &str =
    "com.google.ambient.streaming.multidevicesync.devicelink.dtdi.CHANNEL_NAME";

/// SHA-256 signing certificate digest of `com.google.ambient.streaming` (verified in
/// `AndroidManifest.xml` `com.google.android.gms.dtdi.alternates` & Pixel 9 Pro `dumpsys companiondevice`).
pub const AMBIENT_STREAMING_CERT_SHA256: [u8; 32] = [
    0xA0, 0x8A, 0x4F, 0x9C, 0xD1, 0x54, 0xF5, 0xF0, 0x0D, 0x65, 0x05, 0xA6, 0xEA, 0x16, 0x63, 0x84,
    0xC7, 0x1E, 0x91, 0xF4, 0xC9, 0xD4, 0x68, 0xB9, 0x82, 0xFC, 0x1F, 0xAE, 0x2B, 0x89, 0x2E, 0x31,
];

#[derive(Debug, Error)]
pub enum DtdiError {
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// `brzq.java`: DTDI channel identifier.
#[derive(Clone, PartialEq, Message)]
pub struct DtdiChannelId {
    #[prost(string, tag = "1")]
    pub app_package_name: String,
    #[prost(string, tag = "2")]
    pub channel_name: String,
    #[prost(int32, tag = "3")]
    pub channel_type: i32,
}

/// `brzr`: DTDI channel close reason.
#[derive(Clone, PartialEq, Message)]
pub struct DtdiChannelClosed {
    #[prost(oneof = "dtdi_channel_closed::Reason", tags = "1, 2")]
    pub reason: Option<dtdi_channel_closed::Reason>,
}

pub mod dtdi_channel_closed {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Reason {
        #[prost(int32, tag = "1")]
        InternalReason(i32),
        #[prost(string, tag = "2")]
        AppReason(String),
    }
}

/// `brzs.java`: Top-level DTDI payload carried inside a Nearby Connections `BYTES` payload.
#[derive(Clone, PartialEq, Message)]
pub struct DtdiMessage {
    #[prost(message, optional, tag = "1")]
    pub channel_id: Option<DtdiChannelId>,
    #[prost(oneof = "dtdi_message::Content", tags = "2, 3")]
    pub content: Option<dtdi_message::Content>,
}

pub mod dtdi_message {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Content {
        #[prost(bytes = "vec", tag = "2")]
        Payload(Vec<u8>),
        #[prost(message, tag = "3")]
        ChannelClosed(DtdiChannelClosed),
    }
}

/// `zwx.java`: Outer envelope sent on `com.google.android.gms.dtdi.WakeUpChannel`.
#[derive(Clone, PartialEq, Message)]
pub struct WakeUpEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    pub message_bytes: Vec<u8>,
}

/// `zwp.java`: Union of `StartAndroidComponentRequest` (1) and `Response` (2).
#[derive(Clone, PartialEq, Message)]
pub struct WakeUpMessage {
    #[prost(oneof = "wake_up_message::Kind", tags = "1, 2")]
    pub kind: Option<wake_up_message::Kind>,
}

pub mod wake_up_message {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Request(StartAndroidComponentRequest),
        #[prost(message, tag = "2")]
        Response(StartAndroidComponentResponse),
    }
}

/// `zwt.java`: Expected signing certificate SHA-256 hashes checked by `btoh.c`.
#[derive(Clone, PartialEq, Message)]
pub struct ExpectedCertificates {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub certificates: Vec<Vec<u8>>,
}

/// `zwr.java`: Intent extra entry (`zwq.java`: 2=bool, 3=string, 4=int32, 5=bytes, 6=int64).
#[derive(Clone, PartialEq, Message)]
pub struct WakeUpExtra {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "wake_up_extra::Value", tags = "2, 3, 4, 5, 6")]
    pub value: Option<wake_up_extra::Value>,
}

pub mod wake_up_extra {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Value {
        #[prost(bool, tag = "2")]
        ExtraBoolean(bool),
        #[prost(string, tag = "3")]
        ExtraString(String),
        #[prost(int32, tag = "4")]
        ExtraInt(i32),
        #[prost(bytes = "vec", tag = "5")]
        ExtraBytes(Vec<u8>),
        #[prost(int64, tag = "6")]
        ExtraLong(i64),
    }
}

/// `zwu.java`: `StartAndroidComponentRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct StartAndroidComponentRequest {
    #[prost(string, tag = "1")]
    pub target_package_name: String,
    #[prost(string, tag = "2")]
    pub target_intent_action: String,
    /// `zws.java`: 0=UNKNOWN, 1=ACTIVITY
    #[prost(int32, tag = "3")]
    pub component_type: i32,
    #[prost(message, optional, tag = "4")]
    pub expected_certificates: Option<ExpectedCertificates>,
    #[prost(message, repeated, tag = "5")]
    pub extras: Vec<WakeUpExtra>,
    #[prost(string, tag = "6")]
    pub reason: String,
    #[prost(string, tag = "9")]
    pub request_id: String,
    #[prost(bool, tag = "10")]
    pub request_bandwidth_upgrade: bool,
}

/// `zww.java`: `StartAndroidComponentResponse`.
#[derive(Clone, PartialEq, Message)]
pub struct StartAndroidComponentResponse {
    /// `zwv.java`: 0=UNKNOWN, 1=OK (see `btnm.java:54-97`)
    #[prost(int32, tag = "1")]
    pub status: i32,
    #[prost(string, tag = "3")]
    pub request_id: String,
}

/// Build a wire-exact DTDI `WakeUpChannel` `DtdiMessage` (`brzs`) to silently launch
/// `com.google.ambient.streaming`'s `DtdiIncomingConnectionWakeupActivity` and bind it to `channel_name`.
pub fn build_devicelink_wakeup_message(
    channel_name: &str,
    request_id: &str,
    request_bandwidth_upgrade: bool,
) -> Vec<u8> {
    let req = StartAndroidComponentRequest {
        target_package_name: PACKAGE_AMBIENT_STREAMING.to_string(),
        target_intent_action: ACTION_DEVICELINK_WAKEUP.to_string(),
        component_type: 1, // ACTIVITY
        expected_certificates: Some(ExpectedCertificates {
            certificates: vec![AMBIENT_STREAMING_CERT_SHA256.to_vec()],
        }),
        extras: vec![WakeUpExtra {
            key: EXTRA_DEVICELINK_CHANNEL_NAME.to_string(),
            value: Some(wake_up_extra::Value::ExtraString(channel_name.to_string())),
        }],
        reason: "DeviceLink".to_string(),
        request_id: request_id.to_string(),
        request_bandwidth_upgrade,
    };
    let zwp_bytes = WakeUpMessage {
        kind: Some(wake_up_message::Kind::Request(req)),
    }
    .encode_to_vec();
    let zwx_bytes = WakeUpEnvelope {
        message_bytes: zwp_bytes,
    }
    .encode_to_vec();
    build_channel_message(PACKAGE_DTDI, CHANNEL_WAKEUP, zwx_bytes)
}

/// Wrap an already-enveloped payload in a DTDI `DtdiMessage` (`brzs`).
pub fn build_channel_message(package_name: &str, channel_name: &str, payload: Vec<u8>) -> Vec<u8> {
    build_channel_message_typed(package_name, channel_name, 0, payload)
}

pub fn build_channel_message_typed(
    package_name: &str,
    channel_name: &str,
    channel_type: i32,
    payload: Vec<u8>,
) -> Vec<u8> {
    DtdiMessage {
        channel_id: Some(DtdiChannelId {
            app_package_name: package_name.to_string(),
            channel_name: channel_name.to_string(),
            channel_type,
        }),
        content: Some(dtdi_message::Content::Payload(payload)),
    }
    .encode_to_vec()
}

/// Wrap a raw application payload (e.g. a serialized `DeviceLinkPacket`) inside DTDI's
/// `zwx` payload envelope (`tag 1 = bytes`) and `DtdiMessage` (`brzs`).
/// Verified live on Pixel 9 Pro: `DeviceLink` channels use `channel_type = 1` and wrap
/// every `DeviceLinkPacket` in `zwx` (`0a <len> <packet>`).
pub fn build_app_channel_message(
    package_name: &str,
    channel_name: &str,
    channel_type: i32,
    app_payload: Vec<u8>,
) -> Vec<u8> {
    let zwx_bytes = WakeUpEnvelope {
        message_bytes: app_payload,
    }
    .encode_to_vec();
    build_channel_message_typed(package_name, channel_name, channel_type, zwx_bytes)
}

/// Unwrap DTDI's `zwx` payload envelope (`tag 1 = bytes`) to recover the raw application payload.
pub fn unwrap_channel_payload(raw: &[u8]) -> Result<Vec<u8>, DtdiError> {
    let env = WakeUpEnvelope::decode(raw)?;
    Ok(env.message_bytes)
}

/// Decode an incoming DTDI `DtdiMessage` (`brzs`).
pub fn decode_dtdi_message(raw: &[u8]) -> Result<DtdiMessage, DtdiError> {
    Ok(DtdiMessage::decode(raw)?)
}

/// Decode a `WakeUpChannel` payload (`zwx` -> `zwp`).
pub fn decode_wakeup_envelope(raw: &[u8]) -> Result<WakeUpMessage, DtdiError> {
    let env = WakeUpEnvelope::decode(raw)?;
    Ok(WakeUpMessage::decode(env.message_bytes.as_slice())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtdi_devicelink_wakeup_roundtrip() {
        let wire = build_devicelink_wakeup_message("chan-uuid-123", "req-uuid-456", false);
        let msg = decode_dtdi_message(&wire).unwrap();
        let ch = msg.channel_id.unwrap();
        assert_eq!(ch.app_package_name, PACKAGE_DTDI);
        assert_eq!(ch.channel_name, CHANNEL_WAKEUP);
        let payload = match msg.content.unwrap() {
            dtdi_message::Content::Payload(b) => b,
            _ => panic!("expected payload"),
        };
        let wp = decode_wakeup_envelope(&payload).unwrap();
        match wp.kind.unwrap() {
            wake_up_message::Kind::Request(r) => {
                assert_eq!(r.target_package_name, PACKAGE_AMBIENT_STREAMING);
                assert_eq!(r.target_intent_action, ACTION_DEVICELINK_WAKEUP);
                assert_eq!(r.component_type, 1);
                assert_eq!(r.request_id, "req-uuid-456");
                assert_eq!(r.expected_certificates.unwrap().certificates[0].len(), 32);
            }
            _ => panic!("expected request"),
        }
    }
}
