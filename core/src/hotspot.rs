//! Wire-exact Google Instant Hotspot (`magictether` / Nearby Connections service ID
//! `"nearby.sharedconnectivity"`) protocol codecs.
//!
//! Verified directly from `PrebuiltGmsCoreVic.apk` (`classes8.dex`):
//! - `dhed.java`: JSON envelope `{"type": <int>, "data": "<URL-safe base64 no-wrap>"}`
//! - `dgyb.java`: `ConnectTetherWorker` sends `{"type":3,"data":""}` and receives `type=4` (`dhdd`)
//! - `dhdd.java`: `ConnectTetheringResponse`
//! - `dhdm.java`: `InstantHotspotStatus` (SSID, password, security types, hidden flag)
//! - `dhdy.java`: `TetherAvailabilityResponse`
//! - `dhdl.java` & `dhdu.java`: status and Wi-Fi security enums

use base64::Engine;
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HotspotError {
    #[error("JSON envelope error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64url decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protobuf decode error: {0}")]
    Proto(#[from] prost::DecodeError),
    #[error("unknown magictether message type: {0}")]
    UnknownMessageType(i32),
}

/// Wire message type integer (`dhed.java:44-71`, `type = this.b - 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TetherMessageType {
    TetherAvailabilityRequest = 1,
    TetherAvailabilityResponse = 2,
    ConnectTetheringRequest = 3,
    ConnectTetheringResponse = 4,
    DisconnectTetheringRequest = 5,
    KeepAliveTickle = 6,
    KeepAliveTickleResponse = 7,
}

/// `dhdl.java`: Instant Hotspot status enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum InstantHotspotStatusCode {
    Unknown = 0,
    FeatureDisabled = 1,
    HotspotUnavailable = 2,
    HotspotAvailable = 3,
    HotspotActive = 4,
}

/// `dhdu.java`: Wi-Fi security type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum WifiSecurityType {
    Unknown = 0,
    Open = 1,
    Wep = 2,
    Psk = 3,
    Eap = 4,
    Sae = 5,
    Owe = 6,
}

/// `dhed.java`: outer JSON wire envelope sent as a Nearby Connections `BYTES` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetherJsonEnvelope {
    #[serde(rename = "type")]
    pub msg_type: i32,
    pub data: String,
}

/// `dhdm.java`: InstantHotspotStatus protobuf.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct InstantHotspotStatus {
    /// `dhdl`: 0=UNKNOWN, 1=FEATURE_DISABLED, 2=UNAVAILABLE, 3=AVAILABLE, 4=ACTIVE
    #[prost(int32, optional, tag = "1")]
    pub status_code: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub network_type: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub display_name: Option<String>,
    /// `dhdm.g` (used by `dgvd.java:404`): Hotspot Wi-Fi SSID
    #[prost(string, optional, tag = "4")]
    pub ssid: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub bssid: Option<String>,
    /// `dhdm.i`: packed repeated `dhdu` security types (3=WPA2-PSK, 5=WPA3-SAE, 1=OPEN)
    #[prost(int32, repeated, packed = "true", tag = "6")]
    pub security_types: Vec<i32>,
    /// `dhdm.j` (used by `dgvd.java:404`): Hotspot Wi-Fi passphrase
    #[prost(string, optional, tag = "7")]
    pub password: Option<String>,
    /// `dhdm.k`: whether SSID is hidden
    #[prost(bool, optional, tag = "8")]
    pub is_hidden_ssid: Option<bool>,
    #[prost(int64, optional, tag = "9")]
    pub extra_id: Option<i64>,
}

/// `dhde.java`: DeviceStatus telemetry reported by the host phone in Instant Hotspot responses.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct DeviceStatus {
    #[prost(int32, optional, tag = "1")]
    pub battery_percentage: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub cell_provider: Option<String>,
    #[prost(int32, optional, tag = "3")]
    pub connection_strength: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub wifi_status_raw: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "5")]
    pub is_wifi_connected: Option<bool>,
    /// `dhde.h`: whether cellular data is available (checked by `dgzw.java` & `dhbc.java`)
    #[prost(bool, optional, tag = "6")]
    pub is_cell_data_available: Option<bool>,
    #[prost(string, optional, tag = "10")]
    pub device_name: Option<String>,
}

/// Human-readable name for `ConnectTetheringResponse.response_code` (`dhdc.java` / `dgzw.java`).
pub fn connect_response_code_name(code: i32) -> &'static str {
    match code {
        0 => "UNKNOWN_ERROR",
        1 => "SUCCESS",
        2 => "PROVISIONING_FAILED",
        3 => "TETHERING_TIMEOUT",
        4 => "TETHERING_UNSUPPORTED",
        5 => "NO_CELL_DATA",
        6 => "ENABLING_HOTSPOT_FAILED",
        7 => "ENABLING_HOTSPOT_TIMEOUT",
        8 => "NO_HOTSPOT_CREDENTIALS",
        9 => "INVALID_WIFI_AP_CONFIG",
        10 => "INVALID_WIFI_AP_PASSWORD",
        _ => "OTHER",
    }
}

/// Human-readable name for `TetherAvailabilityResponse.response_code` (`dhdx.java`).
pub fn availability_response_code_name(code: i32) -> &'static str {
    match code {
        0 => "UNKNOWN_ERROR",
        1 => "TETHER_AVAILABLE",
        2 => "SETUP_NEEDED",
        3 => "NO_RECEPTION_OR_CELL_DATA",
        4 => "NO_SIM_CARD",
        5 => "NOTIFICATIONS_DISABLED_LEGACY",
        6 => "NOTIFICATIONS_DISABLED_WITH_CHANNEL",
        7 => "LAST_PROVISIONING_FAILED",
        _ => "OTHER",
    }
}

/// `dhdd.java`: ConnectTetheringResponse protobuf (`type = 4`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct ConnectTetheringResponse {
    #[prost(int32, optional, tag = "1")]
    pub response_code: Option<i32>,
    /// Legacy SSID (`dhdd.d`)
    #[prost(string, optional, tag = "2")]
    pub legacy_ssid: Option<String>,
    /// Legacy password (`dhdd.e`)
    #[prost(string, optional, tag = "3")]
    pub legacy_password: Option<String>,
    /// `dhde`: DeviceStatus raw bytes
    #[prost(bytes = "vec", optional, tag = "4")]
    pub device_status_raw: Option<Vec<u8>>,
    /// `dhdm`: Modern InstantHotspotStatus containing SSID, password, security type
    #[prost(message, optional, tag = "5")]
    pub instant_hotspot_status: Option<InstantHotspotStatus>,
}

/// `dhds.java`: Nearby Wi-Fi credential sharing status inside `TetherAvailabilityResponse` tag 4.
/// Verified from `PrebuiltGmsCoreVic.apk` (`classes8.dex` `dhds.java`, `dgvd.java:205-235, 629-688`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct NearbyWifiStatus {
    /// `dhdr`: `4 = WIFI_AVAILABLE` (shareable PSK/SAE/Open Wi-Fi credentials present)
    #[prost(int32, optional, tag = "1")]
    pub status_code: Option<i32>,
    /// `dhds.e`: Wi-Fi SSID (often quote-wrapped by Android `WifiInfo`)
    #[prost(string, optional, tag = "2")]
    pub ssid: Option<String>,
    /// `dhds.f`: Wi-Fi pre-shared key / password
    #[prost(string, optional, tag = "3")]
    pub password: Option<String>,
    /// `dhds.g`: packed repeated `dhdu` security types (`1=OPEN, 3=PSK, 5=SAE, 6=OWE`)
    #[prost(int32, repeated, packed = "true", tag = "4")]
    pub security_types: Vec<i32>,
    /// `dhds.h`: whether SSID is hidden
    #[prost(bool, optional, tag = "5")]
    pub is_hidden_ssid: Option<bool>,
}

/// `dhdy.java`: TetherAvailabilityResponse protobuf (`type = 2`).
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct TetherAvailabilityResponse {
    #[prost(int32, optional, tag = "1")]
    pub response_code: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub device_status_raw: Option<Vec<u8>>,
    #[prost(message, optional, tag = "3")]
    pub instant_hotspot_status: Option<InstantHotspotStatus>,
    #[prost(message, optional, tag = "4")]
    pub nearby_wifi_status: Option<NearbyWifiStatus>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodedTetherMessage {
    AvailabilityResponse(TetherAvailabilityResponse),
    ConnectResponse(ConnectTetheringResponse),
    Other { msg_type: i32, raw_proto: Vec<u8> },
}

/// Encode a `dhed.java` JSON message (`Base64.URL_SAFE | Base64.NO_WRAP`).
pub fn encode_tether_envelope(msg_type: TetherMessageType, proto_bytes: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::URL_SAFE;
    let env = TetherJsonEnvelope {
        msg_type: msg_type as i32,
        data: b64.encode(proto_bytes),
    };
    serde_json::to_vec(&env).expect("JSON serialization cannot fail")
}

/// Build wire-exact `TetherAvailabilityRequest` (`{"type":1,"data":""}`).
pub fn build_availability_request() -> Vec<u8> {
    encode_tether_envelope(TetherMessageType::TetherAvailabilityRequest, &[])
}

/// Build wire-exact `ConnectTetheringRequest` (`{"type":3,"data":""}`, `dgyb.java:24`).
pub fn build_connect_tethering_request() -> Vec<u8> {
    encode_tether_envelope(TetherMessageType::ConnectTetheringRequest, &[])
}

/// Build wire-exact `DisconnectTetheringRequest` (`{"type":5,"data":""}`).
pub fn build_disconnect_tethering_request() -> Vec<u8> {
    encode_tether_envelope(TetherMessageType::DisconnectTetheringRequest, &[])
}

/// Decode a `dhed.java` JSON payload received from `"nearby.sharedconnectivity"`.
pub fn decode_tether_envelope(wire: &[u8]) -> Result<DecodedTetherMessage, HotspotError> {
    let env: TetherJsonEnvelope = serde_json::from_slice(wire)?;
    let raw = base64::engine::general_purpose::URL_SAFE
        .decode(env.data.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(env.data.trim()))?;
    match env.msg_type {
        2 => Ok(DecodedTetherMessage::AvailabilityResponse(
            TetherAvailabilityResponse::decode(raw.as_slice())?,
        )),
        4 => Ok(DecodedTetherMessage::ConnectResponse(
            ConnectTetheringResponse::decode(raw.as_slice())?,
        )),
        other => Ok(DecodedTetherMessage::Other {
            msg_type: other,
            raw_proto: raw,
        }),
    }
}

fn unquote_wifi_str(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

impl ConnectTetheringResponse {
    /// Extract `(ssid, password, security_type)` preferring modern `instant_hotspot_status` (`dhdm`)
    /// and falling back to legacy `dhdd.d` / `dhdd.e`. Strips surrounding Android `WifiInfo` quotes.
    pub fn credentials(&self) -> Option<(String, String, i32)> {
        if let Some(ref st) = self.instant_hotspot_status {
            if let (Some(ssid), Some(pw)) = (&st.ssid, &st.password) {
                let clean_ssid = unquote_wifi_str(ssid);
                let clean_pw = unquote_wifi_str(pw);
                if !clean_ssid.is_empty() {
                    let sec = st.security_types.first().copied().unwrap_or(3);
                    return Some((clean_ssid, clean_pw, sec));
                }
            }
        }
        if let (Some(ssid), Some(pw)) = (&self.legacy_ssid, &self.legacy_password) {
            let clean_ssid = unquote_wifi_str(ssid);
            let clean_pw = unquote_wifi_str(pw);
            if !clean_ssid.is_empty() {
                return Some((clean_ssid, clean_pw, 3));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_tethering_request_matches_gms_dhed() {
        let wire = build_connect_tethering_request();
        assert_eq!(String::from_utf8(wire).unwrap(), r#"{"type":3,"data":""}"#);
    }

    #[test]
    fn connect_tethering_response_envelope_roundtrip() {
        let resp = ConnectTetheringResponse {
            response_code: Some(0),
            legacy_ssid: None,
            legacy_password: None,
            device_status_raw: None,
            instant_hotspot_status: Some(InstantHotspotStatus {
                status_code: Some(InstantHotspotStatusCode::HotspotActive as i32),
                network_type: Some(1),
                display_name: Some("Pixel 9 Pro".into()),
                ssid: Some("Pixel_9_Pro_Hotspot".into()),
                bssid: Some("aa:bb:cc:dd:ee:ff".into()),
                security_types: vec![WifiSecurityType::Sae as i32],
                password: Some("passphrase123".into()),
                is_hidden_ssid: Some(false),
                extra_id: None,
            }),
        };
        let env = encode_tether_envelope(
            TetherMessageType::ConnectTetheringResponse,
            &resp.encode_to_vec(),
        );
        match decode_tether_envelope(&env).unwrap() {
            DecodedTetherMessage::ConnectResponse(decoded) => {
                assert_eq!(
                    decoded.credentials(),
                    Some(("Pixel_9_Pro_Hotspot".into(), "passphrase123".into(), 5))
                );
            }
            _ => panic!("expected ConnectResponse"),
        }
    }
}
