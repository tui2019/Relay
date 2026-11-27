//! Pure-Rust Google Account OAuth + `location.nearby.presence.v1.NearbyPresenceService` HTTP/2 gRPC client.
//!
//! Flow (verified end-to-end against Google production endpoints):
//! 1. Native `WKWebView` sign-in (`https://accounts.google.com/EmbeddedSetup`) yields an `oauth_token` cookie.
//! 2. `exchange_oauth_token` exchanges `oauth_token` via `https://android.clients.google.com/auth`
//!    for a long-lived AAS master token (`aas_et/...`) + account email.
//! 3. `mint_nearby_presence_token` exchanges `aas_token` for a short-lived `ya29...` OAuth2 Bearer
//!    token scoped to `https://www.googleapis.com/auth/nearbypresence-pa`.
//! 4. Standard HTTP/2 gRPC calls to `https://nearbypresence-pa.googleapis.com:443`:
//!    - `FindMyDusi`: discover this login's server-assigned DUSI
//!    - `UploadNearbyDevice`: register/update this Mac as a Googlebook-class laptop
//!      (`status = DEVICE_STATUS_OPTED_IN (2)`, `form_factor = COMPUTER (2)`, `os_type = ANDROID (2)`)
//!    - `ListMyDevices`: list the account's Cross-Device Services devices
//!    - `ListSharedCredentials`: fetch live Nearby Presence v3 `SharedCredential`s
//!
//! Security: raw tokens and key_seeds are NEVER logged; local session files are stored `0600`.

use crate::presence::SharedCredential;
use base64::Engine;
use prost::Message;
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ANDROID_AUTH_URL: &str = "https://android.clients.google.com/auth";
const NEARBY_PRESENCE_BASE: &str =
    "https://nearbypresence-pa.googleapis.com/location.nearby.presence.v1.NearbyPresenceService";
const GMS_APP: &str = "com.google.android.gms";
const GMS_SIG: &str = "38918a453d07199354f8b19af05ec6562ced5788";
const NEARBY_PRESENCE_SCOPE: &str = "oauth2:https://www.googleapis.com/auth/nearbypresence-pa";

/// Persisted Google Account session (saved with `chmod 0600`, never printed to logs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleAccountSession {
    pub email: String,
    pub android_id: String,
    pub aas_token: String,
    #[serde(default)]
    pub dusi: Option<String>,
    #[serde(default)]
    pub last_sync_unix_secs: Option<u64>,
}

/// Summary of one device in the user's Cross-Device Services group (`ListMyDevices`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearbyDeviceSummary {
    pub dusi: String,
    pub display_name: String,
    pub status: i32,
    pub form_factor: i32,
    pub os_type: i32,
}

/// Result of a full cloud Nearby Presence sync.
#[derive(Debug, Clone)]
pub struct SyncedPresenceData {
    pub dusi: String,
    pub primary_phone_name: Option<String>,
    pub devices: Vec<NearbyDeviceSummary>,
    pub shared_credentials: Vec<SharedCredential>,
    pub synced_at_unix_secs: u64,
}

// ---------------------------------------------------------------------------
// Wire-exact protobufs for `location.nearby.presence.v1.NearbyPresenceService`
// Decompiled from Googlebook OS `PrebuiltGmsCoreVic.apk` (`itxo`–`ityw`)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
struct EmptyProto {}

#[derive(Clone, PartialEq, Message)]
struct FindMyDusiResponse {
    #[prost(string, tag = "1")]
    dusi: String,
}

#[derive(Clone, PartialEq, Message)]
struct DeviceTypeProto {
    /// 0 = PHONE/UNKNOWN, 2 = COMPUTER, 5 = TABLET
    #[prost(int32, tag = "1")]
    form_factor: i32,
    /// 2 = ANDROID (used by Googlebook OS too), 9 = MAC_OS, 10 = CHROME_OS, 28 = ALUMINIUM
    #[prost(int32, tag = "2")]
    os_type: i32,
}

#[derive(Clone, PartialEq, Message)]
struct NearbyDeviceProto {
    #[prost(string, tag = "1")]
    dusi: String,
    #[prost(string, tag = "2")]
    display_name: String,
    #[prost(int64, tag = "3")]
    last_active_timestamp: i64,
    /// 2 = DEVICE_STATUS_OPTED_IN, 3 = DEVICE_STATUS_DEFAULT_OPTED_IN
    #[prost(int32, tag = "4")]
    status: i32,
    #[prost(message, optional, tag = "5")]
    device_type: Option<DeviceTypeProto>,
    #[prost(int32, tag = "6")]
    extra_flag: i32,
    #[prost(int32, repeated, tag = "8")]
    capabilities: Vec<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct ListMyDevicesResponse {
    #[prost(message, repeated, tag = "1")]
    devices: Vec<NearbyDeviceProto>,
}

#[derive(Clone, PartialEq, Message)]
struct ListSharedCredentialsRequest {
    #[prost(string, tag = "1")]
    dusi: String,
}

#[derive(Clone, PartialEq, Message)]
struct SharedCredentialProto {
    #[prost(int64, tag = "1")]
    id: i64,
    #[prost(bytes = "vec", tag = "2")]
    key_seed: Vec<u8>,
    #[prost(int64, tag = "3")]
    start_time_millis: i64,
    #[prost(int64, tag = "4")]
    end_time_millis: i64,
    #[prost(bytes = "vec", tag = "5")]
    encrypted_metadata_bytes_v0: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    metadata_encryption_key_tag_v0: Vec<u8>,
    #[prost(int32, tag = "9")]
    identity_type: i32,
    #[prost(string, tag = "20")]
    version: String,
}

#[derive(Clone, PartialEq, Message)]
struct ListSharedCredentialsResponse {
    #[prost(message, repeated, tag = "1")]
    credentials: Vec<SharedCredentialProto>,
}

#[derive(Clone, PartialEq, Message)]
struct NearbyDeviceUploadData {
    #[prost(message, optional, tag = "1")]
    device: Option<NearbyDeviceProto>,
    #[prost(message, repeated, tag = "2")]
    credentials: Vec<SharedCredentialProto>,
}

#[derive(Clone, PartialEq, Message)]
struct UploadNearbyDeviceRequest {
    #[prost(message, optional, tag = "1")]
    data: Option<NearbyDeviceUploadData>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn generate_android_id() -> String {
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_auth_kv(body: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

fn build_auth_http_client() -> Result<reqwest::Client, String> {
    // HTTP/1.1 TLS client for `android.clients.google.com/auth`
    reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("Failed to build auth HTTP client: {e}"))
}

fn build_grpc_http2_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("Failed to build gRPC HTTP/2 client: {e}"))
}

fn build_grpc_alpn_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("Failed to build gRPC TLS client: {e}"))
}

/// Write a file atomically with `0600` owner-only permissions on Unix.
pub fn write_secret_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Google OAuth (`android.clients.google.com/auth`)
// ---------------------------------------------------------------------------

/// Exchange a one-time `oauth_token` cookie captured from `accounts.google.com/EmbeddedSetup`
/// for a long-lived AAS master token (`aas_et/...`) + account email.
pub async fn exchange_oauth_token(
    oauth_token: &str,
    android_id: &str,
) -> Result<GoogleAccountSession, String> {
    let client = build_auth_http_client()?;
    let params = [
        ("accountType", "HOSTED_OR_GOOGLE"),
        ("Email", ""),
        ("has_permission", "1"),
        ("add_account", "1"),
        ("ACCESS_TOKEN", "1"),
        ("Token", oauth_token.trim()),
        ("service", "ac2dm"),
        ("source", "android"),
        ("androidId", android_id),
        ("device_country", "us"),
        ("operatorCountry", "us"),
        ("lang", "en"),
        ("sdk_version", "17"),
        ("google_play_services_version", "240913000"),
        ("client_sig", GMS_SIG),
        ("callerSig", GMS_SIG),
        ("droidguard_results", "dummy123"),
    ];

    let resp = client
        .post(ANDROID_AUTH_URL)
        .header(USER_AGENT, "GoogleAuth/1.4")
        .header("Accept-Encoding", "identity")
        .header("device", android_id)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Google token exchange network error: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Google token exchange read error: {e}"))?;
    let kv = parse_auth_kv(&text);

    if !status.is_success() {
        let err = kv
            .get("Error")
            .cloned()
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(format!("Google token exchange failed: {err}"));
    }

    let aas_token = kv
        .get("Token")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| {
            let err = kv.get("Error").cloned().unwrap_or_else(|| "missing Token".into());
            format!("Google token exchange missing AAS token: {err}")
        })?;
    let email = kv.get("Email").cloned().unwrap_or_default();

    Ok(GoogleAccountSession {
        email,
        android_id: android_id.to_string(),
        aas_token,
        dusi: None,
        last_sync_unix_secs: None,
    })
}

/// Mint a short-lived `ya29...` OAuth2 Bearer access token for `nearbypresence-pa`.
pub async fn mint_nearby_presence_token(acct: &GoogleAccountSession) -> Result<String, String> {
    let client = build_auth_http_client()?;
    let params = [
        ("accountType", "HOSTED_OR_GOOGLE"),
        ("Email", acct.email.as_str()),
        ("has_permission", "1"),
        ("EncryptedPasswd", acct.aas_token.as_str()),
        ("service", NEARBY_PRESENCE_SCOPE),
        ("source", "android"),
        ("androidId", acct.android_id.as_str()),
        ("app", GMS_APP),
        ("client_sig", GMS_SIG),
        ("device_country", "us"),
        ("operatorCountry", "us"),
        ("lang", "en"),
        ("sdk_version", "17"),
        ("google_play_services_version", "240913000"),
    ];

    let resp = client
        .post(ANDROID_AUTH_URL)
        .header(USER_AGENT, "GoogleAuth/1.4")
        .header("Accept-Encoding", "identity")
        .header("device", acct.android_id.as_str())
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("Google OAuth mint network error: {e}"))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Google OAuth mint read error: {e}"))?;
    let kv = parse_auth_kv(&text);

    if !status.is_success() {
        let err = kv
            .get("Error")
            .cloned()
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(format!("Google OAuth mint failed: {err}"));
    }

    kv.get("Auth")
        .filter(|s| !s.is_empty())
        .cloned()
        .ok_or_else(|| {
            let err = kv.get("Error").cloned().unwrap_or_else(|| "missing Auth".into());
            format!("Google OAuth mint missing Auth token: {err}")
        })
}

// ---------------------------------------------------------------------------
// HTTP/2 gRPC Framing + `NearbyPresenceService` RPCs
// ---------------------------------------------------------------------------

fn grpc_frame_encode<M: Message>(msg: &M) -> Vec<u8> {
    let payload = msg.encode_to_vec();
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0u8); // uncompressed
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

fn grpc_frame_decode<M: Message + Default>(raw: &[u8]) -> Result<M, String> {
    if raw.is_empty() {
        return Ok(M::default());
    }
    if raw.len() < 5 {
        return Err(format!("gRPC frame truncated ({} bytes)", raw.len()));
    }
    let compressed = raw[0];
    if compressed != 0 {
        return Err(format!("unexpected gRPC compression flag: {compressed}"));
    }
    let len = u32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]]) as usize;
    if raw.len() < 5 + len {
        return Err(format!(
            "gRPC payload truncated: expected {len} bytes, got {}",
            raw.len() - 5
        ));
    }
    M::decode(&raw[5..5 + len]).map_err(|e| format!("protobuf decode error: {e}"))
}

async fn grpc_unary<Req: Message, Resp: Message + Default>(
    client: &reqwest::Client,
    method: &str,
    req: &Req,
    bearer: &str,
) -> Result<Resp, String> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    headers.insert(USER_AGENT, HeaderValue::from_static("grpc-java-cronet/1.64.0"));
    let auth_val = HeaderValue::from_str(&format!("Bearer {bearer}"))
        .map_err(|e| format!("invalid bearer header: {e}"))?;
    headers.insert(reqwest::header::AUTHORIZATION, auth_val);

    let url = format!("{NEARBY_PRESENCE_BASE}/{method}");
    let body = grpc_frame_encode(req);
    let resp = client
        .post(&url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("gRPC {method} network error: {e}"))?;

    let http_status = resp.status();
    let grpc_status = resp
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let grpc_message = resp
        .headers()
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let raw = resp
        .bytes()
        .await
        .map_err(|e| format!("gRPC {method} body read error: {e}"))?;

    if !http_status.is_success() {
        return Err(format!(
            "gRPC {method} HTTP {} (grpc-status={grpc_status} msg={grpc_message})",
            http_status.as_u16()
        ));
    }
    if !grpc_status.is_empty() && grpc_status != "0" {
        return Err(format!(
            "gRPC {method} failed: status={grpc_status} msg={grpc_message}"
        ));
    }

    grpc_frame_decode(&raw)
}

/// Full cloud sync:
/// 1. Mint `nearbypresence-pa` Bearer token from stored `aas_token`
/// 2. `FindMyDusi`
/// 3. `UploadNearbyDevice` (register/update this Mac with `display_name`, `status = OPTED_IN (2)`,
///    `form_factor = COMPUTER (2)`, `os_type = ANDROID (2)` — Googlebook laptop icon)
/// 4. `ListMyDevices`
/// 5. `ListSharedCredentials(dusi)` → converts valid v3 credentials into `SharedCredential`s
pub async fn sync_nearby_presence(
    acct: &mut GoogleAccountSession,
    local_display_name: &str,
) -> Result<SyncedPresenceData, String> {
    let bearer = mint_nearby_presence_token(acct).await?;
    // Use ALPN TLS client (negotiates HTTP/2 automatically over TLS ALPN `h2`)
    let client = build_grpc_alpn_client().or_else(|_| build_grpc_http2_client())?;

    // 1. FindMyDusi
    let dusi_resp: FindMyDusiResponse =
        grpc_unary(&client, "FindMyDusi", &EmptyProto {}, &bearer).await?;
    if dusi_resp.dusi.is_empty() {
        return Err("FindMyDusi returned empty DUSI".into());
    }
    let dusi = dusi_resp.dusi;
    acct.dusi = Some(dusi.clone());

    // 2. UploadNearbyDevice — cleanly register/update this Mac as a Googlebook-class laptop
    let clean_name = if local_display_name.trim().is_empty() {
        "Mac".to_string()
    } else {
        local_display_name.trim().to_string()
    };
    let upload_req = UploadNearbyDeviceRequest {
        data: Some(NearbyDeviceUploadData {
            device: Some(NearbyDeviceProto {
                dusi: dusi.clone(),
                display_name: clean_name,
                last_active_timestamp: unix_now_millis(),
                status: 2, // DEVICE_STATUS_OPTED_IN
                device_type: Some(DeviceTypeProto {
                    form_factor: 2, // COMPUTER (laptop icon)
                    os_type: 2,     // ANDROID (matches Googlebook OS)
                }),
                extra_flag: 0,
                capabilities: Vec::new(),
            }),
            credentials: Vec::new(),
        }),
    };
    // Best-effort: if UploadNearbyDevice fails transiently, still proceed to fetch credentials
    let _ = grpc_unary::<_, EmptyProto>(&client, "UploadNearbyDevice", &upload_req, &bearer).await;

    // 3. ListMyDevices
    let devices_resp: ListMyDevicesResponse =
        grpc_unary(&client, "ListMyDevices", &EmptyProto {}, &bearer).await?;
    let devices: Vec<NearbyDeviceSummary> = devices_resp
        .devices
        .into_iter()
        .map(|d| {
            let (ff, os) = d
                .device_type
                .map(|dt| (dt.form_factor, dt.os_type))
                .unwrap_or((0, 0));
            NearbyDeviceSummary {
                dusi: d.dusi,
                display_name: d.display_name,
                status: d.status,
                form_factor: ff,
                os_type: os,
            }
        })
        .collect();

    // Pick the primary opted-in Android phone display name (form_factor == 0 or 1, status >= 2, not self)
    let primary_phone_name = devices
        .iter()
        .find(|d| d.dusi != dusi && d.status >= 2 && (d.form_factor == 0 || d.form_factor == 1) && !d.display_name.is_empty())
        .or_else(|| {
            devices
                .iter()
                .find(|d| d.dusi != dusi && d.status >= 2 && !d.display_name.is_empty())
        })
        .map(|d| d.display_name.clone());

    // 4. ListSharedCredentials
    let creds_resp: ListSharedCredentialsResponse = grpc_unary(
        &client,
        "ListSharedCredentials",
        &ListSharedCredentialsRequest { dusi: dusi.clone() },
        &bearer,
    )
    .await?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let fallback_name = primary_phone_name
        .clone()
        .unwrap_or_else(|| "Android Phone".to_string());

    let mut shared_credentials = Vec::new();
    for c in creds_resp.credentials {
        if c.key_seed.len() != 32 || c.metadata_encryption_key_tag_v0.len() != 32 {
            continue;
        }
        shared_credentials.push(SharedCredential {
            device_name: fallback_name.clone(),
            device_id: c.id.to_string(),
            secret_id_b64: String::new(),
            authenticity_key_b64: b64.encode(&c.key_seed),
            metadata_encryption_key_b64: None,
            metadata_encryption_key_tag_v0_b64: Some(b64.encode(&c.metadata_encryption_key_tag_v0)),
            ldt_key_b64: None,
        });
    }

    let now_secs = unix_now_secs();
    acct.last_sync_unix_secs = Some(now_secs);

    Ok(SyncedPresenceData {
        dusi,
        primary_phone_name,
        devices,
        shared_credentials,
        synced_at_unix_secs: now_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_frame_roundtrip() {
        let req = ListSharedCredentialsRequest {
            dusi: "test-dusi-12345".into(),
        };
        let framed = grpc_frame_encode(&req);
        assert_eq!(framed[0], 0);
        let decoded: ListSharedCredentialsRequest = grpc_frame_decode(&framed).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn parse_auth_kv_lines() {
        let sample = "SID=abc\nEmail=user@example.com\nToken=aas_et/test123\n";
        let kv = parse_auth_kv(sample);
        assert_eq!(kv.get("Email").map(String::as_str), Some("user@example.com"));
        assert_eq!(kv.get("Token").map(String::as_str), Some("aas_et/test123"));
    }
}
