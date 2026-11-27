//! Nearby Presence (BLE 0xFCF1) LDT-XTS-AES-256 Advertisement Parser & Decryptor.
//!
//! Implements the open-source `google/nearby` Nearby Presence v0/v1 BLE Service Data
//! wire format and Length-Doubling Transform (LDT) over XTS-AES-256.
//!
//! Credentials (`SharedCredential`) are supplied locally by the user (e.g. JSON file);
//! this module performs pure local cryptography with no cloud calls or identity spoofing.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// Bluetooth SIG 16-bit Service UUID for Google Nearby Presence (`0xFCF1`).
pub const NEARBY_PRESENCE_SERVICE_UUID: u16 = 0xFCF1;

/// Bluetooth SIG 16-bit Service UUID for Google Nearby Connections (`0xFEF3`).
pub const NEARBY_CONNECTIONS_SERVICE_UUID: u16 = 0xFEF3;

#[derive(Debug, Error)]
pub enum PresenceError {
    #[error("advertisement too short or malformed: {0}")]
    Malformed(&'static str),
    #[error("unsupported Nearby Presence advertisement version: {0}")]
    UnsupportedVersion(u8),
    #[error("no matching SharedCredential decrypted this advertisement")]
    NoMatchingCredential,
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("base64/hex decode error: {0}")]
    Decode(String),
}

/// User-supplied local Nearby Presence `SharedCredential` (public/symmetric material
/// used to decrypt a trusted peer's `0xFCF1` BLE / mDNS presence advertisements).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCredential {
    /// Human-readable label for the remote device (e.g. "Pixel 9 Pro").
    pub device_name: String,
    /// Optional DUSI / endpoint identifier.
    #[serde(default)]
    pub device_id: String,
    /// Optional base64-encoded 32-byte `secret_id` (legacy).
    #[serde(default)]
    pub secret_id_b64: String,
    /// Base64-encoded 32-byte `key_seed` (authenticity key / HKDF input).
    pub authenticity_key_b64: String,
    /// Optional base64-encoded 14-byte `metadata_encryption_key` (v0 identity token).
    #[serde(default)]
    pub metadata_encryption_key_b64: Option<String>,
    /// Optional base64-encoded 32-byte `metadata_encryption_key_tag_v0` (GMS SharedCredential v3 HMAC tag).
    #[serde(default)]
    pub metadata_encryption_key_tag_v0_b64: Option<String>,
    /// Optional base64-encoded 64-byte raw LDT key (if pre-derived instead of HKDF).
    #[serde(default)]
    pub ldt_key_b64: Option<String>,
}

/// Decoded binary keys derived from a [`SharedCredential`].
#[derive(Debug, Clone)]
pub struct DerivedPresenceKey {
    pub device_name: String,
    pub device_id: String,
    pub authenticity_key: [u8; 32],
    pub metadata_encryption_key: Option<[u8; 14]>,
    pub metadata_encryption_key_tag_v0: Option<[u8; 32]>,
    pub ldt_key: [u8; 64],
    pub hmac_key: [u8; 32],
}

impl SharedCredential {
    pub fn derive_keys(&self) -> Result<DerivedPresenceKey, PresenceError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let auth_raw = b64
            .decode(self.authenticity_key_b64.trim())
            .map_err(|e| PresenceError::Decode(e.to_string()))?;
        if auth_raw.len() != 32 {
            return Err(PresenceError::InvalidKeyLength {
                expected: 32,
                actual: auth_raw.len(),
            });
        }
        let mut authenticity_key = [0u8; 32];
        authenticity_key.copy_from_slice(&auth_raw);

        let metadata_encryption_key = if let Some(ref mek_b64) = self.metadata_encryption_key_b64 {
            let mek_raw = b64
                .decode(mek_b64.trim())
                .map_err(|e| PresenceError::Decode(e.to_string()))?;
            if mek_raw.len() != 14 {
                return Err(PresenceError::InvalidKeyLength {
                    expected: 14,
                    actual: mek_raw.len(),
                });
            }
            let mut arr = [0u8; 14];
            arr.copy_from_slice(&mek_raw);
            Some(arr)
        } else {
            None
        };

        let metadata_encryption_key_tag_v0 =
            if let Some(ref tag_b64) = self.metadata_encryption_key_tag_v0_b64 {
                let tag_raw = b64
                    .decode(tag_b64.trim())
                    .map_err(|e| PresenceError::Decode(e.to_string()))?;
                if tag_raw.len() != 32 {
                    return Err(PresenceError::InvalidKeyLength {
                        expected: 32,
                        actual: tag_raw.len(),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&tag_raw);
                Some(arr)
            } else {
                None
            };

        if metadata_encryption_key.is_none() && metadata_encryption_key_tag_v0.is_none() {
            return Err(PresenceError::Malformed(
                "credential must provide metadata_encryption_key_b64 or metadata_encryption_key_tag_v0_b64",
            ));
        }

        let ldt_key = if let Some(ref raw_b64) = self.ldt_key_b64 {
            let bytes = b64
                .decode(raw_b64.trim())
                .map_err(|e| PresenceError::Decode(e.to_string()))?;
            if bytes.len() != 64 {
                return Err(PresenceError::InvalidKeyLength {
                    expected: 64,
                    actual: bytes.len(),
                });
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            arr
        } else {
            derive_ldt_key_from_authenticity_key(&authenticity_key)
        };

        let hmac_key = derive_hmac_key_from_authenticity_key(&authenticity_key);

        Ok(DerivedPresenceKey {
            device_name: self.device_name.clone(),
            device_id: self.device_id.clone(),
            authenticity_key,
            metadata_encryption_key,
            metadata_encryption_key_tag_v0,
            ldt_key,
            hmac_key,
        })
    }
}

/// Check whether MSB-0 action bit `bit_index` is set in a Nearby Presence v0 `ActionBits` slice.
/// Verified live against Pixel 9 Pro (`0x4820` on cellular = bit 10 Instant Hotspot set;
/// `0x480080` on Wi-Fi = bit 10 clear).
pub fn action_bit_set(bits: &[u8], bit_index: usize) -> bool {
    let byte_idx = bit_index / 8;
    let shift = 7 - (bit_index % 8);
    bits.get(byte_idx)
        .map(|&b| (b & (1 << shift)) != 0)
        .unwrap_or(false)
}

/// Wire-exact Nearby Presence `PresenceConnectionAuthenticator` protobuf wrapper (`dsow` in GMS).
#[derive(Clone, PartialEq, Message)]
pub struct PresenceAuthWrapper {
    #[prost(message, optional, tag = "1")]
    pub v1_frame: Option<PresenceAuthV1Frame>,
}

/// Wire-exact `dsoz` oneof container (tag 6 = `AuthenticationFrame`).
#[derive(Clone, PartialEq, Message)]
pub struct PresenceAuthV1Frame {
    #[prost(message, optional, tag = "6")]
    pub authentication_frame: Option<PresenceAuthenticationFrame>,
}

/// Wire-exact `dsov` `AuthenticationFrame` (`PresenceConnectionAuthenticator`).
#[derive(Clone, PartialEq, Message)]
pub struct PresenceAuthenticationFrame {
    /// Must be `1`.
    #[prost(int32, optional, tag = "1")]
    pub version: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub signature: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub broadcast_credential_id_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub discovery_credential_id_hash: Option<Vec<u8>>,
}

/// Wire-exact `dstr.a(sharedSecret, keySeed)` from GMS `PresenceConnectionAuthenticator`:
/// `HKDF-SHA256(salt="Google Nearby", ikm=shared_secret || key_seed, info="Nearby Presence Discoverer Credential Hash", len=32)`.
pub fn derive_presence_credential_hash(shared_secret: &[u8], key_seed: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(shared_secret.len() + key_seed.len());
    ikm.extend_from_slice(shared_secret);
    ikm.extend_from_slice(key_seed);
    let hk = Hkdf::<Sha256>::new(Some(b"Google Nearby"), &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"Nearby Presence Discoverer Credential Hash", &mut out)
        .expect("32 bytes is valid HKDF-SHA256 length");
    out
}

/// Build the serialized `dsow` one-way authentication frame (`dstt` in GMS `dsui.java:218-285`).
/// Contains only `version = 1` and `broadcast_credential_id_hash = dstr.a(ukey2_auth_string, peer_key_seed)`.
pub fn build_one_way_presence_auth_message(shared_secret: &[u8], peer_key_seed: &[u8]) -> Vec<u8> {
    let hash = derive_presence_credential_hash(shared_secret, peer_key_seed);
    let wrapper = PresenceAuthWrapper {
        v1_frame: Some(PresenceAuthV1Frame {
            authentication_frame: Some(PresenceAuthenticationFrame {
                version: Some(1),
                signature: None,
                broadcast_credential_id_hash: Some(hash.to_vec()),
                discovery_credential_id_hash: None,
            }),
        }),
    };
    wrapper.encode_to_vec()
}

/// Decode an incoming `dsow` `PresenceAuthenticationFrame` from a broadcaster peer.
pub fn decode_presence_auth_message(
    raw: &[u8],
) -> Result<PresenceAuthenticationFrame, PresenceError> {
    let wrapper = PresenceAuthWrapper::decode(raw)
        .map_err(|e| PresenceError::Decode(e.to_string()))?;
    wrapper
        .v1_frame
        .and_then(|v1| v1.authentication_frame)
        .ok_or(PresenceError::Malformed("missing PresenceAuthenticationFrame"))
}

/// Derive 64-byte V0 LDT key material via HKDF-SHA256 (`libldt_np_jni.so` / `beto-core`).
pub fn derive_ldt_key_from_authenticity_key(authenticity_key: &[u8; 32]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(Some(b"Google Nearby"), authenticity_key);
    let mut okm = [0u8; 64];
    hk.expand(b"V0 LDT key", &mut okm)
        .expect("64 bytes is valid HKDF-SHA256 length");
    okm
}

/// Derive 32-byte HMAC-SHA256 key for verifying decrypted V0 identity tokens.
pub fn derive_hmac_key_from_authenticity_key(authenticity_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"Google Nearby"), authenticity_key);
    let mut okm = [0u8; 32];
    hk.expand(b"V0 Identity token verification HMAC key", &mut okm)
        .expect("32 bytes is valid HKDF-SHA256 length");
    okm
}

/// Derive 16-byte V0 LDT tweak from 2-byte BLE advertisement salt (`"V0 LDT salt pad"`).
pub fn derive_ldt_tweak(_hmac_key: &[u8; 32], salt: [u8; 2]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"Google Nearby"), &salt);
    let mut tweak = [0u8; 16];
    hk.expand(b"V0 LDT salt pad", &mut tweak)
        .expect("16 bytes is valid HKDF-SHA256 length");
    tweak
}

fn mix_ldt_tweak(tweak: &[u8; 16], tail: &[u8]) -> [u8; 16] {
    let mut out = *tweak;
    for (i, &b) in tail.iter().enumerate() {
        out[i] ^= b;
    }
    out[tail.len()] ^= 0x80;
    out
}

fn xex128_encrypt_block(key32: &[u8; 32], tweak: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let k_block = Aes128::new_from_slice(&key32[..16]).unwrap();
    let k_tweak = Aes128::new_from_slice(&key32[16..32]).unwrap();
    let mut mask = *tweak;
    k_tweak.encrypt_block((&mut mask).into());
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = block[i] ^ mask[i];
    }
    k_block.encrypt_block((&mut b).into());
    for i in 0..16 {
        b[i] ^= mask[i];
    }
    b
}

fn xex128_decrypt_block(key32: &[u8; 32], tweak: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let k_block = Aes128::new_from_slice(&key32[..16]).unwrap();
    let k_tweak = Aes128::new_from_slice(&key32[16..32]).unwrap();
    let mut mask = *tweak;
    k_tweak.encrypt_block((&mut mask).into());
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = block[i] ^ mask[i];
    }
    k_block.decrypt_block((&mut b).into());
    for i in 0..16 {
        b[i] ^= mask[i];
    }
    b
}

/// Length-Doubling Transform (LDT) encryption over AES-128 XEX for `16 <= len <= 31`.
/// Matches GMS `libldt_np_jni.so` (`beto-core/nearby/presence/ldt`).
pub fn ldt_xts_aes256_encrypt(
    key: &[u8; 64],
    tweak: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, PresenceError> {
    if plaintext.len() < 16 || plaintext.len() > 31 {
        return Err(PresenceError::Malformed(
            "LDT payload must be between 16 and 31 bytes",
        ));
    }
    let k1: &[u8; 32] = key[..32].try_into().unwrap();
    let k2: &[u8; 32] = key[32..64].try_into().unwrap();
    let s = plaintext.len() - 16;
    let tail_pt = &plaintext[16..];

    let t2 = mix_ldt_tweak(tweak, tail_pt);
    let head_in: [u8; 16] = plaintext[..16].try_into().unwrap();
    let b1_enc = xex128_encrypt_block(k1, &t2, &head_in);

    let tail_ct = &b1_enc[16 - s..16];
    let mut b0_mid = [0u8; 16];
    b0_mid[..16 - s].copy_from_slice(&b1_enc[..16 - s]);
    b0_mid[16 - s..16].copy_from_slice(tail_pt);

    let t1 = mix_ldt_tweak(tweak, tail_ct);
    let head_ct = xex128_encrypt_block(k2, &t1, &b0_mid);

    let mut out = Vec::with_capacity(plaintext.len());
    out.extend_from_slice(&head_ct);
    out.extend_from_slice(tail_ct);
    Ok(out)
}

/// Inverse of [`ldt_xts_aes256_encrypt`] for `16 <= len <= 31`.
pub fn ldt_xts_aes256_decrypt(
    key: &[u8; 64],
    tweak: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PresenceError> {
    if ciphertext.len() < 16 || ciphertext.len() > 31 {
        return Err(PresenceError::Malformed(
            "LDT payload must be between 16 and 31 bytes",
        ));
    }
    let k1: &[u8; 32] = key[..32].try_into().unwrap();
    let k2: &[u8; 32] = key[32..64].try_into().unwrap();
    let s = ciphertext.len() - 16;
    let tail_ct = &ciphertext[16..];

    let t1 = mix_ldt_tweak(tweak, tail_ct);
    let head_ct: [u8; 16] = ciphertext[..16].try_into().unwrap();
    let b0_mid = xex128_decrypt_block(k2, &t1, &head_ct);

    let tail_pt = &b0_mid[16 - s..16];
    let mut b1_in = [0u8; 16];
    b1_in[..16 - s].copy_from_slice(&b0_mid[..16 - s]);
    b1_in[16 - s..16].copy_from_slice(tail_ct);

    let t2 = mix_ldt_tweak(tweak, tail_pt);
    let head_pt = xex128_decrypt_block(k1, &t2, &b1_in);

    let mut out = Vec::with_capacity(ciphertext.len());
    out.extend_from_slice(&head_pt);
    out.extend_from_slice(tail_pt);
    Ok(out)
}

/// Decoded Nearby Presence Data Element (`google/nearby` `DataElement` v0/v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataElement {
    Salt([u8; 2]),
    Identity { kind: u8, payload: Vec<u8> },
    TxPower(i8),
    ActionBits(Vec<u8>),
    ModelId(Vec<u8>),
    ConnectionStatus(Vec<u8>),
    Unknown { de_type: u8, payload: Vec<u8> },
}

/// Parsed & decrypted Nearby Presence advertisement from a remote Android phone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedPresenceAdv {
    pub version: u8,
    pub device_name: String,
    pub device_id: String,
    pub salt: [u8; 2],
    pub identity_type: u8,
    pub data_elements: Vec<DataElement>,
    /// True if Instant Hotspot / Shared Connectivity action bit is present.
    pub instant_hotspot_available: bool,
    /// True if Cross-Device / DeviceLink action bit is present.
    pub cross_device_available: bool,
}

/// Parse raw Nearby Presence BLE `0xFCF1` Service Data into `(version, DataElements)`.
pub fn parse_v0_data_elements(bytes: &[u8]) -> Result<Vec<DataElement>, PresenceError> {
    let mut idx = 0;
    let mut elements = Vec::new();
    while idx < bytes.len() {
        let hdr = bytes[idx];
        idx += 1;
        let len = ((hdr & 0x70) >> 4) as usize;
        let de_type = hdr & 0x0F;
        let extended = (hdr & 0x80) != 0;
        let actual_len = if extended {
            if idx >= bytes.len() {
                return Err(PresenceError::Malformed("truncated extended DE"));
            }
            let ext = bytes[idx] as usize;
            idx += 1;
            ext
        } else {
            len
        };
        if idx + actual_len > bytes.len() {
            return Err(PresenceError::Malformed("DE payload exceeds buffer"));
        }
        let payload = &bytes[idx..idx + actual_len];
        idx += actual_len;
        let de = match de_type {
            0 if actual_len == 2 => DataElement::Salt([payload[0], payload[1]]),
            1..=4 => DataElement::Identity {
                kind: de_type,
                payload: payload.to_vec(),
            },
            5 if actual_len == 1 => DataElement::TxPower(payload[0] as i8),
            6 => DataElement::ActionBits(payload.to_vec()),
            7 => DataElement::ModelId(payload.to_vec()),
            10 => DataElement::ConnectionStatus(payload.to_vec()),
            _ => DataElement::Unknown {
                de_type,
                payload: payload.to_vec(),
            },
        };
        elements.push(de);
    }
    Ok(elements)
}

/// Attempt to decrypt a raw BLE `0xFCF1` Service Data packet against a list of
/// locally configured [`DerivedPresenceKey`]s.
pub fn decrypt_presence_advertisement(
    service_data: &[u8],
    credentials: &[DerivedPresenceKey],
) -> Result<DecryptedPresenceAdv, PresenceError> {
    if service_data.len() < 4 {
        return Err(PresenceError::Malformed("0xFCF1 payload < 4 bytes"));
    }
    let version = (service_data[0] & 0xE0) >> 5;
    if version != 0 && version != 1 {
        return Err(PresenceError::UnsupportedVersion(version));
    }

    // Support both GMS V0 private/trusted wire header `[0x04, s0, s1, ct...]`
    // and `[0x00, 0x20, s0, s1, id_de, ct...]`.
    let mut salt = None;
    let mut identity_type = 0u8;
    let mut encrypted_section: Option<&[u8]> = None;

    if service_data[0] == 0x04 && service_data.len() >= 19 {
        identity_type = 1;
        salt = Some([service_data[1], service_data[2]]);
        encrypted_section = Some(&service_data[3..]);
    } else {
        let mut idx = 1;
        while idx < service_data.len() {
            let hdr = service_data[idx];
            let de_type = hdr & 0x0F;
            if de_type == 0 {
                let len = ((hdr & 0x70) >> 4) as usize;
                if len != 2 || idx + 3 > service_data.len() {
                    return Err(PresenceError::Malformed("invalid salt DE"));
                }
                salt = Some([service_data[idx + 1], service_data[idx + 2]]);
                idx += 3;
            } else if (1..=4).contains(&de_type) {
                identity_type = de_type;
                // In v0 encrypted advertisements, the remaining bytes after the identity header
                // form the 16..31 byte LDT ciphertext block.
                idx += 1;
                encrypted_section = Some(&service_data[idx..]);
                break;
            } else {
                break;
            }
        }
    }

    let salt = salt.ok_or(PresenceError::Malformed("missing salt DE"))?;
    let ct = encrypted_section.ok_or(PresenceError::Malformed("missing encrypted identity section"))?;
    if ct.len() < 16 || ct.len() > 31 {
        return Err(PresenceError::Malformed(
            "encrypted identity section outside 16..31 byte LDT range",
        ));
    }

    for cred in credentials {
        let tweak = derive_ldt_tweak(&cred.hmac_key, salt);
        if let Ok(pt) = ldt_xts_aes256_decrypt(&cred.ldt_key, &tweak, ct) {
            if pt.len() < 14 {
                continue;
            }
            let matched = if let Some(expected_tag) = cred.metadata_encryption_key_tag_v0 {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = <HmacSha256 as Mac>::new_from_slice(&cred.hmac_key)
                    .expect("HMAC accepts any key length");
                mac.update(&pt[..14]);
                mac.finalize().into_bytes().as_slice() == expected_tag.as_slice()
            } else if let Some(mek) = cred.metadata_encryption_key {
                pt[..14] == mek
            } else {
                false
            };

            if matched {
                let inner_des = parse_v0_data_elements(&pt[14..])?;
                let mut instant_hotspot_available = false;
                let mut cross_device_available = false;
                for de in &inner_des {
                    if let DataElement::ActionBits(bits) = de {
                        // Action bitfield per GMS Nearby Presence v0 (MSB-0 bit indexing):
                        // bit 10 (`0x20` in byte 1) = Instant Tethering / Hotspot (`PresenceAction(10)`).
                        // bit 1 / bit 4 (`0x48` in byte 0) or bit 12 = Cross-Device / Context Sync.
                        if action_bit_set(bits, 10) {
                            instant_hotspot_available = true;
                        }
                        if action_bit_set(bits, 1) || action_bit_set(bits, 4) || action_bit_set(bits, 12) {
                            cross_device_available = true;
                        }
                    }
                }
                return Ok(DecryptedPresenceAdv {
                    version,
                    device_name: cred.device_name.clone(),
                    device_id: cred.device_id.clone(),
                    salt,
                    identity_type,
                    data_elements: inner_des,
                    instant_hotspot_available,
                    cross_device_available,
                });
            }
        }
    }

    Err(PresenceError::NoMatchingCredential)
}

/// Build a test/local v0 encrypted Nearby Presence advertisement (useful for round-trip tests
/// and verifying LDT compatibility).
pub fn build_v0_encrypted_advertisement(
    cred: &DerivedPresenceKey,
    salt: [u8; 2],
    identity_type: u8,
    inner_de_bytes: &[u8],
) -> Result<Vec<u8>, PresenceError> {
    let mek = cred
        .metadata_encryption_key
        .ok_or(PresenceError::Malformed("missing metadata_encryption_key"))?;
    let mut pt = Vec::with_capacity(14 + inner_de_bytes.len());
    pt.extend_from_slice(&mek);
    pt.extend_from_slice(inner_de_bytes);
    let tweak = derive_ldt_tweak(&cred.hmac_key, salt);
    let ct = ldt_xts_aes256_encrypt(&cred.ldt_key, &tweak, &pt)?;

    let mut adv = Vec::with_capacity(5 + ct.len());
    adv.push(0x00); // version 0
    adv.push(0x20); // salt DE: len=2, type=0
    adv.extend_from_slice(&salt);
    adv.push(identity_type & 0x0F); // identity DE marker
    adv.extend_from_slice(&ct);
    Ok(adv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldt_roundtrip_all_valid_lengths() {
        let key = [0x42u8; 64];
        let tweak = [0x11u8; 16];
        for len in 16..=31 {
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)).collect();
            let ct = ldt_xts_aes256_encrypt(&key, &tweak, &pt).unwrap();
            assert_eq!(ct.len(), len);
            assert_ne!(ct, pt);
            let dec = ldt_xts_aes256_decrypt(&key, &tweak, &ct).unwrap();
            assert_eq!(dec, pt);
        }
    }

    #[test]
    fn presence_v0_advertisement_roundtrip_and_hotspot_flag() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let cred = SharedCredential {
            device_name: "Pixel 9 Pro".into(),
            device_id: "pixel-9-pro-test".into(),
            secret_id_b64: b64.encode([0xAAu8; 32]),
            authenticity_key_b64: b64.encode([0x24u8; 32]),
            metadata_encryption_key_b64: Some(b64.encode([0x5Au8; 14])),
            metadata_encryption_key_tag_v0_b64: None,
            ldt_key_b64: None,
        };
        let derived = cred.derive_keys().unwrap();

        // Inner DEs: ActionBits (type=6, len=2 -> 0x26) with MSB-0 bit 1,4 (`0x48`) + bit 10 (`0x20`, Instant Hotspot)
        let inner = [0x26u8, 0x48, 0x20, 0x15, 0xF8]; // ActionBits(0x4820) + TxPower(-8)
        let adv = build_v0_encrypted_advertisement(&derived, [0xBE, 0xEF], 2, &inner).unwrap();
        let parsed = decrypt_presence_advertisement(&adv, &[derived]).unwrap();

        assert_eq!(parsed.device_name, "Pixel 9 Pro");
        assert_eq!(parsed.salt, [0xBE, 0xEF]);
        assert!(parsed.instant_hotspot_available);
        assert!(parsed.cross_device_available);
        assert!(parsed.data_elements.contains(&DataElement::TxPower(-8)));
    }

    #[test]
    fn presence_one_way_auth_frame_roundtrip() {
        let secret = [0x11u8; 32];
        let key_seed = [0x22u8; 32];
        let wire = build_one_way_presence_auth_message(&secret, &key_seed);
        let decoded = decode_presence_auth_message(&wire).unwrap();
        assert_eq!(decoded.version, Some(1));
        assert!(decoded.signature.is_none());
        assert!(decoded.discovery_credential_id_hash.is_none());
        assert_eq!(
            decoded.broadcast_credential_id_hash.as_deref(),
            Some(derive_presence_credential_hash(&secret, &key_seed).as_slice())
        );
    }

    #[test]
    fn v0_gms_header_0x04_with_hmac_tag_decrypts() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let key_seed = [0x37u8; 32];
        let mek = [0x91u8; 14];
        let hmac_key = derive_hmac_key_from_authenticity_key(&key_seed);
        let ldt_key = derive_ldt_key_from_authenticity_key(&key_seed);

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key).unwrap();
        mac.update(&mek);
        let tag_v0 = mac.finalize().into_bytes();

        let cred = SharedCredential {
            device_name: "Android Phone".into(),
            device_id: "test-device-01".into(),
            secret_id_b64: String::new(),
            authenticity_key_b64: b64.encode(key_seed),
            metadata_encryption_key_b64: None,
            metadata_encryption_key_tag_v0_b64: Some(b64.encode(tag_v0)),
            ldt_key_b64: None,
        };
        let derived = cred.derive_keys().unwrap();

        // Build GMS v0 wire packet: [0x04, salt0, salt1, LDT(mek || ActionBits(0x48, 0x00, 0x80))]
        let salt = [0x2b, 0xfe];
        let mut pt = Vec::new();
        pt.extend_from_slice(&mek);
        pt.extend_from_slice(&[0x36, 0x48, 0x00, 0x80]); // ActionBits len=3, type=6
        let tweak = derive_ldt_tweak(&hmac_key, salt);
        let ct = ldt_xts_aes256_encrypt(&ldt_key, &tweak, &pt).unwrap();

        let mut raw = vec![0x04, salt[0], salt[1]];
        raw.extend_from_slice(&ct);

        let parsed = decrypt_presence_advertisement(&raw, &[derived]).unwrap();
        assert_eq!(parsed.device_name, "Android Phone");
        assert_eq!(parsed.salt, [0x2b, 0xfe]);
        assert!(parsed.cross_device_available);
        assert!(!parsed.instant_hotspot_available);
        assert!(parsed
            .data_elements
            .contains(&DataElement::ActionBits(vec![0x48, 0x00, 0x80])));
    }
}
