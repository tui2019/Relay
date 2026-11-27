//! Google UKEY2 Authenticated Key Exchange (`P256_SHA512` + `AES_256_CBC-HMAC_SHA256`)
//! and `D2DConnectionContextV1` (`SecureMessage` / `DeviceToDeviceMessage`).
//!
//! Wire-compatible with `google/ukey2` & `google/nearby` Nearby Connections (`securegcm`).

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use prost::Message;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub const NEXT_PROTOCOL_AES_256_CBC_HMAC_SHA256: &str = "AES_256_CBC-HMAC_SHA256";
pub const CIPHER_P256_SHA512: i32 = 100;

#[derive(Debug, Error)]
pub enum Ukey2Error {
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("unexpected UKEY2 message type: expected {expected}, got {actual}")]
    UnexpectedMessageType { expected: i32, actual: i32 },
    #[error("peer sent UKEY2 alert (type={alert_type}): {message}")]
    PeerAlert { alert_type: i32, message: String },
    #[error("commitment verification failed")]
    CommitmentMismatch,
    #[error("invalid P-256 public key")]
    InvalidPublicKey,
    #[error("HMAC verification failed")]
    BadMac,
    #[error("AES-256-CBC decryption failed")]
    DecryptFailed,
    #[error("sequence number mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: i32, actual: i32 },
    #[error("invalid handshake state")]
    InvalidState,
}

// ---------------------------------------------------------------------------
// Wire-exact UKEY2 protobuf definitions (google/ukey2/proto/ukey.proto)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2Message {
    /// 1=ALERT, 2=CLIENT_INIT, 3=SERVER_INIT, 4=CLIENT_FINISH
    #[prost(int32, optional, tag = "1")]
    pub message_type: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub message_data: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2Alert {
    #[prost(int32, optional, tag = "1")]
    pub r#type: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub error_message: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CipherCommitment {
    #[prost(int32, optional, tag = "1")]
    pub handshake_cipher: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub commitment: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2ClientInit {
    #[prost(int32, optional, tag = "1")]
    pub version: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub random: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "3")]
    pub cipher_commitments: Vec<CipherCommitment>,
    #[prost(string, optional, tag = "4")]
    pub next_protocol: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2ServerInit {
    #[prost(int32, optional, tag = "1")]
    pub version: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub random: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "3")]
    pub handshake_cipher: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub public_key: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2ClientFinished {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub public_key: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Wire-exact SecureMessage / GenericPublicKey protobufs (securemessage.proto)
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct EcP256PublicKey {
    /// Two's complement signed big-endian X coordinate (matching Java BigInteger.toByteArray)
    #[prost(bytes = "vec", required, tag = "1")]
    pub x: Vec<u8>,
    /// Two's complement signed big-endian Y coordinate
    #[prost(bytes = "vec", required, tag = "2")]
    pub y: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GenericPublicKey {
    /// 1 = EC_P256
    #[prost(int32, required, tag = "1")]
    pub r#type: i32,
    #[prost(message, optional, tag = "2")]
    pub ec_p256_public_key: Option<EcP256PublicKey>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SecureMessage {
    #[prost(bytes = "vec", required, tag = "1")]
    pub header_and_body: Vec<u8>,
    #[prost(bytes = "vec", required, tag = "2")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HeaderAndBody {
    #[prost(message, required, tag = "1")]
    pub header: SecureHeader,
    #[prost(bytes = "vec", required, tag = "2")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SecureHeader {
    /// 1 = HMAC_SHA256
    #[prost(int32, required, tag = "1")]
    pub signature_scheme: i32,
    /// 2 = AES_256_CBC
    #[prost(int32, required, tag = "2")]
    pub encryption_scheme: i32,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub iv: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub public_metadata: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GcmMetadata {
    /// 13 (`0x0d`) = DEVICE_TO_DEVICE_MESSAGE (verified live against Pixel 9 Pro!)
    #[prost(int32, required, tag = "1")]
    pub r#type: i32,
    #[prost(int32, optional, tag = "2")]
    pub version: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeviceToDeviceMessage {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub message: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    pub sequence_number: Option<i32>,
}

// ---------------------------------------------------------------------------
// Public key conversion (P-256 <-> GenericPublicKey two's complement)
// ---------------------------------------------------------------------------

fn to_twos_complement_be(unsigned_32: &[u8]) -> Vec<u8> {
    let trimmed = unsigned_32
        .iter()
        .position(|&b| b != 0)
        .map(|pos| &unsigned_32[pos..])
        .unwrap_or(&[0]);
    if (trimmed[0] & 0x80) != 0 {
        let mut out = Vec::with_capacity(trimmed.len() + 1);
        out.push(0x00);
        out.extend_from_slice(trimmed);
        out
    } else {
        trimmed.to_vec()
    }
}

fn from_twos_complement_be(signed: &[u8]) -> Result<[u8; 32], Ukey2Error> {
    let stripped = if signed.len() == 33 && signed[0] == 0x00 {
        &signed[1..]
    } else {
        signed
    };
    if stripped.len() > 32 {
        return Err(Ukey2Error::InvalidPublicKey);
    }
    let mut out = [0u8; 32];
    out[32 - stripped.len()..].copy_from_slice(stripped);
    Ok(out)
}

fn encode_generic_public_key(pk: &PublicKey) -> Vec<u8> {
    let point = pk.to_encoded_point(false);
    let x = to_twos_complement_be(point.x().expect("uncompressed x"));
    let y = to_twos_complement_be(point.y().expect("uncompressed y"));
    let gpk = GenericPublicKey {
        r#type: 1,
        ec_p256_public_key: Some(EcP256PublicKey { x, y }),
    };
    gpk.encode_to_vec()
}

fn decode_generic_public_key(bytes: &[u8]) -> Result<PublicKey, Ukey2Error> {
    let gpk = GenericPublicKey::decode(bytes)?;
    let ec = gpk.ec_p256_public_key.ok_or(Ukey2Error::InvalidPublicKey)?;
    let x = from_twos_complement_be(&ec.x)?;
    let y = from_twos_complement_be(&ec.y)?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..65].copy_from_slice(&y);
    let ep = EncodedPoint::from_bytes(sec1).map_err(|_| Ukey2Error::InvalidPublicKey)?;
    PublicKey::from_sec1_bytes(ep.as_bytes()).map_err(|_| Ukey2Error::InvalidPublicKey)
}

// ---------------------------------------------------------------------------
// UKEY2 Handshake State Machine (Initiator & Responder)
// ---------------------------------------------------------------------------

/// Established encrypted UKEY2 D2D channel (`AES_256_CBC-HMAC_SHA256`).
#[derive(Debug, Clone)]
pub struct D2DConnectionContext {
    encode_enc_key: [u8; 32],
    encode_hmac_key: [u8; 32],
    decode_enc_key: [u8; 32],
    decode_hmac_key: [u8; 32],
    encode_seq: i32,
    decode_seq: i32,
    pub auth_string: [u8; 32],
}

impl D2DConnectionContext {
    /// 4-character human-readable Nearby verification token (matching `google/nearby`).
    pub fn short_auth_token(&self) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        b64.encode(&self.auth_string[..4])
    }

    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.encode_seq += 1;
        let d2d = DeviceToDeviceMessage {
            message: Some(plaintext.to_vec()),
            sequence_number: Some(self.encode_seq),
        };
        let d2d_bytes = d2d.encode_to_vec();

        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let ciphertext = Aes256CbcEnc::new(&self.encode_enc_key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&d2d_bytes);

        let metadata = GcmMetadata {
            r#type: 13, // DEVICE_TO_DEVICE_MESSAGE
            version: Some(1),
        }
        .encode_to_vec();

        let hab = HeaderAndBody {
            header: SecureHeader {
                signature_scheme: 1,  // HMAC_SHA256
                encryption_scheme: 2, // AES_256_CBC
                iv: Some(iv.to_vec()),
                public_metadata: Some(metadata),
            },
            body: ciphertext,
        }
        .encode_to_vec();

        let mut mac =
            HmacSha256::new_from_slice(&self.encode_hmac_key).expect("HMAC accepts 32-byte key");
        mac.update(&hab);
        let sig = mac.finalize().into_bytes().to_vec();

        SecureMessage {
            header_and_body: hab,
            signature: sig,
        }
        .encode_to_vec()
    }

    pub fn decrypt_message(&mut self, wire: &[u8]) -> Result<Vec<u8>, Ukey2Error> {
        let sm = SecureMessage::decode(wire)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.decode_hmac_key).expect("HMAC accepts 32-byte key");
        mac.update(&sm.header_and_body);
        mac.verify_slice(&sm.signature)
            .map_err(|_| Ukey2Error::BadMac)?;

        let hab = HeaderAndBody::decode(sm.header_and_body.as_slice())?;
        let iv_vec = hab.header.iv.ok_or(Ukey2Error::DecryptFailed)?;
        if iv_vec.len() != 16 {
            return Err(Ukey2Error::DecryptFailed);
        }
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_vec);

        let pt = Aes256CbcDec::new(&self.decode_enc_key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&hab.body)
            .map_err(|_| Ukey2Error::DecryptFailed)?;

        let d2d = DeviceToDeviceMessage::decode(pt.as_slice())?;
        self.decode_seq += 1;
        let seq = d2d.sequence_number.unwrap_or(0);
        if seq != self.decode_seq {
            return Err(Ukey2Error::SequenceMismatch {
                expected: self.decode_seq,
                actual: seq,
            });
        }
        Ok(d2d.message.unwrap_or_default())
    }
}

fn derive_d2d_context(
    shared_secret_raw: &[u8],
    client_init_wire: &[u8],
    server_init_wire: &[u8],
    is_client: bool,
) -> D2DConnectionContext {
    // IKM = SHA256(DH shared secret)
    let ikm = Sha256::digest(shared_secret_raw);
    let mut info = Vec::with_capacity(client_init_wire.len() + server_init_wire.len());
    info.extend_from_slice(client_init_wire);
    info.extend_from_slice(server_init_wire);

    let hk_auth = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 auth"), &ikm);
    let mut auth_string = [0u8; 32];
    hk_auth
        .expand(&info, &mut auth_string)
        .expect("32 bytes valid");

    let hk_next = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 next"), &ikm);
    let mut next_secret = [0u8; 32];
    hk_next
        .expand(&info, &mut next_secret)
        .expect("32 bytes valid");

    // Derive client & server directional keys from next_secret using salt = SHA256("D2D")
    let d2d_salt = Sha256::digest(b"D2D");
    let hk_d2d = Hkdf::<Sha256>::new(Some(&d2d_salt), &next_secret);
    let mut client_key = [0u8; 32];
    let mut server_key = [0u8; 32];
    hk_d2d.expand(b"client", &mut client_key).unwrap();
    hk_d2d.expand(b"server", &mut server_key).unwrap();

    // Derive separate AES-256-CBC and HMAC-SHA256 subkeys per direction (matching SecureMessage)
    let subkey = |base: &[u8; 32], purpose: &[u8]| -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&Sha256::digest(b"SecureMessage")), base);
        let mut out = [0u8; 32];
        hk.expand(purpose, &mut out).unwrap();
        out
    };

    let c_enc = subkey(&client_key, b"ENC:2");
    let c_mac = subkey(&client_key, b"SIG:1");
    let s_enc = subkey(&server_key, b"ENC:2");
    let s_mac = subkey(&server_key, b"SIG:1");

    if is_client {
        D2DConnectionContext {
            encode_enc_key: c_enc,
            encode_hmac_key: c_mac,
            decode_enc_key: s_enc,
            decode_hmac_key: s_mac,
            encode_seq: 0,
            decode_seq: 0,
            auth_string,
        }
    } else {
        D2DConnectionContext {
            encode_enc_key: s_enc,
            encode_hmac_key: s_mac,
            decode_enc_key: c_enc,
            decode_hmac_key: c_mac,
            encode_seq: 0,
            decode_seq: 0,
            auth_string,
        }
    }
}

/// UKEY2 Initiator (Mac connecting to Android Phone).
pub struct Ukey2Initiator {
    secret: Option<EphemeralSecret>,
    client_init_wire: Vec<u8>,
    client_finish_wire: Vec<u8>,
}

impl Ukey2Initiator {
    /// Create a new UKEY2 initiator and return the wire-encoded `CLIENT_INIT` message.
    pub fn start() -> (Self, Vec<u8>) {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        let gpk_bytes = encode_generic_public_key(&public);

        let finish_inner = Ukey2ClientFinished {
            public_key: Some(gpk_bytes),
        }
        .encode_to_vec();
        let client_finish_wire = Ukey2Message {
            message_type: Some(4), // CLIENT_FINISH
            message_data: Some(finish_inner),
        }
        .encode_to_vec();

        let commitment = Sha512::digest(&client_finish_wire).to_vec();
        let mut random = vec![0u8; 32];
        OsRng.fill_bytes(&mut random);

        let init_inner = Ukey2ClientInit {
            version: Some(1),
            random: Some(random),
            cipher_commitments: vec![CipherCommitment {
                handshake_cipher: Some(CIPHER_P256_SHA512),
                commitment: Some(commitment),
            }],
            next_protocol: Some(NEXT_PROTOCOL_AES_256_CBC_HMAC_SHA256.to_string()),
        }
        .encode_to_vec();

        let client_init_wire = Ukey2Message {
            message_type: Some(2), // CLIENT_INIT
            message_data: Some(init_inner),
        }
        .encode_to_vec();

        (
            Self {
                secret: Some(secret),
                client_init_wire: client_init_wire.clone(),
                client_finish_wire,
            },
            client_init_wire,
        )
    }

    /// Process `SERVER_INIT` from the phone and return `(CLIENT_FINISH wire bytes, D2DConnectionContext)`.
    pub fn handle_server_init(
        mut self,
        server_init_wire: &[u8],
    ) -> Result<(Vec<u8>, D2DConnectionContext), Ukey2Error> {
        let msg = Ukey2Message::decode(server_init_wire)?;
        let mtype = msg.message_type.unwrap_or(0);
        if mtype == 1 {
            let alert = Ukey2Alert::decode(msg.message_data.unwrap_or_default().as_slice())?;
            return Err(Ukey2Error::PeerAlert {
                alert_type: alert.r#type.unwrap_or(0),
                message: alert.error_message.unwrap_or_default(),
            });
        }
        if mtype != 3 {
            return Err(Ukey2Error::UnexpectedMessageType {
                expected: 3,
                actual: mtype,
            });
        }
        let server_init = Ukey2ServerInit::decode(msg.message_data.unwrap_or_default().as_slice())?;
        let peer_pk = decode_generic_public_key(&server_init.public_key.unwrap_or_default())?;
        let secret = self.secret.take().ok_or(Ukey2Error::InvalidState)?;
        let shared = secret.diffie_hellman(&peer_pk);

        let ctx = derive_d2d_context(
            shared.raw_secret_bytes().as_slice(),
            &self.client_init_wire,
            server_init_wire,
            true,
        );
        Ok((self.client_finish_wire, ctx))
    }
}

/// UKEY2 Responder (for testing or when Mac accepts incoming Nearby Connections).
pub struct Ukey2Responder {
    secret: Option<EphemeralSecret>,
    client_init_wire: Vec<u8>,
    server_init_wire: Vec<u8>,
    expected_commitment: Vec<u8>,
}

impl Ukey2Responder {
    pub fn handle_client_init(client_init_wire: &[u8]) -> Result<(Self, Vec<u8>), Ukey2Error> {
        let msg = Ukey2Message::decode(client_init_wire)?;
        if msg.message_type.unwrap_or(0) != 2 {
            return Err(Ukey2Error::UnexpectedMessageType {
                expected: 2,
                actual: msg.message_type.unwrap_or(0),
            });
        }
        let ci = Ukey2ClientInit::decode(msg.message_data.unwrap_or_default().as_slice())?;
        let commit = ci
            .cipher_commitments
            .into_iter()
            .find(|c| c.handshake_cipher == Some(CIPHER_P256_SHA512))
            .and_then(|c| c.commitment)
            .ok_or(Ukey2Error::CommitmentMismatch)?;

        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        let mut random = vec![0u8; 32];
        OsRng.fill_bytes(&mut random);

        let si_inner = Ukey2ServerInit {
            version: Some(1),
            random: Some(random),
            handshake_cipher: Some(CIPHER_P256_SHA512),
            public_key: Some(encode_generic_public_key(&public)),
        }
        .encode_to_vec();

        let server_init_wire = Ukey2Message {
            message_type: Some(3),
            message_data: Some(si_inner),
        }
        .encode_to_vec();

        Ok((
            Self {
                secret: Some(secret),
                client_init_wire: client_init_wire.to_vec(),
                server_init_wire: server_init_wire.clone(),
                expected_commitment: commit,
            },
            server_init_wire,
        ))
    }

    pub fn handle_client_finish(
        mut self,
        client_finish_wire: &[u8],
    ) -> Result<D2DConnectionContext, Ukey2Error> {
        let digest = Sha512::digest(client_finish_wire);
        if digest.as_slice() != self.expected_commitment.as_slice() {
            return Err(Ukey2Error::CommitmentMismatch);
        }
        let msg = Ukey2Message::decode(client_finish_wire)?;
        if msg.message_type.unwrap_or(0) != 4 {
            return Err(Ukey2Error::UnexpectedMessageType {
                expected: 4,
                actual: msg.message_type.unwrap_or(0),
            });
        }
        let cf = Ukey2ClientFinished::decode(msg.message_data.unwrap_or_default().as_slice())?;
        let peer_pk = decode_generic_public_key(&cf.public_key.unwrap_or_default())?;
        let secret = self.secret.take().ok_or(Ukey2Error::InvalidState)?;
        let shared = secret.diffie_hellman(&peer_pk);

        Ok(derive_d2d_context(
            shared.raw_secret_bytes().as_slice(),
            &self.client_init_wire,
            &self.server_init_wire,
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ukey2_full_handshake_and_encrypted_exchange() {
        let (initiator, client_init) = Ukey2Initiator::start();
        let (responder, server_init) = Ukey2Responder::handle_client_init(&client_init).unwrap();
        let (client_finish, mut client_ctx) = initiator.handle_server_init(&server_init).unwrap();
        let mut server_ctx = responder.handle_client_finish(&client_finish).unwrap();

        assert_eq!(client_ctx.auth_string, server_ctx.auth_string);
        assert_eq!(client_ctx.short_auth_token(), server_ctx.short_auth_token());

        let c2s = client_ctx.encrypt_message(b"hello pixel over ukey2");
        assert_eq!(server_ctx.decrypt_message(&c2s).unwrap(), b"hello pixel over ukey2");

        let s2c = server_ctx.encrypt_message(b"hotspot ssid=Pixel9");
        assert_eq!(client_ctx.decrypt_message(&s2c).unwrap(), b"hotspot ssid=Pixel9");
    }
}
