//! Google Weave BLE GATT transport (`0xFEF3`: TX `...0101`, RX `...0102`) and
//! Nearby Connections BLE v2 `BlePacket` / `SocketControlFrame` framing.
//!
//! Wire-compatible with `google/nearby/internal/weave/packet.{h,cc}` and
//! `google/nearby/connections/implementation/mediums/ble/ble_packet.cc`.

use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SERVICE_ID_DTDI: &str = "com.google.android.gms.dtdi";

#[derive(Debug, Error)]
pub enum WeaveError {
    #[error("malformed weave packet")]
    MalformedPacket,
    #[error("peer sent Weave control error packet")]
    ControlError,
    #[error("unexpected Weave packet counter: expected {expected}, got {actual}")]
    UnexpectedCounter { expected: u8, actual: u8 },
}

/// Compute the 3-byte Nearby Connections BLE v2 `service_id_hash = SHA256(service_id)[..3]`.
pub fn service_id_hash(service_id: &str) -> [u8; 3] {
    let digest = Sha256::digest(service_id.as_bytes());
    [digest[0], digest[1], digest[2]]
}

// ---------------------------------------------------------------------------
// Nearby Connections `proto/mediums/ble_frames.proto`
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct SocketControlFrame {
    /// 1 = INTRODUCTION, 2 = DISCONNECTION, 3 = PACKET_ACKNOWLEDGEMENT
    #[prost(int32, optional, tag = "1")]
    pub r#type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub introduction: Option<IntroductionFrame>,
    #[prost(message, optional, tag = "3")]
    pub disconnection: Option<BleDisconnectionFrame>,
    #[prost(message, optional, tag = "4")]
    pub packet_acknowledgement: Option<PacketAcknowledgementFrame>,
}

#[derive(Clone, PartialEq, Message)]
pub struct IntroductionFrame {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub service_id_hash: Option<Vec<u8>>,
    /// 1 = V1, 2 = V2
    #[prost(int32, optional, tag = "2")]
    pub socket_version: Option<i32>,
    #[prost(string, optional, tag = "3")]
    pub service_id_hash_salt: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BleDisconnectionFrame {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub service_id_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PacketAcknowledgementFrame {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub service_id_hash: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    pub received_size: Option<i32>,
}

/// Build a Nearby Connections BLE v2 Control Introduction `BlePacket`:
/// `[0x00, 0x00, 0x00] || SocketControlFrame::INTRODUCTION`.
pub fn build_ble_v2_introduction(hash: [u8; 3]) -> Vec<u8> {
    let ctrl = SocketControlFrame {
        r#type: Some(1),
        introduction: Some(IntroductionFrame {
            service_id_hash: Some(hash.to_vec()),
            socket_version: Some(2), // V2
            service_id_hash_salt: None,
        }),
        disconnection: None,
        packet_acknowledgement: None,
    }
    .encode_to_vec();

    let mut out = Vec::with_capacity(3 + ctrl.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&ctrl);
    out
}

/// Build a Nearby Connections BLE v2 Data `BlePacket`:
/// `service_id_hash[3] || u32_be(payload.len()) || payload` (matching `ble_socket.cc:57-71`).
pub fn build_ble_v2_data(hash: [u8; 3], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len());
    out.extend_from_slice(&hash);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build a Nearby Connections BLE v2 `PACKET_ACKNOWLEDGEMENT` control packet.
pub fn build_ble_v2_ack(hash: [u8; 3], received_size: i32) -> Vec<u8> {
    let ctrl = SocketControlFrame {
        r#type: Some(3),
        introduction: None,
        disconnection: None,
        packet_acknowledgement: Some(PacketAcknowledgementFrame {
            service_id_hash: Some(hash.to_vec()),
            received_size: Some(received_size),
        }),
    }
    .encode_to_vec();
    let mut out = Vec::with_capacity(3 + ctrl.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    out.extend_from_slice(&ctrl);
    out
}

// ---------------------------------------------------------------------------
// Weave BLE GATT Packetizer / Depacketizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeaveRxEvent {
    ConnectionConfirm {
        selected_version: u16,
        selected_mtu: u16,
        extra_data: Vec<u8>,
    },
    DataMessage(Vec<u8>),
    Incomplete,
}

/// Stateful Weave BLE GATT framer (`min_ver=1`, `max_ver=1`, 3-bit wrap counter).
pub struct WeaveFramer {
    tx_counter: u8,
    max_packet_size: usize,
    rx_buf: Vec<u8>,
    rx_in_progress: bool,
}

impl WeaveFramer {
    pub fn new(initial_mtu: usize) -> Self {
        Self {
            tx_counter: 0,
            max_packet_size: initial_mtu.max(20),
            rx_buf: Vec::new(),
            rx_in_progress: false,
        }
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        self.max_packet_size = mtu.max(20);
    }

    fn next_tx_counter(&mut self) -> u8 {
        let c = self.tx_counter;
        self.tx_counter = (self.tx_counter + 1) & 0x07;
        c
    }

    /// Build the 7-byte Weave Connection Request control packet (`0x80 || ver=1..1 || mtu`).
    pub fn build_connection_request(&mut self, max_packet_size: u16) -> Vec<u8> {
        let cnt = self.next_tx_counter();
        let hdr = 0x80 | ((cnt & 0x07) << 4); // control=1, cmd=0 (kControlConnectionRequest)
        let mut pkt = Vec::with_capacity(7);
        pkt.push(hdr);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&max_packet_size.to_be_bytes());
        pkt
    }

    /// Fragment a message into one or more Weave data packets respecting `max_packet_size`.
    pub fn packetize_data(&mut self, msg: &[u8]) -> Vec<Vec<u8>> {
        let chunk_max = self.max_packet_size.saturating_sub(1).max(1);
        let chunks: Vec<&[u8]> = if msg.is_empty() {
            vec![&[]]
        } else {
            msg.chunks(chunk_max).collect()
        };
        let total = chunks.len();
        let mut out = Vec::with_capacity(total);
        for (i, ch) in chunks.into_iter().enumerate() {
            let cnt = self.next_tx_counter();
            let mut hdr = (cnt & 0x07) << 4;
            if i == 0 {
                hdr |= 0x08; // is_first_packet
            }
            if i + 1 == total {
                hdr |= 0x04; // is_last_packet
            }
            let mut pkt = Vec::with_capacity(1 + ch.len());
            pkt.push(hdr);
            pkt.extend_from_slice(ch);
            out.push(pkt);
        }
        out
    }

    /// Feed a single GATT indication received on `00000100-0004-1000-8000-001A11000102`.
    pub fn feed_rx(&mut self, packet: &[u8]) -> Result<WeaveRxEvent, WeaveError> {
        if packet.is_empty() {
            return Err(WeaveError::MalformedPacket);
        }
        let hdr = packet[0];
        let is_control = (hdr & 0x80) != 0;
        if is_control {
            let cmd = hdr & 0x0F;
            match cmd {
                1 => {
                    if packet.len() < 5 {
                        return Err(WeaveError::MalformedPacket);
                    }
                    let selected_version = u16::from_be_bytes([packet[1], packet[2]]);
                    let selected_mtu = u16::from_be_bytes([packet[3], packet[4]]);
                    self.set_mtu(selected_mtu as usize);
                    Ok(WeaveRxEvent::ConnectionConfirm {
                        selected_version,
                        selected_mtu,
                        extra_data: packet[5..].to_vec(),
                    })
                }
                2 => Err(WeaveError::ControlError),
                _ => Err(WeaveError::MalformedPacket),
            }
        } else {
            let is_first = (hdr & 0x08) != 0;
            let is_last = (hdr & 0x04) != 0;
            if is_first {
                self.rx_buf.clear();
                self.rx_in_progress = true;
            }
            if !self.rx_in_progress {
                return Err(WeaveError::MalformedPacket);
            }
            self.rx_buf.extend_from_slice(&packet[1..]);
            if is_last {
                self.rx_in_progress = false;
                Ok(WeaveRxEvent::DataMessage(std::mem::take(&mut self.rx_buf)))
            } else {
                Ok(WeaveRxEvent::Incomplete)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weave_fragmentation_and_reassembly() {
        let mut tx = WeaveFramer::new(20);
        let req = tx.build_connection_request(512);
        assert_eq!(req, vec![0x80, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00]);

        let mut rx = WeaveFramer::new(20);
        assert_eq!(
            rx.feed_rx(&[0x81, 0x00, 0x01, 0x00, 0x14]).unwrap(),
            WeaveRxEvent::ConnectionConfirm {
                selected_version: 1,
                selected_mtu: 20,
                extra_data: vec![],
            }
        );

        let payload: Vec<u8> = (0..45u8).collect();
        let pkts = tx.packetize_data(&payload);
        assert_eq!(pkts.len(), 3); // 19 + 19 + 7
        assert_eq!(rx.feed_rx(&pkts[0]).unwrap(), WeaveRxEvent::Incomplete);
        assert_eq!(rx.feed_rx(&pkts[1]).unwrap(), WeaveRxEvent::Incomplete);
        assert_eq!(
            rx.feed_rx(&pkts[2]).unwrap(),
            WeaveRxEvent::DataMessage(payload)
        );
    }

    #[test]
    fn dtdi_service_id_hash_matches() {
        assert_eq!(service_id_hash(SERVICE_ID_DTDI), [0xFD, 0x10, 0x08]);
    }
}
