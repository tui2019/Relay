//! Android 17 `TaskContinuity` Universal Clipboard & Task Handoff wire protobufs.
//!
//! Field numbers verified directly from Googlebook OS / Android 17 `services.jar`:
//! - `TaskContinuityMessenger.java` (CompanionDeviceManager message ID `1130858628`)
//! - `TaskContinuityMessage.java`
//! - `UniversalClipboardClipTransferStartMessage.java`
//! - `UniversalClipboardClipTransferChunkMessage.java`
//! - `EncodedClipData.java` & `EncodedClipDataItem.java`
//! - `TaskStackBroadcastMessage.java`, `HandoffRequestMessage.java`, `HandoffRequestResultMessage.java`

use prost::Message;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// CompanionDeviceManager message type ID registered by `TaskContinuityMessenger.java:119`.
pub const CDM_MESSAGE_ID_TASK_CONTINUITY: i32 = 1_130_858_628;

/// Default maximum chunk size matching Android's Universal Clipboard chunking.
pub const DEFAULT_CLIP_CHUNK_SIZE: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum ContinuityError {
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("unknown clipboard transfer id: {0}")]
    UnknownTransfer(String),
    #[error("invalid chunk index {chunk_id} (expected < {expected})")]
    InvalidChunkIndex { chunk_id: usize, expected: usize },
}

/// `TaskContinuityMessage.java`
#[derive(Clone, PartialEq, Message)]
pub struct TaskContinuityMessage {
    #[prost(oneof = "task_continuity_message::Payload", tags = "1, 2, 3, 4, 5")]
    pub payload: Option<task_continuity_message::Payload>,
}

pub mod task_continuity_message {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "1")]
        TaskStackBroadcast(TaskStackBroadcastMessage),
        #[prost(message, tag = "2")]
        HandoffRequest(HandoffRequestMessage),
        #[prost(message, tag = "3")]
        HandoffRequestResult(HandoffRequestResultMessage),
        #[prost(message, tag = "4")]
        ClipboardTransferStart(UniversalClipboardClipTransferStartMessage),
        #[prost(message, tag = "5")]
        ClipboardTransferChunk(UniversalClipboardClipTransferChunkMessage),
    }
}

/// `UniversalClipboardClipTransferStartMessage.java`
#[derive(Clone, PartialEq, Message)]
pub struct UniversalClipboardClipTransferStartMessage {
    #[prost(string, tag = "1")]
    pub transfer_id: String,
    #[prost(string, tag = "2")]
    pub device_id: String,
    #[prost(string, tag = "3")]
    pub device_name: String,
    #[prost(int32, tag = "4")]
    pub expected_chunk_count: i32,
}

/// `UniversalClipboardClipTransferChunkMessage.java`
#[derive(Clone, PartialEq, Message)]
pub struct UniversalClipboardClipTransferChunkMessage {
    #[prost(string, tag = "1")]
    pub transfer_id: String,
    #[prost(int32, tag = "2")]
    pub chunk_id: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub chunk_content: Vec<u8>,
}

/// `EncodedClipData.java`
#[derive(Clone, PartialEq, Message)]
pub struct EncodedClipData {
    #[prost(string, optional, tag = "1")]
    pub label: Option<String>,
    #[prost(bool, tag = "2")]
    pub is_sensitive: bool,
    #[prost(int64, tag = "3")]
    pub timestamp_ms: i64,
    #[prost(message, repeated, tag = "4")]
    pub items: Vec<EncodedClipDataItem>,
}

/// `EncodedClipDataItem.java`
#[derive(Clone, PartialEq, Message)]
pub struct EncodedClipDataItem {
    #[prost(string, optional, tag = "1")]
    pub text: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub html_text: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub uri: Option<String>,
}

/// `TaskStackBroadcastMessage.java`
#[derive(Clone, PartialEq, Message)]
pub struct TaskStackBroadcastMessage {
    #[prost(bool, tag = "1")]
    pub is_empty: bool,
    #[prost(message, repeated, tag = "2")]
    pub remote_tasks: Vec<RemoteTaskInfo>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RemoteTaskInfo {
    #[prost(int32, tag = "1")]
    pub task_id: i32,
    #[prost(string, optional, tag = "2")]
    pub label: Option<String>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub icon_png: Option<Vec<u8>>,
    #[prost(int64, tag = "4")]
    pub last_used_time_ms: i64,
}

/// `HandoffRequestMessage.java`
#[derive(Clone, PartialEq, Message)]
pub struct HandoffRequestMessage {
    #[prost(int32, tag = "1")]
    pub task_id: i32,
}

/// `HandoffRequestResultMessage.java`
#[derive(Clone, PartialEq, Message)]
pub struct HandoffRequestResultMessage {
    #[prost(int32, tag = "1")]
    pub status_code: i32,
    #[prost(int32, tag = "2")]
    pub task_id: i32,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub activities_raw: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Chunked Universal Clipboard Encoder & Reassembler
// ---------------------------------------------------------------------------

/// Encode a plain-text (or HTML/URI) clipboard update into the exact Android 17
/// `TaskContinuityMessage` sequence (`Start` + N `Chunk` messages).
pub fn encode_clipboard_transfer(
    device_id: &str,
    device_name: &str,
    clip: &EncodedClipData,
    max_chunk_size: usize,
) -> Vec<TaskContinuityMessage> {
    let encoded = clip.encode_to_vec();
    let chunk_size = max_chunk_size.max(1);
    let chunks: Vec<&[u8]> = if encoded.is_empty() {
        vec![&[]]
    } else {
        encoded.chunks(chunk_size).collect()
    };
    let transfer_id = Uuid::new_v4().to_string();

    let mut out = Vec::with_capacity(1 + chunks.len());
    out.push(TaskContinuityMessage {
        payload: Some(task_continuity_message::Payload::ClipboardTransferStart(
            UniversalClipboardClipTransferStartMessage {
                transfer_id: transfer_id.clone(),
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                expected_chunk_count: chunks.len() as i32,
            },
        )),
    });
    for (idx, chunk) in chunks.into_iter().enumerate() {
        out.push(TaskContinuityMessage {
            payload: Some(task_continuity_message::Payload::ClipboardTransferChunk(
                UniversalClipboardClipTransferChunkMessage {
                    transfer_id: transfer_id.clone(),
                    chunk_id: idx as i32,
                    chunk_content: chunk.to_vec(),
                },
            )),
        });
    }
    out
}

struct PendingClipTransfer {
    expected: usize,
    received: usize,
    chunks: Vec<Option<Vec<u8>>>,
}

/// Stateful reassembler mirroring Android's `ClipDataTransferManager`.
#[derive(Default)]
pub struct ClipboardTransferReassembler {
    pending: HashMap<String, PendingClipTransfer>,
}

impl ClipboardTransferReassembler {
    pub fn start_transfer(&mut self, msg: &UniversalClipboardClipTransferStartMessage) {
        let count = msg.expected_chunk_count.max(0) as usize;
        self.pending.insert(
            msg.transfer_id.clone(),
            PendingClipTransfer {
                expected: count,
                received: 0,
                chunks: vec![None; count],
            },
        );
    }

    pub fn push_chunk(
        &mut self,
        msg: &UniversalClipboardClipTransferChunkMessage,
    ) -> Result<Option<EncodedClipData>, ContinuityError> {
        let state = self
            .pending
            .get_mut(&msg.transfer_id)
            .ok_or_else(|| ContinuityError::UnknownTransfer(msg.transfer_id.clone()))?;
        let idx = msg.chunk_id as usize;
        if idx >= state.expected {
            return Err(ContinuityError::InvalidChunkIndex {
                chunk_id: idx,
                expected: state.expected,
            });
        }
        if state.chunks[idx].is_none() {
            state.received += 1;
        }
        state.chunks[idx] = Some(msg.chunk_content.clone());
        if state.received == state.expected {
            let done = self.pending.remove(&msg.transfer_id).unwrap();
            let mut full = Vec::new();
            for chunk in done.chunks.into_iter().flatten() {
                full.extend_from_slice(&chunk);
            }
            let clip = EncodedClipData::decode(full.as_slice())?;
            return Ok(Some(clip));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn universal_clipboard_chunked_roundtrip() {
        let clip = EncodedClipData {
            label: Some("macOS Clipboard".into()),
            is_sensitive: false,
            timestamp_ms: 1_760_000_000_000,
            items: vec![EncodedClipDataItem {
                text: Some("Copied from Mac to Pixel 9 Pro! ".repeat(20)),
                html_text: None,
                uri: Some("https://example.com".into()),
            }],
        };
        let msgs = encode_clipboard_transfer("mac-01", "MacBook Pro", &clip, 64);
        assert!(msgs.len() > 2);

        let mut reassembler = ClipboardTransferReassembler::default();
        let mut final_clip = None;
        for msg in msgs {
            let wire = msg.encode_to_vec();
            let decoded = TaskContinuityMessage::decode(wire.as_slice()).unwrap();
            match decoded.payload.unwrap() {
                task_continuity_message::Payload::ClipboardTransferStart(s) => {
                    reassembler.start_transfer(&s);
                }
                task_continuity_message::Payload::ClipboardTransferChunk(c) => {
                    if let Some(done) = reassembler.push_chunk(&c).unwrap() {
                        final_clip = Some(done);
                    }
                }
                _ => {}
            }
        }
        assert_eq!(final_clip.unwrap(), clip);
    }
}
