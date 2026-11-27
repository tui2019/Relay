//! Android 17 `QuickAccessService` (`com.google.ambient.streaming`, `mfc.java`)
//! remote `/sdcard` read/write filesystem RPC protobufs over `DeviceLink`.
//!
//! Verified directly from Pixel 9 Pro `base.apk`:
//! - Read: `GetDocument` (`mho`/`mhp`), `GetChildDocuments` (`mhn`/`mhj`), `OpenDocument` (`mhy`/`mia`/`mhk`)
//! - Write: `CreateDocument` (`mhd`/`mhe`), `WriteDocument` (`mja`/`miz`/`mhk`/`miy`/`mjc`),
//!   `DeleteDocument` (`mhg`/`mhh`), `RenameDocument` (`miu`/`miv`), `MoveDocument` (`mht`/`mhu`)
//! Requires ZERO hardware attestation.

use prost::Message;
use serde::{Deserialize, Serialize};

pub const MIME_DIRECTORY: &str = "vnd.android.document/directory";

/// Path-based request used by `GetDocument` (`mho`), `GetChildDocuments` (`mhn`),
/// `OpenDocument` (`mhy`), and `DeleteDocument` (`mhg`) — all share `string path = 1`.
#[derive(Clone, PartialEq, Message)]
pub struct QuickAccessPathRequest {
    #[prost(string, optional, tag = "1")]
    pub path: Option<String>,
}

/// `mhj.java`: Document metadata entry for a file or directory under `/sdcard`.
#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct QuickAccessDocument {
    #[prost(string, optional, tag = "1")]
    pub document_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub display_name: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub mime_type: Option<String>,
    #[prost(uint64, optional, tag = "4")]
    pub size: Option<u64>,
    #[prost(int32, optional, tag = "5")]
    pub flags: Option<i32>,
    #[prost(uint64, optional, tag = "7")]
    pub last_modified_ms: Option<u64>,
    #[prost(string, optional, tag = "8")]
    pub summary: Option<String>,
}

impl QuickAccessDocument {
    pub fn is_directory(&self) -> bool {
        self.mime_type.as_deref() == Some(MIME_DIRECTORY)
    }
}

/// `mhp.java`: `GetDocument` response (`oneof { 1=not_found, 2=document }`).
#[derive(Clone, PartialEq, Message)]
pub struct GetDocumentResponse {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub error: Option<Vec<u8>>,
    #[prost(message, optional, tag = "2")]
    pub document: Option<QuickAccessDocument>,
}

/// `mhk.java`: Inner bytes payload of an `OpenDocument` / `WriteDocument` chunk (`tag 1 = bytes`).
#[derive(Clone, PartialEq, Message)]
pub struct OpenDocumentChunkData {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data: Option<Vec<u8>>,
}

/// `mia.java` / `mhz.java`: `OpenDocument` streamed chunk (`1 = METADATA (mhx)`, `2 = CHUNK (mhk)`).
#[derive(Clone, PartialEq, Message)]
pub struct OpenDocumentChunk {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub metadata: Option<Vec<u8>>,
    #[prost(message, optional, tag = "2")]
    pub chunk: Option<OpenDocumentChunkData>,
}

/// `mhd.java`: `CreateDocument` request (`1=parent_path`, `2=display_name`, `3=mime_type`).
#[derive(Clone, PartialEq, Message)]
pub struct CreateDocumentRequest {
    #[prost(string, optional, tag = "1")]
    pub parent_path: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub display_name: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub mime_type: Option<String>,
}

/// `mhe.java` / `miv.java`: `CreateDocument` and `RenameDocument` response (`1=success`, `2=document`).
#[derive(Clone, PartialEq, Message)]
pub struct DocumentMutationResponse {
    #[prost(bool, optional, tag = "1")]
    pub success: Option<bool>,
    #[prost(message, optional, tag = "2")]
    pub document: Option<QuickAccessDocument>,
}

/// `mhh.java` / `mhu.java` / `mjc.java`: Simple boolean response for `DeleteDocument`,
/// `MoveDocument`, and `WriteDocument` (`1=success`).
#[derive(Clone, PartialEq, Message)]
pub struct SimpleBoolResponse {
    #[prost(bool, optional, tag = "1")]
    pub success: Option<bool>,
}

/// `miu.java`: `RenameDocument` request (`1=path`, `2=new_display_name`).
#[derive(Clone, PartialEq, Message)]
pub struct RenameDocumentRequest {
    #[prost(string, optional, tag = "1")]
    pub path: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub new_display_name: Option<String>,
}

/// `mht.java`: `MoveDocument` request (`1=source_path`, `2=destination_parent_path`).
#[derive(Clone, PartialEq, Message)]
pub struct MoveDocumentRequest {
    #[prost(string, optional, tag = "1")]
    pub path: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub destination_parent_path: Option<String>,
}

/// `miz.java`: `WriteDocument` initial path metadata (`1=path`).
#[derive(Clone, PartialEq, Message)]
pub struct WriteDocumentPath {
    #[prost(string, optional, tag = "1")]
    pub path: Option<String>,
}

/// `miy.java`: `WriteDocument` final size verification (`1=total_size`).
#[derive(Clone, PartialEq, Message)]
pub struct WriteDocumentSize {
    #[prost(uint64, optional, tag = "1")]
    pub total_size: Option<u64>,
}

/// `mja.java`: `WriteDocument` client-stream packet (`oneof { 1=miz, 2=mhk, 3=miy }`).
#[derive(Clone, PartialEq, Message)]
pub struct WriteDocumentMessage {
    #[prost(oneof = "write_document_message::Part", tags = "1, 2, 3")]
    pub part: Option<write_document_message::Part>,
}

pub mod write_document_message {
    use super::*;
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Part {
        #[prost(message, tag = "1")]
        Path(WriteDocumentPath),
        #[prost(message, tag = "2")]
        Chunk(OpenDocumentChunkData),
        #[prost(message, tag = "3")]
        TotalSize(WriteDocumentSize),
    }
}

pub fn build_path_request(path: &str) -> Vec<u8> {
    QuickAccessPathRequest {
        path: Some(path.to_string()),
    }
    .encode_to_vec()
}

pub fn build_create_request(parent_path: &str, display_name: &str, mime_type: &str) -> Vec<u8> {
    CreateDocumentRequest {
        parent_path: Some(parent_path.to_string()),
        display_name: Some(display_name.to_string()),
        mime_type: Some(mime_type.to_string()),
    }
    .encode_to_vec()
}

pub fn build_rename_request(path: &str, new_name: &str) -> Vec<u8> {
    RenameDocumentRequest {
        path: Some(path.to_string()),
        new_display_name: Some(new_name.to_string()),
    }
    .encode_to_vec()
}

pub fn build_move_request(path: &str, dest_parent_path: &str) -> Vec<u8> {
    MoveDocumentRequest {
        path: Some(path.to_string()),
        destination_parent_path: Some(dest_parent_path.to_string()),
    }
    .encode_to_vec()
}

/// Build the sequence of `mja` client-stream messages for `WriteDocument`:
/// 1) `miz(path)`, 2) 3072-byte `mhk(chunk)` items, 3) `miy(total_size)`.
pub fn build_write_stream_messages(path: &str, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    out.push(
        WriteDocumentMessage {
            part: Some(write_document_message::Part::Path(WriteDocumentPath {
                path: Some(path.to_string()),
            })),
        }
        .encode_to_vec(),
    );
    for chunk in bytes.chunks(3072) {
        out.push(
            WriteDocumentMessage {
                part: Some(write_document_message::Part::Chunk(OpenDocumentChunkData {
                    data: Some(chunk.to_vec()),
                })),
            }
            .encode_to_vec(),
        );
    }
    out.push(
        WriteDocumentMessage {
            part: Some(write_document_message::Part::TotalSize(WriteDocumentSize {
                total_size: Some(bytes.len() as u64),
            })),
        }
        .encode_to_vec(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_document_stream_roundtrip() {
        let msgs = build_write_stream_messages("/Download/test.txt", b"hello pixel");
        assert_eq!(msgs.len(), 3);
        let m0 = WriteDocumentMessage::decode(msgs[0].as_slice()).unwrap();
        let m1 = WriteDocumentMessage::decode(msgs[1].as_slice()).unwrap();
        let m2 = WriteDocumentMessage::decode(msgs[2].as_slice()).unwrap();
        assert_eq!(
            m0.part,
            Some(write_document_message::Part::Path(WriteDocumentPath {
                path: Some("/Download/test.txt".into())
            }))
        );
        assert_eq!(
            m1.part,
            Some(write_document_message::Part::Chunk(OpenDocumentChunkData {
                data: Some(b"hello pixel".to_vec())
            }))
        );
        assert_eq!(
            m2.part,
            Some(write_document_message::Part::TotalSize(WriteDocumentSize {
                total_size: Some(11)
            }))
        );
    }
}
