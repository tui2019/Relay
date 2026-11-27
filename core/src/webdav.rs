//! Loopback HTTP/1.1 API + RFC 4918 WebDAV server backed live by Android 17 `QuickAccessService`.
//!
//! Serves both:
//! - Fast JSON + binary read/write API (`/_api/health`, `/_api/stat`, `/_api/list`, `/_api/read`,
//!   `/_api/create`, `/_api/write`, `/_api/delete`, `/_api/rename`, `/_api/move`) for the native
//!   macOS `NSFileProviderReplicatedExtension` (`RelayFileProvider.appex` in Finder Locations)
//! - RFC 4918 WebDAV (`OPTIONS`, `PROPFIND`, `HEAD`, `GET`) as a standard fallback.

use crate::quickaccess::QuickAccessDocument;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

/// RPC requests forwarded from the HTTP/FileProvider server to the active `DeviceLink` session.
pub enum QuickAccessRpc {
    GetDocument {
        path: String,
        reply: oneshot::Sender<Result<QuickAccessDocument, String>>,
    },
    GetChildDocuments {
        path: String,
        reply: oneshot::Sender<Result<Vec<QuickAccessDocument>, String>>,
    },
    OpenDocument {
        path: String,
        reply: oneshot::Sender<Result<Vec<u8>, String>>,
    },
    CreateDocument {
        parent_path: String,
        display_name: String,
        mime_type: String,
        reply: oneshot::Sender<Result<QuickAccessDocument, String>>,
    },
    WriteDocument {
        path: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    DeleteDocument {
        path: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
    RenameDocument {
        path: String,
        new_name: String,
        reply: oneshot::Sender<Result<QuickAccessDocument, String>>,
    },
    MoveDocument {
        path: String,
        dest_parent_path: String,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

#[derive(Clone)]
struct CachedEntries<T> {
    fetched_at: Instant,
    value: T,
}

#[derive(Default)]
struct DavCache {
    docs: HashMap<String, CachedEntries<QuickAccessDocument>>,
    children: HashMap<String, CachedEntries<Vec<QuickAccessDocument>>>,
}

const CACHE_TTL: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct QuickAccessClient {
    tx: mpsc::Sender<QuickAccessRpc>,
    connected: Arc<AtomicBool>,
    cache: Arc<Mutex<DavCache>>,
}

impl QuickAccessClient {
    pub fn new(tx: mpsc::Sender<QuickAccessRpc>, connected: Arc<AtomicBool>) -> Self {
        Self {
            tx,
            connected,
            cache: Arc::new(Mutex::new(DavCache::default())),
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn invalidate_cache(&self) {
        let mut cache = self.cache.lock().await;
        cache.docs.clear();
        cache.children.clear();
    }

    pub async fn get_document(&self, path: &str) -> Result<QuickAccessDocument, String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        {
            let cache = self.cache.lock().await;
            if let Some(hit) = cache.docs.get(path) {
                if hit.fetched_at.elapsed() < CACHE_TTL {
                    return Ok(hit.value.clone());
                }
            }
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::GetDocument {
                path: path.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let doc = tokio::time::timeout(Duration::from_secs(6), rrx)
            .await
            .map_err(|_| "QuickAccess GetDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())??;
        let mut cache = self.cache.lock().await;
        cache.docs.insert(
            path.to_string(),
            CachedEntries {
                fetched_at: Instant::now(),
                value: doc.clone(),
            },
        );
        Ok(doc)
    }

    pub async fn get_child_documents(&self, path: &str) -> Result<Vec<QuickAccessDocument>, String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        {
            let cache = self.cache.lock().await;
            if let Some(hit) = cache.children.get(path) {
                if hit.fetched_at.elapsed() < CACHE_TTL {
                    return Ok(hit.value.clone());
                }
            }
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::GetChildDocuments {
                path: path.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let list = tokio::time::timeout(Duration::from_secs(8), rrx)
            .await
            .map_err(|_| "QuickAccess GetChildDocuments timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())??;
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        for d in &list {
            if let Some(id) = &d.document_id {
                cache.docs.insert(
                    normalize_qa_path(id),
                    CachedEntries {
                        fetched_at: now,
                        value: d.clone(),
                    },
                );
            }
        }
        cache.children.insert(
            path.to_string(),
            CachedEntries {
                fetched_at: now,
                value: list.clone(),
            },
        );
        Ok(list)
    }

    pub async fn open_document(&self, path: &str) -> Result<Vec<u8>, String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::OpenDocument {
                path: path.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        tokio::time::timeout(Duration::from_secs(60), rrx)
            .await
            .map_err(|_| "QuickAccess OpenDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())?
    }

    pub async fn create_document(
        &self,
        parent_path: &str,
        display_name: &str,
        mime_type: &str,
    ) -> Result<QuickAccessDocument, String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::CreateDocument {
                parent_path: parent_path.to_string(),
                display_name: display_name.to_string(),
                mime_type: mime_type.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let res = tokio::time::timeout(Duration::from_secs(10), rrx)
            .await
            .map_err(|_| "QuickAccess CreateDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())?;
        if res.is_ok() {
            self.invalidate_cache().await;
        }
        res
    }

    pub async fn write_document(&self, path: &str, data: Vec<u8>) -> Result<(), String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::WriteDocument {
                path: path.to_string(),
                data,
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let res = tokio::time::timeout(Duration::from_secs(60), rrx)
            .await
            .map_err(|_| "QuickAccess WriteDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())?;
        if res.is_ok() {
            self.invalidate_cache().await;
        }
        res
    }

    pub async fn delete_document(&self, path: &str) -> Result<(), String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::DeleteDocument {
                path: path.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let res = tokio::time::timeout(Duration::from_secs(10), rrx)
            .await
            .map_err(|_| "QuickAccess DeleteDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())?;
        if res.is_ok() {
            self.invalidate_cache().await;
        }
        res
    }

    pub async fn rename_document(
        &self,
        path: &str,
        new_name: &str,
    ) -> Result<QuickAccessDocument, String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::RenameDocument {
                path: path.to_string(),
                new_name: new_name.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let res = tokio::time::timeout(Duration::from_secs(10), rrx)
            .await
            .map_err(|_| "QuickAccess RenameDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())?;
        if res.is_ok() {
            self.invalidate_cache().await;
        }
        res
    }

    pub async fn move_document(&self, path: &str, dest_parent_path: &str) -> Result<(), String> {
        if !self.is_connected() {
            return Err("DeviceLink not connected".to_string());
        }
        let (rtx, rrx) = oneshot::channel();
        self.tx
            .send(QuickAccessRpc::MoveDocument {
                path: path.to_string(),
                dest_parent_path: dest_parent_path.to_string(),
                reply: rtx,
            })
            .await
            .map_err(|_| "DeviceLink not connected".to_string())?;
        let res = tokio::time::timeout(Duration::from_secs(10), rrx)
            .await
            .map_err(|_| "QuickAccess MoveDocument timeout".to_string())?
            .map_err(|_| "DeviceLink closed".to_string())?;
        if res.is_ok() {
            self.invalidate_cache().await;
        }
        res
    }
}

/// Bind and serve the loopback FileProvider API + WebDAV server until cancelled.
pub async fn serve_webdav(port: u16, client: QuickAccessClient) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("WebDAV bind 127.0.0.1:{port} failed: {e}"))?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("WebDAV accept error: {e}"))?;
        let c = client.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, c).await;
        });
    }
}

async fn handle_connection(stream: TcpStream, client: QuickAccessClient) -> Result<(), String> {
    let mut reader = BufReader::new(stream);
    loop {
        let mut req_line = String::new();
        let n = reader
            .read_line(&mut req_line)
            .await
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        let req_line = req_line.trim_end_matches(&['\r', '\n'][..]);
        if req_line.is_empty() {
            continue;
        }
        let mut parts = req_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let raw_target = parts.next().unwrap_or("/");

        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut hline = String::new();
            let hn = reader
                .read_line(&mut hline)
                .await
                .map_err(|e| e.to_string())?;
            if hn == 0 {
                break;
            }
            let hline = hline.trim_end_matches(&['\r', '\n'][..]);
            if hline.is_empty() {
                break;
            }
            if let Some((k, v)) = hline.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let (target_path, query_str) = raw_target
            .split_once('?')
            .map(|(p, q)| (p, Some(q)))
            .unwrap_or((raw_target, None));

        let mut req_body = Vec::new();
        if let Some(cl) = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
        {
            let max_body = if target_path == "/_api/write" {
                128 * 1024 * 1024
            } else {
                2 * 1024 * 1024
            };
            if cl > 0 && cl <= max_body {
                req_body = vec![0u8; cl];
                reader
                    .read_exact(&mut req_body)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }

        let keep_alive = headers
            .get("connection")
            .map(|c| !c.eq_ignore_ascii_case("close"))
            .unwrap_or(true);
        let conn_hdr = if keep_alive { "keep-alive" } else { "close" };
        let stream = reader.get_mut();

        // Fast JSON/binary read+write API endpoints for native macOS FileProvider extension
        if target_path.starts_with("/_api/") {
            let qa_path = query_str
                .and_then(|q| extract_query_param(q, "path"))
                .map(|p| normalize_qa_path(&percent_decode(&p)))
                .unwrap_or_else(|| "/".to_string());

            match (method, target_path) {
                ("GET", "/_api/health") => {
                    let body = serde_json::json!({
                        "connected": client.is_connected()
                    })
                    .to_string();
                    write_json(stream, "200 OK", &body, conn_hdr).await?;
                }
                ("GET", "/_api/stat") => match client.get_document(&qa_path).await {
                    Ok(doc) => {
                        let body = serde_json::to_string(&doc).unwrap_or_else(|_| "{}".into());
                        write_json(stream, "200 OK", &body, conn_hdr).await?;
                    }
                    Err(e) if e.contains("not connected") || e.contains("timeout") => {
                        write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                    }
                    Err(_) => {
                        write_simple(stream, "404 Not Found", conn_hdr).await?;
                    }
                },
                ("GET", "/_api/list") => match client.get_child_documents(&qa_path).await {
                    Ok(list) => {
                        let body = serde_json::to_string(&list).unwrap_or_else(|_| "[]".into());
                        write_json(stream, "200 OK", &body, conn_hdr).await?;
                    }
                    Err(e) if e.contains("not connected") || e.contains("timeout") => {
                        write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                    }
                    Err(_) => {
                        write_simple(stream, "404 Not Found", conn_hdr).await?;
                    }
                },
                ("GET", "/_api/read") => match client.open_document(&qa_path).await {
                    Ok(bytes) => {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/octet-stream\r\n\
                             Content-Length: {}\r\n\
                             Connection: {conn_hdr}\r\n\r\n",
                            bytes.len()
                        );
                        stream
                            .write_all(resp.as_bytes())
                            .await
                            .map_err(|e| e.to_string())?;
                        stream
                            .write_all(&bytes)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    Err(e) if e.contains("not connected") || e.contains("timeout") => {
                        write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                    }
                    Err(_) => {
                        write_simple(stream, "404 Not Found", conn_hdr).await?;
                    }
                },
                ("POST", "/_api/create") => {
                    let parent = query_str
                        .and_then(|q| extract_query_param(q, "parent"))
                        .map(|p| normalize_qa_path(&percent_decode(&p)))
                        .unwrap_or_else(|| "/".to_string());
                    let name = query_str
                        .and_then(|q| extract_query_param(q, "name"))
                        .map(|n| percent_decode(&n))
                        .unwrap_or_default();
                    let mime = query_str
                        .and_then(|q| extract_query_param(q, "mime"))
                        .map(|m| percent_decode(&m))
                        .unwrap_or_else(|| "application/octet-stream".to_string());
                    if name.is_empty() {
                        write_simple(stream, "400 Bad Request", conn_hdr).await?;
                    } else {
                        match client.create_document(&parent, &name, &mime).await {
                            Ok(doc) => {
                                let body =
                                    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".into());
                                write_json(stream, "200 OK", &body, conn_hdr).await?;
                            }
                            Err(e) if e.contains("not connected") || e.contains("timeout") => {
                                write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                            }
                            Err(e) => {
                                let body = serde_json::json!({ "error": e }).to_string();
                                write_json(stream, "500 Internal Server Error", &body, conn_hdr)
                                    .await?;
                            }
                        }
                    }
                }
                ("PUT", "/_api/write") | ("POST", "/_api/write") => {
                    match client.write_document(&qa_path, req_body).await {
                        Ok(()) => {
                            write_json(stream, "200 OK", r#"{"ok":true}"#, conn_hdr).await?;
                        }
                        Err(e) if e.contains("not connected") || e.contains("timeout") => {
                            write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                        }
                        Err(e) => {
                            let body = serde_json::json!({ "error": e }).to_string();
                            write_json(stream, "500 Internal Server Error", &body, conn_hdr)
                                .await?;
                        }
                    }
                }
                ("POST", "/_api/delete") | ("DELETE", "/_api/delete") => {
                    match client.delete_document(&qa_path).await {
                        Ok(()) => {
                            write_json(stream, "200 OK", r#"{"ok":true}"#, conn_hdr).await?;
                        }
                        Err(e) if e.contains("not connected") || e.contains("timeout") => {
                            write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                        }
                        Err(e) => {
                            let body = serde_json::json!({ "error": e }).to_string();
                            write_json(stream, "500 Internal Server Error", &body, conn_hdr)
                                .await?;
                        }
                    }
                }
                ("POST", "/_api/rename") => {
                    let new_name = query_str
                        .and_then(|q| extract_query_param(q, "name"))
                        .map(|n| percent_decode(&n))
                        .unwrap_or_default();
                    if new_name.is_empty() {
                        write_simple(stream, "400 Bad Request", conn_hdr).await?;
                    } else {
                        match client.rename_document(&qa_path, &new_name).await {
                            Ok(doc) => {
                                let body =
                                    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".into());
                                write_json(stream, "200 OK", &body, conn_hdr).await?;
                            }
                            Err(e) if e.contains("not connected") || e.contains("timeout") => {
                                write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                            }
                            Err(e) => {
                                let body = serde_json::json!({ "error": e }).to_string();
                                write_json(stream, "500 Internal Server Error", &body, conn_hdr)
                                    .await?;
                            }
                        }
                    }
                }
                ("POST", "/_api/move") => {
                    let dest = query_str
                        .and_then(|q| extract_query_param(q, "dest"))
                        .map(|d| normalize_qa_path(&percent_decode(&d)))
                        .unwrap_or_else(|| "/".to_string());
                    match client.move_document(&qa_path, &dest).await {
                        Ok(()) => {
                            write_json(stream, "200 OK", r#"{"ok":true}"#, conn_hdr).await?;
                        }
                        Err(e) if e.contains("not connected") || e.contains("timeout") => {
                            write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                        }
                        Err(e) => {
                            let body = serde_json::json!({ "error": e }).to_string();
                            write_json(stream, "500 Internal Server Error", &body, conn_hdr)
                                .await?;
                        }
                    }
                }
                _ => {
                    write_simple(stream, "404 Not Found", conn_hdr).await?;
                }
            }
            stream.flush().await.map_err(|e| e.to_string())?;
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        // WebDAV endpoints
        let decoded = percent_decode(target_path);
        let qa_path = normalize_qa_path(&decoded);

        match method {
            "OPTIONS" => {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     DAV: 1, 2\r\n\
                     MS-Author-Via: DAV\r\n\
                     Allow: OPTIONS, GET, HEAD, PROPFIND\r\n\
                     Content-Length: 0\r\n\
                     Connection: {conn_hdr}\r\n\r\n"
                );
                stream
                    .write_all(resp.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "PROPFIND" => {
                if is_macos_ignored_path(&qa_path) {
                    write_simple(stream, "404 Not Found", conn_hdr).await?;
                } else {
                    let depth = headers.get("depth").map(|s| s.as_str()).unwrap_or("1");
                    match client.get_document(&qa_path).await {
                        Ok(doc) => {
                            let mut entries = Vec::new();
                            entries.push((qa_path.clone(), doc.clone()));
                            if depth != "0" && doc.is_directory() {
                                if let Ok(children) = client.get_child_documents(&qa_path).await {
                                    for ch in children {
                                        let cpath = ch
                                            .document_id
                                            .as_deref()
                                            .map(normalize_qa_path)
                                            .unwrap_or_else(|| {
                                                let name = ch.display_name.as_deref().unwrap_or("");
                                                if qa_path == "/" {
                                                    format!("/{name}")
                                                } else {
                                                    format!("{qa_path}/{name}")
                                                }
                                            });
                                        entries.push((cpath, ch));
                                    }
                                }
                            }
                            let xml = render_multistatus(&entries);
                            let resp = format!(
                                "HTTP/1.1 207 Multi-Status\r\n\
                                 Content-Type: application/xml; charset=\"utf-8\"\r\n\
                                 Content-Length: {}\r\n\
                                 Connection: {conn_hdr}\r\n\r\n",
                                xml.len()
                            );
                            stream
                                .write_all(resp.as_bytes())
                                .await
                                .map_err(|e| e.to_string())?;
                            stream
                                .write_all(xml.as_bytes())
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        Err(e) if e.contains("not connected") || e.contains("timeout") => {
                            write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                        }
                        Err(_) => {
                            write_simple(stream, "404 Not Found", conn_hdr).await?;
                        }
                    }
                }
            }
            "HEAD" => {
                if is_macos_ignored_path(&qa_path) {
                    write_simple(stream, "404 Not Found", conn_hdr).await?;
                } else {
                    match client.get_document(&qa_path).await {
                        Ok(doc) => {
                            let size = doc.size.unwrap_or(0);
                            let mime = doc
                                .mime_type
                                .as_deref()
                                .filter(|m| !m.is_empty() && !doc.is_directory())
                                .unwrap_or("application/octet-stream");
                            let last_mod = format_http_date(doc.last_modified_ms.unwrap_or(0));
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\n\
                                 Content-Type: {mime}\r\n\
                                 Content-Length: {size}\r\n\
                                 Last-Modified: {last_mod}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Connection: {conn_hdr}\r\n\r\n"
                            );
                            stream
                                .write_all(resp.as_bytes())
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        Err(e) if e.contains("not connected") || e.contains("timeout") => {
                            write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                        }
                        Err(_) => {
                            write_simple(stream, "404 Not Found", conn_hdr).await?;
                        }
                    }
                }
            }
            "GET" => {
                if is_macos_ignored_path(&qa_path) {
                    write_simple(stream, "404 Not Found", conn_hdr).await?;
                } else if qa_path == "/" {
                    let body = b"Relay QuickAccess\n";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain; charset=utf-8\r\n\
                         Content-Length: {}\r\n\
                         Connection: {conn_hdr}\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(resp.as_bytes())
                        .await
                        .map_err(|e| e.to_string())?;
                    stream.write_all(body).await.map_err(|e| e.to_string())?;
                } else {
                    let mime = client
                        .get_document(&qa_path)
                        .await
                        .ok()
                        .and_then(|d| d.mime_type)
                        .filter(|m| !m.is_empty() && m != "vnd.android.document/directory")
                        .unwrap_or_else(|| "application/octet-stream".to_string());
                    match client.open_document(&qa_path).await {
                        Ok(bytes) => {
                            if let Some((start, end)) = headers
                                .get("range")
                                .and_then(|r| parse_byte_range(r, bytes.len()))
                            {
                                let slice = &bytes[start..=end];
                                let resp = format!(
                                    "HTTP/1.1 206 Partial Content\r\n\
                                     Content-Type: {mime}\r\n\
                                     Content-Range: bytes {start}-{end}/{}\r\n\
                                     Content-Length: {}\r\n\
                                     Accept-Ranges: bytes\r\n\
                                     Connection: {conn_hdr}\r\n\r\n",
                                    bytes.len(),
                                    slice.len()
                                );
                                stream
                                    .write_all(resp.as_bytes())
                                    .await
                                    .map_err(|e| e.to_string())?;
                                stream.write_all(slice).await.map_err(|e| e.to_string())?;
                            } else {
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: {mime}\r\n\
                                     Content-Length: {}\r\n\
                                     Accept-Ranges: bytes\r\n\
                                     Connection: {conn_hdr}\r\n\r\n",
                                    bytes.len()
                                );
                                stream
                                    .write_all(resp.as_bytes())
                                    .await
                                    .map_err(|e| e.to_string())?;
                                stream.write_all(&bytes).await.map_err(|e| e.to_string())?;
                            }
                        }
                        Err(e) if e.contains("not connected") || e.contains("timeout") => {
                            write_simple(stream, "503 Service Unavailable", conn_hdr).await?;
                        }
                        Err(_) => {
                            write_simple(stream, "404 Not Found", conn_hdr).await?;
                        }
                    }
                }
            }
            _ => {
                write_simple(stream, "405 Method Not Allowed", conn_hdr).await?;
            }
        }

        stream.flush().await.map_err(|e| e.to_string())?;
        if !keep_alive {
            return Ok(());
        }
    }
}

async fn write_simple(stream: &mut TcpStream, status: &str, conn_hdr: &str) -> Result<(), String> {
    let resp =
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: {conn_hdr}\r\n\r\n");
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

async fn write_json(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
    conn_hdr: &str,
) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: {conn_hdr}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(body.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

fn extract_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

pub fn normalize_qa_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let without_trailing = trimmed.trim_end_matches('/');
    if without_trailing.is_empty() {
        "/".to_string()
    } else if without_trailing.starts_with('/') {
        without_trailing.to_string()
    } else {
        format!("/{without_trailing}")
    }
}

fn is_macos_ignored_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    matches!(
        name,
        ".DS_Store"
            | ".Spotlight-V100"
            | ".Trashes"
            | ".fseventsd"
            | ".TemporaryItems"
            | ".ql_disablethumbnails"
            | ".metadata_never_index"
            | "Backups.backupdb"
            | "mach_kernel"
    ) || name.starts_with("._")
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for &b in path.as_bytes() {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn render_multistatus(entries: &[(String, QuickAccessDocument)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
    );
    for (path, doc) in entries {
        let is_dir = doc.is_directory() || path == "/";
        let mut href = percent_encode_path(path);
        if is_dir && !href.ends_with('/') {
            href.push('/');
        }
        let display = if path == "/" {
            "Android Phone".to_string()
        } else {
            doc.display_name
                .clone()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| path.rsplit('/').next().unwrap_or("").to_string())
        };
        let last_mod = format_http_date(doc.last_modified_ms.unwrap_or(0));
        xml.push_str("  <D:response>\n");
        xml.push_str(&format!("    <D:href>{}</D:href>\n", xml_escape(&href)));
        xml.push_str("    <D:propstat>\n      <D:prop>\n");
        xml.push_str(&format!(
            "        <D:displayname>{}</D:displayname>\n",
            xml_escape(&display)
        ));
        xml.push_str(&format!(
            "        <D:getlastmodified>{}</D:getlastmodified>\n",
            last_mod
        ));
        if is_dir {
            xml.push_str("        <D:resourcetype><D:collection/></D:resourcetype>\n");
        } else {
            let size = doc.size.unwrap_or(0);
            let mime = doc
                .mime_type
                .as_deref()
                .filter(|m| !m.is_empty())
                .unwrap_or("application/octet-stream");
            xml.push_str("        <D:resourcetype/>\n");
            xml.push_str(&format!(
                "        <D:getcontentlength>{size}</D:getcontentlength>\n"
            ));
            xml.push_str(&format!(
                "        <D:getcontenttype>{}</D:getcontenttype>\n",
                xml_escape(mime)
            ));
        }
        xml.push_str(
            "      </D:prop>\n      <D:status>HTTP/1.1 200 OK</D:status>\n    </D:propstat>\n  </D:response>\n",
        );
    }
    xml.push_str("</D:multistatus>\n");
    xml
}

fn parse_byte_range(header: &str, total: usize) -> Option<(usize, usize)> {
    if total == 0 {
        return None;
    }
    let spec = header.strip_prefix("bytes=")?;
    let first = spec.split(',').next()?.trim();
    let (s, e) = first.split_once('-')?;
    if s.is_empty() {
        let suffix: usize = e.parse().ok()?;
        let start = total.saturating_sub(suffix);
        return Some((start, total - 1));
    }
    let start: usize = s.parse().ok()?;
    if start >= total {
        return None;
    }
    let end = if e.is_empty() {
        total - 1
    } else {
        e.parse::<usize>().ok()?.min(total - 1)
    };
    if start <= end {
        Some((start, end))
    } else {
        None
    }
}

pub fn format_http_date(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let dow = ((days + 4).rem_euclid(7)) as usize;
    let dow_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as usize;
    let year = y + if month <= 2 { 1 } else { 0 };
    let mon_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        dow_names[dow],
        day,
        mon_names[month - 1],
        year,
        hour,
        min,
        sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webdav_path_and_date_formatting() {
        assert_eq!(normalize_qa_path("/DCIM/Camera/"), "/DCIM/Camera");
        assert_eq!(normalize_qa_path("/"), "/");
        assert_eq!(percent_decode("/My%20File%20%281%29.jpg"), "/My File (1).jpg");
        assert_eq!(percent_encode_path("/My File.jpg"), "/My%20File.jpg");
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(parse_byte_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_byte_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(
            extract_query_param("path=%2FDCIM&x=1", "path"),
            Some("%2FDCIM".to_string())
        );
    }

    #[test]
    fn webdav_multistatus_xml_generation() {
        let doc = QuickAccessDocument {
            document_id: Some("/DCIM".into()),
            display_name: Some("DCIM".into()),
            mime_type: Some("vnd.android.document/directory".into()),
            size: None,
            flags: Some(136),
            last_modified_ms: Some(1_700_000_000_000),
            summary: None,
        };
        let xml = render_multistatus(&[("/DCIM".into(), doc)]);
        assert!(xml.contains("<D:href>/DCIM/</D:href>"));
        assert!(xml.contains("<D:collection/>"));
    }
}
