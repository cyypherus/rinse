use reticulum::destination::link::{Link, LinkEvent};
use reticulum::destination::{DestinationDesc, DestinationName, SingleOutputDestination};
use reticulum::hash::AddressHash;
use reticulum::packet::PacketContext;
use reticulum::resource::{ResourceHandleResult, ResourceManager};
use reticulum::transport::Transport;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, Mutex};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub enum PageRequestResult {
    Success { url: String, content: String },
    Failed { url: String, reason: String },
    TimedOut { url: String },
}

struct PendingRequest {
    url: String,
    resource_manager: ResourceManager,
}

pub fn node_aspect_name() -> DestinationName {
    DestinationName::new("nomadnetwork", "node")
}

pub fn is_node_announce(dest: &SingleOutputDestination) -> bool {
    let expected = node_aspect_name();
    dest.desc.name.as_name_hash_slice() == expected.as_name_hash_slice()
}

pub struct NodeClient {
    transport: Arc<Transport>,
    known_nodes: Arc<Mutex<HashMap<[u8; 16], DestinationDesc>>>,
    pending: Arc<Mutex<HashMap<AddressHash, PendingRequest>>>,
    result_tx: mpsc::Sender<PageRequestResult>,
}

impl NodeClient {
    pub fn new(
        transport: Arc<Transport>,
        result_tx: mpsc::Sender<PageRequestResult>,
    ) -> Self {
        Self {
            transport,
            known_nodes: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            result_tx,
        }
    }

    pub async fn register_node(&self, node_dest: &SingleOutputDestination) {
        let mut node_hash_bytes = [0u8; 16];
        node_hash_bytes.copy_from_slice(node_dest.desc.address_hash.as_slice());

        log::debug!("Registered node: {}", hex::encode(node_hash_bytes),);

        self.known_nodes
            .lock()
            .await
            .insert(node_hash_bytes, node_dest.desc);
    }

    pub async fn register_saved_node(
        &self,
        hash: [u8; 16],
        public_key: [u8; 32],
        verifying_key: [u8; 32],
    ) {
        use reticulum::destination::{DestinationDesc, DestinationName};
        use reticulum::hash::AddressHash;
        use reticulum::identity::Identity;

        let identity = Identity::new_from_slices(&public_key, &verifying_key);
        let address_hash = AddressHash::from_bytes(&hash);
        let name = DestinationName::new("nomadnetwork", "node");

        let desc = DestinationDesc {
            identity,
            address_hash,
            name,
        };

        log::debug!("Registered saved node: {}", hex::encode(hash));

        self.known_nodes.lock().await.insert(hash, desc);
    }

    pub async fn request_page(&self, node_hash: [u8; 16], path: String) -> Result<(), String> {
        let node_desc = {
            let nodes = self.known_nodes.lock().await;
            nodes.get(&node_hash).cloned()
        };

        let node_desc = match node_desc {
            Some(d) => d,
            None => return Err("Unknown node - no announce received".to_string()),
        };

        let url = format!("{}:{}", hex::encode(node_hash), path);

        let mut link_events = self.transport.out_link_events();
        let link = self.transport.link(node_desc).await;
        let link_id = *link.lock().await.id();

        log::debug!("NodeClient: link {} created, subscribed to events", link_id);

        self.pending.lock().await.insert(
            link_id,
            PendingRequest {
                url: url.clone(),
                resource_manager: ResourceManager::new(),
            },
        );

        let pending = self.pending.clone();
        let transport = self.transport.clone();
        let result_tx = self.result_tx.clone();

        tokio::spawn(async move {
            let timeout = tokio::time::sleep(REQUEST_TIMEOUT);
            tokio::pin!(timeout);

            loop {
                tokio::select! {
                    _ = &mut timeout => {
                        let mut pending = pending.lock().await;
                        if let Some(req) = pending.remove(&link_id) {
                            let _ = result_tx.send(PageRequestResult::TimedOut { url: req.url }).await;
                        }
                        break;
                    }
                    result = link_events.recv() => {
                        match result {
                            Ok(event_data) if event_data.id == link_id => {
                                log::debug!("NodeClient: received event for link {}", link_id);
                                match event_data.event {
                                    LinkEvent::Activated => {
                                        log::info!("NodeClient: link {} activated, sending page request", link_id);
                                        if let Err(e) = send_page_request(&transport, &link, &path).await {
                                            let mut pending = pending.lock().await;
                                            if let Some(req) = pending.remove(&link_id) {
                                                let _ = result_tx.send(PageRequestResult::Failed {
                                                    url: req.url,
                                                    reason: e,
                                                }).await;
                                            }
                                            break;
                                        }
                                    }
                                    LinkEvent::Data(payload) => {
                                        let mut pending_guard = pending.lock().await;
                                        if let Some(req) = pending_guard.remove(&link_id) {
                                            match parse_page_response(payload.as_slice()) {
                                                Ok(content) => {
                                                    let _ = result_tx.send(PageRequestResult::Success {
                                                        url: req.url,
                                                        content,
                                                    }).await;
                                                }
                                                Err(e) => {
                                                    let _ = result_tx.send(PageRequestResult::Failed {
                                                        url: req.url,
                                                        reason: e,
                                                    }).await;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    LinkEvent::ResourcePacket { context, data } => {
                                        log::debug!("NodeClient: resource packet {:?} {}B", context, data.len());
                                        let result = handle_resource_packet(
                                            &pending,
                                            &link_id,
                                            context,
                                            &data,
                                            &link,
                                            &transport,
                                        ).await;

                                        if let Some(page_data) = result {
                                            let mut pending_guard = pending.lock().await;
                                            if let Some(req) = pending_guard.remove(&link_id) {
                                                match parse_resource_content(&page_data) {
                                                    Ok(content) => {
                                                        let _ = result_tx.send(PageRequestResult::Success {
                                                            url: req.url,
                                                            content,
                                                        }).await;
                                                    }
                                                    Err(e) => {
                                                        let _ = result_tx.send(PageRequestResult::Failed {
                                                            url: req.url,
                                                            reason: e,
                                                        }).await;
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    }
                                    LinkEvent::Response { request_id: _, data } => {
                                        log::debug!("NodeClient: direct response {}B", data.len());
                                        let mut pending_guard = pending.lock().await;
                                        if let Some(req) = pending_guard.remove(&link_id) {
                                            match String::from_utf8(data) {
                                                Ok(content) => {
                                                    let _ = result_tx.send(PageRequestResult::Success {
                                                        url: req.url,
                                                        content,
                                                    }).await;
                                                }
                                                Err(e) => {
                                                    let _ = result_tx.send(PageRequestResult::Failed {
                                                        url: req.url,
                                                        reason: format!("Invalid UTF-8: {}", e),
                                                    }).await;
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    LinkEvent::Closed => {
                                        let mut pending_guard = pending.lock().await;
                                        if let Some(req) = pending_guard.remove(&link_id) {
                                            let _ = result_tx.send(PageRequestResult::Failed {
                                                url: req.url,
                                                reason: "Link closed".to_string(),
                                            }).await;
                                        }
                                        break;
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => {}
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

async fn send_page_request(
    transport: &Arc<Transport>,
    link: &Arc<Mutex<reticulum::destination::link::Link>>,
    path: &str,
) -> Result<(), String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let path_hash = compute_path_hash(path);

    let request_data: (f64, serde_bytes::ByteBuf, Option<()>) = (
        timestamp,
        serde_bytes::ByteBuf::from(path_hash.to_vec()),
        None,
    );
    let packed = rmp_serde::to_vec(&request_data).map_err(|e| e.to_string())?;

    let link_guard = link.lock().await;
    let mut packet = link_guard
        .data_packet(&packed)
        .map_err(|e| format!("{:?}", e))?;
    packet.context = PacketContext::Request;
    drop(link_guard);

    transport.send_packet(packet).await;
    Ok(())
}

fn compute_path_hash(path: &str) -> [u8; 16] {
    let hash = Sha256::digest(path.as_bytes());
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[..16]);
    result
}

fn parse_page_response(data: &[u8]) -> Result<String, String> {
    let response: (f64, Vec<u8>, Option<Vec<u8>>) =
        rmp_serde::from_slice(data).map_err(|e| format!("Failed to parse response: {}", e))?;

    let content_bytes = response.2.ok_or("No content in response")?;
    String::from_utf8(content_bytes).map_err(|e| format!("Invalid UTF-8: {}", e))
}

async fn handle_resource_packet(
    pending: &Arc<Mutex<HashMap<AddressHash, PendingRequest>>>,
    link_id: &AddressHash,
    context: PacketContext,
    data: &[u8],
    link: &Arc<Mutex<Link>>,
    transport: &Arc<Transport>,
) -> Option<Vec<u8>> {
    let mut pending_guard = pending.lock().await;
    let req = pending_guard.get_mut(link_id)?;

    let link_guard = link.lock().await;
    let decrypt_fn = |ciphertext: &[u8]| -> Option<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len() + 64];
        link_guard
            .decrypt(ciphertext, &mut buf)
            .ok()
            .map(|s| s.to_vec())
    };

    let result = req.resource_manager.handle_packet(
        &reticulum::packet::Packet {
            header: Default::default(),
            ifac: None,
            destination: *link_id,
            transport: None,
            context,
            data: {
                let mut buf = reticulum::packet::PacketDataBuffer::new();
                buf.safe_write(data);
                buf
            },
        },
        link_id,
        &decrypt_fn,
    );

    match result {
        ResourceHandleResult::RequestParts(hash) => {
            log::debug!("NodeClient: requesting resource parts for {}", hash);
            let encrypt_fn = |plaintext: &[u8]| -> Option<Vec<u8>> {
                let mut buf = vec![0u8; plaintext.len() + 64];
                link_guard
                    .encrypt(plaintext, &mut buf)
                    .ok()
                    .map(|s| s.to_vec())
            };

            // Capture plaintext during encryption for self-test
            let captured_plaintext: std::cell::RefCell<Option<Vec<u8>>> =
                std::cell::RefCell::new(None);
            let encrypt_fn_with_capture = |plaintext: &[u8]| -> Option<Vec<u8>> {
                *captured_plaintext.borrow_mut() = Some(plaintext.to_vec());
                encrypt_fn(plaintext)
            };

            if let Some(request_packet) =
                req.resource_manager
                    .create_request_packet(&hash, link_id, encrypt_fn_with_capture)
            {
                log::debug!(
                    "NodeClient: sending resource request ctx={:?} data_len={}",
                    request_packet.context,
                    request_packet.data.len()
                );

                // Self-test: verify we can decrypt what we encrypted and it matches original
                if let Some(original_plaintext) = captured_plaintext.borrow().clone() {
                    let encrypted_data = request_packet.data.as_slice();
                    let decrypt_result = decrypt_fn(encrypted_data);
                    match decrypt_result {
                        Some(decrypted) => {
                            if decrypted == original_plaintext {
                                log::debug!(
                                    "NodeClient: self-test PASSED - round-trip {} bytes OK",
                                    original_plaintext.len()
                                );
                            } else {
                                log::error!(
                                    "NodeClient: self-test MISMATCH - original {} bytes, decrypted {} bytes",
                                    original_plaintext.len(),
                                    decrypted.len()
                                );
                                log::error!("  original:  {}", hex::encode(&original_plaintext));
                                log::error!("  decrypted: {}", hex::encode(&decrypted));
                            }
                        }
                        None => {
                            log::error!(
                                "NodeClient: self-test FAILED - could not decrypt our own encrypted data ({} bytes)",
                                encrypted_data.len()
                            );
                        }
                    }
                }

                drop(link_guard);
                drop(pending_guard);
                transport.send_packet(request_packet).await;
            }
            None
        }
        ResourceHandleResult::Assemble(hash) => {
            log::info!("NodeClient: assembling resource {}", hash);
            if let Some((data, proof_packet)) = req
                .resource_manager
                .assemble_and_prove(&hash, link_id, decrypt_fn)
            {
                drop(link_guard);
                drop(pending_guard);
                transport.send_packet(proof_packet).await;
                Some(data)
            } else {
                log::error!("NodeClient: failed to assemble resource {}", hash);
                None
            }
        }
        ResourceHandleResult::None => None,
    }
}

fn parse_resource_content(data: &[u8]) -> Result<String, String> {
    let response: (serde_bytes::ByteBuf, serde_bytes::ByteBuf) = rmp_serde::from_slice(data)
        .map_err(|e| format!("Failed to parse resource response: {}", e))?;

    let content =
        String::from_utf8(response.1.to_vec()).map_err(|e| format!("Invalid UTF-8: {}", e))?;

    if let Err(e) = std::fs::write(".rinse/last_page.mu", &content) {
        log::warn!("Failed to save page to .rinse/last_page.mu: {}", e);
    }

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_request_format() {
        let path = "/page/index.mu";
        let path_hash = compute_path_hash(path);

        let timestamp: f64 = 1736541605.123;
        let request_data: (f64, serde_bytes::ByteBuf, Option<()>) = (
            timestamp,
            serde_bytes::ByteBuf::from(path_hash.to_vec()),
            None,
        );
        let packed = rmp_serde::to_vec(&request_data).unwrap();

        println!("Path: {}", path);
        println!("Path hash: {}", hex::encode(path_hash));
        println!("Packed length: {}", packed.len());
        println!("Packed hex: {}", hex::encode(&packed));

        // Python produces 29 bytes for this structure
        assert!(
            packed.len() <= 30,
            "Packed data too large: {} bytes",
            packed.len()
        );
    }
}
