use crate::network::node_registry::NodeRegistry;
use crate::network::types::NodeInfo;

use rinse::{Address, AspectHash, Destination};

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

const NODE_ASPECT_NAME: &str = "nomadnetwork.node";

pub struct NetworkClient {
    registry: Arc<RwLock<NodeRegistry>>,
    known_addresses: Arc<RwLock<HashSet<Address>>>,
    node_announce_tx: broadcast::Sender<NodeInfo>,
}

impl NetworkClient {
    pub fn new(registry: NodeRegistry) -> Self {
        let (node_announce_tx, _) = broadcast::channel(64);

        Self {
            registry: Arc::new(RwLock::new(registry)),
            known_addresses: Arc::new(RwLock::new(HashSet::new())),
            node_announce_tx,
        }
    }

    pub fn node_announces(&self) -> broadcast::Receiver<NodeInfo> {
        self.node_announce_tx.subscribe()
    }

    pub async fn handle_destinations_changed(&self, destinations: Vec<Destination>) {
        let mut known = self.known_addresses.write().await;
        let node_aspect = AspectHash::from_name(NODE_ASPECT_NAME);

        for dest in destinations {
            if dest.aspect != node_aspect {
                continue;
            }

            let is_new = !known.contains(&dest.address);

            if is_new {
                let name = match dest
                    .app_data
                    .as_ref()
                    .and_then(|data| parse_display_name(data))
                {
                    Some(name) => name,
                    None => {
                        known.insert(dest.address);
                        continue;
                    }
                };

                let node = NodeInfo {
                    hash: dest.address,
                    name,
                    identify: false,
                };

                known.insert(dest.address);

                {
                    let mut reg = self.registry.write().await;
                    reg.save(node.clone());
                }

                let _ = self.node_announce_tx.send(node);
            }
        }
    }

    pub async fn registry_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, NodeRegistry> {
        self.registry.write().await
    }
}

impl Clone for NetworkClient {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            known_addresses: self.known_addresses.clone(),
            node_announce_tx: self.node_announce_tx.clone(),
        }
    }
}

fn parse_display_name(app_data: &[u8]) -> Option<String> {
    if app_data.is_empty() {
        return None;
    }

    if (app_data[0] >= 0x90 && app_data[0] <= 0x9f) || app_data[0] == 0xdc {
        if let Ok(data) = rmp_serde::from_slice::<Vec<Option<serde_bytes::ByteBuf>>>(app_data) {
            if let Some(Some(name_bytes)) = data.first() {
                return String::from_utf8(name_bytes.to_vec()).ok();
            }
        }
        if let Ok(data) = rmp_serde::from_slice::<Vec<Option<String>>>(app_data) {
            if let Some(name) = data.first() {
                return name.clone();
            }
        }
        return None;
    }

    String::from_utf8(app_data.to_vec()).ok()
}
