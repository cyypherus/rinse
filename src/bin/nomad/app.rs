use rinse::{AsyncNode, AsyncTcpTransport, Interface, ServiceId};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::config::{Config, ConfigError, InterfaceConfig};
use crate::identity::{Identity, IdentityError};

#[derive(Error, Debug)]
pub enum AppError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct NomadApp {
    config: Config,
    identity: Identity,
    node: Arc<Mutex<AsyncNode<AsyncTcpTransport>>>,
    service_id: Option<ServiceId>,
    dest_hash: [u8; 16],
    interface_status: HashMap<String, bool>,
    announced_on_startup: bool,
}

impl NomadApp {
    pub async fn new() -> Result<Self, AppError> {
        let config = Config::load()?;
        let identity = Identity::load_or_generate()?;

        log::info!("Identity loaded");

        let relay_enabled = config.network.relay;
        let mut node = AsyncNode::new(relay_enabled);

        let service_id = node.add_service("nomadnetwork.node", &["/page/*"], identity.inner());
        let dest_hash = node.service_address(service_id).unwrap();

        log::info!("Our address: {}", hex::encode(dest_hash));

        let enabled_interfaces = config.enabled_interfaces();
        if enabled_interfaces.is_empty() {
            log::warn!("No interfaces configured! Add interfaces to config.toml");
        }

        let mut interface_status = HashMap::new();

        for (name, iface_config) in &enabled_interfaces {
            match iface_config {
                InterfaceConfig::TCPClientInterface {
                    target_host,
                    target_port,
                    ..
                } => {
                    let addr = format!("{}:{}", target_host, target_port);
                    log::info!("Connecting to {} ({})", name, addr);
                    match AsyncTcpTransport::connect(&addr).await {
                        Ok(transport) => {
                            node.add_interface(Interface::new(transport));
                            interface_status.insert(name.to_string(), true);
                        }
                        Err(e) => {
                            log::warn!("Failed to connect to {}: {}", addr, e);
                            interface_status.insert(name.to_string(), false);
                        }
                    }
                }
                InterfaceConfig::TCPServerInterface {
                    listen_ip,
                    listen_port,
                    ..
                } => {
                    let addr = format!("{}:{}", listen_ip, listen_port);
                    log::info!("TCP server {} ({}) - not yet supported", name, addr);
                    interface_status.insert(name.to_string(), false);
                }
            }
        }

        let announced_on_startup = !enabled_interfaces.is_empty();
        if announced_on_startup {
            node.announce(service_id);
            log::info!("Announced on network");
        }

        Ok(Self {
            config,
            identity,
            node: Arc::new(Mutex::new(node)),
            service_id: Some(service_id),
            dest_hash,
            interface_status,
            announced_on_startup,
        })
    }

    pub fn dest_hash(&self) -> [u8; 16] {
        self.dest_hash
    }

    pub fn take_node(&mut self) -> Arc<Mutex<AsyncNode<AsyncTcpTransport>>> {
        self.node.clone()
    }

    pub fn take_service_id(&mut self) -> ServiceId {
        self.service_id.take().expect("service_id already taken")
    }

    pub fn relay_enabled(&self) -> bool {
        self.config.network.relay
    }

    pub fn interface_status(&self) -> &HashMap<String, bool> {
        &self.interface_status
    }

    pub fn announced_on_startup(&self) -> bool {
        self.announced_on_startup
    }

    pub fn take_identity(self) -> Identity {
        self.identity
    }
}
