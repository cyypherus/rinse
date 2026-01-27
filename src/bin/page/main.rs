use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rinse::config::{Config, InterfaceConfig, load_or_generate_identity};
use rinse::{Address, AsyncNode, AsyncTcpTransport, Interface, ServiceEvent, ServiceId};
use tokio::net::TcpListener;

mod pages;

pub struct PageState {
    pub messages: Vec<(String, String)>,
    pub known_users: HashMap<Address, String>,
}

impl PageState {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            known_users: HashMap::new(),
        }
    }

    pub fn get_username(&self, identity: Option<Address>) -> Option<&str> {
        identity.and_then(|id| self.known_users.get(&id).map(|s| s.as_str()))
    }

    pub fn set_username(&mut self, identity: Address, name: String) {
        if !name.trim().is_empty() {
            self.known_users.insert(identity, name);
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load().expect("Failed to load config");
    let identity = load_or_generate_identity().expect("Failed to load identity");
    let state = Arc::new(Mutex::new(PageState::new()));

    let node_name = config
        .name
        .clone()
        .unwrap_or_else(|| "Page Server".to_string());

    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(config.network.relay);

    let paths = vec!["/page/index.mu", "/page/guestbook.mu", "/page/about.mu"];
    let service = node.add_service("nomadnetwork.node", &paths, &identity);
    let addr = node.service_address(service).unwrap();
    log::info!("Node: {} ({})", node_name, hex::encode(addr));

    for (name, iface) in config.enabled_interfaces() {
        match iface {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host, target_port);
                log::info!("[{}] Connecting to {}", name, addr);
                match AsyncTcpTransport::connect(&addr).await {
                    Ok(transport) => {
                        node.add_interface(Interface::new(transport));
                    }
                    Err(e) => {
                        log::warn!("[{}] Failed to connect: {}", name, e);
                    }
                }
            }
            InterfaceConfig::TCPServerInterface {
                listen_ip,
                listen_port,
                ..
            } => {
                let addr = format!("{}:{}", listen_ip, listen_port);
                log::info!("[{}] Listening on {}", name, addr);
                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        tokio::spawn(accept_loop(name.to_string(), listener, node.clone()));
                    }
                    Err(e) => {
                        log::warn!("[{}] Failed to bind: {}", name, e);
                    }
                }
            }
        }
    }

    let name = node_name.clone();
    let name_bytes = node_name.into_bytes();
    let node_clone = node.clone();
    let state_clone = state.clone();

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        node_clone.announce_with_app_data(service, Some(name_bytes.clone()));
        log::info!("Announced service");

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.reset();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    node_clone.announce_with_app_data(service, Some(name_bytes.clone()));
                    log::info!("Re-announced service");
                }
                event = node_clone.recv(service) => {
                    let Some(event) = event else { break };
                    handle_event(&node_clone, service, &state_clone, &name, event).await;
                }
            }
        }
    });

    node.run().await;
}

async fn accept_loop(name: String, listener: TcpListener, node: AsyncNode<AsyncTcpTransport>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                log::info!("[{}] Connection from {}", name, peer);
                match AsyncTcpTransport::from_stream(peer.to_string(), stream) {
                    Ok(transport) => {
                        node.add_interface(Interface::new(transport));
                    }
                    Err(e) => {
                        log::warn!("[{}] Failed to create transport: {}", name, e);
                    }
                }
            }
            Err(e) => {
                log::warn!("[{}] Accept error: {}", name, e);
            }
        }
    }
}

fn parse_form_data(data: &[u8]) -> HashMap<String, String> {
    if data.is_empty() {
        return HashMap::new();
    }
    rmp_serde::from_slice(data).unwrap_or_default()
}

async fn handle_event(
    node: &AsyncNode<AsyncTcpTransport>,
    service: ServiceId,
    state: &Arc<Mutex<PageState>>,
    name: &str,
    event: ServiceEvent,
) {
    let ServiceEvent::Request {
        request_id,
        path,
        data,
        remote_identity,
        ..
    } = event
    else {
        return;
    };

    let form_data = parse_form_data(&data);
    log::info!(
        "Request path='{}' form_data={:?} identity={:?}",
        path,
        form_data,
        remote_identity.map(hex::encode)
    );

    let response = match path.as_str() {
        "/page/index.mu" => pages::index(state, name, &form_data, remote_identity),
        "/page/guestbook.mu" => pages::guestbook(state, &form_data, remote_identity),
        "/page/about.mu" => pages::about(name),
        _ => pages::not_found(&path),
    };

    if let Err(e) = node
        .respond(service, request_id, response.as_bytes(), None, true)
        .await
    {
        log::warn!("Failed to respond: {:?}", e);
    }
}
