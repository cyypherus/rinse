use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{IdentityAddress, IncomingRequest, Interface, Node, NodeBuilder, TcpTransport};
use tokio::net::TcpListener;

mod pages;

pub struct PageState {
    pub messages: Vec<(String, String)>,
    pub known_users: HashMap<IdentityAddress, String>,
}

impl PageState {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            known_users: HashMap::new(),
        }
    }

    pub fn get_username(&self, identity: Option<IdentityAddress>) -> Option<&str> {
        identity.and_then(|id| self.known_users.get(&id).map(|s| s.as_str()))
    }

    pub fn set_username(&mut self, identity: IdentityAddress, name: String) {
        if !name.trim().is_empty() {
            self.known_users.insert(identity, name);
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load_from(".rinse/config.toml").expect("Failed to load config");
    let identity =
        load_or_create_persistent_identity(".rinse/identity").expect("Failed to load identity");
    let state = Arc::new(Mutex::new(PageState::new()));

    let node_name = config
        .name
        .clone()
        .unwrap_or_else(|| "Page Server".to_string());

    let mut builder: NodeBuilder<TcpTransport> = if config.network.relay {
        NodeBuilder::packet_forwarding_relay()
    } else {
        NodeBuilder::non_forwarding_endpoint()
    };

    let paths = vec!["/page/index.mu", "/page/guestbook.mu", "/page/about.mu"];
    let service = builder.register_local_service("nomadnetwork.node", &paths, &identity);
    let addr = service.destination_address;
    let service = service.id;
    log::info!("Node: {} ({})", node_name, hex::encode(addr));

    let mut listeners = Vec::new();
    for (name, iface) in config.enabled_interfaces() {
        match iface {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host, target_port);
                log::info!("[{}] Connecting to {}", name, addr);
                match TcpTransport::connect(&addr).await {
                    Ok(transport) => {
                        builder.add_initial_interface(Interface::new(transport));
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
                        listeners.push((name.to_string(), listener));
                    }
                    Err(e) => {
                        log::warn!("[{}] Failed to bind: {}", name, e);
                    }
                }
            }
        }
    }

    let (node, runtime) = builder.build();
    for (name, listener) in listeners {
        tokio::spawn(accept_loop(name, listener, node.clone()));
    }

    let name = node_name.clone();
    let name_bytes = node_name.into_bytes();
    let node_clone = node.clone();
    let state_clone = state.clone();

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = node_clone.queue_service_announcement_with_data(service, name_bytes.clone());
        log::info!("Announced service");

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.reset();
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = node_clone
                        .queue_service_announcement_with_data(service, name_bytes.clone());
                    log::info!("Re-announced service");
                }
                request = node_clone.recv_request(service) => {
                    let Ok(request) = request else { break };
                    handle_request(&node_clone, &state_clone, &name, request).await;
                }
            }
        }
    });

    runtime.run().await;
}

async fn accept_loop(name: String, listener: TcpListener, node: Node<TcpTransport>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                log::info!("[{}] Connection from {}", name, peer);
                match TcpTransport::from_accepted_stream(stream) {
                    Ok(transport) => {
                        if node.attach_interface(Interface::new(transport)).is_err() {
                            return;
                        }
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

async fn handle_request(
    node: &Node<TcpTransport>,
    state: &Arc<Mutex<PageState>>,
    name: &str,
    request: IncomingRequest,
) {
    let form_data = parse_form_data(&request.data);
    log::info!(
        "Request path='{}' form_data={:?} identity={:?}",
        request.path,
        form_data,
        request.authenticated_remote_identity.map(hex::encode)
    );

    let response = match request.path.as_str() {
        "/page/index.mu" => pages::index(
            state,
            name,
            &form_data,
            request.authenticated_remote_identity,
        ),
        "/page/guestbook.mu" => {
            pages::guestbook(state, &form_data, request.authenticated_remote_identity)
        }
        "/page/about.mu" => pages::about(name),
        _ => pages::not_found(&request.path),
    };

    if let Err(e) = node
        .respond(request.request_id, response.as_bytes(), None, true)
        .await
    {
        log::warn!("Failed to respond: {:?}", e);
    }
}
