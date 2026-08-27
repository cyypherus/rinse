#[path = "../common.rs"]
mod common;
mod pages;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{
    IdentityHash, InterfaceLimits, Link, LinkEvent, NodeBuilder, NodeConfig, NodeHandle,
    RatchetAction, RequestPath, Service, ServiceConfig, ServiceEvent, ServiceName,
};
use tokio::net::TcpListener;

pub struct PageState {
    pub messages: Vec<(String, String)>,
    pub known_users: HashMap<IdentityHash, String>,
}

impl PageState {
    fn new() -> Self {
        Self {
            messages: Vec::new(),
            known_users: HashMap::new(),
        }
    }

    pub fn get_username(&self, identity: Option<IdentityHash>) -> Option<&str> {
        identity.and_then(|identity| self.known_users.get(&identity).map(String::as_str))
    }

    pub fn set_username(&mut self, identity: IdentityHash, name: String) {
        if !name.trim().is_empty() {
            self.known_users.insert(identity, name);
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config = Config::load_from(".rinse/config.toml").expect("failed to load config");
    let identity =
        load_or_create_persistent_identity(".rinse/identity").expect("failed to load identity");
    let name = config.name.clone().unwrap_or_else(|| "Page Server".into());
    let mode = if config.network.relay {
        NodeConfig::relay()
    } else {
        NodeConfig::endpoint()
    };
    let mut builder = NodeBuilder::new(mode);
    let mut listeners = Vec::new();
    for (interface_name, interface) in config.enabled_interfaces() {
        match interface {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let address = format!("{target_host}:{target_port}");
                match common::TcpHdlc::connect(&address).await {
                    Ok(interface) => {
                        builder = builder.interface(interface, interface_limits());
                        log::info!("[{interface_name}] connected to {address}");
                    }
                    Err(error) => {
                        log::warn!("[{interface_name}] failed to connect to {address}: {error}");
                    }
                }
            }
            InterfaceConfig::TCPServerInterface {
                listen_ip,
                listen_port,
                ..
            } => {
                let address = format!("{listen_ip}:{listen_port}");
                match TcpListener::bind(&address).await {
                    Ok(listener) => listeners.push(listener),
                    Err(error) => {
                        log::warn!("[{interface_name}] failed to listen on {address}: {error}");
                    }
                }
            }
        }
    }
    let (node, task) = builder.build().expect("failed to build node");
    let running = tokio::spawn(task.run());
    for listener in listeners {
        tokio::spawn(accept_connections(listener, node.clone()));
    }
    let paths = ["/page/index.mu", "/page/guestbook.mu", "/page/about.mu"]
        .map(|path| RequestPath::new(path).unwrap());
    let service = node
        .register_service(
            ServiceConfig::new(
                ServiceName::new("nomadnetwork.node").unwrap(),
                identity,
                paths,
                None,
            )
            .unwrap(),
        )
        .await
        .expect("failed to register service");
    log::info!(
        "{name} at {}",
        hex::encode(service.destination().as_bytes())
    );
    serve(service, Arc::new(Mutex::new(PageState::new())), name).await;
    node.shutdown().await;
    running.await.unwrap().unwrap();
}

async fn accept_connections(listener: TcpListener, node: NodeHandle) {
    while let Ok((stream, peer)) = listener.accept().await {
        log::info!("accepted {peer}");
        let Ok(interface) = common::TcpHdlc::new(stream) else {
            continue;
        };
        if node
            .attach_interface(interface, interface_limits())
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn serve(mut service: Service, state: Arc<Mutex<PageState>>, name: String) {
    let mut announcements = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = announcements.tick() => {
                if let Err(error) = service
                    .announce(Bytes::copy_from_slice(name.as_bytes()), RatchetAction::Keep)
                    .await
                {
                    log::warn!("announce failed: {error:?}");
                }
            }
            event = service.receive() => match event {
                Ok(ServiceEvent::IncomingLink(link)) => match link.accept().await {
                    Ok(link) => { tokio::spawn(serve_link(link, state.clone(), name.clone())); }
                    Err(error) => log::warn!("link acceptance failed: {error:?}"),
                },
                Ok(_) => {},
                Err(_) => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
}

async fn serve_link(mut link: Link, state: Arc<Mutex<PageState>>, name: String) {
    let mut identity = None;
    while let Ok(event) = link.receive().await {
        match event {
            LinkEvent::Identified(peer) => identity = Some(peer),
            LinkEvent::Request(request) => {
                let form = parse_form_data(request.body());
                let response = render(&state, &name, request.path().as_str(), &form, identity);
                if let Err(error) = request.respond(Bytes::from(response)).await {
                    log::warn!("response failed: {error:?}");
                }
            }
            LinkEvent::Datagram(_) => {}
        }
    }
}

fn parse_form_data(data: &[u8]) -> HashMap<String, String> {
    rmp_serde::from_slice(data).unwrap_or_default()
}

fn render(
    state: &Arc<Mutex<PageState>>,
    name: &str,
    path: &str,
    form: &HashMap<String, String>,
    identity: Option<IdentityHash>,
) -> String {
    match path {
        "/page/index.mu" => pages::index(state, name, form, identity),
        "/page/guestbook.mu" => pages::guestbook(state, form, identity),
        "/page/about.mu" => pages::about(name),
        _ => pages::not_found(path),
    }
}

fn interface_limits() -> InterfaceLimits {
    InterfaceLimits::new(65_535, 256, 1_048_576).unwrap()
}
