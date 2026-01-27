use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rinse::config::{load_or_generate_identity, Config, InterfaceConfig};
use rinse::{AsyncNode, AsyncTcpTransport, Interface, ServiceEvent, ServiceId};
use tokio::net::TcpListener;

fn load_directory(base: &Path, current: &Path, files: &mut HashMap<String, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            load_directory(base, &path, files);
        } else if path.is_file()
            && let Ok(relative) = path.strip_prefix(base)
            && let Ok(data) = std::fs::read(&path)
        {
            let request_path = format!("/{}", relative.display());
            log::info!("Loaded {} ({} bytes)", request_path, data.len());
            files.insert(request_path, data);
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load().expect("failed to load config");
    let identity = load_or_generate_identity().expect("failed to load identity");

    let dir_arg = std::env::args().nth(1);
    let name = config.name.clone().unwrap_or_else(|| "Rinse File Server".to_string());
    let aspect = config.serve.aspect.clone();
    let dir_str = dir_arg.or(config.serve.directory.clone()).expect("no directory specified");

    let dir = std::path::PathBuf::from(&dir_str);
    if !dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", dir_str);
        std::process::exit(1);
    }
    let dir = dir.canonicalize().expect("failed to canonicalize path");

    let mut files: HashMap<String, Vec<u8>> = HashMap::new();
    load_directory(&dir, &dir, &mut files);
    let paths: Vec<String> = files.keys().cloned().collect();
    log::info!("Loaded {} files from {}", files.len(), dir.display());
    let files = Arc::new(files);

    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(config.network.relay);

    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    let service = node.add_service(&aspect, &path_refs, &identity);
    let addr = node.service_address(service).unwrap();
    log::info!("Node: {} ({}) aspect={}", name, hex::encode(addr), aspect);

    for (iface_name, iface_config) in config.enabled_interfaces() {
        match iface_config {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host, target_port);
                log::info!("Connecting to {} ({})", iface_name, addr);
                match AsyncTcpTransport::connect(&addr).await {
                    Ok(transport) => {
                        node.add_interface(Interface::new(transport));
                    }
                    Err(e) => {
                        log::warn!("Failed to connect to {}: {}", iface_name, e);
                    }
                }
            }
            InterfaceConfig::TCPServerInterface {
                listen_ip,
                listen_port,
                ..
            } => {
                let addr = format!("{}:{}", listen_ip, listen_port);
                log::info!("Listening on {} ({})", iface_name, addr);
                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        tokio::spawn(accept_loop(listener, node.clone()));
                    }
                    Err(e) => {
                        log::warn!("Failed to bind {}: {}", iface_name, e);
                    }
                }
            }
        }
    }

    let name_bytes = name.into_bytes();

    let node_clone = node.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    node_clone.announce_with_app_data(service, Some(name_bytes.clone()));
                    log::debug!("Announced service");
                }
                event = node_clone.recv(service) => {
                    let Some(event) = event else { break };
                    handle_event(&node_clone, service, &files, event).await;
                }
            }
        }
    });

    node.run().await;
}

async fn accept_loop(listener: TcpListener, node: AsyncNode<AsyncTcpTransport>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                log::info!("Accepted connection from {}", peer);
                match AsyncTcpTransport::from_stream(peer.to_string(), stream) {
                    Ok(transport) => {
                        node.add_interface(Interface::new(transport));
                    }
                    Err(e) => {
                        log::warn!("Failed to create transport: {}", e);
                    }
                }
            }
            Err(e) => {
                log::warn!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_event(
    node: &AsyncNode<AsyncTcpTransport>,
    service: ServiceId,
    files: &HashMap<String, Vec<u8>>,
    event: ServiceEvent,
) {
    let ServiceEvent::Request {
        request_id,
        path,
        data,
        ..
    } = event
    else {
        return;
    };

    log::info!("Request path='{}' data_len={}", path, data.len());

    let key = if path.starts_with('/') {
        path.clone()
    } else {
        format!("/{}", path)
    };

    let response = match files.get(&key) {
        Some(data) => {
            log::info!("Serving {} ({} bytes)", key, data.len());
            data.clone()
        }
        None => {
            log::warn!("Not found: {}", key);
            b"error: not found".to_vec()
        }
    };

    if let Err(e) = node
        .respond(service, request_id, &response, None, true)
        .await
    {
        log::warn!("Failed to respond: {:?}", e);
    }
}
