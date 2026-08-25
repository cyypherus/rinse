use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{IncomingRequest, Interface, Node, NodeBuilder, TcpTransport};
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

    let config = Config::load_from(".rinse/config.toml").expect("failed to load config");
    let identity =
        load_or_create_persistent_identity(".rinse/identity").expect("failed to load identity");

    let mut args = std::env::args().skip(1);
    let dir_str = args
        .next()
        .expect("usage: rinse-serve <directory> [aspect]");
    let aspect = args.next().unwrap_or_else(|| "files".to_string());
    let name = config
        .name
        .clone()
        .unwrap_or_else(|| "Rinse File Server".to_string());

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

    let mut builder: NodeBuilder<TcpTransport> = if config.network.relay {
        NodeBuilder::packet_forwarding_relay()
    } else {
        NodeBuilder::non_forwarding_endpoint()
    };

    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    let service = builder.register_local_service(&aspect, &path_refs, &identity);
    let addr = service.destination_address;
    let service = service.id;
    log::info!("Node: {} ({}) aspect={}", name, hex::encode(addr), aspect);

    let mut listeners = Vec::new();
    for (iface_name, iface_config) in config.enabled_interfaces() {
        match iface_config {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host, target_port);
                log::info!("Connecting to {} ({})", iface_name, addr);
                match TcpTransport::connect(&addr).await {
                    Ok(transport) => {
                        builder.add_initial_interface(Interface::new(transport));
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
                        listeners.push(listener);
                    }
                    Err(e) => {
                        log::warn!("Failed to bind {}: {}", iface_name, e);
                    }
                }
            }
        }
    }

    let (node, runtime) = builder.build();
    for listener in listeners {
        tokio::spawn(accept_loop(listener, node.clone()));
    }

    let name_bytes = name.into_bytes();

    let node_clone = node.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = node_clone
                        .queue_service_announcement_with_data(service, name_bytes.clone());
                    log::debug!("Announced service");
                }
                request = node_clone.recv_request(service) => {
                    let Ok(request) = request else { break };
                    handle_request(&node_clone, &files, request).await;
                }
            }
        }
    });

    runtime.run().await;
}

async fn accept_loop(listener: TcpListener, node: Node<TcpTransport>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                log::info!("Accepted connection from {}", peer);
                match TcpTransport::from_accepted_stream(stream) {
                    Ok(transport) => {
                        if node.attach_interface(Interface::new(transport)).is_err() {
                            return;
                        }
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

async fn handle_request(
    node: &Node<TcpTransport>,
    files: &HashMap<String, Vec<u8>>,
    request: IncomingRequest,
) {
    log::info!(
        "Request path='{}' data_len={}",
        request.path,
        request.data.len()
    );

    let key = if request.path.starts_with('/') {
        request.path.clone()
    } else {
        format!("/{}", request.path)
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
        .respond(request.request_id, &response, None, true)
        .await
    {
        log::warn!("Failed to respond: {:?}", e);
    }
}
