use std::path::{Path, PathBuf};
use std::sync::Arc;

use rinse::{AsyncNode, AsyncTcpTransport, Identity, Interface, ServiceEvent, ServiceId};
use tokio::net::TcpListener;

fn scan_directory(base: &Path, current: &Path, paths: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(current) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_directory(base, &path, paths);
            } else if path.is_file()
                && let Ok(relative) = path.strip_prefix(base)
            {
                let request_path = format!("/{}", relative.display());
                paths.push(request_path);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();

    let mut name = "Rinse File Server".to_string();
    let mut dir_arg = None;
    let mut connect_addr = None;
    let mut listen_addr = "0.0.0.0:4242".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = args.get(i + 1).expect("--name requires a value").clone();
                i += 2;
            }
            "--connect" => {
                connect_addr = Some(
                    args.get(i + 1)
                        .expect("--connect requires an address")
                        .clone(),
                );
                i += 2;
            }
            "--listen" => {
                listen_addr = args
                    .get(i + 1)
                    .expect("--listen requires an address")
                    .clone();
                i += 2;
            }
            arg if !arg.starts_with('-') && dir_arg.is_none() => {
                dir_arg = Some(arg.to_string());
                i += 1;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    let dir_str = dir_arg.unwrap_or_else(|| {
        eprintln!("Usage: {} <directory> [options]", args[0]);
        eprintln!("  --name <name>      - Display name (default: Rinse File Server)");
        eprintln!("  --connect <addr>   - Connect to an existing node");
        eprintln!("  --listen <addr>    - Listen address (default: 0.0.0.0:4242)");
        std::process::exit(1);
    });

    let dir = PathBuf::from(&dir_str);
    if !dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", dir_str);
        std::process::exit(1);
    }
    let dir = Arc::new(dir.canonicalize().expect("failed to canonicalize path"));

    let mut paths: Vec<String> = Vec::new();
    scan_directory(&dir, &dir, &mut paths);
    log::info!("Registered {} paths", paths.len());
    for p in &paths {
        log::debug!("  {}", p);
    }

    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());

    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    let service = node.add_service("nomadnetwork.node", &path_refs, &identity);
    let addr = node.service_address(service).unwrap();
    log::info!("Node: {} ({})", name, hex::encode(addr));

    if let Some(addr) = connect_addr {
        log::info!("Connecting to {}", addr);
        let transport = AsyncTcpTransport::connect(&addr)
            .await
            .expect("failed to connect");
        node.add_interface(Interface::new(transport));
    } else {
        log::info!("Listening on {}", listen_addr);
        let listener = TcpListener::bind(&listen_addr)
            .await
            .expect("failed to bind");

        // Spawn accept loop
        tokio::spawn(accept_loop(listener, node.clone()));
    }

    log::info!("Serving files from {}", dir.display());
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
                event = node_clone.receive(service) => {
                    let Some(event) = event else { break };
                    handle_event(&node_clone, service, &dir, event).await;
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
    dir: &std::path::Path,
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

    let filename = path.trim_start_matches('/');
    let file_path = dir.join(filename);

    let response = if !file_path.starts_with(dir) {
        log::warn!("Path traversal attempt: {}", filename);
        b"error: invalid path".to_vec()
    } else {
        match tokio::fs::read(&file_path).await {
            Ok(data) => {
                log::info!("Serving {} ({} bytes)", file_path.display(), data.len());
                data
            }
            Err(e) => {
                log::warn!("Failed to read {}: {}", file_path.display(), e);
                format!("error: {}", e).into_bytes()
            }
        }
    };

    if let Err(e) = node.respond(service, request_id, &response).await {
        log::warn!("Failed to respond: {:?}", e);
    }
}
