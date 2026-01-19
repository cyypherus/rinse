use std::path::{Path, PathBuf};
use std::sync::Arc;

use rinse::{AsyncNode, Identity, ServiceHandle};

fn scan_directory(base: &Path, current: &Path, paths: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(current) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_directory(base, &path, paths);
            } else if path.is_file()
                && let Ok(relative) = path.strip_prefix(base)
            {
                let request_path = format!("/page/{}", relative.display());
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
    if paths.is_empty() {
        paths.push("/page/index.mu".to_string());
    }
    log::info!("Registered {} paths", paths.len());
    for p in &paths {
        log::debug!("  {}", p);
    }

    let mut node = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());

    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    let mut service = node.add_service("nomadnetwork.node", &path_refs, &identity);
    let addr = service.address();
    log::info!("Node: {} ({})", name, hex::encode(addr));

    if let Some(addr) = connect_addr {
        log::info!("Connecting to {}", addr);
        node.connect(&addr).await.expect("failed to connect");
    } else {
        node.listen(&listen_addr).await.expect("failed to listen");
    }

    log::info!("Serving files from {}", dir.display());
    let name_bytes = name.into_bytes();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    service.announce_with_app_data(&name_bytes);
                    log::debug!("Announced service");
                }
                req = service.recv_request() => {
                    let Some(req) = req else { break };
                    handle_request(&mut service, &dir, req).await;
                }
            }
        }
    });

    node.run().await;
}

async fn handle_request(
    service: &mut ServiceHandle,
    dir: &std::path::Path,
    req: rinse::IncomingRequest,
) {
    log::info!(
        "Request from {} path='{}' data_len={}",
        hex::encode(&req.from[..4]),
        req.path,
        req.data.len()
    );

    let response = if req.path.is_empty()
        || req.path == "/"
        || req.path == "/page"
        || req.path.starts_with("/page/")
    {
        let filename = req
            .path
            .strip_prefix("/page")
            .unwrap_or(&req.path)
            .trim_start_matches('/');
        let filename = if filename.is_empty() {
            "index.mu"
        } else {
            filename
        };
        let file_path = dir.join(filename);

        if !file_path.starts_with(dir) {
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
        }
    } else {
        log::warn!("Unknown path: {}", req.path);
        b"error: unknown path".to_vec()
    };

    if let Err(e) = service.respond(req.request_id, &response).await {
        log::warn!("Failed to respond: {:?}", e);
    }
}
