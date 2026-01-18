use std::path::PathBuf;
use std::sync::Arc;

use rinse::{AsyncNode, Identity, ServiceHandle};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory> [listen_addr]", args[0]);
        eprintln!("  directory    - Directory to serve files from");
        eprintln!("  listen_addr  - Address to listen on (default: 0.0.0.0:4242)");
        std::process::exit(1);
    }

    let dir = PathBuf::from(&args[1]);
    if !dir.is_dir() {
        eprintln!("Error: '{}' is not a directory", args[1]);
        std::process::exit(1);
    }
    let dir = Arc::new(dir.canonicalize().expect("failed to canonicalize path"));

    let listen_addr = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:4242");

    let mut node = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());

    let mut service = node.add_service("fileserver", &["file"], &identity);
    let addr = service.address();
    log::info!("Service address: {}", hex::encode(addr));

    service.announce();

    let listener = TcpListener::bind(listen_addr)
        .await
        .expect("failed to bind");
    log::info!("Listening on {}", listen_addr);
    log::info!("Serving files from {}", dir.display());

    let dir_clone = dir.clone();
    tokio::spawn(async move {
        serve_requests(&mut service, &dir_clone).await;
    });

    let accept_task = async {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    log::info!("Accepted connection from {}", peer);
                    node.add_tcp_stream(stream);
                }
                Err(e) => {
                    log::warn!("Accept error: {}", e);
                }
            }
        }
    };

    tokio::select! {
        _ = accept_task => {}
        _ = node.run() => {}
    }
}

async fn serve_requests(service: &mut ServiceHandle, dir: &PathBuf) {
    loop {
        let Some(req) = service.recv_request().await else {
            break;
        };

        log::info!(
            "Request from {} path='{}' data_len={}",
            hex::encode(&req.from[..4]),
            req.path,
            req.data.len()
        );

        let response = if req.path == "file" {
            let filename = String::from_utf8_lossy(&req.data);
            let file_path = dir.join(filename.as_ref());

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
            b"error: unknown path".to_vec()
        };

        if let Err(e) = service.respond(req.request_id, &response).await {
            log::warn!("Failed to respond: {:?}", e);
        }
    }
}
