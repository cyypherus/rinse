use rinse::config::{Config, InterfaceConfig, load_or_generate_identity};
use rinse::{Interface, Node, TcpTransport};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load().expect("failed to load config");
    let identity = load_or_generate_identity().expect("failed to load identity");

    let args: Vec<String> = std::env::args().collect();

    let mut node_id_arg = None;
    let mut path_arg = None;
    let mut output_file = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                output_file = Some(args.get(i + 1).expect("--output requires a path").clone());
                i += 2;
            }
            arg if !arg.starts_with('-') && node_id_arg.is_none() => {
                node_id_arg = Some(arg.to_string());
                i += 1;
            }
            arg if !arg.starts_with('-') && path_arg.is_none() => {
                path_arg = Some(arg.to_string());
                i += 1;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    let node_id_hex = node_id_arg.unwrap_or_else(|| {
        eprintln!("Usage: request <node_id> <path> [options]");
        eprintln!("  --output <file>    - Write response to file instead of stdout");
        std::process::exit(1);
    });

    let path = path_arg.unwrap_or_else(|| {
        eprintln!("Usage: request <node_id> <path> [options]");
        eprintln!("  --output <file>    - Write response to file instead of stdout");
        std::process::exit(1);
    });

    let node_id: [u8; 16] = hex::decode(&node_id_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| {
            eprintln!("Error: node_id must be 32 hex characters (16 bytes)");
            std::process::exit(1);
        });

    let mut node: Node<TcpTransport> = Node::new(config.network.relay);
    let service = node.add_service("nomadnetwork.node", &[], &identity);

    for (name, iface) in config.enabled_interfaces() {
        if let InterfaceConfig::TCPClientInterface {
            target_host,
            target_port,
            ..
        } = iface
        {
            let addr = format!("{}:{}", target_host, target_port);
            log::info!("[{}] Connecting to {}", name, addr);
            match TcpTransport::connect(&addr).await {
                Ok(transport) => {
                    node.add_interface(Interface::new(transport));
                }
                Err(e) => {
                    log::warn!("[{}] Failed to connect: {}", name, e);
                }
            }
        }
    }

    log::info!(
        "Requesting path '{}' from node {}",
        path,
        hex::encode(node_id)
    );

    let node_clone = node.clone();
    let node_task = tokio::spawn(async move {
        node.run().await;
    });

    let node_for_progress = node_clone.clone();
    let progress_task = tokio::spawn(async move {
        loop {
            let Some(progress) = node_for_progress.recv_progress(service).await else {
                break;
            };
            let pct = if progress.total_bytes > 0 {
                (progress.received_bytes as f64 / progress.total_bytes as f64) * 100.0
            } else {
                0.0
            };
            eprint!(
                "\rProgress: {}/{} bytes ({:.1}%)    ",
                progress.received_bytes, progress.total_bytes, pct
            );
        }
    });

    let link = node_clone
        .establish_link(service, node_id)
        .await
        .expect("Failed to establish link");
    let response = node_clone.request(service, link, &path, &[]).await;

    progress_task.abort();

    match response {
        Ok(resp) => {
            log::info!("Received {} bytes", resp.data.len());
            if let Some(output_path) = output_file {
                tokio::fs::write(&output_path, &resp.data)
                    .await
                    .expect("failed to write output file");
                log::info!("Written to {}", output_path);
            } else {
                use std::io::Write;
                std::io::stdout()
                    .write_all(&resp.data)
                    .expect("failed to write to stdout");
            }
        }
        Err(e) => {
            eprintln!("Request failed: {:?}", e);
            std::process::exit(1);
        }
    }

    node_task.abort();
}
