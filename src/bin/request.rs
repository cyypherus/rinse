use rinse::{AsyncNode, AsyncTcpTransport, Identity, Interface, ServiceEvent};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();

    let mut node_id_arg = None;
    let mut path_arg = None;
    let mut connect_addr = None;
    let mut output_file = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--connect" => {
                connect_addr = Some(
                    args.get(i + 1)
                        .expect("--connect requires an address")
                        .clone(),
                );
                i += 2;
            }
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
        eprintln!("Usage: {} <node_id> <path> [options]", args[0]);
        eprintln!("  --connect <addr>   - Connect to an existing node (required)");
        eprintln!("  --output <file>    - Write response to file instead of stdout");
        std::process::exit(1);
    });

    let path = path_arg.unwrap_or_else(|| {
        eprintln!("Usage: {} <node_id> <path> [options]", args[0]);
        eprintln!("  --connect <addr>   - Connect to an existing node (required)");
        eprintln!("  --output <file>    - Write response to file instead of stdout");
        std::process::exit(1);
    });

    let connect_addr = connect_addr.unwrap_or_else(|| {
        eprintln!("Error: --connect is required");
        std::process::exit(1);
    });

    let node_id: [u8; 16] = hex::decode(&node_id_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| {
            eprintln!("Error: node_id must be 32 hex characters (16 bytes)");
            std::process::exit(1);
        });

    let mut node = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());

    let service = node.add_service("nomadnetwork.node", &[], &identity);

    log::info!("Connecting to {}", connect_addr);
    let transport = AsyncTcpTransport::connect(&connect_addr)
        .await
        .expect("failed to connect");
    node.add_interface(Interface::new(transport));

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
            match node_for_progress.recv(service).await {
                Some(ServiceEvent::ResourceProgress {
                    received_bytes,
                    total_bytes,
                    ..
                }) => {
                    let pct = if total_bytes > 0 {
                        (received_bytes as f64 / total_bytes as f64) * 100.0
                    } else {
                        0.0
                    };
                    eprint!(
                        "\rProgress: {}/{} bytes ({:.1}%)    ",
                        received_bytes, total_bytes, pct
                    );
                }
                Some(ServiceEvent::RequestResult { .. }) => {
                    eprintln!();
                    break;
                }
                _ => {}
            }
        }
    });

    let response = node_clone.request(service, node_id, &path, &[]).await;

    progress_task.abort();

    match response {
        Ok((data, _metadata)) => {
            log::info!("Received {} bytes", data.len());
            if let Some(output_path) = output_file {
                tokio::fs::write(&output_path, &data)
                    .await
                    .expect("failed to write output file");
                log::info!("Written to {}", output_path);
            } else {
                use std::io::Write;
                std::io::stdout()
                    .write_all(&data)
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
