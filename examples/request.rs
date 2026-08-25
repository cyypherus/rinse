use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{Interface, NodeBuilder, TcpTransport};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load_from(".rinse/config.toml").expect("failed to load config");
    let identity =
        load_or_create_persistent_identity(".rinse/identity").expect("failed to load identity");

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

    let mut builder: NodeBuilder<TcpTransport> = if config.network.relay {
        NodeBuilder::packet_forwarding_relay()
    } else {
        NodeBuilder::non_forwarding_endpoint()
    };
    let service = builder
        .register_local_service("nomadnetwork.node", &[], &identity)
        .id;

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
                    builder.add_initial_interface(Interface::new(transport));
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

    let (node, runtime) = builder.build();
    let node_clone = node.clone();
    let node_task = tokio::spawn(runtime.run());

    let link = node_clone
        .establish_link_from(service, node_id)
        .await
        .expect("Failed to establish link");
    let response = node_clone.request(link, &path, &[]).await;

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
