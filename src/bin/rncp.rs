use std::path::PathBuf;
use std::time::Instant;

use rinse::{AsyncNode, AsyncTcpTransport, Identity, Interface, ServiceEvent, ServiceId};
use tokio::net::TcpListener;

const APP_NAME: &str = "rncp";

fn size_str(num: f64) -> String {
    let units = ["", "K", "M", "G", "T", "P"];
    let mut n = num;
    for unit in &units {
        if n.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{:.0} B", n)
            } else {
                format!("{:.2} {}B", n, unit)
            };
        }
        n /= 1000.0;
    }
    format!("{:.2} YB", n)
}

fn prettyhexrep(hash: &[u8]) -> String {
    let hex = hex::encode(hash);
    format!("<{}>", hex)
}

struct Args {
    listen: bool,
    fetch: bool,
    file: Option<String>,
    destination: Option<String>,
    connect: Option<String>,
    listen_addr: String,
    save_dir: Option<String>,
    silent: bool,
    verbose: bool,
    no_compress: bool,
    timeout: u64,
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut result = Args {
        listen: false,
        fetch: false,
        file: None,
        destination: None,
        connect: None,
        listen_addr: "0.0.0.0:4242".to_string(),
        save_dir: None,
        silent: false,
        verbose: false,
        no_compress: false,
        timeout: 120,
    };

    let mut positional = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-l" | "--listen" => {
                result.listen = true;
                i += 1;
            }
            "-f" | "--fetch" => {
                result.fetch = true;
                i += 1;
            }
            "-S" | "--silent" => {
                result.silent = true;
                i += 1;
            }
            "-v" | "--verbose" => {
                result.verbose = true;
                i += 1;
            }
            "-C" | "--no-compress" => {
                result.no_compress = true;
                i += 1;
            }
            "--connect" => {
                result.connect = Some(args.get(i + 1).expect("--connect requires address").clone());
                i += 2;
            }
            "--listen-addr" => {
                result.listen_addr = args
                    .get(i + 1)
                    .expect("--listen-addr requires address")
                    .clone();
                i += 2;
            }
            "-s" | "--save" => {
                result.save_dir = Some(args.get(i + 1).expect("--save requires path").clone());
                i += 2;
            }
            "-w" => {
                result.timeout = args
                    .get(i + 1)
                    .expect("-w requires seconds")
                    .parse()
                    .expect("invalid timeout");
                i += 2;
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                std::process::exit(0);
            }
            "--version" => {
                println!("rncp 0.1.0 (rinse)");
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') => {
                positional.push(arg.to_string());
                i += 1;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    if !positional.is_empty() {
        result.file = Some(positional[0].clone());
    }
    if positional.len() >= 2 {
        result.destination = Some(positional[1].clone());
    }

    result
}

fn print_usage(program: &str) {
    eprintln!("Reticulum File Transfer Utility (Rust)");
    eprintln!();
    eprintln!("Usage:");
    eprintln!(
        "  {} <file> <destination>     Send file to destination",
        program
    );
    eprintln!(
        "  {} -f <file> <destination>  Fetch file from destination",
        program
    );
    eprintln!(
        "  {} -l                        Listen for incoming transfers",
        program
    );
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -l, --listen       Listen for incoming transfers");
    eprintln!("  -f, --fetch        Fetch file from remote instead of sending");
    eprintln!("  -v, --verbose      Enable debug logging");
    eprintln!("  -S, --silent       Disable progress output");
    eprintln!("  -C, --no-compress  Disable compression");
    eprintln!("  -s, --save <path>  Save received files to directory");
    eprintln!("  -w <seconds>       Timeout (default: 120)");
    eprintln!("  --connect <addr>   Connect to TCP address");
    eprintln!("  --listen-addr <addr>  Listen address (default: 0.0.0.0:4242)");
    eprintln!("  -h, --help         Show this help");
    eprintln!("  --version          Show version");
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    let log_level = if args.verbose { "debug" } else { "warn" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    if args.listen {
        listen(args).await;
    } else if args.fetch {
        fetch(args).await;
    } else if args.file.is_some() && args.destination.is_some() {
        send(args).await;
    } else {
        print_usage(&std::env::args().next().unwrap_or_default());
        std::process::exit(1);
    }
}

async fn listen(args: Args) {
    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());

    let service = node.add_service(APP_NAME, &["fetch_file"], &identity);
    let addr = node.service_address(service).unwrap();

    println!("rncp listening on {}", prettyhexrep(&addr));

    let save_dir = args.save_dir.map(PathBuf::from);
    if let Some(ref dir) = save_dir
        && !dir.is_dir()
    {
        eprintln!("Save directory does not exist: {}", dir.display());
        std::process::exit(1);
    }

    if let Some(connect_addr) = &args.connect {
        log::info!("Connecting to {}", connect_addr);
        match AsyncTcpTransport::connect(connect_addr).await {
            Ok(transport) => {
                node.add_interface(Interface::new(transport));
            }
            Err(e) => {
                eprintln!("Failed to connect: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        log::info!("Listening on {}", args.listen_addr);
        let listener = TcpListener::bind(&args.listen_addr)
            .await
            .expect("failed to bind");
        tokio::spawn(accept_loop(listener, node.clone()));
    }

    node.announce(service);

    let node_clone = node.clone();
    let no_compress = args.no_compress;
    tokio::spawn(async move {
        handle_listen_events(node_clone, service, save_dir, no_compress).await;
    });

    node.run().await;
}

async fn accept_loop(listener: TcpListener, node: AsyncNode<AsyncTcpTransport>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                log::info!("Accepted connection from {}", peer);
                if let Ok(transport) = AsyncTcpTransport::from_stream(peer.to_string(), stream) {
                    node.add_interface(Interface::new(transport));
                }
            }
            Err(e) => {
                log::warn!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_listen_events(
    node: AsyncNode<AsyncTcpTransport>,
    service: ServiceId,
    save_dir: Option<PathBuf>,
    no_compress: bool,
) {
    loop {
        let Some(event) = node.receive(service).await else {
            break;
        };

        match event {
            ServiceEvent::Request {
                request_id,
                path,
                data,
                ..
            } => {
                if path == "fetch_file" {
                    let file_path_str = String::from_utf8_lossy(&data);
                    let file_path = PathBuf::from(file_path_str.as_ref());

                    log::info!("Fetch request for: {}", file_path.display());

                    if file_path.is_file() {
                        match tokio::fs::read(&file_path).await {
                            Ok(file_data) => {
                                let filename = file_path
                                    .file_name()
                                    .map(|s| s.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let metadata =
                                    rmp_serde::to_vec(&[("name", filename)]).unwrap_or_default();

                                println!(
                                    "Sending {} ({}) to client",
                                    file_path.display(),
                                    size_str(file_data.len() as f64)
                                );

                                if let Err(e) = node
                                    .respond(
                                        service,
                                        request_id,
                                        &file_data,
                                        Some(&metadata),
                                        !no_compress,
                                    )
                                    .await
                                {
                                    log::warn!("Failed to send file: {:?}", e);
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to read file: {}", e);
                                let _ = node.respond(service, request_id, b"", None, false).await;
                            }
                        }
                    } else {
                        log::warn!("File not found: {}", file_path.display());
                        let _ = node.respond(service, request_id, b"", None, false).await;
                    }
                }
            }
            ServiceEvent::ResourceProgress {
                received_bytes,
                total_bytes,
                ..
            } => {
                let pct = if total_bytes > 0 {
                    (received_bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };
                eprint!(
                    "\rReceiving: {} / {} ({:.1}%)    ",
                    size_str(received_bytes as f64),
                    size_str(total_bytes as f64),
                    pct
                );
            }
            ServiceEvent::RequestResult { result, .. } => {
                eprintln!();
                match result {
                    Ok((_, data, metadata)) => {
                        let filename =
                            extract_filename(&metadata).unwrap_or("received_file".into());
                        let save_path = if let Some(ref dir) = save_dir {
                            dir.join(&filename)
                        } else {
                            PathBuf::from(&filename)
                        };

                        let final_path = unique_path(&save_path);
                        if let Err(e) = tokio::fs::write(&final_path, &data).await {
                            eprintln!("Failed to save file: {}", e);
                        } else {
                            println!(
                                "Received {} ({})",
                                final_path.display(),
                                size_str(data.len() as f64)
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Transfer failed: {:?}", e);
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_filename(metadata: &Option<Vec<u8>>) -> Option<String> {
    let data = metadata.as_ref()?;
    let parsed: Vec<(&str, String)> = rmp_serde::from_slice(data).ok()?;
    parsed
        .into_iter()
        .find(|(k, _)| *k == "name")
        .map(|(_, v)| v)
}

fn unique_path(path: &std::path::Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }
    let mut counter = 1;
    loop {
        let new_path = PathBuf::from(format!("{}.{}", path.display(), counter));
        if !new_path.exists() {
            return new_path;
        }
        counter += 1;
    }
}

async fn send(args: Args) {
    let file_path = PathBuf::from(args.file.as_ref().unwrap());
    let dest_hex = args.destination.as_ref().unwrap();

    if !file_path.is_file() {
        eprintln!("File not found: {}", file_path.display());
        std::process::exit(1);
    }

    let dest_hash: [u8; 16] = hex::decode(dest_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| {
            eprintln!("Invalid destination hash (must be 32 hex chars)");
            std::process::exit(1);
        });

    let file_data = std::fs::read(&file_path).unwrap_or_else(|e| {
        eprintln!("Failed to read file: {}", e);
        std::process::exit(1);
    });

    let filename = file_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let connect_addr = args.connect.unwrap_or_else(|| {
        eprintln!("Error: --connect is required");
        std::process::exit(1);
    });

    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());
    let service = node.add_service(APP_NAME, &[], &identity);

    if !args.silent {
        eprint!("Connecting to relay... ");
    }

    match AsyncTcpTransport::connect(&connect_addr).await {
        Ok(transport) => {
            node.add_interface(Interface::new(transport));
        }
        Err(e) => {
            eprintln!("failed: {}", e);
            std::process::exit(1);
        }
    }

    if !args.silent {
        eprintln!("ok");
    }

    let node_clone = node.clone();
    let node_task = tokio::spawn(async move {
        node.run().await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let start_time = Instant::now();
    let timeout = std::time::Duration::from_secs(args.timeout);
    let silent = args.silent;

    let node_for_progress = node_clone.clone();
    let silent_clone = silent;
    let progress_task = tokio::spawn(async move {
        loop {
            match node_for_progress.receive(service).await {
                Some(ServiceEvent::ResourceProgress {
                    received_bytes,
                    total_bytes,
                    ..
                }) => {
                    if !silent_clone {
                        let pct = if total_bytes > 0 {
                            (received_bytes as f64 / total_bytes as f64) * 100.0
                        } else {
                            0.0
                        };
                        eprint!(
                            "\rSending: {} / {} ({:.1}%)    ",
                            size_str(received_bytes as f64),
                            size_str(total_bytes as f64),
                            pct
                        );
                    }
                }
                Some(ServiceEvent::RequestResult { .. }) => {
                    break;
                }
                _ => {}
            }
        }
    });

    if !silent {
        eprint!(
            "Sending {} ({}) to {}... ",
            filename,
            size_str(file_data.len() as f64),
            prettyhexrep(&dest_hash)
        );
    }

    let result = tokio::time::timeout(
        timeout,
        node_clone.request(service, dest_hash, "receive_file", &file_data),
    )
    .await;

    progress_task.abort();
    let elapsed = start_time.elapsed();

    match result {
        Ok(Ok(_)) => {
            if !silent {
                let speed = file_data.len() as f64 / elapsed.as_secs_f64();
                eprintln!();
                println!(
                    "Transfer complete: {} in {:.1}s ({}ps)",
                    size_str(file_data.len() as f64),
                    elapsed.as_secs_f64(),
                    size_str(speed)
                );
                println!(
                    "{} copied to {}",
                    file_path.display(),
                    prettyhexrep(&dest_hash)
                );
            }
        }
        Ok(Err(e)) => {
            eprintln!("failed: {:?}", e);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("timed out after {}s", args.timeout);
            std::process::exit(1);
        }
    }

    node_task.abort();
}

async fn fetch(args: Args) {
    let remote_path = args.file.unwrap_or_else(|| {
        eprintln!("File path required");
        std::process::exit(1);
    });
    let dest_hex = args.destination.unwrap_or_else(|| {
        eprintln!("Destination required");
        std::process::exit(1);
    });

    let dest_hash: [u8; 16] = hex::decode(&dest_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| {
            eprintln!("Invalid destination hash (must be 32 hex chars)");
            std::process::exit(1);
        });

    let connect_addr = args.connect.unwrap_or_else(|| {
        eprintln!("Error: --connect is required");
        std::process::exit(1);
    });

    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(false);
    let identity = Identity::generate(&mut rand::thread_rng());
    let service = node.add_service(APP_NAME, &[], &identity);

    if !args.silent {
        eprint!("Connecting to relay... ");
    }

    match AsyncTcpTransport::connect(&connect_addr).await {
        Ok(transport) => {
            node.add_interface(Interface::new(transport));
        }
        Err(e) => {
            eprintln!("failed: {}", e);
            std::process::exit(1);
        }
    }

    if !args.silent {
        eprintln!("ok");
    }

    let node_clone = node.clone();
    let node_task = tokio::spawn(async move {
        node.run().await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let silent = args.silent;
    let timeout = std::time::Duration::from_secs(args.timeout);
    let save_dir = args.save_dir.map(PathBuf::from);

    if !silent {
        eprint!(
            "Requesting {} from {}... ",
            remote_path,
            prettyhexrep(&dest_hash)
        );
    }

    let start_time = Instant::now();

    let node_for_progress = node_clone.clone();
    let silent_clone = silent;
    let progress_task = tokio::spawn(async move {
        loop {
            match node_for_progress.receive(service).await {
                Some(ServiceEvent::ResourceProgress {
                    received_bytes,
                    total_bytes,
                    ..
                }) => {
                    if !silent_clone {
                        let pct = if total_bytes > 0 {
                            (received_bytes as f64 / total_bytes as f64) * 100.0
                        } else {
                            0.0
                        };
                        eprint!(
                            "\rTransferring: {} / {} ({:.1}%)    ",
                            size_str(received_bytes as f64),
                            size_str(total_bytes as f64),
                            pct
                        );
                    }
                }
                Some(ServiceEvent::RequestResult { .. }) => {
                    break;
                }
                _ => {}
            }
        }
    });

    let result = tokio::time::timeout(
        timeout,
        node_clone.request(service, dest_hash, "fetch_file", remote_path.as_bytes()),
    )
    .await;

    progress_task.abort();
    let elapsed = start_time.elapsed();

    match result {
        Ok(Ok((data, metadata))) => {
            if data.is_empty() {
                eprintln!("File not found on remote");
                std::process::exit(1);
            }

            let filename = extract_filename(&metadata).unwrap_or_else(|| {
                PathBuf::from(&remote_path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or("fetched_file".into())
            });

            let save_path = if let Some(ref dir) = save_dir {
                dir.join(&filename)
            } else {
                PathBuf::from(&filename)
            };

            let final_path = unique_path(&save_path);

            if let Err(e) = tokio::fs::write(&final_path, &data).await {
                eprintln!("Failed to save file: {}", e);
                std::process::exit(1);
            }

            if !silent {
                let speed = data.len() as f64 / elapsed.as_secs_f64();
                println!(
                    "complete ({} in {:.1}s, {}ps)",
                    size_str(data.len() as f64),
                    elapsed.as_secs_f64(),
                    size_str(speed)
                );
                println!(
                    "{} fetched from {}",
                    final_path.display(),
                    prettyhexrep(&dest_hash)
                );
            }
        }
        Ok(Err(e)) => {
            eprintln!("Fetch failed: {:?}", e);
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("Fetch timed out");
            std::process::exit(1);
        }
    }

    node_task.abort();
}
