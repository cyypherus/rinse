mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{
    IncomingRequest, Link, LinkEvent, NodeHandle, RatchetAction, RequestPath, Service,
    ServiceConfig, ServiceEvent, ServiceName,
};
use tokio::net::TcpListener;

type Files = Arc<HashMap<String, Vec<u8>>>;

fn load_directory(base: &Path, current: &Path, files: &mut HashMap<String, Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
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
            if RequestPath::new(request_path.clone()).is_ok() {
                files.insert(request_path, data);
            } else {
                log::warn!("skipping unsupported request path {request_path}");
            }
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
    let directory = args
        .next()
        .expect("usage: serve <directory> [service-name]");
    let service_name = args.next().unwrap_or_else(|| "files".into());
    let directory = Path::new(&directory)
        .canonicalize()
        .expect("invalid directory");
    let mut files = HashMap::new();
    load_directory(&directory, &directory, &mut files);
    let request_paths: Vec<_> = files
        .keys()
        .map(|path| RequestPath::new(path.clone()).unwrap())
        .collect();
    let files = Arc::new(files);
    let mut builder = common::node_builder(config.network.relay);
    let mut listeners = Vec::new();
    for (name, interface) in config.enabled_interfaces() {
        match interface {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let address = format!("{target_host}:{target_port}");
                match common::TcpHdlc::connect(&address).await {
                    Ok(interface) => {
                        builder = builder.interface(interface, common::interface_limits());
                        log::info!("[{name}] connected to {address}");
                    }
                    Err(error) => log::warn!("[{name}] failed to connect to {address}: {error}"),
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
                    Err(error) => log::warn!("[{name}] failed to listen on {address}: {error}"),
                }
            }
        }
    }
    let (node, task) = builder.build().expect("failed to build node");
    let running = tokio::spawn(task.run());
    for listener in listeners {
        tokio::spawn(accept_connections(listener, node.clone()));
    }
    let service = node
        .register_service(
            ServiceConfig::new(
                ServiceName::new(service_name).expect("invalid service name"),
                identity,
                request_paths,
                None,
            )
            .expect("invalid service configuration"),
        )
        .await
        .expect("failed to register service");
    log::info!(
        "serving {} files from {} at {}",
        files.len(),
        directory.display(),
        hex::encode(service.destination().as_bytes())
    );
    serve(service, files).await;
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
            .attach_interface(interface, common::interface_limits())
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn serve(mut service: Service, files: Files) {
    let mut announcements = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = announcements.tick() => {
                if let Err(error) = service.announce(Bytes::new(), RatchetAction::Keep).await {
                    log::warn!("announce failed: {error:?}");
                }
            }
            event = service.receive() => match event {
                Ok(ServiceEvent::IncomingLink(link)) => match link.accept().await {
                    Ok(link) => { tokio::spawn(serve_link(link, files.clone())); }
                    Err(error) => log::warn!("link acceptance failed: {error:?}"),
                },
                Ok(_) => {},
                Err(_) => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
}

async fn serve_link(mut link: Link, files: Files) {
    while let Ok(event) = link.receive().await {
        if let LinkEvent::Request(request) = event {
            respond(request, &files).await;
        }
    }
}

async fn respond(request: IncomingRequest, files: &HashMap<String, Vec<u8>>) {
    let body = files
        .get(request.path().as_str())
        .cloned()
        .unwrap_or_else(|| b"error: not found".to_vec());
    if let Err(error) = request.respond(Bytes::from(body)).await {
        log::warn!("response failed: {error:?}");
    }
}
