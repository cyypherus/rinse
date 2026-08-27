mod common;

use bytes::Bytes;
use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{
    Destination, InterfaceLimits, NodeBuilder, NodeConfig, RequestPath, ServiceConfig, ServiceName,
};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config = Config::load_from(".rinse/config.toml").expect("failed to load config");
    let identity =
        load_or_create_persistent_identity(".rinse/identity").expect("failed to load identity");
    let mut args = std::env::args().skip(1);
    let destination = args.next().unwrap_or_else(|| usage());
    let path = args.next().unwrap_or_else(|| usage());
    let mut output = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--output" | "-o" => output = Some(args.next().unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }
    let destination = Destination::from_bytes(
        hex::decode(destination)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or_else(|| {
                eprintln!("destination must be 32 hex characters");
                std::process::exit(1);
            }),
    );
    let mode = if config.network.relay {
        NodeConfig::relay()
    } else {
        NodeConfig::endpoint()
    };
    let mut builder = NodeBuilder::new(mode);
    for (name, interface) in config.enabled_interfaces() {
        if let InterfaceConfig::TCPClientInterface {
            target_host,
            target_port,
            ..
        } = interface
        {
            let address = format!("{target_host}:{target_port}");
            match common::TcpHdlc::connect(&address).await {
                Ok(interface) => {
                    builder = builder.interface(interface, interface_limits());
                    log::info!("[{name}] connected to {address}");
                }
                Err(error) => log::warn!("[{name}] failed to connect to {address}: {error}"),
            }
        }
    }
    let (node, task) = builder.build().expect("failed to build node");
    let running = tokio::spawn(task.run());
    let service = node
        .register_service(
            ServiceConfig::new(
                ServiceName::new("nomadnetwork.node").unwrap(),
                identity,
                [],
                None,
            )
            .unwrap(),
        )
        .await
        .expect("failed to register local service");
    let link = node
        .open_link(destination)
        .await
        .expect("failed to establish link");
    let sender = link.send_handle();
    service
        .identify_on(&sender)
        .await
        .expect("failed to identify link");
    let response = sender
        .request(RequestPath::new(path).unwrap(), Bytes::new())
        .await
        .expect("request failed");
    if let Some(path) = output {
        std::fs::write(&path, &response).expect("failed to write response");
        log::info!("wrote {} bytes to {path}", response.len());
    } else {
        use std::io::Write;
        std::io::stdout()
            .write_all(&response)
            .expect("failed to write response");
    }
    node.shutdown().await;
    running.await.unwrap().unwrap();
}

fn interface_limits() -> InterfaceLimits {
    InterfaceLimits::new(65_535, 256, 1_048_576).unwrap()
}

fn usage() -> ! {
    eprintln!("usage: request <destination> <path> [-o <file>]");
    std::process::exit(1)
}
