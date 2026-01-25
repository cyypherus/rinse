mod app;
mod config;
mod identity;
mod network;
mod tui;

use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;

use rinse::{AsyncTcpTransport, Interface, RequestError, ServiceEvent};

use tokio::sync::{mpsc, oneshot};

use app::NomadApp;
use config::{Config, InterfaceConfig};
use network::{NetworkClient, NodeRegistry};
use simplelog::{Config as LogConfig, LevelFilter, WriteLogger};
use tui::{InterfaceInfo, InterfaceKind, NetworkEvent, TuiApp, TuiCommand};

struct FetchReq {
    dest: [u8; 16],
    path: String,
    form_data: HashMap<String, String>,
    identify: bool,
    reply: oneshot::Sender<Result<Vec<u8>, String>>,
}

enum InternalCmd {
    Fetch(FetchReq),
    GetStats(oneshot::Sender<rinse::StatsSnapshot>),
}

fn build_interface_info(config: &Config, status: &HashMap<String, bool>) -> Vec<InterfaceInfo> {
    config
        .enabled_interfaces()
        .iter()
        .map(|(name, iface_config)| {
            let (kind, address) = match iface_config {
                InterfaceConfig::TCPClientInterface {
                    target_host,
                    target_port,
                    ..
                } => (
                    InterfaceKind::TcpClient,
                    format!("{}:{}", target_host, target_port),
                ),
                InterfaceConfig::TCPServerInterface {
                    listen_ip,
                    listen_port,
                    ..
                } => (
                    InterfaceKind::TcpServer,
                    format!("{}:{}", listen_ip, listen_port),
                ),
            };
            let connected = status.get(*name).copied().unwrap_or(false);
            InterfaceInfo {
                name: name.to_string(),
                kind,
                address,
                connected,
            }
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(".rinse")?;
    let log_file = File::create(".rinse/nomad.log")?;
    WriteLogger::init(LevelFilter::Trace, LogConfig::default(), log_file)?;

    log::info!("Starting Nomad...");

    let config = Config::load()?;
    let interface_configs: HashMap<String, InterfaceConfig> = config
        .enabled_interfaces()
        .into_iter()
        .map(|(name, cfg)| (name.to_string(), cfg.clone()))
        .collect();

    let (
        node,
        service_id,
        dest_hash,
        relay_enabled,
        interface_info,
        identity,
        announced_on_startup,
    ) = {
        let mut nomad = NomadApp::new().await?;
        let dest_hash = nomad.dest_hash();
        let relay_enabled = nomad.relay_enabled();
        let interface_info = build_interface_info(&config, nomad.interface_status());
        let announced_on_startup = nomad.announced_on_startup();
        let node = nomad.take_node();
        let service_id = nomad.take_service_id();
        let identity = nomad.take_identity();
        (
            node,
            service_id,
            dest_hash,
            relay_enabled,
            interface_info,
            identity,
            announced_on_startup,
        )
    };

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(100);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<TuiCommand>(100);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (internal_tx, mut internal_rx) = mpsc::channel::<InternalCmd>(32);

    let registry = NodeRegistry::new(".rinse/nodes.toml");
    let initial_nodes: Vec<_> = registry.all().into_iter().cloned().collect();
    let network_client = Arc::new(NetworkClient::new(registry));

    let network_client_clone = network_client.clone();
    let event_tx_clone = event_tx.clone();
    let internal_tx_stats = internal_tx.clone();

    let node_for_run = Arc::try_unwrap(node)
        .ok()
        .expect("node still has multiple references")
        .into_inner();
    let node_clone = node_for_run.clone();

    let node_task = tokio::spawn(async move {
        node_for_run.run().await;
    });

    let node = Arc::new(node_clone);
    let node_for_network = node.clone();
    let node_for_receive = node.clone();

    let network_task = tokio::spawn(async move {
        let node = node_for_network;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    log::info!("Shutdown signal received");
                    break;
                }
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        TuiCommand::Announce => {
                            let _ = event_tx_clone.send(NetworkEvent::Status("Announcing...".to_string())).await;
                            log::info!("Announce command received");
                            node.announce(service_id);
                            log::info!("Announce completed");
                            let _ = event_tx_clone.send(NetworkEvent::AnnounceSent).await;
                        }
                        TuiCommand::FetchPage { node: target_node, path, form_data } => {
                            log::info!("FetchPage command received: {} path={} form_data={:?}", target_node.hash_hex(), path, form_data);
                            let url = format!("{}:{}", target_node.hash_hex(), path);
                            let event_tx = event_tx_clone.clone();
                            let internal_tx = internal_tx.clone();

                            tokio::spawn(async move {
                                log::info!("Spawned fetch task for {}", url);
                                let _ = event_tx.send(NetworkEvent::Status("Sending request...".into())).await;

                                let (reply_tx, reply_rx) = oneshot::channel();
                                log::info!("Sending InternalCmd::Fetch");
                                let _ = internal_tx.send(InternalCmd::Fetch(FetchReq {
                                    dest: target_node.hash,
                                    path: path.clone(),
                                    form_data,
                                    identify: target_node.identify,
                                    reply: reply_tx,
                                })).await;
                                log::info!("InternalCmd::Fetch sent, waiting for reply");

                                let _ = event_tx.send(NetworkEvent::Status("Awaiting response...".into())).await;

                                match reply_rx.await {
                                    Ok(Ok(data)) => {
                                        let _ = event_tx.send(NetworkEvent::PageReceived { url, data }).await;
                                    }
                                    Ok(Err(e)) => {
                                        let _ = event_tx.send(NetworkEvent::PageFailed { url, reason: e }).await;
                                    }
                                    Err(_) => {
                                        let _ = event_tx.send(NetworkEvent::PageFailed { url, reason: "Request cancelled".into() }).await;
                                    }
                                }
                            });
                        }
                        TuiCommand::DownloadFile { node: target_node, path, filename } => {
                            log::info!("Download requested: {} from {} path={}", filename, target_node.name, path);
                            let event_tx = event_tx_clone.clone();
                            let internal_tx = internal_tx.clone();

                            tokio::spawn(async move {
                                let _ = event_tx.send(NetworkEvent::Status(format!("Downloading {}...", filename))).await;

                                let (reply_tx, reply_rx) = oneshot::channel();
                                let _ = internal_tx.send(InternalCmd::Fetch(FetchReq {
                                    dest: target_node.hash,
                                    path,
                                    form_data: HashMap::new(),
                                    identify: target_node.identify,
                                    reply: reply_tx,
                                })).await;

                                match reply_rx.await {
                                    Ok(Ok(data)) => {
                                        let download_dir = std::path::Path::new(".rinse/downloads");
                                        if let Err(e) = std::fs::create_dir_all(download_dir) {
                                            let _ = event_tx.send(NetworkEvent::DownloadFailed {
                                                filename,
                                                reason: format!("Failed to create downloads dir: {}", e),
                                            }).await;
                                            return;
                                        }

                                        let file_path = download_dir.join(&filename);
                                        log::info!("Writing {} bytes to {:?}", data.len(), file_path);
                                        match std::fs::write(&file_path, &data) {
                                            Ok(_) => {
                                                log::info!("Download complete: {:?}", file_path);
                                                let _ = event_tx.send(NetworkEvent::DownloadComplete {
                                                    filename,
                                                    path: file_path.display().to_string(),
                                                }).await;
                                            }
                                            Err(e) => {
                                                log::error!("Failed to write file: {}", e);
                                                let _ = event_tx.send(NetworkEvent::DownloadFailed {
                                                    filename,
                                                    reason: format!("Failed to write file: {}", e),
                                                }).await;
                                            }
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        log::error!("Download failed: {}", e);
                                        let _ = event_tx.send(NetworkEvent::DownloadFailed {
                                            filename,
                                            reason: e,
                                        }).await;
                                    }
                                    Err(_) => {
                                        let _ = event_tx.send(NetworkEvent::DownloadFailed {
                                            filename,
                                            reason: "Request cancelled".into(),
                                        }).await;
                                    }
                                }
                            });
                        }
                        TuiCommand::Reconnect { name } => {
                            log::info!("Reconnect requested for interface: {}", name);
                            if let Some(iface_config) = interface_configs.get(&name) {
                                let addr = match iface_config {
                                    InterfaceConfig::TCPClientInterface { target_host, target_port, .. } => {
                                        format!("{}:{}", target_host, target_port)
                                    }
                                    InterfaceConfig::TCPServerInterface { listen_ip, listen_port, .. } => {
                                        format!("{}:{}", listen_ip, listen_port)
                                    }
                                };
                                let event_tx = event_tx_clone.clone();
                                let name_clone = name.clone();
                                let node = node.clone();
                                tokio::spawn(async move {
                                    let _ = event_tx.send(NetworkEvent::Status(
                                        format!("Connecting to {}...", name_clone)
                                    )).await;
                                    match AsyncTcpTransport::connect(&addr).await {
                                        Ok(transport) => {
                                            node.add_interface(Interface::new(transport));
                                            log::info!("Reconnected to {}", name_clone);
                                            let _ = event_tx.send(NetworkEvent::InterfaceStatus {
                                                name: name_clone.clone(),
                                                connected: true,
                                            }).await;
                                            let _ = event_tx.send(NetworkEvent::Status(
                                                format!("Connected to {}", name_clone)
                                            )).await;
                                        }
                                        Err(e) => {
                                            log::warn!("Failed to reconnect to {}: {}", name_clone, e);
                                            let _ = event_tx.send(NetworkEvent::InterfaceStatus {
                                                name: name_clone.clone(),
                                                connected: false,
                                            }).await;
                                            let _ = event_tx.send(NetworkEvent::Status(
                                                format!("Failed to connect to {}: {}", name_clone, e)
                                            )).await;
                                        }
                                    }
                                });
                            } else {
                                log::warn!("Unknown interface: {}", name);
                            }
                        }
                        TuiCommand::SaveNode { node: target_node } => {
                            log::info!("Saving node: {} ({})", target_node.name, target_node.hash_hex());
                            network_client_clone.registry_mut().await.save(target_node);
                        }
                        TuiCommand::RemoveNode { hash } => {
                            log::info!("Removing node: {}", hex::encode(hash));
                            network_client_clone.registry_mut().await.remove(&hash);
                        }
                        TuiCommand::ToggleNodeIdentify { hash } => {
                            log::info!("Toggling self-identify for node: {}", hex::encode(hash));
                            network_client_clone.registry_mut().await.toggle_identify(&hash);
                        }
                    }
                }
                Some(cmd) = internal_rx.recv() => {
                    match cmd {
                        InternalCmd::Fetch(req) => {
                            log::info!("Processing fetch request: dest={} path={} identify={} form_data={:?}", hex::encode(req.dest), req.path, req.identify, req.form_data);
                            let request_data = build_page_request(&req.form_data);
                            let node = node.clone();
                            let path = req.path.clone();
                            let identity_for_req = identity.inner().clone();

                            tokio::spawn(async move {
                                if !node.request_path(req.dest).await {
                                    log::error!("Path request failed");
                                    let _ = req.reply.send(Err("Path not found".to_string()));
                                    return;
                                }

                                let Some(link) = node.establish_link(service_id, req.dest).await else {
                                    log::error!("Failed to establish link");
                                    let _ = req.reply.send(Err("Failed to establish link".to_string()));
                                    return;
                                };

                                if req.identify {
                                    log::info!("Self-identify enabled, identifying before request");
                                    node.self_identify(link, &identity_for_req);
                                }

                                log::info!("Calling node.request()");
                                let result = match node.request(service_id, link, &path, &request_data).await {
                                    Ok((response, _metadata)) => {
                                        log::info!("Got response: {} bytes", response.len());
                                        Ok(response)
                                    }
                                    Err(e) => {
                                        log::error!("Request failed: {:?}", e);
                                        let msg = match e {
                                            RequestError::Timeout => "Request timed out".to_string(),
                                            RequestError::LinkFailed => "Failed to establish link".to_string(),
                                            RequestError::LinkClosed => "Link closed".to_string(),
                                            RequestError::TransferFailed => "Transfer failed".to_string(),
                                        };
                                        Err(msg)
                                    }
                                };
                                log::info!("Sending reply");
                                let _ = req.reply.send(result);
                            });
                        }
                        InternalCmd::GetStats(reply) => {
                            let stats = node.stats().await;
                            let _ = reply.send(stats);
                        }
                    }
                }
            }
        }
    });

    let network_client_for_receive = network_client.clone();
    let event_tx_receive = event_tx.clone();
    let receive_task = tokio::spawn(async move {
        loop {
            match node_for_receive.recv(service_id).await {
                Some(ServiceEvent::DestinationsChanged) => {
                    let destinations = node_for_receive.known_destinations().await;
                    network_client_for_receive
                        .handle_destinations_changed(destinations)
                        .await;
                }
                Some(ServiceEvent::ResourceProgress {
                    received_bytes,
                    total_bytes,
                    ..
                }) => {
                    let _ = event_tx_receive
                        .send(NetworkEvent::ResourceProgress {
                            received_bytes,
                            total_bytes,
                        })
                        .await;
                }
                _ => {}
            }
        }
    });

    let mut node_announces = network_client.node_announces();
    let event_tx_announce = event_tx.clone();

    let announce_task = tokio::spawn(async move {
        while let Ok(node) = node_announces.recv().await {
            log::info!("Node announce: {} ({})", node.name, node.hash_hex());
            let _ = event_tx_announce
                .send(NetworkEvent::NodeAnnounce(node))
                .await;
        }
    });

    let event_tx_stats = event_tx.clone();
    let stats_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let (reply_tx, reply_rx) = oneshot::channel();
            if internal_tx_stats
                .send(InternalCmd::GetStats(reply_tx))
                .await
                .is_ok()
            {
                if let Ok(stats) = reply_rx.await {
                    let _ = event_tx_stats.send(NetworkEvent::RelayStats(stats)).await;
                }
            }
        }
    });

    let tui_result = tokio::task::spawn_blocking(move || {
        let mut tui = TuiApp::new(
            dest_hash,
            initial_nodes,
            relay_enabled,
            interface_info,
            announced_on_startup,
            event_rx,
            cmd_tx,
        )?;
        tui.run()
    })
    .await?;

    let _ = shutdown_tx.send(()).await;
    let _ = network_task.await;
    announce_task.abort();
    stats_task.abort();
    receive_task.abort();
    node_task.abort();

    tui_result?;
    Ok(())
}

fn build_page_request(form_data: &HashMap<String, String>) -> Vec<u8> {
    if form_data.is_empty() {
        Vec::new()
    } else {
        rmp_serde::to_vec(form_data).unwrap_or_default()
    }
}
