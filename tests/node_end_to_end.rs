use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
#[cfg(feature = "tcp")]
use rinse::TcpHdlcInterface;
use rinse::{
    BufferChunk, ChannelMessage, ChannelReceive, InboundPacket, Interface, InterfaceError,
    InterfaceLimits, Link, LinkEvent, MessageType, NodeBuilder, NodeConfig, NodeError,
    OutboundPacket, PrivateIdentity, RatchetAction, RequestPath, Service, ServiceConfig,
    ServiceEvent, ServiceName, StreamId,
};

struct MemoryInterface {
    inbound: Pin<Box<async_channel::Receiver<Vec<u8>>>>,
    outbound: async_channel::Sender<Vec<u8>>,
    forward: Arc<AtomicBool>,
}

impl Interface for MemoryInterface {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        self.inbound
            .recv()
            .await
            .map(InboundPacket::new)
            .map_err(|_| InterfaceError::Closed)
    }

    async fn send(&self, packet: OutboundPacket) -> Result<(), InterfaceError> {
        if !self.forward.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.outbound
            .try_send(packet.into_bytes())
            .map_err(|_| InterfaceError::Closed)
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        Ok(())
    }
}

fn connected_interfaces() -> (MemoryInterface, MemoryInterface, [Arc<AtomicBool>; 2]) {
    let (left, left_inbound) = async_channel::unbounded();
    let (right, right_inbound) = async_channel::unbounded();
    let left_forward = Arc::new(AtomicBool::new(true));
    let right_forward = Arc::new(AtomicBool::new(true));
    (
        MemoryInterface {
            inbound: Box::pin(left_inbound),
            outbound: right,
            forward: left_forward.clone(),
        },
        MemoryInterface {
            inbound: Box::pin(right_inbound),
            outbound: left,
            forward: right_forward.clone(),
        },
        [left_forward, right_forward],
    )
}

fn node(interface: MemoryInterface) -> (rinse::NodeHandle, rinse::NodeTask) {
    NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            interface,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap()
}

async fn service(node: &rinse::NodeHandle, name: &str, paths: &[&str]) -> Service {
    let mut secret = [0; 64];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    node.register_service(
        ServiceConfig::new(
            ServiceName::new(name).unwrap(),
            PrivateIdentity::from_secret_bytes(secret).unwrap(),
            paths.iter().map(|path| RequestPath::new(*path).unwrap()),
            None,
        )
        .unwrap(),
    )
    .await
    .unwrap()
}

async fn accept_link(service: &mut Service) -> Link {
    loop {
        if let ServiceEvent::IncomingLink(link) = service.receive().await.unwrap() {
            return link.accept().await.unwrap();
        }
    }
}

#[tokio::test]
async fn dropping_the_last_client_stops_the_node() {
    let (interface, _peer, _) = connected_interfaces();
    let (node, task) = node(interface);
    drop(node);
    task.run().await.unwrap();
}

#[tokio::test]
async fn service_receive_survives_cancellation_and_finishes_when_node_stops() {
    for abort in [false, true] {
        let (left, _right, _) = connected_interfaces();
        let (node, task) = node(left);
        let running = tokio::spawn(task.run());
        let mut service = service(&node, "receive.lifecycle", &[]).await;
        {
            let mut canceled = Box::pin(service.receive());
            assert!(futures_util::poll!(&mut canceled).is_pending());
        }
        let mut receive = Box::pin(service.receive());
        assert!(futures_util::poll!(&mut receive).is_pending());
        if abort {
            running.abort();
            assert!(running.await.unwrap_err().is_cancelled());
            assert!(matches!(receive.await, Err(NodeError::NodeStopping)));
        } else {
            node.shutdown().await;
            running.await.unwrap().unwrap();
            assert!(matches!(receive.await, Err(NodeError::ResourceClosed)));
        }
        assert!(matches!(
            service.receive().await,
            Err(NodeError::NodeStopping)
        ));
    }
}

#[tokio::test]
async fn concurrent_sends_report_each_admission_failure() {
    let (left, right, _) = connected_interfaces();
    let (sender, sender_task) = NodeBuilder::new(NodeConfig::endpoint())
        .interface(left, InterfaceLimits::new(65_535, 4, 1_048_576).unwrap())
        .build()
        .unwrap();
    let (receiver, receiver_task) = node(right);
    let sender_task = tokio::spawn(sender_task.run());
    let receiver_task = tokio::spawn(receiver_task.run());
    let mut client = service(&sender, "admission.client", &[]).await;
    let mut server = service(&receiver, "admission.server", &[]).await;
    server
        .announce(Bytes::new(), RatchetAction::Keep)
        .await
        .unwrap();
    while !matches!(client.receive().await.unwrap(), ServiceEvent::Announce(_)) {}
    let results = futures_util::future::join_all((0..64u8).map(|index| {
        sender.send(
            if index == 63 {
                rinse::Destination::from_bytes([0; 16])
            } else {
                server.destination()
            },
            Bytes::from(vec![index]),
        )
    }))
    .await;
    for (index, result) in results.into_iter().enumerate() {
        assert_eq!(
            result,
            match index {
                0..4 => Ok(()),
                63 => Err(NodeError::NoRoute),
                _ => Err(NodeError::InterfaceUnavailable),
            }
        );
    }
    for index in 0..4u8 {
        let event = tokio::time::timeout(Duration::from_secs(30), server.receive())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, ServiceEvent::Datagram(body) if body.as_ref() == [index]));
    }
    sender.shutdown().await;
    receiver.shutdown().await;
    sender_task.await.unwrap().unwrap();
    receiver_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn concurrent_sends_preserve_contents_order_and_results() {
    let (left, right, _) = connected_interfaces();
    let (sender, sender_task) = NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            left,
            InterfaceLimits::new(65_535, 16384, 16_777_216).unwrap(),
        )
        .build()
        .unwrap();
    let (receiver, receiver_task) = node(right);
    let sender_task = tokio::spawn(sender_task.run());
    let receiver_task = tokio::spawn(receiver_task.run());
    let mut client = service(&sender, "parallel.client", &[]).await;
    let mut server = receiver
        .register_service(
            ServiceConfig::new(
                ServiceName::new("parallel.server").unwrap(),
                PrivateIdentity::from_secret_bytes([23; 64]).unwrap(),
                [],
                None,
            )
            .unwrap()
            .event_capacity(std::num::NonZeroUsize::new(16384).unwrap()),
        )
        .await
        .unwrap();
    for ratchet in [RatchetAction::Keep, RatchetAction::Rotate] {
        server.announce(Bytes::new(), ratchet).await.unwrap();
        while !matches!(client.receive().await.unwrap(), ServiceEvent::Announce(_)) {}
        assert_eq!(
            sender
                .send(server.destination(), Bytes::from(vec![0; 384]))
                .await,
            Err(NodeError::InvalidInput)
        );
        let bodies: Vec<_> = (0..16384u32)
            .map(|index| {
                let mut body = vec![index as u8; [4, 9, 16, 256, 383][index as usize % 5]];
                body[..4].copy_from_slice(&index.to_le_bytes());
                Bytes::from(body)
            })
            .collect();
        for window in bodies.chunks(4096) {
            for result in futures_util::future::join_all(
                window
                    .iter()
                    .map(|body| sender.send(server.destination(), body.clone())),
            )
            .await
            {
                result.unwrap();
            }
        }
        for expected in bodies {
            let event = tokio::time::timeout(Duration::from_secs(30), server.receive())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(event, ServiceEvent::Datagram(body) if body == expected));
        }
    }
    drop(client);
    drop(server);
    sender.shutdown().await;
    receiver.shutdown().await;
    sender_task.await.unwrap().unwrap();
    receiver_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn responder_close_during_link_open_has_a_closed_outcome_without_runtime_panic() {
    let (client_interface, server_interface, _) = connected_interfaces();
    let (client_node, client_task) = node(client_interface);
    let (server_node, server_task) = node(server_interface);
    let client_running = tokio::spawn(client_task.run());
    let server_running = tokio::spawn(server_task.run());
    let mut client_service = service(&client_node, "close.client", &[]).await;
    let mut server_service = service(&server_node, "close.server", &[]).await;
    server_service
        .announce(Bytes::new(), RatchetAction::Keep)
        .await
        .unwrap();
    loop {
        if let ServiceEvent::Announce(discovered) = client_service.receive().await.unwrap()
            && discovered.destination() == server_service.destination()
        {
            break;
        }
    }
    let destination = server_service.destination();
    let close = tokio::spawn(async move {
        accept_link(&mut server_service)
            .await
            .close()
            .await
            .unwrap();
    });
    match client_node.open_link(destination).await {
        Ok(mut link) => assert!(link.receive().await.is_err()),
        Err(NodeError::ResourceClosed) => {}
        Err(error) => panic!("unexpected link outcome: {error:?}"),
    }
    close.await.unwrap();
    client_node.shutdown().await;
    server_node.shutdown().await;
    assert!(client_running.await.unwrap().is_ok());
    assert!(server_running.await.unwrap().is_ok());
}

#[tokio::test]
async fn public_api_connects_services_links_requests_channels_and_buffers() {
    let (client_interface, server_interface, _) = connected_interfaces();
    let (client_node, client_task) = node(client_interface);
    let (server_node, server_task) = node(server_interface);
    let client_running = tokio::spawn(client_task.run());
    let server_running = tokio::spawn(server_task.run());
    let mut client_service = service(&client_node, "test.client", &[]).await;
    let mut server_service = service(&server_node, "test.server", &["/echo"]).await;
    server_service
        .announce(Bytes::from_static(b"server"), RatchetAction::Keep)
        .await
        .unwrap();
    loop {
        if let ServiceEvent::Announce(discovered) = client_service.receive().await.unwrap()
            && discovered.destination() == server_service.destination()
        {
            break;
        }
    }
    let (client_link, server_link) = tokio::join!(
        client_node.open_link(server_service.destination()),
        accept_link(&mut server_service)
    );
    let client_link = client_link.unwrap();
    let mut server_link = server_link;
    let client_sender = client_link.send_handle();
    let (_, identified) = tokio::join!(client_service.identify_on(&client_sender), async {
        loop {
            if let LinkEvent::Identified(identity) = server_link.receive().await.unwrap() {
                break identity;
            }
        }
    });
    assert_ne!(identified.as_bytes(), &[0; 16]);
    client_sender
        .send(Bytes::from_static(b"datagram"))
        .await
        .unwrap();
    assert!(matches!(
        server_link.receive().await.unwrap(),
        LinkEvent::Datagram(body) if body == b"datagram".as_slice()
    ));
    let server_response = async {
        loop {
            if let LinkEvent::Request(request) = server_link.receive().await.unwrap() {
                assert_eq!(request.path().as_str(), "/echo");
                assert_eq!(request.body(), b"request");
                request
                    .respond(Bytes::from_static(b"response"))
                    .await
                    .unwrap();
                break;
            }
        }
    };
    let (response, ()) = tokio::join!(
        client_sender.request(
            RequestPath::new("/echo").unwrap(),
            Bytes::from_static(b"request")
        ),
        server_response
    );
    assert_eq!(response.unwrap(), b"response".as_slice());
    let client_channel = client_sender.open_channel().await.unwrap();
    let mut server_channel = server_link.send_handle().open_channel().await.unwrap();
    client_channel
        .send_handle()
        .send(
            ChannelMessage::new(
                MessageType::new(0x0101).unwrap(),
                Bytes::from_static(b"channel"),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        server_channel.receive().await.unwrap(),
        ChannelReceive::Message(message) if message.body() == b"channel"
    ));
    let mut buffer = client_channel
        .send_handle()
        .open_buffer(StreamId::new(7).unwrap())
        .await
        .unwrap();
    assert_eq!(
        buffer.write(Bytes::from_static(b"buffer ")).await.unwrap(),
        7
    );
    assert_eq!(buffer.finish(Bytes::from_static(b"end")).await.unwrap(), 3);
    let mut received = Vec::new();
    loop {
        match server_channel.receive().await.unwrap() {
            ChannelReceive::Buffer {
                stream,
                chunk: BufferChunk::Data(data),
            } => {
                assert_eq!(stream, StreamId::new(7).unwrap());
                received.extend_from_slice(&data);
            }
            ChannelReceive::Buffer {
                stream,
                chunk: BufferChunk::End(data),
            } => {
                assert_eq!(stream, StreamId::new(7).unwrap());
                received.extend_from_slice(&data);
                break;
            }
            ChannelReceive::Message(_) => {}
        }
    }
    assert_eq!(received, b"buffer end");
    client_link.close().await.unwrap();
    client_node.shutdown().await;
    server_node.shutdown().await;
    client_running.await.unwrap().unwrap();
    server_running.await.unwrap().unwrap();
}

#[tokio::test]
async fn relay_forwards_service_routes_between_interfaces() {
    let (server_interface, relay_server, _) = connected_interfaces();
    let (client_interface, relay_client, _) = connected_interfaces();
    let (server_node, server_task) = node(server_interface);
    let (client_node, client_task) = node(client_interface);
    let (relay_node, relay_task) = NodeBuilder::new(NodeConfig::relay())
        .interface(
            relay_server,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .interface(
            relay_client,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap();
    let server_running = tokio::spawn(server_task.run());
    let client_running = tokio::spawn(client_task.run());
    let relay_running = tokio::spawn(relay_task.run());
    let mut server_service = service(&server_node, "relay.server", &[]).await;
    let mut client_service = service(&client_node, "relay.client", &[]).await;
    server_service
        .announce(Bytes::new(), RatchetAction::Keep)
        .await
        .unwrap();
    loop {
        if let ServiceEvent::Announce(announce) = client_service.receive().await.unwrap()
            && announce.destination() == server_service.destination()
        {
            break;
        }
    }
    let (client_link, server_link) = tokio::join!(
        client_node.open_link(server_service.destination()),
        accept_link(&mut server_service)
    );
    let client_link = client_link.unwrap();
    let client_sender = client_link.send_handle();
    let server_sender = server_link.send_handle();
    let (client_channel, server_channel) =
        tokio::join!(client_sender.open_channel(), server_sender.open_channel());
    let client_channel = client_channel.unwrap();
    let mut server_channel = server_channel.unwrap();
    let client_channel_sender = client_channel.send_handle();
    let delivered = client_channel_sender.send(
        ChannelMessage::new(
            MessageType::new(0x0101).unwrap(),
            Bytes::from_static(b"relayed channel"),
        )
        .unwrap(),
    );
    let received = server_channel.receive();
    let (delivered, received) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(delivered, received)
    })
    .await
    .expect("relayed channel delivery proof timed out");
    delivered.unwrap();
    assert!(matches!(
        received.unwrap(),
        ChannelReceive::Message(message) if message.body() == b"relayed channel"
    ));
    client_link.close().await.unwrap();
    let _ = server_link.close().await;
    client_node.shutdown().await;
    server_node.shutdown().await;
    relay_node.shutdown().await;
    client_running.await.unwrap().unwrap();
    server_running.await.unwrap().unwrap();
    relay_running.await.unwrap().unwrap();
}

#[cfg(feature = "tcp")]
#[tokio::test]
#[cfg(feature = "tcp")]
async fn tcp_relay_forwards_service_routes_between_interfaces() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (relay_node, relay_task) = NodeBuilder::new(NodeConfig::relay()).build().unwrap();
    let relay_running = tokio::spawn(relay_task.run());
    let relay_acceptor = relay_node.clone();
    let accepting = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            relay_acceptor
                .attach_interface(
                    TcpHdlcInterface::new(stream).unwrap(),
                    InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
                )
                .await
                .unwrap();
        }
    });
    let server_interface = TcpHdlcInterface::connect(&address.to_string())
        .await
        .unwrap();
    let client_interface = TcpHdlcInterface::connect(&address.to_string())
        .await
        .unwrap();
    let (server_node, server_task) = NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            server_interface,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap();
    let (client_node, client_task) = NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            client_interface,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap();
    accepting.await.unwrap();
    let server_running = tokio::spawn(server_task.run());
    let client_running = tokio::spawn(client_task.run());
    let mut server_service = service(&server_node, "tcp.relay.server", &[]).await;
    let mut client_service = service(&client_node, "tcp.relay.client", &[]).await;
    server_service
        .announce(Bytes::new(), RatchetAction::Keep)
        .await
        .unwrap();
    loop {
        if let ServiceEvent::Announce(announce) = client_service.receive().await.unwrap()
            && announce.destination() == server_service.destination()
        {
            break;
        }
    }
    let (client_link, server_link) = tokio::join!(
        client_node.open_link(server_service.destination()),
        accept_link(&mut server_service)
    );
    let client_link = client_link.unwrap();
    let client_sender = client_link.send_handle();
    let server_sender = server_link.send_handle();
    let (client_channel, server_channel) =
        tokio::join!(client_sender.open_channel(), server_sender.open_channel());
    let client_channel = client_channel.unwrap();
    let mut server_channel = server_channel.unwrap();
    let client_channel_sender = client_channel.send_handle();
    let delivered = client_channel_sender.send(
        ChannelMessage::new(
            MessageType::new(0x0101).unwrap(),
            Bytes::from_static(b"tcp relayed channel"),
        )
        .unwrap(),
    );
    let received = server_channel.receive();
    let (delivered, received) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(delivered, received)
    })
    .await
    .expect("TCP-relayed channel delivery proof timed out");
    delivered.unwrap();
    assert!(matches!(
        received.unwrap(),
        ChannelReceive::Message(message) if message.body() == b"tcp relayed channel"
    ));
    client_link.close().await.unwrap();
    let _ = server_link.close().await;
    client_node.shutdown().await;
    server_node.shutdown().await;
    relay_node.shutdown().await;
    client_running.await.unwrap().unwrap();
    server_running.await.unwrap().unwrap();
    relay_running.await.unwrap().unwrap();
}

#[cfg(feature = "tcp")]
#[tokio::test]
#[cfg(feature = "tcp")]
async fn tcp_relay_opens_parallel_links_to_one_service() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (relay_node, relay_task) = NodeBuilder::new(NodeConfig::relay()).build().unwrap();
    let relay_running = tokio::spawn(relay_task.run());
    let relay_acceptor = relay_node.clone();
    let accepting = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            relay_acceptor
                .attach_interface(
                    TcpHdlcInterface::new(stream).unwrap(),
                    InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
                )
                .await
                .unwrap();
        }
    });
    let server_interface = TcpHdlcInterface::connect(&address.to_string())
        .await
        .unwrap();
    let client_interface = TcpHdlcInterface::connect(&address.to_string())
        .await
        .unwrap();
    let (server_node, server_task) = NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            server_interface,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap();
    let (client_node, client_task) = NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            client_interface,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap();
    accepting.await.unwrap();
    let server_running = tokio::spawn(server_task.run());
    let client_running = tokio::spawn(client_task.run());
    let mut server_service = service(&server_node, "parallel.server", &[]).await;
    let mut client_service = service(&client_node, "parallel.client", &[]).await;
    server_service
        .announce(Bytes::new(), RatchetAction::Keep)
        .await
        .unwrap();
    loop {
        if let ServiceEvent::Announce(announce) = client_service.receive().await.unwrap()
            && announce.destination() == server_service.destination()
        {
            break;
        }
    }
    let destination = server_service.destination();
    let clients = async {
        futures_util::future::try_join_all((0..8).map(|_| client_node.open_link(destination))).await
    };
    let servers = async {
        let mut links = Vec::new();
        for _ in 0..8 {
            links.push(accept_link(&mut server_service).await);
        }
        links
    };
    let (clients, servers) = tokio::join!(clients, servers);
    let clients = clients.unwrap();
    assert_eq!(clients.len(), 8);
    assert_eq!(servers.len(), 8);
    let client_channels = futures_util::future::try_join_all(clients.iter().map(|link| {
        let sender = link.send_handle();
        async move { sender.open_channel().await }
    }))
    .await
    .unwrap();
    for (ordinal, channel) in client_channels.iter().enumerate() {
        channel
            .send_handle()
            .send(
                ChannelMessage::new(
                    MessageType::new(0x0101).unwrap(),
                    Bytes::from(vec![ordinal as u8]),
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
    let mut server_channels = futures_util::future::try_join_all(servers.iter().map(|link| {
        let sender = link.send_handle();
        async move { sender.open_channel().await }
    }))
    .await
    .unwrap();
    for (ordinal, channel) in server_channels.iter_mut().enumerate() {
        assert!(matches!(
            channel.receive().await.unwrap(),
            ChannelReceive::Message(message) if message.body() == [ordinal as u8]
        ));
    }
    client_node.shutdown().await;
    server_node.shutdown().await;
    relay_node.shutdown().await;
    drop(clients);
    drop(servers);
    client_running.await.unwrap().unwrap();
    server_running.await.unwrap().unwrap();
    relay_running.await.unwrap().unwrap();
}

#[tokio::test]
async fn rotating_an_announcement_returns_only_the_new_restart_secret() {
    let (left, _right, _) = connected_interfaces();
    let (node, task) = node(left);
    let running = tokio::spawn(task.run());
    let service = service(&node, "test.ratchet", &[]).await;
    assert!(
        service
            .announce(Bytes::new(), RatchetAction::Rotate)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        service
            .announce(Bytes::new(), RatchetAction::Keep)
            .await
            .unwrap()
            .is_none()
    );
    node.shutdown().await;
    running.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn learned_routes_expire() {
    let (client_interface, server_interface, forwarding) = connected_interfaces();
    let (client_node, client_task) = node(client_interface);
    let (server_node, server_task) = node(server_interface);
    let client_running = tokio::spawn(client_task.run());
    let server_running = tokio::spawn(server_task.run());
    let mut client_service = service(&client_node, "expiry.client", &[]).await;
    let server_service = service(&server_node, "expiry.server", &[]).await;
    server_service
        .announce(Bytes::new(), RatchetAction::Keep)
        .await
        .unwrap();
    loop {
        if let ServiceEvent::Announce(discovered) = client_service.receive().await.unwrap()
            && discovered.destination() == server_service.destination()
        {
            break;
        }
    }
    forwarding[0].store(false, Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(8 * 24 * 60 * 60)).await;
    tokio::task::yield_now().await;
    let destination = server_service.destination();
    let pending = tokio::spawn({
        let node = client_node.clone();
        async move { node.send(destination, Bytes::from_static(b"expired")).await }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    assert_eq!(pending.await.unwrap(), Err(NodeError::NoRoute));
    client_node.shutdown().await;
    server_node.shutdown().await;
    client_running.await.unwrap().unwrap();
    server_running.await.unwrap().unwrap();
}
