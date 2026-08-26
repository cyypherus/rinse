use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use rinse::{
    BufferChunk, ChannelMessage, ChannelReceive, Clock, EmbassyClock, InboundPacket,
    InlinePacketWork, Interface, InterfaceError, InterfaceLimits, Link, LinkEvent, MessageType,
    MonoTime, NodeBuilder, NodeConfig, OutboundPacket, PrivateIdentity, RatchetAction, RequestPath,
    SendError, Service, ServiceConfig, ServiceEvent, ServiceName, StreamId, SystemEntropy,
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

fn node_with_clock<C: Clock>(
    interface: MemoryInterface,
    clock: C,
) -> (rinse::NodeHandle, rinse::NodeTask<C>) {
    NodeBuilder::new(
        NodeConfig::endpoint(),
        clock,
        InlinePacketWork,
        SystemEntropy,
    )
    .interface(
        interface,
        InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
    )
    .build()
    .unwrap()
}

fn node(interface: MemoryInterface) -> (rinse::NodeHandle, rinse::NodeTask<EmbassyClock>) {
    node_with_clock(interface, EmbassyClock)
}

#[derive(Clone)]
struct TestClock {
    now: Arc<AtomicU64>,
    sleepers: Arc<Mutex<Vec<Waker>>>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            now: Arc::new(AtomicU64::new(1)),
            sleepers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn advance(&self, duration: Duration) {
        self.now.fetch_add(
            u64::try_from(duration.as_micros()).unwrap(),
            Ordering::Relaxed,
        );
        for sleeper in std::mem::take(&mut *self.sleepers.lock().unwrap()) {
            sleeper.wake();
        }
    }
}

struct TestSleep {
    clock: TestClock,
    deadline: MonoTime,
}

impl Future for TestSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.clock.now() >= self.deadline {
            Poll::Ready(())
        } else {
            let mut sleepers = self.clock.sleepers.lock().unwrap();
            if !sleepers.iter().any(|waker| waker.will_wake(cx.waker())) {
                sleepers.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl Clock for TestClock {
    type Sleep<'a> = TestSleep;

    fn now(&self) -> MonoTime {
        MonoTime::from_micros(self.now.load(Ordering::Relaxed))
    }

    fn sleep_until(&self, deadline: MonoTime) -> Self::Sleep<'_> {
        TestSleep {
            clock: self.clone(),
            deadline,
        }
    }
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
async fn rotating_an_announcement_returns_only_the_new_restart_secret() {
    let (left, _right, _) = connected_interfaces();
    let (node, task) = node(left);
    let running = tokio::spawn(task.run());
    let service = service(&node, "test.ratchet", &[]).await;
    let rotated = service
        .announce(Bytes::new(), RatchetAction::Rotate)
        .await
        .unwrap()
        .expect("rotation must return the committed restart secret");
    assert_ne!(rotated.to_bytes(), [0; 32]);
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

#[tokio::test]
async fn learned_routes_expire() {
    let (client_interface, server_interface, forwarding) = connected_interfaces();
    let clock = TestClock::new();
    let (client_node, client_task) = node_with_clock(client_interface, clock.clone());
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
    clock.advance(Duration::from_secs(8 * 24 * 60 * 60));
    tokio::task::yield_now().await;
    let destination = server_service.destination();
    let pending = tokio::spawn({
        let node = client_node.clone();
        async move { node.send(destination, Bytes::from_static(b"expired")).await }
    });
    tokio::task::yield_now().await;
    clock.advance(Duration::from_secs(61));
    assert_eq!(pending.await.unwrap(), Err(SendError::NoRoute));
    client_node.shutdown().await;
    server_node.shutdown().await;
    client_running.await.unwrap().unwrap();
    server_running.await.unwrap().unwrap();
}
