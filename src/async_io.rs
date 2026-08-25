use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::future::{AbortHandle, Abortable};
use futures_util::stream::{FuturesUnordered, StreamExt};
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{mpsc, oneshot, watch};

use crate::handle::{
    DecryptLaterDeliveredPayloadError, EncryptForLaterDeliveryError, EstablishLinkError,
    IncomingRequest, KnownDestination, LinkRttError, RatchetConfigurationError,
    RatchetKeysForRestart, RatchetKeysForRestartError, ReceiveError, RequestError, RespondError,
    Response, RuntimeStopped, ServiceEvent, ServiceId,
};
use crate::node::{PreparedInbound, ProtocolTimer, ScheduledTimer};
use crate::packet::DestinationAddress;
use crate::request::RequestId;
use crate::stats::LifetimeStats;
use crate::{Interface, PrivateIdentity, Transport};

#[cfg(feature = "tcp")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "tcp")]
use tokio::net::TcpStream;

#[cfg(feature = "tcp")]
use crate::transports::hdlc::{HDLC_FLAG, hdlc_escape, hdlc_unescape};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LinkContext, LinkDataDestination, Packet};

    struct TestTransport {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    struct ConnectedTransport {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl Transport for TestTransport {
        fn poll_send(&mut self, _: &mut Context<'_>, _: &[u8]) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Option<Vec<u8>>>> {
            self.inbound.poll_recv(cx).map(Ok)
        }
    }

    impl Transport for ConnectedTransport {
        fn poll_send(&mut self, _: &mut Context<'_>, frame: &[u8]) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.outbound.send(frame.to_vec()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "transport closed")
            }))
        }

        fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Option<Vec<u8>>>> {
            self.inbound.poll_recv(cx).map(Ok)
        }
    }

    fn connected_transports() -> (ConnectedTransport, ConnectedTransport) {
        let (left_tx, left_rx) = mpsc::unbounded_channel();
        let (right_tx, right_rx) = mpsc::unbounded_channel();
        (
            ConnectedTransport {
                inbound: left_rx,
                outbound: right_tx,
            },
            ConnectedTransport {
                inbound: right_rx,
                outbound: left_tx,
            },
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parallel_packet_preparation_preserves_input_order() {
        let packets: Vec<_> = (0..128)
            .map(|index| {
                let destination = if index % 2 == 0 {
                    LinkDataDestination::Direct([index as u8; 16])
                } else {
                    LinkDataDestination::Transport {
                        transport_id: [255 - index as u8; 16],
                        link_id: [index as u8; 16],
                    }
                };
                Packet::LinkData {
                    hops: 0,
                    destination,
                    context: LinkContext::Resource,
                    data: vec![index as u8; 512],
                }
            })
            .collect();
        let raw = packets
            .iter()
            .enumerate()
            .map(|(index, packet)| (packet.to_bytes(), index))
            .collect();

        let prepared = NodeRuntime::<TestTransport>::prepare_received(raw);

        assert_eq!(prepared.len(), packets.len());
        for (index, (prepared, expected)) in prepared.into_iter().zip(packets).enumerate() {
            let expected_hash = expected.packet_hash();
            let (packet, packet_hash, _, source) = prepared.into_parts();
            assert_eq!(source, index);
            assert_eq!(packet_hash, expected_hash);
            assert_eq!(packet, expected);
        }
    }

    #[tokio::test]
    async fn builder_starts_one_runtime() {
        let mut builder: NodeBuilder<TestTransport> = NodeBuilder::non_forwarding_endpoint();
        let mut rng = StdRng::seed_from_u64(1);
        let service =
            builder.register_local_service("service", &[], &PrivateIdentity::generate(&mut rng));
        assert_ne!(service.destination_address, [0; 16]);
        let service = service.id;
        let (node, runtime) = builder.build();

        let runtime = tokio::spawn(runtime.run());
        tokio::task::yield_now().await;
        runtime.abort();
        assert!(runtime.await.unwrap_err().is_cancelled());
        let (_, inbound) = mpsc::unbounded_channel();
        assert_eq!(
            node.attach_interface(Interface::new(TestTransport { inbound })),
            Err(crate::RuntimeStopped)
        );
        assert_eq!(
            node.export_ratchet_keys_for_restart(service).await,
            Err(RatchetKeysForRestartError::RuntimeStopped)
        );
        assert_eq!(
            node.link_rtt(crate::LinkHandle([0; 16])).await,
            Err(LinkRttError::RuntimeStopped)
        );
        assert_eq!(
            node.encrypt_payload_for_later_delivery([0; 16], &[]).await,
            Err(EncryptForLaterDeliveryError::RuntimeStopped)
        );
        assert_eq!(
            node.decrypt_later_delivered_payload(
                service,
                &crate::DestinationCiphertext::from_bytes(vec![0; 32]).unwrap(),
            )
            .await,
            Err(DecryptLaterDeliveredPayloadError::RuntimeStopped)
        );
    }

    #[tokio::test]
    async fn runtime_ends_after_last_node_handle_is_dropped() {
        let builder: NodeBuilder<TestTransport> = NodeBuilder::non_forwarding_endpoint();
        let (node, runtime) = builder.build();
        let runtime = tokio::spawn(runtime.run());
        drop(node);
        tokio::time::timeout(Duration::from_secs(1), runtime)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn service_receivers_close_with_runtime() {
        let mut builder: NodeBuilder<TestTransport> = NodeBuilder::non_forwarding_endpoint();
        let mut rng = StdRng::seed_from_u64(1);
        let service = builder
            .register_local_service("service", &[], &PrivateIdentity::generate(&mut rng))
            .id;
        let (node, runtime) = builder.build();
        let runtime = tokio::spawn(runtime.run());
        runtime.abort();
        assert!(runtime.await.unwrap_err().is_cancelled());
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), node.recv_request(service)).await,
            Ok(Err(ReceiveError::RuntimeStopped))
        ));
    }

    #[tokio::test]
    async fn request_completion_stays_owned_by_runtime() {
        let (client_transport, server_transport) = connected_transports();
        let mut rng = StdRng::seed_from_u64(1);

        let mut server_builder = NodeBuilder::non_forwarding_endpoint();
        let server_service = server_builder.register_local_service(
            "server",
            &["/echo"],
            &PrivateIdentity::generate(&mut rng),
        );
        server_builder.add_initial_interface(Interface::new(server_transport));
        let (server, server_runtime) = server_builder.build();

        let mut client_builder = NodeBuilder::non_forwarding_endpoint();
        let client_service = client_builder.register_local_service(
            "client",
            &[],
            &PrivateIdentity::generate(&mut rng),
        );
        client_builder.add_initial_interface(Interface::new(client_transport));
        let (client, client_runtime) = client_builder.build();

        let server_run = tokio::spawn(server_runtime.run());
        let client_run = tokio::spawn(client_runtime.run());
        server
            .queue_service_announcement(server_service.id)
            .unwrap();
        client
            .ensure_route_to(server_service.destination_address)
            .await
            .unwrap();
        let link = client
            .establish_link_from(client_service.id, server_service.destination_address)
            .await
            .unwrap();

        let responder = tokio::spawn(async move {
            let request = server.recv_request(server_service.id).await.unwrap();
            server
                .respond(request.request_id, &request.data, None, false)
                .await
                .unwrap();
        });
        let response = client.request(link, "/echo", b"payload").await.unwrap();
        assert_eq!(response.data, b"payload");
        responder.await.unwrap();
        server_run.abort();
        client_run.abort();
    }

    #[test]
    fn runtime_runs_without_tokio() {
        futures_lite::future::block_on(async {
            let builder: NodeBuilder<TestTransport> = NodeBuilder::non_forwarding_endpoint();
            let (node, runtime) = builder.build();
            futures_lite::future::zip(runtime.run(), async move {
                embassy_time::Timer::after_millis(1).await;
                drop(node);
            })
            .await;
        });
    }

    #[test]
    fn protocol_timer_wakes_without_runtime_activity() {
        futures_lite::future::block_on(async {
            let destination = [7; 16];
            let timestamp = Instant::now();
            let event = ProtocolTimerFuture::new(ScheduledTimer {
                at: timestamp + Duration::from_millis(1),
                event: ProtocolTimer::ReversePathExpiry(destination),
            })
            .await;
            assert_eq!(event.at, timestamp + Duration::from_millis(1));
            assert!(matches!(
                event.event,
                ProtocolTimer::ReversePathExpiry(expired) if expired == destination
            ));
        });
    }

    #[tokio::test]
    async fn input_wakes_idle_runtime() {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let mut builder = NodeBuilder::non_forwarding_endpoint();
        builder.add_initial_interface(Interface::new(TestTransport {
            inbound: inbound_rx,
        }));
        let (node, runtime) = builder.build();
        let observer = node.clone();
        let runtime = tokio::spawn(runtime.run());
        tokio::task::yield_now().await;

        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct([1; 16]),
            context: LinkContext::Resource,
            data: vec![1],
        };
        inbound_tx.send(packet.to_bytes()).unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if observer.lifetime_stats().packets_received == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        runtime.abort();
    }
}

#[cfg(feature = "tcp")]
fn hdlc_extract_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        let start = buf.iter().position(|&b| b == HDLC_FLAG)?;
        let end = buf[start + 1..]
            .iter()
            .position(|&b| b == HDLC_FLAG)
            .map(|p| p + start + 1)?;

        let frame_data = &buf[start + 1..end];

        if frame_data.is_empty() {
            *buf = buf[start + 1..].to_vec();
            continue;
        }

        let unescaped = hdlc_unescape(frame_data);
        if unescaped.len() >= 2 {
            *buf = buf[end..].to_vec();
            return Some(unescaped);
        }

        *buf = buf[end..].to_vec();
    }
}

#[cfg(feature = "tcp")]
pub struct AsyncTcpTransport {
    stream: TcpStream,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
    written: usize,
}

#[cfg(feature = "tcp")]
impl AsyncTcpTransport {
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self::start(stream))
    }

    pub fn from_accepted_stream(stream: TcpStream) -> std::io::Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self::start(stream))
    }

    fn start(stream: TcpStream) -> Self {
        Self {
            stream,
            inbound: Vec::new(),
            outbound: Vec::new(),
            written: 0,
        }
    }
}

#[cfg(feature = "tcp")]
impl Transport for AsyncTcpTransport {
    fn poll_send(&mut self, cx: &mut Context<'_>, frame: &[u8]) -> Poll<std::io::Result<()>> {
        if self.outbound.is_empty() {
            let escaped = hdlc_escape(frame);
            self.outbound.reserve(escaped.len() + 2);
            self.outbound.push(HDLC_FLAG);
            self.outbound.extend(escaped);
            self.outbound.push(HDLC_FLAG);
            self.written = 0;
        }
        while self.written < self.outbound.len() {
            let this = &mut *self;
            match Pin::new(&mut this.stream).poll_write(cx, &this.outbound[this.written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TCP connection closed",
                    )));
                }
                Poll::Ready(Ok(written)) => this.written += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        match Pin::new(&mut self.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.outbound.clear();
                self.written = 0;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }

    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Option<Vec<u8>>>> {
        loop {
            if let Some(frame) = hdlc_extract_frame(&mut self.inbound) {
                return Poll::Ready(Ok(Some(frame)));
            }
            let mut bytes = [0; 65536];
            let mut read = ReadBuf::new(&mut bytes);
            match Pin::new(&mut self.stream).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    return Poll::Ready(Ok(None));
                }
                Poll::Ready(Ok(())) => self.inbound.extend_from_slice(read.filled()),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

type RequestCompletion = oneshot::Sender<Result<(Vec<u8>, Option<Vec<u8>>), RequestError>>;
type RespondCompletion = oneshot::Sender<Result<(), RespondError>>;

#[derive(Clone)]
struct ServiceSenders {
    request_tx: async_channel::Sender<IncomingRequest>,
    datagram_tx: async_channel::Sender<crate::ReceivedDatagram>,
    channel_tx: async_channel::Sender<(crate::LinkHandle, crate::ChannelMessage)>,
    buffer_tx: async_channel::Sender<(crate::LinkHandle, crate::LinkBufferStreamChunk)>,
}

#[derive(Clone)]
struct ServiceReceivers {
    request_rx: async_channel::Receiver<IncomingRequest>,
    datagram_rx: async_channel::Receiver<crate::ReceivedDatagram>,
    channel_rx: async_channel::Receiver<(crate::LinkHandle, crate::ChannelMessage)>,
    buffer_rx: async_channel::Receiver<(crate::LinkHandle, crate::LinkBufferStreamChunk)>,
}

enum Command<T: Transport> {
    AddInterface {
        interface: Box<Interface<T>>,
    },
    Announce {
        service: ServiceId,
        app_data: Option<Vec<u8>>,
    },
    ConfigureAnnouncementRatchets {
        service: ServiceId,
        interval: Duration,
        restored_keys: Option<RatchetKeysForRestart>,
        reply: oneshot::Sender<Result<(), RatchetConfigurationError>>,
    },
    ExportRatchetKeysForRestart {
        service: ServiceId,
        reply: oneshot::Sender<Result<RatchetKeysForRestart, RatchetKeysForRestartError>>,
    },
    Request {
        link: crate::LinkHandle,
        path: String,
        data: Vec<u8>,
        completion: RequestCompletion,
    },
    Respond {
        request_id: RequestId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
        completion: RespondCompletion,
    },
    SendDestinationDatagram {
        destination: DestinationAddress,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), crate::handle::SendDestinationDatagramError>>,
    },
    SendLinkDatagram {
        link: crate::LinkHandle,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), crate::SendLinkDatagramError>>,
    },
    SendChannel {
        link: crate::LinkHandle,
        message: crate::ChannelMessage,
        reply: oneshot::Sender<Result<(), crate::ChannelSendError>>,
    },
    SendBuffer {
        link: crate::LinkHandle,
        raw: Vec<u8>,
        processed: usize,
        reply: oneshot::Sender<Result<crate::QueuedLinkBufferStreamData, crate::ChannelSendError>>,
    },
    CreateLink {
        service: ServiceId,
        destination: DestinationAddress,
        reply: oneshot::Sender<Option<crate::LinkHandle>>,
    },
    LinkStatus {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Option<crate::LinkStatus>>,
    },
    LinkRtt {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Result<Duration, LinkRttError>>,
    },
    CloseLink {
        link: crate::LinkHandle,
        reply: oneshot::Sender<bool>,
    },
    AuthenticateToLinkPeer {
        link: crate::LinkHandle,
        identity: Box<crate::PrivateIdentity>,
        reply: oneshot::Sender<Result<(), crate::LinkPeerAuthenticationError>>,
    },
    AwaitLinkActive {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Result<(), EstablishLinkError>>,
    },
    RequestPath {
        destination: DestinationAddress,
        reply: oneshot::Sender<bool>,
    },
    EncryptForLaterDelivery {
        destination: DestinationAddress,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, EncryptForLaterDeliveryError>>,
    },
    DecryptLaterDeliveredPayload {
        service: ServiceId,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, DecryptLaterDeliveredPayloadError>>,
    },
}

struct ProtocolTimerFuture {
    timer: embassy_time::Timer,
    scheduled: ScheduledTimer,
}

impl ProtocolTimerFuture {
    fn new(scheduled: ScheduledTimer) -> Self {
        let remaining = scheduled.at.saturating_duration_since(Instant::now());
        Self {
            timer: embassy_time::Timer::after(embassy_time::Duration::from_micros(
                remaining.as_micros().min(u64::MAX as u128) as u64,
            )),
            scheduled,
        }
    }
}

impl Future for ProtocolTimerFuture {
    type Output = ScheduledTimer;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.timer).poll(cx) {
            Poll::Ready(()) => Poll::Ready(self.scheduled),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct NodeRuntime<T: Transport> {
    protocol: crate::node::Protocol<T, StdRng>,
    command_rx: mpsc::UnboundedReceiver<Command<T>>,
    link_waiters: HashMap<crate::LinkHandle, Vec<oneshot::Sender<Result<(), EstablishLinkError>>>>,
    path_waiters: HashMap<DestinationAddress, Vec<oneshot::Sender<bool>>>,
    destinations_tx: watch::Sender<Vec<KnownDestination>>,
    stats_tx: watch::Sender<LifetimeStats>,
    request_completions: HashMap<RequestId, RequestCompletion>,
    respond_completions: HashMap<RequestId, RespondCompletion>,
    pending_channel_sends: VecDeque<(
        crate::LinkHandle,
        crate::ChannelMessage,
        oneshot::Sender<Result<(), crate::ChannelSendError>>,
    )>,
    pending_buffer_sends: VecDeque<(
        crate::LinkHandle,
        Vec<u8>,
        usize,
        oneshot::Sender<Result<crate::QueuedLinkBufferStreamData, crate::ChannelSendError>>,
    )>,
    timers: FuturesUnordered<Abortable<ProtocolTimerFuture>>,
    timer_abort_handles: HashMap<ProtocolTimer, AbortHandle>,
    services: HashMap<ServiceId, ServiceSenders>,
}

pub struct NodeBuilder<T: Transport> {
    protocol: crate::node::Protocol<T, StdRng>,
    services: HashMap<ServiceId, (ServiceSenders, ServiceReceivers)>,
}

pub struct Node<T: Transport> {
    services: HashMap<ServiceId, ServiceReceivers>,
    command_tx: mpsc::UnboundedSender<Command<T>>,
    destinations_rx: watch::Receiver<Vec<KnownDestination>>,
    stats_rx: watch::Receiver<LifetimeStats>,
}

pub struct OutboundLinkBufferStream<'a, T: Transport> {
    node: &'a Node<T>,
    link: crate::LinkHandle,
    stream_id: crate::LinkBufferStreamId,
}

impl<T: Transport> Clone for Node<T> {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            command_tx: self.command_tx.clone(),
            destinations_rx: self.destinations_rx.clone(),
            stats_rx: self.stats_rx.clone(),
        }
    }
}

impl<T: Transport> NodeBuilder<T> {
    pub fn non_forwarding_endpoint() -> Self {
        Self::with_packet_forwarding(false)
    }

    pub fn packet_forwarding_relay() -> Self {
        Self::with_packet_forwarding(true)
    }

    fn with_packet_forwarding(forward_packets: bool) -> Self {
        Self {
            protocol: crate::node::Protocol::with_rng(StdRng::from_entropy(), forward_packets),
            services: HashMap::new(),
        }
    }

    pub fn add_initial_interface(&mut self, interface: Interface<T>) {
        self.protocol.add_interface(interface);
    }

    pub fn register_local_service(
        &mut self,
        service_name: &str,
        accepted_request_paths: &[&str],
        private_identity: &PrivateIdentity,
    ) -> crate::RegisteredLocalService {
        let (request_tx, request_rx) = async_channel::unbounded();
        let (datagram_tx, datagram_rx) = async_channel::unbounded();
        let (channel_tx, channel_rx) = async_channel::unbounded();
        let (buffer_tx, buffer_rx) = async_channel::unbounded();

        let service_id =
            self.protocol
                .add_service(service_name, accepted_request_paths, private_identity);
        let address = self.protocol.service_address(service_id).unwrap();

        self.services.insert(
            service_id,
            (
                ServiceSenders {
                    request_tx,
                    datagram_tx,
                    channel_tx,
                    buffer_tx,
                },
                ServiceReceivers {
                    request_rx,
                    datagram_rx,
                    channel_rx,
                    buffer_rx,
                },
            ),
        );
        crate::RegisteredLocalService {
            id: service_id,
            destination_address: address,
        }
    }

    pub fn build(self) -> (Node<T>, NodeRuntime<T>) {
        let Self { protocol, services } = self;
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (destinations_tx, destinations_rx) = watch::channel(Vec::new());
        let (stats_tx, stats_rx) = watch::channel(LifetimeStats::default());
        let mut service_senders = HashMap::with_capacity(services.len());
        let mut service_receivers = HashMap::with_capacity(services.len());
        for (service, (senders, receivers)) in services {
            service_senders.insert(service, senders);
            service_receivers.insert(service, receivers);
        }

        (
            Node {
                services: service_receivers,
                command_tx,
                destinations_rx,
                stats_rx,
            },
            NodeRuntime {
                protocol,
                command_rx,
                link_waiters: HashMap::new(),
                path_waiters: HashMap::new(),
                destinations_tx,
                stats_tx,
                request_completions: HashMap::new(),
                respond_completions: HashMap::new(),
                pending_channel_sends: VecDeque::new(),
                pending_buffer_sends: VecDeque::new(),
                timers: FuturesUnordered::new(),
                timer_abort_handles: HashMap::new(),
                services: service_senders,
            },
        )
    }
}

impl<T: Transport> Node<T> {
    pub fn begin_link_buffer_stream(
        &self,
        link: crate::LinkHandle,
        stream_id: crate::LinkBufferStreamId,
    ) -> OutboundLinkBufferStream<'_, T> {
        OutboundLinkBufferStream {
            node: self,
            link,
            stream_id,
        }
    }

    pub fn attach_interface(&self, interface: Interface<T>) -> Result<(), crate::RuntimeStopped> {
        self.command_tx
            .send(Command::AddInterface {
                interface: Box::new(interface),
            })
            .map_err(|_| crate::RuntimeStopped)
    }

    pub fn queue_service_announcement(
        &self,
        service: ServiceId,
    ) -> Result<(), crate::AnnounceError> {
        if !self.services.contains_key(&service) {
            return Err(crate::AnnounceError::ServiceNotFound);
        }
        self.command_tx
            .send(Command::Announce {
                service,
                app_data: None,
            })
            .map_err(|_| crate::AnnounceError::RuntimeStopped)
    }

    pub fn queue_service_announcement_with_data(
        &self,
        service: ServiceId,
        announcement_data: Vec<u8>,
    ) -> Result<(), crate::AnnounceError> {
        if !self.services.contains_key(&service) {
            return Err(crate::AnnounceError::ServiceNotFound);
        }
        self.command_tx
            .send(Command::Announce {
                service,
                app_data: Some(announcement_data),
            })
            .map_err(|_| crate::AnnounceError::RuntimeStopped)
    }

    pub async fn configure_announcement_ratchet_rotation(
        &self,
        local_service: ServiceId,
        minimum_rotation_interval: Duration,
        restored_keys: Option<RatchetKeysForRestart>,
    ) -> Result<(), RatchetConfigurationError> {
        let (reply, result) = oneshot::channel();
        self.command_tx
            .send(Command::ConfigureAnnouncementRatchets {
                service: local_service,
                interval: minimum_rotation_interval,
                restored_keys,
                reply,
            })
            .map_err(|_| RatchetConfigurationError::RuntimeStopped)?;
        result
            .await
            .unwrap_or(Err(RatchetConfigurationError::RuntimeStopped))
    }

    pub async fn export_ratchet_keys_for_restart(
        &self,
        local_service: ServiceId,
    ) -> Result<RatchetKeysForRestart, RatchetKeysForRestartError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::ExportRatchetKeysForRestart {
                service: local_service,
                reply: reply_tx,
            })
            .map_err(|_| RatchetKeysForRestartError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(RatchetKeysForRestartError::RuntimeStopped))
    }

    pub async fn send_destination_datagram(
        &self,
        destination: DestinationAddress,
        data: &[u8],
    ) -> Result<(), crate::handle::SendDestinationDatagramError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::SendDestinationDatagram {
                destination,
                data: data.to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| crate::handle::SendDestinationDatagramError::RuntimeStopped)?;
        reply_rx.await.unwrap_or(Err(
            crate::handle::SendDestinationDatagramError::RuntimeStopped,
        ))
    }

    pub async fn send_link_datagram(
        &self,
        link: crate::LinkHandle,
        data: &[u8],
    ) -> Result<(), crate::SendLinkDatagramError> {
        let (reply, result) = oneshot::channel();
        self.command_tx
            .send(Command::SendLinkDatagram {
                link,
                data: data.to_vec(),
                reply,
            })
            .map_err(|_| crate::SendLinkDatagramError::RuntimeStopped)?;
        result
            .await
            .unwrap_or(Err(crate::SendLinkDatagramError::RuntimeStopped))
    }

    pub async fn queue_channel_message(
        &self,
        link: crate::LinkHandle,
        message: crate::ChannelMessage,
    ) -> Result<(), crate::ChannelSendError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::SendChannel {
                link,
                message,
                reply: reply_tx,
            })
            .map_err(|_| crate::ChannelSendError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(crate::ChannelSendError::RuntimeStopped))
    }

    pub async fn recv_channel_message(
        &self,
        service: ServiceId,
    ) -> Result<(crate::LinkHandle, crate::ChannelMessage), ReceiveError> {
        let receiver = self
            .services
            .get(&service)
            .map(|channels| channels.channel_rx.clone())
            .ok_or(ReceiveError::ServiceNotFound)?;
        receiver
            .recv()
            .await
            .map_err(|_| ReceiveError::RuntimeStopped)
    }

    async fn queue_link_buffer_stream_data(
        &self,
        link: crate::LinkHandle,
        stream_id: crate::LinkBufferStreamId,
        data: &[u8],
    ) -> Result<crate::QueuedLinkBufferStreamData, crate::ChannelSendError> {
        let encoded = crate::buffer::encode(stream_id, data, false);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::SendBuffer {
                link,
                raw: encoded.0,
                processed: encoded.1,
                reply: reply_tx,
            })
            .map_err(|_| crate::ChannelSendError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(crate::ChannelSendError::RuntimeStopped))
    }

    async fn queue_link_buffer_stream_end(
        &self,
        link: crate::LinkHandle,
        stream_id: crate::LinkBufferStreamId,
    ) -> Result<(), crate::ChannelSendError> {
        let (raw, _) = crate::buffer::encode(stream_id, &[], true);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::SendBuffer {
                link,
                raw,
                processed: 0,
                reply: reply_tx,
            })
            .map_err(|_| crate::ChannelSendError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(crate::ChannelSendError::RuntimeStopped))
            .map(|_| ())
    }

    pub async fn recv_link_buffer_stream_chunk(
        &self,
        service: ServiceId,
    ) -> Result<(crate::LinkHandle, crate::LinkBufferStreamChunk), ReceiveError> {
        let receiver = self
            .services
            .get(&service)
            .map(|channels| channels.buffer_rx.clone())
            .ok_or(ReceiveError::ServiceNotFound)?;
        receiver
            .recv()
            .await
            .map_err(|_| ReceiveError::RuntimeStopped)
    }

    pub fn known_destinations(&self) -> Vec<KnownDestination> {
        self.destinations_rx.borrow().clone()
    }

    pub fn lifetime_stats(&self) -> LifetimeStats {
        self.stats_rx.borrow().clone()
    }

    pub async fn request(
        &self,
        link: crate::LinkHandle,
        path: &str,
        data: &[u8],
    ) -> Result<Response, RequestError> {
        let (completion, result) = oneshot::channel();
        self.command_tx
            .send(Command::Request {
                link,
                path: path.to_string(),
                data: data.to_vec(),
                completion,
            })
            .map_err(|_| RequestError::RuntimeStopped)?;
        result
            .await
            .unwrap_or(Err(RequestError::RuntimeStopped))
            .map(|(data, metadata)| Response { data, metadata })
    }

    pub async fn respond(
        &self,
        request_id: RequestId,
        data: &[u8],
        metadata: Option<&[u8]>,
        compress: bool,
    ) -> Result<(), RespondError> {
        let (completion, result) = oneshot::channel();
        self.command_tx
            .send(Command::Respond {
                request_id,
                data: data.to_vec(),
                metadata: metadata.map(|m| m.to_vec()),
                compress,
                completion,
            })
            .map_err(|_| RespondError::RuntimeStopped)?;
        result.await.unwrap_or(Err(RespondError::RuntimeStopped))
    }

    pub async fn recv_request(&self, service: ServiceId) -> Result<IncomingRequest, ReceiveError> {
        let request_rx = self
            .services
            .get(&service)
            .map(|channels| channels.request_rx.clone())
            .ok_or(ReceiveError::ServiceNotFound)?;
        request_rx
            .recv()
            .await
            .map_err(|_| ReceiveError::RuntimeStopped)
    }

    pub async fn recv_datagram(
        &self,
        service: ServiceId,
    ) -> Result<crate::ReceivedDatagram, ReceiveError> {
        let datagram_rx = self
            .services
            .get(&service)
            .map(|channels| channels.datagram_rx.clone())
            .ok_or(ReceiveError::ServiceNotFound)?;
        datagram_rx
            .recv()
            .await
            .map_err(|_| ReceiveError::RuntimeStopped)
    }

    pub async fn wait_for_known_destinations_to_differ_from(
        &self,
        previous_snapshot: &[KnownDestination],
    ) -> Result<Vec<KnownDestination>, RuntimeStopped> {
        let mut snapshots = self.destinations_rx.clone();
        loop {
            let current = snapshots.borrow().clone();
            if current != previous_snapshot {
                return Ok(current);
            }
            snapshots.changed().await.map_err(|_| RuntimeStopped)?;
        }
    }

    pub async fn ensure_route_to(
        &self,
        destination: DestinationAddress,
    ) -> Result<KnownDestination, crate::handle::RouteDiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::RequestPath {
                destination,
                reply: reply_tx,
            })
            .map_err(|_| crate::handle::RouteDiscoveryError::RuntimeStopped)?;
        if !reply_rx
            .await
            .map_err(|_| crate::handle::RouteDiscoveryError::RuntimeStopped)?
        {
            return Err(crate::handle::RouteDiscoveryError::NotFound);
        }
        self.destinations_rx
            .borrow()
            .iter()
            .find(|known| known.address == destination)
            .cloned()
            .ok_or(crate::handle::RouteDiscoveryError::NotFound)
    }

    pub async fn establish_link_from(
        &self,
        local_service: ServiceId,
        remote_destination: DestinationAddress,
    ) -> Result<crate::LinkHandle, EstablishLinkError> {
        self.ensure_route_to(remote_destination)
            .await
            .map_err(|error| match error {
                crate::RouteDiscoveryError::NotFound => EstablishLinkError::DestinationUnreachable,
                crate::RouteDiscoveryError::RuntimeStopped => EstablishLinkError::RuntimeStopped,
            })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::CreateLink {
                service: local_service,
                destination: remote_destination,
                reply: reply_tx,
            })
            .map_err(|_| EstablishLinkError::RuntimeStopped)?;
        let link = reply_rx
            .await
            .ok()
            .flatten()
            .ok_or(EstablishLinkError::DestinationUnreachable)?;

        let (active_tx, active_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::AwaitLinkActive {
            link,
            reply: active_tx,
        });
        active_rx
            .await
            .ok()
            .and_then(|r| r.ok())
            .ok_or(EstablishLinkError::Timeout)?;
        Ok(link)
    }

    pub async fn close_link(&self, link: crate::LinkHandle) -> Result<(), crate::LinkLookupError> {
        let (reply, result) = oneshot::channel();
        self.command_tx
            .send(Command::CloseLink { link, reply })
            .map_err(|_| crate::LinkLookupError::RuntimeStopped)?;
        if result
            .await
            .map_err(|_| crate::LinkLookupError::RuntimeStopped)?
        {
            Ok(())
        } else {
            Err(crate::LinkLookupError::LinkNotFound)
        }
    }

    pub async fn link_status(
        &self,
        link: crate::LinkHandle,
    ) -> Result<crate::LinkStatus, crate::LinkLookupError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::LinkStatus {
                link,
                reply: reply_tx,
            })
            .map_err(|_| crate::LinkLookupError::RuntimeStopped)?;
        reply_rx
            .await
            .map_err(|_| crate::LinkLookupError::RuntimeStopped)?
            .ok_or(crate::LinkLookupError::LinkNotFound)
    }

    pub async fn link_rtt(&self, link: crate::LinkHandle) -> Result<Duration, LinkRttError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::LinkRtt {
                link,
                reply: reply_tx,
            })
            .map_err(|_| LinkRttError::RuntimeStopped)?;
        reply_rx.await.unwrap_or(Err(LinkRttError::RuntimeStopped))
    }

    pub async fn authenticate_to_link_peer_as(
        &self,
        link: crate::LinkHandle,
        identity: &crate::PrivateIdentity,
    ) -> Result<(), crate::LinkPeerAuthenticationError> {
        let (reply, result) = oneshot::channel();
        self.command_tx
            .send(Command::AuthenticateToLinkPeer {
                link,
                identity: Box::new(identity.clone()),
                reply,
            })
            .map_err(|_| crate::LinkPeerAuthenticationError::RuntimeStopped)?;
        result
            .await
            .unwrap_or(Err(crate::LinkPeerAuthenticationError::RuntimeStopped))
    }

    pub async fn encrypt_payload_for_later_delivery(
        &self,
        destination: DestinationAddress,
        plaintext: &[u8],
    ) -> Result<crate::DestinationCiphertext, EncryptForLaterDeliveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::EncryptForLaterDelivery {
                destination,
                data: plaintext.to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| EncryptForLaterDeliveryError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(EncryptForLaterDeliveryError::RuntimeStopped))
            .map(crate::DestinationCiphertext::from_validated_bytes)
    }

    pub async fn decrypt_later_delivered_payload(
        &self,
        local_service: ServiceId,
        ciphertext: &crate::DestinationCiphertext,
    ) -> Result<Vec<u8>, DecryptLaterDeliveredPayloadError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::DecryptLaterDeliveredPayload {
                service: local_service,
                data: ciphertext.as_bytes().to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| DecryptLaterDeliveredPayloadError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(DecryptLaterDeliveredPayloadError::RuntimeStopped))
    }
}

impl<T: Transport> OutboundLinkBufferStream<'_, T> {
    pub async fn queue_data(
        &mut self,
        data: &[u8],
    ) -> Result<crate::QueuedLinkBufferStreamData, crate::ChannelSendError> {
        self.node
            .queue_link_buffer_stream_data(self.link, self.stream_id, data)
            .await
    }

    pub async fn finish(self) -> Result<(), crate::ChannelSendError> {
        self.node
            .queue_link_buffer_stream_end(self.link, self.stream_id)
            .await
    }
}

impl<T: Transport> NodeRuntime<T> {
    pub async fn run(mut self) {
        enum Activity<C> {
            Received(Vec<(Vec<u8>, usize)>),
            Command(Option<C>),
            Timer(Result<ScheduledTimer, futures_util::future::Aborted>),
        }

        loop {
            let NodeRuntime {
                protocol,
                command_rx,
                timers,
                ..
            } = &mut self;
            let timer = async {
                if timers.is_empty() {
                    futures_lite::future::pending().await
                } else {
                    Activity::Timer(timers.next().await.unwrap())
                }
            };
            let received = async {
                Activity::Received(
                    futures_lite::future::poll_fn(|cx| protocol.poll_received(cx)).await,
                )
            };
            let command = async { Activity::Command(command_rx.recv().await) };
            let activity =
                futures_lite::future::or(received, futures_lite::future::or(command, timer)).await;
            let now = Instant::now();
            let events = match activity {
                Activity::Received(received) => {
                    let received = Self::prepare_received(received);
                    self.protocol.process(now, received)
                }
                Activity::Command(Some(command)) => {
                    self.handle_command(command, now);
                    self.protocol.process(now, Vec::new())
                }
                Activity::Command(None) => break,
                Activity::Timer(Ok(timer)) => {
                    if self.timer_abort_handles.remove(&timer.event).is_none() {
                        continue;
                    }
                    self.protocol.handle_timer(now, timer)
                }
                Activity::Timer(Err(_)) => continue,
            };
            self.complete_activity(events);
        }
    }

    fn complete_activity(&mut self, events: Vec<ServiceEvent>) {
        while let Some((link, message, _)) = self.pending_channel_sends.front() {
            match self
                .protocol
                .try_queue_channel_message(*link, message.clone())
            {
                Ok(()) => {
                    let (_, _, reply) = self.pending_channel_sends.pop_front().unwrap();
                    let _ = reply.send(Ok(()));
                }
                Err(crate::channel::QueueChannelError::WindowFull) => break,
                Err(crate::channel::QueueChannelError::LinkNotFound) => {
                    let (_, _, reply) = self.pending_channel_sends.pop_front().unwrap();
                    let _ = reply.send(Err(crate::ChannelSendError::LinkNotFound));
                }
                Err(crate::channel::QueueChannelError::LinkNotActive) => {
                    let (_, _, reply) = self.pending_channel_sends.pop_front().unwrap();
                    let _ = reply.send(Err(crate::ChannelSendError::LinkNotActive));
                }
            }
        }
        while let Some((link, raw, _, _)) = self.pending_buffer_sends.front() {
            match self.protocol.send_buffer_data(*link, raw) {
                Ok(()) => {
                    let (_, _, processed, reply) = self.pending_buffer_sends.pop_front().unwrap();
                    let _ = reply.send(Ok(crate::QueuedLinkBufferStreamData {
                        input_prefix_bytes_queued: processed,
                    }));
                }
                Err(crate::channel::QueueChannelError::WindowFull) => break,
                Err(crate::channel::QueueChannelError::LinkNotFound) => {
                    let (_, _, _, reply) = self.pending_buffer_sends.pop_front().unwrap();
                    let _ = reply.send(Err(crate::ChannelSendError::LinkNotFound));
                }
                Err(crate::channel::QueueChannelError::LinkNotActive) => {
                    let (_, _, _, reply) = self.pending_buffer_sends.pop_front().unwrap();
                    let _ = reply.send(Err(crate::ChannelSendError::LinkNotActive));
                }
            }
        }

        let mut destinations_changed = false;
        for event in events {
            match event {
                ServiceEvent::Request {
                    service,
                    request_id,
                    path,
                    data,
                    remote_identity,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let _ = channels.request_tx.try_send(IncomingRequest {
                            request_id,
                            path,
                            data,
                            authenticated_remote_identity: remote_identity
                                .map(crate::IdentityAddress::from_bytes),
                        });
                    }
                }
                ServiceEvent::Raw {
                    service,
                    link,
                    data,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let datagram = match link {
                            Some(link) => crate::ReceivedDatagram::Link { link, data },
                            None => crate::ReceivedDatagram::Destination { data },
                        };
                        let _ = channels.datagram_tx.try_send(datagram);
                    }
                }
                ServiceEvent::Channel {
                    service,
                    link,
                    message,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let _ = channels.channel_tx.try_send((link, message));
                    }
                }
                ServiceEvent::Buffer {
                    service,
                    link,
                    chunk,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let _ = channels.buffer_tx.try_send((link, chunk));
                    }
                }
                #[cfg(test)]
                ServiceEvent::ResourceProgress { .. } => {}
                ServiceEvent::RequestResult { request_id, result } => {
                    if let Some(tx) = self.request_completions.remove(&request_id) {
                        let _ = tx.send(result.map(|(_, data, metadata)| (data, metadata)));
                    }
                }
                ServiceEvent::RespondResult { request_id, result } => {
                    if let Some(tx) = self.respond_completions.remove(&request_id) {
                        let _ = tx.send(result);
                    }
                }
                ServiceEvent::DestinationsChanged => destinations_changed = true,
                ServiceEvent::PathRequestResult { destination, found } => {
                    if let Some(waiters) = self.path_waiters.remove(&destination) {
                        for tx in waiters {
                            let _ = tx.send(found);
                        }
                    }
                }
            }
        }
        if destinations_changed {
            self.destinations_tx
                .send_replace(self.protocol.known_destinations());
        }
        self.stats_tx.send_replace(self.protocol.stats());

        self.link_waiters.retain(
            |link, waiters| match self.protocol.lookup_link_status(*link) {
                Some(crate::LinkStatus::Active) => {
                    for tx in waiters.drain(..) {
                        let _ = tx.send(Ok(()));
                    }
                    false
                }
                Some(crate::LinkStatus::Closed) | None => {
                    for tx in waiters.drain(..) {
                        let _ = tx.send(Err(EstablishLinkError::Timeout));
                    }
                    false
                }
                Some(_) => true,
            },
        );
        for timer in self.protocol.take_scheduled_timers() {
            let (abort_handle, abort_registration) = AbortHandle::new_pair();
            if let Some(previous) = self.timer_abort_handles.insert(timer.event, abort_handle) {
                previous.abort();
            }
            self.timers.push(Abortable::new(
                ProtocolTimerFuture::new(timer),
                abort_registration,
            ));
        }
    }

    fn prepare_received(received: Vec<(Vec<u8>, usize)>) -> Vec<PreparedInbound> {
        #[cfg(feature = "parallel-packet-processing")]
        if received.len() >= 32
            && received.iter().map(|(raw, _)| raw.len()).sum::<usize>() / received.len() >= 256
        {
            use rayon::prelude::*;

            return received
                .into_par_iter()
                .filter_map(|(raw, source)| PreparedInbound::parse(raw, source))
                .collect();
        }
        received
            .into_iter()
            .filter_map(|(raw, source)| PreparedInbound::parse(raw, source))
            .collect()
    }

    fn handle_command(&mut self, cmd: Command<T>, now: Instant) {
        match cmd {
            Command::AddInterface { interface } => {
                self.protocol.add_interface(*interface);
            }
            Command::Announce { service, app_data } => {
                if let Some(data) = app_data {
                    self.protocol.announce_with_app_data(service, Some(data));
                } else {
                    self.protocol.announce(service);
                }
            }
            Command::ConfigureAnnouncementRatchets {
                service,
                interval,
                restored_keys,
                reply,
            } => {
                let _ = reply.send(self.protocol.configure_announcement_ratchet_rotation(
                    service,
                    interval,
                    restored_keys,
                    now,
                ));
            }
            Command::ExportRatchetKeysForRestart { service, reply } => {
                let _ = reply.send(self.protocol.ratchet_keys_for_restart(service));
            }
            Command::Request {
                link,
                path,
                data,
                completion,
            } => match self.protocol.request_over_link(link, &path, &data) {
                Ok(request_id) => {
                    self.request_completions.insert(request_id, completion);
                }
                Err(error) => {
                    let _ = completion.send(Err(error));
                }
            },
            Command::Respond {
                request_id,
                data,
                metadata,
                compress,
                completion,
            } => {
                match self.protocol.respond_checked(
                    request_id,
                    &data,
                    metadata.as_deref(),
                    compress,
                ) {
                    Ok(()) => {
                        self.respond_completions.insert(request_id, completion);
                    }
                    Err(error) => {
                        let _ = completion.send(Err(error));
                    }
                }
            }
            Command::SendDestinationDatagram {
                destination,
                data,
                reply,
            } => {
                let _ = reply.send(self.protocol.send_destination_datagram(destination, &data));
            }
            Command::SendLinkDatagram { link, data, reply } => {
                let _ = reply.send(self.protocol.send_link_datagram(link, &data));
            }
            Command::SendChannel {
                link,
                message,
                reply,
            } => {
                match self
                    .protocol
                    .try_queue_channel_message(link, message.clone())
                {
                    Ok(()) => {
                        let _ = reply.send(Ok(()));
                    }
                    Err(crate::channel::QueueChannelError::WindowFull) => {
                        self.pending_channel_sends.push_back((link, message, reply));
                    }
                    Err(crate::channel::QueueChannelError::LinkNotFound) => {
                        let _ = reply.send(Err(crate::ChannelSendError::LinkNotFound));
                    }
                    Err(crate::channel::QueueChannelError::LinkNotActive) => {
                        let _ = reply.send(Err(crate::ChannelSendError::LinkNotActive));
                    }
                }
            }
            Command::SendBuffer {
                link,
                raw,
                processed,
                reply,
            } => match self.protocol.send_buffer_data(link, &raw) {
                Ok(()) => {
                    let _ = reply.send(Ok(crate::QueuedLinkBufferStreamData {
                        input_prefix_bytes_queued: processed,
                    }));
                }
                Err(crate::channel::QueueChannelError::WindowFull) => {
                    self.pending_buffer_sends
                        .push_back((link, raw, processed, reply));
                }
                Err(crate::channel::QueueChannelError::LinkNotFound) => {
                    let _ = reply.send(Err(crate::ChannelSendError::LinkNotFound));
                }
                Err(crate::channel::QueueChannelError::LinkNotActive) => {
                    let _ = reply.send(Err(crate::ChannelSendError::LinkNotActive));
                }
            },
            Command::CreateLink {
                service,
                destination,
                reply,
            } => {
                let _ = reply.send(self.protocol.create_link(service, destination, now));
            }
            Command::LinkStatus { link, reply } => {
                let _ = reply.send(self.protocol.lookup_link_status(link));
            }
            Command::LinkRtt { link, reply } => {
                let _ = reply.send(self.protocol.link_rtt(link));
            }
            Command::CloseLink { link, reply } => {
                let _ = reply.send(self.protocol.close_link(link));
            }
            Command::AuthenticateToLinkPeer {
                link,
                identity,
                reply,
            } => {
                let _ = reply.send(self.protocol.authenticate_to_link_peer(link, &identity));
            }
            Command::AwaitLinkActive { link, reply } => {
                match self.protocol.lookup_link_status(link) {
                    Some(crate::LinkStatus::Active) => {
                        let _ = reply.send(Ok(()));
                    }
                    Some(crate::LinkStatus::Closed) | None => {
                        let _ = reply.send(Err(EstablishLinkError::Timeout));
                    }
                    Some(_) => self.link_waiters.entry(link).or_default().push(reply),
                }
            }
            Command::RequestPath { destination, reply } => {
                if self.protocol.has_path(destination) {
                    let _ = reply.send(true);
                } else {
                    match self.path_waiters.entry(destination) {
                        std::collections::hash_map::Entry::Vacant(waiters) => {
                            self.protocol.request_path(destination, now);
                            waiters.insert(vec![reply]);
                        }
                        std::collections::hash_map::Entry::Occupied(mut waiters) => {
                            waiters.get_mut().push(reply);
                        }
                    }
                }
            }
            Command::EncryptForLaterDelivery {
                destination,
                data,
                reply,
            } => {
                let _ = reply.send(self.protocol.encrypt_for_later_delivery(destination, &data));
            }
            Command::DecryptLaterDeliveredPayload {
                service,
                data,
                reply,
            } => {
                let _ = reply.send(
                    self.protocol
                        .decrypt_later_delivered_payload(service, &data),
                );
            }
        }
    }
}
