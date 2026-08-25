use std::collections::HashMap;
#[cfg(feature = "tcp")]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
#[cfg(feature = "tcp")]
use std::task::Waker;
#[cfg(any(test, feature = "tcp"))]
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot, watch};

use crate::handle::{
    AppDecryptError, AppEncryptError, Destination, EstablishLinkError, IncomingRequest,
    LinkRttError, RatchetSnapshotError, ReceiveError, RequestError, ResourceError, RespondError,
    Response, ServiceEvent, ServiceId,
};
use crate::node::PreparedInbound;
use crate::packet::DestinationAddress;
use crate::request::RequestId;
use crate::stats::LifetimeStats;
use crate::{Interface, PrivateIdentity, Transport};

#[cfg(feature = "tcp")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tcp")]
use tokio::net::TcpStream;

#[cfg(feature = "tcp")]
use crate::transports::hdlc::{HDLC_FLAG, hdlc_escape, hdlc_unescape};

#[cfg(feature = "tcp")]
fn hdlc_frame(data: &[u8]) -> Vec<u8> {
    let escaped = hdlc_escape(data);
    let mut result = Vec::with_capacity(escaped.len() + 2);
    result.push(HDLC_FLAG);
    result.extend(escaped);
    result.push(HDLC_FLAG);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LinkContext, LinkDataDestination, Packet};

    struct TestTransport {
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl Transport for TestTransport {
        fn send(&mut self, _: &[u8]) {}

        fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
            self.inbound.poll_recv(cx)
        }

        fn send_ready(&self) -> bool {
            true
        }
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

        let prepared = Node::<TestTransport>::prepare_received(raw).await;

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
    async fn clones_share_runtime_setup() {
        let mut node: Node<TestTransport> = Node::endpoint();
        let mut setup = node.clone();
        let mut rng = StdRng::seed_from_u64(1);
        let service = setup
            .add_service("service", &[], &PrivateIdentity::generate(&mut rng))
            .unwrap();
        assert_eq!(
            setup.service_address(service),
            node.service_address(service)
        );

        let runtime = tokio::spawn(setup.run());
        tokio::task::yield_now().await;
        runtime.abort();
        assert!(runtime.await.unwrap_err().is_cancelled());
        assert_eq!(
            node.add_service("late", &[], &PrivateIdentity::generate(&mut rng)),
            Err(crate::ServiceRegistrationError::RuntimeStarted)
        );
        assert_eq!(
            node.ratchet_secret_snapshot(service).await,
            Err(RatchetSnapshotError::RuntimeStopped)
        );
        assert_eq!(
            node.link_rtt(crate::LinkHandle([0; 16])).await,
            Err(LinkRttError::RuntimeStopped)
        );
        assert_eq!(
            node.app_encrypt_for([0; 16], &[]).await,
            Err(AppEncryptError::RuntimeStopped)
        );
        assert_eq!(
            node.app_decrypt_as(service, &[]).await,
            Err(AppDecryptError::RuntimeStopped)
        );
    }

    #[tokio::test]
    async fn input_wakes_idle_runtime() {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let node = Node::endpoint();
        node.add_interface(Interface::new(TestTransport {
            inbound: inbound_rx,
        }));
        let observer = node.clone();
        let runtime = tokio::spawn(node.run());
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
struct Inbound {
    packets: VecDeque<Vec<u8>>,
    waker: Option<Waker>,
    closed: bool,
}

#[cfg(feature = "tcp")]
type InboundQueue = Arc<StdMutex<Inbound>>;

#[cfg(feature = "tcp")]
pub struct AsyncTcpTransport {
    addr: String,
    inbox: InboundQueue,
    outbox: mpsc::UnboundedSender<Vec<u8>>,
    connected: Arc<StdMutex<bool>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    io_task: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "tcp")]
impl AsyncTcpTransport {
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Self::from_stream(addr.to_string(), stream)
    }

    pub fn from_stream(addr: String, stream: TcpStream) -> std::io::Result<Self> {
        let inbox = Arc::new(StdMutex::new(Inbound {
            packets: VecDeque::new(),
            waker: None,
            closed: false,
        }));
        let (outbox, outbound) = mpsc::unbounded_channel();
        let connected = Arc::new(StdMutex::new(true));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let io_task = tokio::spawn(tcp_io_task(
            stream,
            inbox.clone(),
            outbound,
            connected.clone(),
            shutdown_rx,
        ));

        Ok(Self {
            addr,
            inbox,
            outbox,
            connected,
            shutdown_tx: Some(shutdown_tx),
            io_task: Some(io_task),
        })
    }

    pub async fn reconnect(&mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            match tx.send(()).await {
                Ok(()) | Err(_) => {}
            }
        }
        if let Some(io_task) = self.io_task.take() {
            io_task.await.map_err(std::io::Error::other)?;
        }

        let stream = TcpStream::connect(&self.addr).await?;
        stream.set_nodelay(true)?;

        *self.connected.lock().unwrap() = true;
        let mut inbox = self.inbox.lock().unwrap();
        inbox.packets.clear();
        inbox.closed = false;
        drop(inbox);
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let (outbox, outbound) = mpsc::unbounded_channel();
        self.shutdown_tx = Some(shutdown_tx);
        self.outbox = outbox;

        self.io_task = Some(tokio::spawn(tcp_io_task(
            stream,
            self.inbox.clone(),
            outbound,
            self.connected.clone(),
            shutdown_rx,
        )));

        Ok(())
    }
}

#[cfg(feature = "tcp")]
impl Drop for AsyncTcpTransport {
    fn drop(&mut self) {
        if let Some(io_task) = self.io_task.take() {
            io_task.abort();
        }
    }
}

#[cfg(feature = "tcp")]
impl Transport for AsyncTcpTransport {
    fn send(&mut self, data: &[u8]) {
        let _ = self.outbox.send(data.to_vec());
    }

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut inbox = self.inbox.lock().unwrap();
        if let Some(packet) = inbox.packets.pop_front() {
            Poll::Ready(Some(packet))
        } else if inbox.closed {
            Poll::Ready(None)
        } else {
            inbox.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn send_ready(&self) -> bool {
        true
    }

    fn is_connected(&self) -> bool {
        *self.connected.lock().unwrap()
    }
}

#[cfg(feature = "tcp")]
async fn tcp_io_task(
    stream: TcpStream,
    inbox: InboundQueue,
    mut outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    connected: Arc<StdMutex<bool>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let (mut reader, mut writer) = stream.into_split();

    let inbox_clone = inbox.clone();
    let read_task = async move {
        let mut buf = [0u8; 65536];
        let mut hdlc_buf = Vec::new();

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    hdlc_buf.extend_from_slice(&buf[..n]);
                    while let Some(frame) = hdlc_extract_frame(&mut hdlc_buf) {
                        let mut inbox = inbox_clone.lock().unwrap();
                        inbox.packets.push_back(frame);
                        if let Some(waker) = inbox.waker.take() {
                            waker.wake();
                        }
                    }
                }
                Err(_) => break,
            }
        }
    };

    let write_task = async move {
        while let Some(data) = outbound.recv().await {
            let frame = hdlc_frame(&data);
            if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
                return;
            }
        }
    };

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
        _ = shutdown_rx.recv() => {}
    }

    *connected.lock().unwrap() = false;
    let mut inbox = inbox.lock().unwrap();
    inbox.closed = true;
    if let Some(waker) = inbox.waker.take() {
        waker.wake();
    }
}

#[cfg(feature = "tcp")]
impl Interface<AsyncTcpTransport> {
    pub async fn reconnect(&mut self) -> std::io::Result<()> {
        self.transport.reconnect().await
    }
}

type RequestWaiters = Arc<
    StdMutex<HashMap<RequestId, oneshot::Sender<Result<(Vec<u8>, Option<Vec<u8>>), RequestError>>>>,
>;
type RespondWaiters = Arc<StdMutex<HashMap<RequestId, oneshot::Sender<Result<(), RespondError>>>>>;
type Receiver<T> = Arc<TokioMutex<mpsc::UnboundedReceiver<T>>>;
#[derive(Clone)]
struct ServiceChannels {
    request_tx: mpsc::UnboundedSender<IncomingRequest>,
    request_rx: Receiver<IncomingRequest>,
    raw_tx: mpsc::UnboundedSender<Vec<u8>>,
    raw_rx: Receiver<Vec<u8>>,
    resource_tx: mpsc::UnboundedSender<(crate::LinkHandle, Vec<u8>)>,
    resource_rx: Receiver<(crate::LinkHandle, Vec<u8>)>,
    progress_tx: mpsc::UnboundedSender<crate::handle::ResponseTransferProgress>,
    progress_rx: Receiver<crate::handle::ResponseTransferProgress>,
    channel_tx: mpsc::UnboundedSender<(crate::LinkHandle, crate::LinkChannelMessage)>,
    channel_rx: Receiver<(crate::LinkHandle, crate::LinkChannelMessage)>,
    buffer_tx: mpsc::UnboundedSender<(crate::LinkHandle, crate::BufferStreamChunk)>,
    buffer_rx: Receiver<(crate::LinkHandle, crate::BufferStreamChunk)>,
    request_waiters: RequestWaiters,
    respond_waiters: RespondWaiters,
}

enum Command<T: Transport> {
    AddInterface {
        interface: Box<Interface<T>>,
    },
    Announce {
        service: ServiceId,
        app_data: Option<Vec<u8>>,
    },
    EnableRatchets {
        service: ServiceId,
        interval: Duration,
        restored_ratchet_secrets: Option<Vec<[u8; 32]>>,
    },
    ExportRatchets {
        service: ServiceId,
        reply: oneshot::Sender<Result<Vec<[u8; 32]>, RatchetSnapshotError>>,
    },
    Request {
        service: ServiceId,
        link: crate::LinkHandle,
        path: String,
        data: Vec<u8>,
        reply: oneshot::Sender<RequestId>,
    },
    Respond {
        request_id: RequestId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    },
    SendRaw {
        dest: DestinationAddress,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), crate::handle::SendError>>,
    },
    SendLinkData {
        link: crate::LinkHandle,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), crate::SendUnreliableError>>,
    },
    SendChannel {
        link: crate::LinkHandle,
        message: crate::LinkChannelMessage,
        reply: oneshot::Sender<Result<(), crate::LinkChannelError>>,
    },
    SendBuffer {
        link: crate::LinkHandle,
        raw: Vec<u8>,
        processed: usize,
        reply: oneshot::Sender<Result<usize, crate::BufferStreamError>>,
    },
    CreateLink {
        service: ServiceId,
        destination: DestinationAddress,
        reply: oneshot::Sender<Option<crate::LinkHandle>>,
    },
    LinkStatus {
        link: crate::LinkHandle,
        reply: oneshot::Sender<crate::LinkStatus>,
    },
    LinkRtt {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Result<Duration, LinkRttError>>,
    },
    CloseLink {
        link: crate::LinkHandle,
    },
    SelfIdentify {
        link: crate::LinkHandle,
        identity: Box<crate::PrivateIdentity>,
    },
    AdvertiseResource {
        link: crate::LinkHandle,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
        reply: oneshot::Sender<bool>,
    },
    AwaitLinkActive {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Result<(), EstablishLinkError>>,
    },
    RequestPath {
        destination: DestinationAddress,
        reply: oneshot::Sender<bool>,
    },
    ProvePacket {
        service: ServiceId,
        packet_data: Vec<u8>,
    },
    AppEncryptFor {
        destination: DestinationAddress,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, AppEncryptError>>,
    },
    AppDecryptAs {
        service: ServiceId,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, AppDecryptError>>,
    },
}

struct Runtime<T: Transport> {
    protocol: crate::node::Protocol<T, StdRng>,
    command_rx: mpsc::UnboundedReceiver<Command<T>>,
    link_waiters: HashMap<crate::LinkHandle, Vec<oneshot::Sender<Result<(), EstablishLinkError>>>>,
    path_waiters: HashMap<DestinationAddress, Vec<oneshot::Sender<bool>>>,
    destinations_changed_tx: watch::Sender<()>,
    destinations_tx: watch::Sender<Vec<Destination>>,
    stats_tx: watch::Sender<LifetimeStats>,
}

pub struct Node<T: Transport> {
    services: Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
    service_addresses: Arc<StdMutex<HashMap<ServiceId, DestinationAddress>>>,
    command_tx: mpsc::UnboundedSender<Command<T>>,
    destinations_changed_rx: watch::Receiver<()>,
    destinations_rx: watch::Receiver<Vec<Destination>>,
    stats_rx: watch::Receiver<LifetimeStats>,
    inner: Arc<StdMutex<Option<Runtime<T>>>>,
}

impl<T: Transport> Clone for Node<T> {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            service_addresses: self.service_addresses.clone(),
            command_tx: self.command_tx.clone(),
            destinations_changed_rx: self.destinations_changed_rx.clone(),
            destinations_rx: self.destinations_rx.clone(),
            stats_rx: self.stats_rx.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<T: Transport> Node<T> {
    pub fn endpoint() -> Self {
        Self::with_packet_forwarding(false)
    }

    pub fn relay() -> Self {
        Self::with_packet_forwarding(true)
    }

    fn with_packet_forwarding(forward_packets: bool) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (destinations_changed_tx, destinations_changed_rx) = watch::channel(());
        let (destinations_tx, destinations_rx) = watch::channel(Vec::new());
        let (stats_tx, stats_rx) = watch::channel(LifetimeStats::default());
        let rng = StdRng::from_entropy();

        Self {
            services: Arc::new(StdMutex::new(HashMap::new())),
            service_addresses: Arc::new(StdMutex::new(HashMap::new())),
            command_tx,
            destinations_changed_rx,
            destinations_rx,
            stats_rx,
            inner: Arc::new(StdMutex::new(Some(Runtime {
                protocol: crate::node::Protocol::with_rng(rng, forward_packets),
                command_rx,
                link_waiters: HashMap::new(),
                path_waiters: HashMap::new(),
                destinations_changed_tx,
                destinations_tx,
                stats_tx,
            }))),
        }
    }

    pub fn add_interface(&self, interface: Interface<T>) {
        let _ = self.command_tx.send(Command::AddInterface {
            interface: Box::new(interface),
        });
    }

    pub fn add_service(
        &mut self,
        service_name: &str,
        request_paths: &[&str],
        private_identity: &PrivateIdentity,
    ) -> Result<ServiceId, crate::ServiceRegistrationError> {
        let mut runtime = self.inner.lock().unwrap();
        let inner = runtime
            .as_mut()
            .ok_or(crate::ServiceRegistrationError::RuntimeStarted)?;

        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let (resource_tx, resource_rx) = mpsc::unbounded_channel();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        let (channel_tx, channel_rx) = mpsc::unbounded_channel();
        let (buffer_tx, buffer_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(StdMutex::new(HashMap::new()));
        let respond_waiters: RespondWaiters = Arc::new(StdMutex::new(HashMap::new()));

        let service_id = inner
            .protocol
            .add_service(service_name, request_paths, private_identity);
        let address = inner.protocol.service_address(service_id).unwrap();

        self.services.lock().unwrap().insert(
            service_id,
            ServiceChannels {
                request_tx,
                request_rx: Arc::new(TokioMutex::new(request_rx)),
                raw_tx,
                raw_rx: Arc::new(TokioMutex::new(raw_rx)),
                resource_tx,
                resource_rx: Arc::new(TokioMutex::new(resource_rx)),
                progress_tx,
                progress_rx: Arc::new(TokioMutex::new(progress_rx)),
                channel_tx,
                channel_rx: Arc::new(TokioMutex::new(channel_rx)),
                buffer_tx,
                buffer_rx: Arc::new(TokioMutex::new(buffer_rx)),
                request_waiters,
                respond_waiters,
            },
        );
        self.service_addresses
            .lock()
            .unwrap()
            .insert(service_id, address);

        Ok(service_id)
    }

    pub fn service_address(&self, service: ServiceId) -> Option<DestinationAddress> {
        self.service_addresses
            .lock()
            .unwrap()
            .get(&service)
            .copied()
    }

    pub fn announce(&self, service: ServiceId) {
        let _ = self.command_tx.send(Command::Announce {
            service,
            app_data: None,
        });
    }

    pub fn announce_with_app_data(&self, service: ServiceId, app_data: Vec<u8>) {
        let _ = self.command_tx.send(Command::Announce {
            service,
            app_data: Some(app_data),
        });
    }

    pub fn enable_ratchet_rotation(
        &self,
        service: ServiceId,
        interval: Duration,
        restored_ratchet_secrets: Option<Vec<[u8; 32]>>,
    ) {
        let _ = self.command_tx.send(Command::EnableRatchets {
            service,
            interval,
            restored_ratchet_secrets,
        });
    }

    pub async fn ratchet_secret_snapshot(
        &self,
        service: ServiceId,
    ) -> Result<Vec<[u8; 32]>, RatchetSnapshotError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::ExportRatchets {
                service,
                reply: reply_tx,
            })
            .map_err(|_| RatchetSnapshotError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(RatchetSnapshotError::RuntimeStopped))
    }

    pub async fn send_raw(
        &self,
        dest: DestinationAddress,
        data: &[u8],
    ) -> Result<(), crate::handle::SendError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::SendRaw {
            dest,
            data: data.to_vec(),
            reply: reply_tx,
        });
        reply_rx
            .await
            .unwrap_or(Err(crate::handle::SendError::DestinationUnknown))
    }

    pub async fn send_unreliable(
        &self,
        link: crate::LinkHandle,
        data: &[u8],
    ) -> Result<(), crate::SendUnreliableError> {
        let (reply, result) = oneshot::channel();
        self.command_tx
            .send(Command::SendLinkData {
                link,
                data: data.to_vec(),
                reply,
            })
            .map_err(|_| crate::SendUnreliableError::RuntimeStopped)?;
        result
            .await
            .unwrap_or(Err(crate::SendUnreliableError::RuntimeStopped))
    }

    pub async fn send_link_channel_message(
        &self,
        link: crate::LinkHandle,
        message: crate::LinkChannelMessage,
    ) -> Result<(), crate::LinkChannelError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::SendChannel {
            link,
            message,
            reply: reply_tx,
        });
        reply_rx
            .await
            .unwrap_or(Err(crate::LinkChannelError::LinkNotFound))
    }

    pub async fn recv_link_channel_message(
        &self,
        service: ServiceId,
    ) -> Result<(crate::LinkHandle, crate::LinkChannelMessage), ReceiveError> {
        let receiver = self
            .services
            .lock()
            .unwrap()
            .get(&service)
            .map(|channels| channels.channel_rx.clone())
            .ok_or(ReceiveError::ServiceNotFound)?;
        receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or(ReceiveError::RuntimeStopped)
    }

    pub async fn send_buffer_stream_chunk(
        &self,
        link: crate::LinkHandle,
        stream_id: u16,
        data: &[u8],
        end_of_stream: bool,
    ) -> Result<usize, crate::BufferStreamError> {
        let encoded = if data.len() < 1024 {
            crate::buffer::encode(stream_id, data, end_of_stream)?
        } else {
            let data = data.to_vec();
            tokio::task::spawn_blocking(move || {
                crate::buffer::encode(stream_id, &data, end_of_stream)
            })
            .await
            .map_err(|_| crate::BufferStreamError::CompressionFailed)??
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::SendBuffer {
            link,
            raw: encoded.0,
            processed: encoded.1,
            reply: reply_tx,
        });
        reply_rx
            .await
            .unwrap_or(Err(crate::BufferStreamError::Channel(
                crate::LinkChannelError::LinkNotFound,
            )))
    }

    pub async fn recv_buffer_stream_chunk(
        &self,
        service: ServiceId,
    ) -> Result<(crate::LinkHandle, crate::BufferStreamChunk), ReceiveError> {
        let receiver = self
            .services
            .lock()
            .unwrap()
            .get(&service)
            .map(|channels| channels.buffer_rx.clone())
            .ok_or(ReceiveError::ServiceNotFound)?;
        receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or(ReceiveError::RuntimeStopped)
    }

    pub fn destination_snapshot(&self) -> Vec<Destination> {
        self.destinations_rx.borrow().clone()
    }

    pub fn lifetime_stats(&self) -> LifetimeStats {
        self.stats_rx.borrow().clone()
    }

    pub async fn request(
        &self,
        local_service: ServiceId,
        link: crate::LinkHandle,
        path: &str,
        data: &[u8],
    ) -> Result<Response, RequestError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Request {
            service: local_service,
            link,
            path: path.to_string(),
            data: data.to_vec(),
            reply: reply_tx,
        });

        let request_id = reply_rx.await.map_err(|_| RequestError::RuntimeStopped)?;

        let request_waiters = {
            let services = self.services.lock().unwrap();
            let Some(channels) = services.get(&local_service) else {
                return Err(RequestError::ServiceNotFound);
            };
            channels.request_waiters.clone()
        };

        let (waiter_tx, waiter_rx) = oneshot::channel();
        request_waiters
            .lock()
            .unwrap()
            .insert(request_id, waiter_tx);

        waiter_rx
            .await
            .unwrap_or(Err(RequestError::RuntimeStopped))
            .map(|(data, metadata)| Response { data, metadata })
    }

    pub async fn respond(
        &self,
        local_service: ServiceId,
        request_id: RequestId,
        data: &[u8],
        metadata: Option<&[u8]>,
        compress: bool,
    ) -> Result<(), RespondError> {
        let respond_waiters = {
            let services = self.services.lock().unwrap();
            let Some(channels) = services.get(&local_service) else {
                return Err(RespondError::LinkClosed);
            };
            channels.respond_waiters.clone()
        };

        let (waiter_tx, waiter_rx) = oneshot::channel();
        respond_waiters
            .lock()
            .unwrap()
            .insert(request_id, waiter_tx);

        let _ = self.command_tx.send(Command::Respond {
            request_id,
            data: data.to_vec(),
            metadata: metadata.map(|m| m.to_vec()),
            compress,
        });

        waiter_rx.await.unwrap_or(Err(RespondError::LinkClosed))
    }

    pub async fn recv_request(&self, service: ServiceId) -> Result<IncomingRequest, ReceiveError> {
        let request_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .ok_or(ReceiveError::ServiceNotFound)?;
            channels.request_rx.clone()
        };
        request_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(ReceiveError::RuntimeStopped)
    }

    pub async fn recv_raw(&self, service: ServiceId) -> Result<Vec<u8>, ReceiveError> {
        let raw_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .ok_or(ReceiveError::ServiceNotFound)?;
            channels.raw_rx.clone()
        };
        raw_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(ReceiveError::RuntimeStopped)
    }

    pub async fn recv_resource(
        &self,
        service: ServiceId,
    ) -> Result<(crate::LinkHandle, Vec<u8>), ReceiveError> {
        let resource_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .ok_or(ReceiveError::ServiceNotFound)?;
            channels.resource_rx.clone()
        };
        resource_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(ReceiveError::RuntimeStopped)
    }

    pub async fn recv_response_transfer_progress(
        &self,
        service: ServiceId,
    ) -> Result<crate::handle::ResponseTransferProgress, ReceiveError> {
        let progress_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .ok_or(ReceiveError::ServiceNotFound)?;
            channels.progress_rx.clone()
        };
        progress_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(ReceiveError::RuntimeStopped)
    }

    pub async fn wait_for_destination_change(&mut self) {
        let _ = self.destinations_changed_rx.changed().await;
    }

    pub async fn discover_route(
        &self,
        destination: DestinationAddress,
    ) -> Result<(), crate::handle::RouteDiscoveryError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::RequestPath {
                destination,
                reply: reply_tx,
            })
            .map_err(|_| crate::handle::RouteDiscoveryError::RuntimeStopped)?;
        if reply_rx
            .await
            .map_err(|_| crate::handle::RouteDiscoveryError::RuntimeStopped)?
        {
            Ok(())
        } else {
            Err(crate::handle::RouteDiscoveryError::NotFound)
        }
    }

    pub async fn establish_link(
        &self,
        service: ServiceId,
        destination: DestinationAddress,
    ) -> Result<crate::LinkHandle, EstablishLinkError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::CreateLink {
            service,
            destination,
            reply: reply_tx,
        });
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

    pub fn close_link(&self, link: crate::LinkHandle) {
        let _ = self.command_tx.send(Command::CloseLink { link });
    }

    pub async fn link_status(&self, link: crate::LinkHandle) -> crate::LinkStatus {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::LinkStatus {
            link,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or(crate::LinkStatus::Closed)
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

    pub fn self_identify(&self, link: crate::LinkHandle, identity: &crate::PrivateIdentity) {
        let _ = self.command_tx.send(Command::SelfIdentify {
            link,
            identity: Box::new(identity.clone()),
        });
    }

    pub async fn offer_resource(
        &self,
        link: crate::LinkHandle,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    ) -> Result<(), ResourceError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::AdvertiseResource {
            link,
            data,
            metadata,
            compress,
            reply: reply_tx,
        });
        reply_rx
            .await
            .ok()
            .filter(|advertised| *advertised)
            .map(|_| ())
            .ok_or(ResourceError::InvalidLink)
    }

    pub fn broadcast_delivery_proof(&self, service: ServiceId, packet_data: &[u8]) {
        let _ = self.command_tx.send(Command::ProvePacket {
            service,
            packet_data: packet_data.to_vec(),
        });
    }

    /// Encrypt data for a known destination at the application layer.
    ///
    /// This is NOT transport encryption - rinse handles that automatically.
    /// Use this when you need to pre-encrypt data for a recipient who will
    /// receive it later through an intermediary (e.g., a store-and-forward
    /// server that shouldn't be able to read the contents).
    ///
    /// The destination must have announced and be in the path table.
    /// Returns the encrypted blob (ephemeral public key + ciphertext).
    pub async fn app_encrypt_for(
        &self,
        destination: DestinationAddress,
        data: &[u8],
    ) -> Result<Vec<u8>, AppEncryptError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::AppEncryptFor {
                destination,
                data: data.to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| AppEncryptError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(AppEncryptError::RuntimeStopped))
    }

    /// Decrypt data that was application-layer encrypted for one of our services.
    ///
    /// This is the counterpart to `app_encrypt_for`. Use this to decrypt data
    /// that was pre-encrypted for your service and delivered through an
    /// intermediary (e.g., fetched from a store-and-forward server).
    ///
    /// The data format is: ephemeral public key (32 bytes) + ciphertext.
    pub async fn app_decrypt_as(
        &self,
        service: ServiceId,
        data: &[u8],
    ) -> Result<Vec<u8>, AppDecryptError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(Command::AppDecryptAs {
                service,
                data: data.to_vec(),
                reply: reply_tx,
            })
            .map_err(|_| AppDecryptError::RuntimeStopped)?;
        reply_rx
            .await
            .unwrap_or(Err(AppDecryptError::RuntimeStopped))
    }

    pub async fn run(self) {
        let Some(mut inner) = self.inner.lock().unwrap().take() else {
            panic!("node runtime already started");
        };

        let mut next_wake = Self::poll(&mut inner, &self.services, Vec::new()).await;

        loop {
            let deadline = async {
                match next_wake {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending().await,
                }
            };
            let mut command = None;
            let mut received = Vec::new();
            let protocol = &mut inner.protocol;
            let command_rx = &mut inner.command_rx;

            tokio::select! {
                biased;
                raw = std::future::poll_fn(|cx| protocol.poll_received(cx)) => {
                    received = raw;
                }
                cmd = command_rx.recv() => command = cmd,
                _ = deadline => {}
            }
            if let Some(command) = command {
                Self::handle_command(&mut inner, command, Instant::now());
            }
            next_wake = Self::poll(&mut inner, &self.services, received).await;
        }
    }

    async fn poll(
        inner: &mut Runtime<T>,
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
        received: Vec<(Vec<u8>, usize)>,
    ) -> Option<Instant> {
        let now = Instant::now();
        let received = Self::prepare_received(received).await;
        let (events, next_wake) = inner.protocol.poll_prepared(now, received);

        for event in &events {
            if let ServiceEvent::PathRequestResult { destination, found } = event
                && let Some(waiters) = inner.path_waiters.remove(destination)
            {
                for tx in waiters {
                    let _ = tx.send(*found);
                }
            }
        }

        let destinations_changed = events
            .iter()
            .any(|event| matches!(event, ServiceEvent::DestinationsChanged));
        Self::dispatch_events(services, &inner.destinations_changed_tx, events);
        if destinations_changed {
            inner
                .destinations_tx
                .send_replace(inner.protocol.known_destinations());
        }
        inner.stats_tx.send_replace(inner.protocol.stats());

        inner.link_waiters.retain(|link, waiters| {
            let status = inner.protocol.link_status(*link);
            if status == crate::LinkStatus::Active {
                for tx in waiters.drain(..) {
                    let _ = tx.send(Ok(()));
                }
                false
            } else if status == crate::LinkStatus::Closed {
                for tx in waiters.drain(..) {
                    let _ = tx.send(Err(EstablishLinkError::Timeout));
                }
                false
            } else {
                true
            }
        });

        next_wake
    }

    async fn prepare_received(received: Vec<(Vec<u8>, usize)>) -> Vec<PreparedInbound> {
        if received.len() < 32
            || received.iter().map(|(raw, _)| raw.len()).sum::<usize>() / received.len() < 256
        {
            return received
                .into_iter()
                .filter_map(|(raw, source)| PreparedInbound::parse(raw, source))
                .collect();
        }

        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(received.len());
        let chunk_size = received.len().div_ceil(workers);
        let mut tasks = tokio::task::JoinSet::new();
        let mut chunks: Vec<Vec<_>> = (0..workers)
            .map(|_| Vec::with_capacity(chunk_size))
            .collect();
        for (index, item) in received.into_iter().enumerate() {
            chunks[index / chunk_size].push((index, item));
        }
        for chunk in chunks.into_iter().filter(|chunk| !chunk.is_empty()) {
            tasks.spawn_blocking(move || {
                chunk
                    .into_iter()
                    .filter_map(|(index, (raw, source))| {
                        PreparedInbound::parse(raw, source).map(|packet| (index, packet))
                    })
                    .collect::<Vec<_>>()
            });
        }

        let mut prepared = Vec::new();
        while let Some(result) = tasks.join_next().await {
            let mut chunk = result.expect("packet preparation task failed");
            prepared.append(&mut chunk);
        }
        prepared.sort_unstable_by_key(|(index, _)| *index);
        prepared.into_iter().map(|(_, packet)| packet).collect()
    }

    fn dispatch_events(
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
        destinations_tx: &watch::Sender<()>,
        events: Vec<ServiceEvent>,
    ) {
        let services = services.lock().unwrap();
        for event in events {
            match event {
                ServiceEvent::Request {
                    service,
                    request_id,
                    path,
                    data,
                    remote_identity,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let _ = channels.request_tx.send(IncomingRequest {
                            request_id,
                            path,
                            data,
                            authenticated_remote_identity: remote_identity,
                        });
                    }
                }
                ServiceEvent::Raw { service, data } => {
                    if let Some(channels) = services.get(&service) {
                        let _ = channels.raw_tx.send(data);
                    }
                }
                ServiceEvent::Channel {
                    service,
                    link,
                    message,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let _ = channels.channel_tx.send((link, message));
                    }
                }
                ServiceEvent::Buffer {
                    service,
                    link,
                    chunk,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let _ = channels.buffer_tx.send((link, chunk));
                    }
                }
                ServiceEvent::Resource {
                    service,
                    link,
                    data,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let _ = channels.resource_tx.send((link, data));
                    }
                }
                ServiceEvent::ResourceProgress {
                    service,
                    request_id,
                    received_parts,
                    total_parts,
                    received_bytes,
                    total_bytes,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let _ =
                            channels
                                .progress_tx
                                .send(crate::handle::ResponseTransferProgress {
                                    request_id,
                                    received_parts,
                                    total_parts,
                                    received_bytes,
                                    total_bytes,
                                });
                    }
                }
                ServiceEvent::RequestResult {
                    service,
                    request_id,
                    result,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let mut waiters = channels.request_waiters.lock().unwrap();
                        if let Some(tx) = waiters.remove(&request_id) {
                            let _ = tx.send(result.map(|(_, data, metadata)| (data, metadata)));
                        }
                    }
                }
                ServiceEvent::RespondResult {
                    service,
                    request_id,
                    result,
                } => {
                    if let Some(channels) = services.get(&service) {
                        let mut waiters = channels.respond_waiters.lock().unwrap();
                        if let Some(tx) = waiters.remove(&request_id) {
                            let _ = tx.send(result);
                        }
                    }
                }
                ServiceEvent::DestinationsChanged => {
                    let _ = destinations_tx.send(());
                }
                ServiceEvent::PathRequestResult { .. } => {}
            }
        }
    }

    fn handle_command(inner: &mut Runtime<T>, cmd: Command<T>, now: Instant) {
        match cmd {
            Command::AddInterface { interface } => {
                inner.protocol.add_interface(*interface);
            }
            Command::Announce { service, app_data } => {
                if let Some(data) = app_data {
                    inner.protocol.announce_with_app_data(service, Some(data));
                } else {
                    inner.protocol.announce(service);
                }
            }
            Command::EnableRatchets {
                service,
                interval,
                restored_ratchet_secrets,
            } => {
                inner.protocol.enable_ratchet_rotation(
                    service,
                    interval,
                    restored_ratchet_secrets,
                    now,
                );
            }
            Command::ExportRatchets { service, reply } => {
                let _ = reply.send(inner.protocol.ratchet_secret_snapshot(service));
            }
            Command::Request {
                service,
                link,
                path,
                data,
                reply,
            } => {
                if let Some(request_id) = inner.protocol.request(service, link, &path, &data) {
                    let _ = reply.send(request_id);
                }
            }
            Command::Respond {
                request_id,
                data,
                metadata,
                compress,
            } => {
                inner
                    .protocol
                    .respond(request_id, &data, metadata.as_deref(), compress);
            }
            Command::SendRaw { dest, data, reply } => {
                let _ = reply.send(inner.protocol.send_raw(dest, &data));
            }
            Command::SendLinkData { link, data, reply } => {
                let _ = reply.send(inner.protocol.send_unreliable(link, &data));
            }
            Command::SendChannel {
                link,
                message,
                reply,
            } => {
                let _ = reply.send(inner.protocol.send_link_channel_message(link, message));
            }
            Command::SendBuffer {
                link,
                raw,
                processed,
                reply,
            } => {
                let _ = reply.send(
                    inner
                        .protocol
                        .send_buffer_data(link, &raw)
                        .map(|()| processed)
                        .map_err(crate::BufferStreamError::from),
                );
            }
            Command::CreateLink {
                service,
                destination,
                reply,
            } => {
                let _ = reply.send(inner.protocol.create_link(service, destination, now));
            }
            Command::LinkStatus { link, reply } => {
                let _ = reply.send(inner.protocol.link_status(link));
            }
            Command::LinkRtt { link, reply } => {
                let _ = reply.send(inner.protocol.link_rtt(link));
            }
            Command::CloseLink { link } => {
                inner.protocol.close_link(link);
            }
            Command::SelfIdentify { link, identity } => {
                inner.protocol.self_identify(link, &identity);
            }
            Command::AdvertiseResource {
                link,
                data,
                metadata,
                compress,
                reply,
            } => {
                let advertised = inner
                    .protocol
                    .offer_resource(link, data, metadata, compress)
                    .is_some();
                let _ = reply.send(advertised);
            }
            Command::AwaitLinkActive { link, reply } => {
                if inner.protocol.link_status(link) == crate::LinkStatus::Active {
                    let _ = reply.send(Ok(()));
                } else if inner.protocol.link_status(link) == crate::LinkStatus::Closed {
                    let _ = reply.send(Err(EstablishLinkError::Timeout));
                } else {
                    inner.link_waiters.entry(link).or_default().push(reply);
                }
            }
            Command::RequestPath { destination, reply } => {
                if inner.protocol.has_path(destination) {
                    let _ = reply.send(true);
                } else {
                    inner.protocol.request_path(destination, now);
                    inner
                        .path_waiters
                        .entry(destination)
                        .or_default()
                        .push(reply);
                }
            }
            Command::ProvePacket {
                service,
                packet_data,
            } => {
                inner
                    .protocol
                    .broadcast_delivery_proof(service, &packet_data);
            }
            Command::AppEncryptFor {
                destination,
                data,
                reply,
            } => {
                let _ = reply.send(inner.protocol.app_encrypt_for(destination, &data));
            }
            Command::AppDecryptAs {
                service,
                data,
                reply,
            } => {
                let _ = reply.send(inner.protocol.app_decrypt_as(service, &data));
            }
        }
    }
}
