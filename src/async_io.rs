use std::collections::HashMap;
#[cfg(feature = "tcp")]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{Mutex as TokioMutex, Notify, mpsc, oneshot, watch};

use crate::handle::{
    Destination, IncomingRequest, LinkError, RequestError, ResourceError, RespondError, Response,
    ServiceEvent, ServiceId,
};
use crate::node::PreparedInbound;
use crate::packet::Address;
use crate::request::RequestId;
use crate::stats::StatsSnapshot;
use crate::{Identity, Interface, Transport};

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

    struct TestTransport;

    impl Transport for TestTransport {
        fn send(&mut self, _: &[u8]) {}

        fn recv(&mut self) -> Option<Vec<u8>> {
            None
        }

        fn bandwidth_available(&self) -> bool {
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
        let node: Node<TestTransport> = Node::new(false);
        let mut setup = node.clone();
        let mut rng = StdRng::seed_from_u64(1);
        let service = setup.add_service("service", &[], &Identity::generate(&mut rng));
        assert_eq!(
            setup.service_address(service),
            node.service_address(service)
        );

        let runtime = tokio::spawn(setup.run());
        tokio::task::yield_now().await;
        runtime.abort();
        assert!(runtime.await.unwrap_err().is_cancelled());
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
type PacketQueue = Arc<StdMutex<VecDeque<Vec<u8>>>>;

#[cfg(feature = "tcp")]
pub struct AsyncTcpTransport {
    addr: String,
    inbox: PacketQueue,
    outbox: PacketQueue,
    connected: Arc<StdMutex<bool>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    io_task: Option<tokio::task::JoinHandle<()>>,
    inbound_notifier: Arc<StdMutex<Option<Arc<Notify>>>>,
}

#[cfg(feature = "tcp")]
impl AsyncTcpTransport {
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Self::from_stream(addr.to_string(), stream)
    }

    pub fn from_stream(addr: String, stream: TcpStream) -> std::io::Result<Self> {
        let inbox: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
        let outbox: PacketQueue = Arc::new(StdMutex::new(VecDeque::new()));
        let connected = Arc::new(StdMutex::new(true));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let inbound_notifier = Arc::new(StdMutex::new(None));

        let io_task = tokio::spawn(tcp_io_task(
            stream,
            inbox.clone(),
            outbox.clone(),
            connected.clone(),
            inbound_notifier.clone(),
            shutdown_rx,
        ));

        Ok(Self {
            addr,
            inbox,
            outbox,
            connected,
            shutdown_tx: Some(shutdown_tx),
            io_task: Some(io_task),
            inbound_notifier,
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
        self.inbox.lock().unwrap().clear();
        self.outbox.lock().unwrap().clear();

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        self.io_task = Some(tokio::spawn(tcp_io_task(
            stream,
            self.inbox.clone(),
            self.outbox.clone(),
            self.connected.clone(),
            self.inbound_notifier.clone(),
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
        self.outbox.lock().unwrap().push_back(data.to_vec());
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbox.lock().unwrap().pop_front()
    }

    fn bandwidth_available(&self) -> bool {
        true
    }

    fn is_connected(&self) -> bool {
        *self.connected.lock().unwrap()
    }

    fn set_inbound_notifier(&mut self, notifier: Arc<Notify>) {
        *self.inbound_notifier.lock().unwrap() = Some(notifier);
    }
}

#[cfg(feature = "tcp")]
async fn tcp_io_task(
    stream: TcpStream,
    inbox: PacketQueue,
    outbox: PacketQueue,
    connected: Arc<StdMutex<bool>>,
    inbound_notifier: Arc<StdMutex<Option<Arc<Notify>>>>,
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
                        inbox_clone.lock().unwrap().push_back(frame);
                        if let Some(notifier) = inbound_notifier.lock().unwrap().as_ref() {
                            notifier.notify_one();
                        }
                    }
                }
                Err(_) => break,
            }
        }
    };

    let write_task = async move {
        let mut interval = tokio::time::interval(Duration::from_micros(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            let packets: Vec<Vec<u8>> = outbox.lock().unwrap().drain(..).collect();
            for data in packets {
                let frame = hdlc_frame(&data);
                if writer.write_all(&frame).await.is_err() {
                    return;
                }
            }

            if writer.flush().await.is_err() {
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
    progress_tx: mpsc::UnboundedSender<crate::handle::Progress>,
    progress_rx: Receiver<crate::handle::Progress>,
    channel_tx: mpsc::UnboundedSender<(crate::LinkHandle, crate::ChannelMessage)>,
    channel_rx: Receiver<(crate::LinkHandle, crate::ChannelMessage)>,
    buffer_tx: mpsc::UnboundedSender<(crate::LinkHandle, crate::BufferChunk)>,
    buffer_rx: Receiver<(crate::LinkHandle, crate::BufferChunk)>,
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
        existing_ratchets: Option<Vec<[u8; 32]>>,
    },
    ExportRatchets {
        service: ServiceId,
        reply: oneshot::Sender<Option<Vec<[u8; 32]>>>,
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
        dest: Address,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), crate::handle::SendError>>,
    },
    SendLinkData {
        link: crate::LinkHandle,
        data: Vec<u8>,
    },
    SendChannel {
        link: crate::LinkHandle,
        message: crate::ChannelMessage,
        reply: oneshot::Sender<Result<(), crate::ChannelError>>,
    },
    SendBuffer {
        link: crate::LinkHandle,
        raw: Vec<u8>,
        processed: usize,
        reply: oneshot::Sender<Result<usize, crate::BufferError>>,
    },
    CreateLink {
        service: ServiceId,
        destination: Address,
        reply: oneshot::Sender<Option<crate::LinkHandle>>,
    },
    LinkStatus {
        link: crate::LinkHandle,
        reply: oneshot::Sender<crate::LinkStatus>,
    },
    LinkRtt {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Option<u64>>,
    },
    CloseLink {
        link: crate::LinkHandle,
    },
    SelfIdentify {
        link: crate::LinkHandle,
        identity: Box<crate::Identity>,
    },
    LinkRequest {
        link: crate::LinkHandle,
        path: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Option<RequestId>>,
    },
    AdvertiseResource {
        link: crate::LinkHandle,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
        reply: oneshot::Sender<Option<crate::ResourceHandle>>,
    },
    AwaitLinkActive {
        link: crate::LinkHandle,
        reply: oneshot::Sender<Result<(), LinkError>>,
    },
    RequestPath {
        destination: Address,
        reply: oneshot::Sender<bool>,
    },
    ProvePacket {
        service: ServiceId,
        packet_data: Vec<u8>,
    },
    AppEncryptFor {
        destination: Address,
        data: Vec<u8>,
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    AppDecryptAs {
        service: ServiceId,
        data: Vec<u8>,
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
}

struct Runtime<T: Transport> {
    protocol: crate::node::Protocol<T, StdRng>,
    command_rx: mpsc::UnboundedReceiver<Command<T>>,
    link_waiters: HashMap<crate::LinkHandle, Vec<oneshot::Sender<Result<(), LinkError>>>>,
    path_waiters: HashMap<Address, Vec<oneshot::Sender<bool>>>,
    destinations_changed_tx: watch::Sender<()>,
    destinations_tx: watch::Sender<Vec<Destination>>,
    stats_tx: watch::Sender<StatsSnapshot>,
    inbound_ready: Arc<Notify>,
}

pub struct Node<T: Transport> {
    services: Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
    service_addresses: Arc<StdMutex<HashMap<ServiceId, Address>>>,
    command_tx: mpsc::UnboundedSender<Command<T>>,
    destinations_changed_rx: watch::Receiver<()>,
    destinations_rx: watch::Receiver<Vec<Destination>>,
    stats_rx: watch::Receiver<StatsSnapshot>,
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
    pub fn new(transport: bool) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (destinations_changed_tx, destinations_changed_rx) = watch::channel(());
        let (destinations_tx, destinations_rx) = watch::channel(Vec::new());
        let (stats_tx, stats_rx) = watch::channel(StatsSnapshot::default());
        let inbound_ready = Arc::new(Notify::new());
        let rng = StdRng::from_entropy();

        Self {
            services: Arc::new(StdMutex::new(HashMap::new())),
            service_addresses: Arc::new(StdMutex::new(HashMap::new())),
            command_tx,
            destinations_changed_rx,
            destinations_rx,
            stats_rx,
            inner: Arc::new(StdMutex::new(Some(Runtime {
                protocol: crate::node::Protocol::with_rng(rng, transport),
                command_rx,
                link_waiters: HashMap::new(),
                path_waiters: HashMap::new(),
                destinations_changed_tx,
                destinations_tx,
                stats_tx,
                inbound_ready,
            }))),
        }
    }

    pub fn add_interface(&self, interface: Interface<T>) {
        let _ = self.command_tx.send(Command::AddInterface {
            interface: Box::new(interface),
        });
    }

    pub fn add_service(&mut self, name: &str, paths: &[&str], identity: &Identity) -> ServiceId {
        let mut runtime = self.inner.lock().unwrap();
        let inner = runtime
            .as_mut()
            .expect("add_service requires the original Node");

        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let (resource_tx, resource_rx) = mpsc::unbounded_channel();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        let (channel_tx, channel_rx) = mpsc::unbounded_channel();
        let (buffer_tx, buffer_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(StdMutex::new(HashMap::new()));
        let respond_waiters: RespondWaiters = Arc::new(StdMutex::new(HashMap::new()));

        let service_id = inner.protocol.add_service(name, paths, identity);
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

        service_id
    }

    pub fn service_address(&self, service: ServiceId) -> Option<Address> {
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

    pub fn announce_with_app_data(&self, service: ServiceId, app_data: Option<Vec<u8>>) {
        let _ = self
            .command_tx
            .send(Command::Announce { service, app_data });
    }

    pub fn enable_ratchets(
        &self,
        service: ServiceId,
        interval: Duration,
        existing_ratchets: Option<Vec<[u8; 32]>>,
    ) {
        let _ = self.command_tx.send(Command::EnableRatchets {
            service,
            interval,
            existing_ratchets,
        });
    }

    pub async fn export_ratchets(&self, service: ServiceId) -> Option<Vec<[u8; 32]>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::ExportRatchets {
            service,
            reply: reply_tx,
        });
        reply_rx.await.ok().flatten()
    }

    pub async fn send_raw(
        &self,
        dest: Address,
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

    pub fn send_link_data(&self, link: crate::LinkHandle, data: &[u8]) {
        let _ = self.command_tx.send(Command::SendLinkData {
            link,
            data: data.to_vec(),
        });
    }

    pub async fn send_channel(
        &self,
        link: crate::LinkHandle,
        message: crate::ChannelMessage,
    ) -> Result<(), crate::ChannelError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::SendChannel {
            link,
            message,
            reply: reply_tx,
        });
        reply_rx
            .await
            .unwrap_or(Err(crate::ChannelError::InvalidLink))
    }

    pub async fn recv_channel(
        &self,
        service: ServiceId,
    ) -> Option<(crate::LinkHandle, crate::ChannelMessage)> {
        let receiver = self
            .services
            .lock()
            .unwrap()
            .get(&service)
            .map(|channels| channels.channel_rx.clone())?;
        receiver.lock().await.recv().await
    }

    pub async fn send_buffer(
        &self,
        link: crate::LinkHandle,
        stream_id: u16,
        data: &[u8],
        eof: bool,
    ) -> Result<usize, crate::BufferError> {
        let encoded = if data.len() < 1024 {
            crate::buffer::encode(stream_id, data, eof)?
        } else {
            let data = data.to_vec();
            tokio::task::spawn_blocking(move || crate::buffer::encode(stream_id, &data, eof))
                .await
                .map_err(|_| crate::BufferError::DecompressionFailed)??
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::SendBuffer {
            link,
            raw: encoded.0,
            processed: encoded.1,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or(Err(crate::BufferError::Channel(
            crate::ChannelError::InvalidLink,
        )))
    }

    pub async fn recv_buffer(
        &self,
        service: ServiceId,
    ) -> Option<(crate::LinkHandle, crate::BufferChunk)> {
        let receiver = self
            .services
            .lock()
            .unwrap()
            .get(&service)
            .map(|channels| channels.buffer_rx.clone())?;
        receiver.lock().await.recv().await
    }

    pub async fn known_destinations(&self) -> Vec<Destination> {
        self.destinations_rx.borrow().clone()
    }

    pub async fn stats(&self) -> StatsSnapshot {
        self.stats_rx.borrow().clone()
    }

    pub async fn request(
        &self,
        service: ServiceId,
        link: crate::LinkHandle,
        path: &str,
        data: &[u8],
    ) -> Result<Response, RequestError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Request {
            service,
            link,
            path: path.to_string(),
            data: data.to_vec(),
            reply: reply_tx,
        });

        let request_id = reply_rx.await.map_err(|_| RequestError::LinkFailed)?;

        let request_waiters = {
            let services = self.services.lock().unwrap();
            let Some(channels) = services.get(&service) else {
                return Err(RequestError::LinkFailed);
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
            .unwrap_or(Err(RequestError::LinkFailed))
            .map(|(data, metadata)| Response { data, metadata })
    }

    pub async fn respond(
        &self,
        service: ServiceId,
        request_id: RequestId,
        data: &[u8],
        metadata: Option<&[u8]>,
        compress: bool,
    ) -> Result<(), RespondError> {
        let respond_waiters = {
            let services = self.services.lock().unwrap();
            let Some(channels) = services.get(&service) else {
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

    pub async fn recv_request(&self, service: ServiceId) -> Option<IncomingRequest> {
        let request_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .expect("invalid ServiceId - service not registered");
            channels.request_rx.clone()
        };
        request_rx.lock().await.recv().await
    }

    pub async fn recv_raw(&self, service: ServiceId) -> Option<Vec<u8>> {
        let raw_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .expect("invalid ServiceId - service not registered");
            channels.raw_rx.clone()
        };
        raw_rx.lock().await.recv().await
    }

    pub async fn recv_resource(&self, service: ServiceId) -> Option<(crate::LinkHandle, Vec<u8>)> {
        let resource_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .expect("invalid ServiceId - service not registered");
            channels.resource_rx.clone()
        };
        resource_rx.lock().await.recv().await
    }

    pub async fn recv_progress(&self, service: ServiceId) -> Option<crate::handle::Progress> {
        let progress_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .expect("invalid ServiceId - service not registered");
            channels.progress_rx.clone()
        };
        progress_rx.lock().await.recv().await
    }

    pub async fn destinations_changed(&mut self) {
        let _ = self.destinations_changed_rx.changed().await;
    }

    pub async fn request_path(
        &self,
        destination: Address,
    ) -> Result<(), crate::handle::PathNotFound> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::RequestPath {
            destination,
            reply: reply_tx,
        });
        if reply_rx.await.unwrap_or(false) {
            Ok(())
        } else {
            Err(crate::handle::PathNotFound)
        }
    }

    pub async fn establish_link(
        &self,
        service: ServiceId,
        destination: Address,
    ) -> Result<crate::LinkHandle, LinkError> {
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
            .ok_or(LinkError::DestinationUnreachable)?;

        let (active_tx, active_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::AwaitLinkActive {
            link,
            reply: active_tx,
        });
        active_rx
            .await
            .ok()
            .and_then(|r| r.ok())
            .ok_or(LinkError::Timeout)?;
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

    pub async fn link_rtt(&self, link: crate::LinkHandle) -> Option<u64> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::LinkRtt {
            link,
            reply: reply_tx,
        });
        reply_rx.await.ok().flatten()
    }

    pub fn self_identify(&self, link: crate::LinkHandle, identity: &crate::Identity) {
        let _ = self.command_tx.send(Command::SelfIdentify {
            link,
            identity: Box::new(identity.clone()),
        });
    }

    pub async fn link_request(
        &self,
        link: crate::LinkHandle,
        path: &str,
        data: &[u8],
    ) -> Result<RequestId, RequestError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::LinkRequest {
            link,
            path: path.to_string(),
            data: data.to_vec(),
            reply: reply_tx,
        });
        reply_rx
            .await
            .ok()
            .flatten()
            .ok_or(RequestError::LinkFailed)
    }

    pub async fn advertise_resource(
        &self,
        link: crate::LinkHandle,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    ) -> Result<crate::ResourceHandle, ResourceError> {
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
            .flatten()
            .ok_or(ResourceError::InvalidLink)
    }

    pub fn prove_packet(&self, service: ServiceId, packet_data: &[u8]) {
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
    pub async fn app_encrypt_for(&self, destination: Address, data: &[u8]) -> Option<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::AppEncryptFor {
            destination,
            data: data.to_vec(),
            reply: reply_tx,
        });
        reply_rx.await.ok().flatten()
    }

    /// Decrypt data that was application-layer encrypted for one of our services.
    ///
    /// This is the counterpart to `app_encrypt_for`. Use this to decrypt data
    /// that was pre-encrypted for your service and delivered through an
    /// intermediary (e.g., fetched from a store-and-forward server).
    ///
    /// The data format is: ephemeral public key (32 bytes) + ciphertext.
    pub async fn app_decrypt_as(&self, service: ServiceId, data: &[u8]) -> Option<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::AppDecryptAs {
            service,
            data: data.to_vec(),
            reply: reply_tx,
        });
        reply_rx.await.ok().flatten()
    }

    pub async fn run(self) {
        let Some(mut inner) = self.inner.lock().unwrap().take() else {
            panic!("node runtime already started");
        };

        let mut next_wake: Option<Instant> = None;

        loop {
            let sleep_duration = next_wake
                .map(|t| t.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_millis(10))
                .min(Duration::from_millis(10))
                .max(Duration::from_millis(1));

            tokio::select! {
                biased;
                Some(cmd) = inner.command_rx.recv() => {
                    Self::handle_command(&mut inner, cmd, Instant::now());
                }
                _ = inner.inbound_ready.notified() => {}
                _ = tokio::time::sleep(sleep_duration) => {}
            }
            next_wake = Self::poll(&mut inner, &self.services).await;
        }
    }

    async fn poll(
        inner: &mut Runtime<T>,
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
    ) -> Option<Instant> {
        let now = Instant::now();
        let received = inner.protocol.drain_received();
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
                    let _ = tx.send(Err(LinkError::Timeout));
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
                            remote_identity,
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
                        let _ = channels.progress_tx.send(crate::handle::Progress {
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
            Command::AddInterface { mut interface } => {
                interface
                    .transport
                    .set_inbound_notifier(inner.inbound_ready.clone());
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
                existing_ratchets,
            } => {
                inner
                    .protocol
                    .enable_ratchets(service, interval, existing_ratchets, now);
            }
            Command::ExportRatchets { service, reply } => {
                let _ = reply.send(inner.protocol.export_ratchets(service));
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
            Command::SendLinkData { link, data } => {
                inner.protocol.send_link_data(link, &data);
            }
            Command::SendChannel {
                link,
                message,
                reply,
            } => {
                let _ = reply.send(inner.protocol.send_channel(link, message));
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
                        .map_err(crate::BufferError::from),
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
            Command::LinkRequest {
                link,
                path,
                data,
                reply,
            } => {
                let _ = reply.send(inner.protocol.link_request(link, &path, &data, now));
            }
            Command::AdvertiseResource {
                link,
                data,
                metadata,
                compress,
                reply,
            } => {
                let _ = reply.send(
                    inner
                        .protocol
                        .advertise_resource(link, data, metadata, compress),
                );
            }
            Command::AwaitLinkActive { link, reply } => {
                if inner.protocol.link_status(link) == crate::LinkStatus::Active {
                    let _ = reply.send(Ok(()));
                } else if inner.protocol.link_status(link) == crate::LinkStatus::Closed {
                    let _ = reply.send(Err(LinkError::Timeout));
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
                inner.protocol.prove_packet(service, &packet_data);
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
