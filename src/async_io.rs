use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{mpsc, oneshot};

use crate::aspect::AspectHash;
use crate::handle::{RequestError, RespondError, ServiceEvent, ServiceId};
use crate::packet::Address;
use crate::request::RequestId;
use crate::stats::StatsSnapshot;
use crate::{Identity, Interface, Transport};

#[cfg(feature = "tcp")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "tcp")]
use tokio::net::TcpStream;

#[cfg(feature = "tcp")]
use crate::transports::tcp::{HDLC_FLAG, hdlc_escape, hdlc_unescape};

#[cfg(feature = "tcp")]
fn hdlc_frame(data: &[u8]) -> Vec<u8> {
    let escaped = hdlc_escape(data);
    let mut result = Vec::with_capacity(escaped.len() + 2);
    result.push(HDLC_FLAG);
    result.extend(escaped);
    result.push(HDLC_FLAG);
    result
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

type Inbox = Arc<Mutex<VecDeque<Vec<u8>>>>;
type Outbox = Arc<Mutex<VecDeque<Vec<u8>>>>;

pub struct AsyncTransport {
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<Mutex<bool>>,
}

#[cfg(feature = "tcp")]
struct TransportIo {
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<Mutex<bool>>,
}

#[cfg(feature = "tcp")]
impl AsyncTransport {
    fn new() -> (Self, TransportIo) {
        let inbox = Arc::new(Mutex::new(VecDeque::new()));
        let outbox = Arc::new(Mutex::new(VecDeque::new()));
        let connected = Arc::new(Mutex::new(true));

        let transport = Self {
            inbox: inbox.clone(),
            outbox: outbox.clone(),
            connected: connected.clone(),
        };

        let io = TransportIo {
            inbox,
            outbox,
            connected,
        };

        (transport, io)
    }
}

impl Transport for AsyncTransport {
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
}

pub struct IncomingRequest {
    pub request_id: RequestId,
    pub path: String,
    pub data: Vec<u8>,
}

pub struct IncomingRaw {
    pub data: Vec<u8>,
}

pub struct Destination {
    pub address: Address,
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub aspect: AspectHash,
}

type RequestWaiters =
    Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<Vec<u8>, RequestError>>>>>;
type RespondWaiters = Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<(), RespondError>>>>>;

struct ServiceChannels {
    request_tx: mpsc::UnboundedSender<IncomingRequest>,
    raw_tx: mpsc::UnboundedSender<IncomingRaw>,
    request_waiters: RequestWaiters,
    respond_waiters: RespondWaiters,
}

enum Command {
    Announce {
        service: ServiceId,
        app_data: Option<Vec<u8>>,
    },
    Request {
        service: ServiceId,
        dest: Address,
        path: String,
        data: Vec<u8>,
        reply: oneshot::Sender<RequestId>,
    },
    Respond {
        request_id: RequestId,
        data: Vec<u8>,
    },
    SendRaw {
        dest: Address,
        data: Vec<u8>,
    },
    GetDestinations {
        reply: oneshot::Sender<Vec<Destination>>,
    },
    GetStats {
        reply: oneshot::Sender<StatsSnapshot>,
    },
    AddInterface {
        interface: Box<Interface<AsyncTransport>>,
    },
    Connect {
        request: ConnectRequest,
        reply: oneshot::Sender<Result<(), String>>,
    },
}

#[derive(Debug, Clone)]
pub enum ConnectRequest {
    #[cfg(feature = "tcp")]
    TcpClient { addr: String },
    #[cfg(feature = "tcp")]
    TcpServer { addr: String },
}

pub struct AsyncNode {
    node: crate::Node<AsyncTransport, StdRng>,
    services: HashMap<ServiceId, ServiceChannels>,
    command_tx: mpsc::UnboundedSender<Command>,
    command_rx: mpsc::UnboundedReceiver<Command>,
    wake_tx: mpsc::Sender<()>,
    wake_rx: mpsc::Receiver<()>,
}

impl AsyncNode {
    pub fn new(transport: bool) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (wake_tx, wake_rx) = mpsc::channel(16);
        let rng = StdRng::from_entropy();

        Self {
            node: crate::Node::with_rng(rng, transport),
            services: HashMap::new(),
            command_tx,
            command_rx,
            wake_tx,
            wake_rx,
        }
    }

    pub fn add_service(
        &mut self,
        name: &str,
        paths: &[&str],
        identity: &Identity,
    ) -> ServiceHandle {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(Mutex::new(HashMap::new()));
        let respond_waiters: RespondWaiters = Arc::new(Mutex::new(HashMap::new()));

        let service_id = self.node.add_service(name, paths, identity);
        let address = self.node.service_address(service_id).unwrap();

        self.services.insert(
            service_id,
            ServiceChannels {
                request_tx,
                raw_tx,
                request_waiters: request_waiters.clone(),
                respond_waiters: respond_waiters.clone(),
            },
        );

        ServiceHandle {
            service_id,
            address,
            command_tx: self.command_tx.clone(),
            request_rx,
            raw_rx,
            request_waiters,
            respond_waiters,
        }
    }

    pub fn add_interface(&mut self, transport: AsyncTransport) {
        self.node.add_interface(Interface::new(transport));
    }

    pub fn send_raw(&self, dest: Address, data: &[u8]) {
        let _ = self.command_tx.send(Command::SendRaw {
            dest,
            data: data.to_vec(),
        });
    }

    pub async fn destinations(&self) -> Vec<Destination> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .command_tx
            .send(Command::GetDestinations { reply: reply_tx });
        reply_rx.await.unwrap_or_default()
    }

    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(1000));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                Some(cmd) = self.command_rx.recv() => {
                    self.handle_command(cmd, Instant::now());
                }
                _ = self.wake_rx.recv() => {
                    while self.wake_rx.try_recv().is_ok() {}
                    self.poll(Instant::now());
                }
                _ = tick_interval.tick() => {
                    self.poll(Instant::now());
                }
            }
        }
    }

    fn poll(&mut self, now: Instant) {
        let events = self.node.poll(now);
        self.dispatch_events(events);
    }

    fn dispatch_events(&mut self, events: Vec<ServiceEvent>) {
        for event in events {
            match event {
                ServiceEvent::Request {
                    service,
                    request_id,
                    path,
                    data,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let _ = channels.request_tx.send(IncomingRequest {
                            request_id,
                            path,
                            data,
                        });
                    }
                }
                ServiceEvent::RequestResult {
                    service,
                    request_id,
                    result,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let mut waiters = channels.request_waiters.lock().unwrap();
                        if let Some(tx) = waiters.remove(&request_id) {
                            let _ = tx.send(result.map(|(_, data)| data));
                        }
                    }
                }
                ServiceEvent::RespondResult {
                    service,
                    request_id,
                    result,
                } => {
                    if let Some(channels) = self.services.get(&service) {
                        let mut waiters = channels.respond_waiters.lock().unwrap();
                        if let Some(tx) = waiters.remove(&request_id) {
                            let _ = tx.send(result);
                        }
                    }
                }
                ServiceEvent::Raw { service, data } => {
                    if let Some(channels) = self.services.get(&service) {
                        let _ = channels.raw_tx.send(IncomingRaw { data });
                    }
                }
                ServiceEvent::DestinationsChanged => {
                    // Consumers can call node.destinations() to get current destinations
                }
            }
        }
    }

    fn handle_command(&mut self, cmd: Command, now: Instant) {
        match cmd {
            Command::Announce { service, app_data } => {
                if let Some(data) = app_data {
                    self.node.announce_with_app_data(service, Some(data));
                } else {
                    self.node.announce(service);
                }
            }
            Command::Request {
                service,
                dest,
                path,
                data,
                reply,
            } => {
                let request_id = self.node.request(service, dest, &path, &data, now);
                let _ = reply.send(request_id);
            }
            Command::Respond { request_id, data } => {
                self.node.respond(request_id, &data);
            }
            Command::SendRaw { dest, data } => {
                self.node.send_raw(dest, &data);
            }
            Command::GetDestinations { reply } => {
                let destinations: Vec<Destination> = self
                    .node
                    .known_destinations()
                    .into_iter()
                    .map(|d| Destination {
                        address: d.address,
                        app_data: d.app_data,
                        hops: d.hops,
                        aspect: d.aspect,
                    })
                    .collect();
                let _ = reply.send(destinations);
            }
            Command::GetStats { reply } => {
                let _ = reply.send(self.node.stats());
            }
            Command::AddInterface { interface } => {
                log::info!("[ASYNC] adding interface via command");
                self.node.add_interface(*interface);
            }
            Command::Connect { request, reply } => {
                let command_tx = self.command_tx.clone();
                let wake_tx = self.wake_tx.clone();
                match request {
                    #[cfg(feature = "tcp")]
                    ConnectRequest::TcpClient { addr } => {
                        log::info!("[ASYNC] tcp client connect to {}", addr);
                        tokio::spawn(async move {
                            match TcpStream::connect(&addr).await {
                                Ok(stream) => {
                                    log::info!("[ASYNC] connected to {}", addr);
                                    if let Err(e) = stream.set_nodelay(true) {
                                        log::warn!("Failed to set TCP_NODELAY: {}", e);
                                    }
                                    let (transport, io) = AsyncTransport::new();
                                    let interface = Box::new(Interface::new(transport));
                                    let _ = command_tx.send(Command::AddInterface { interface });
                                    tokio::spawn(tcp_io_task(stream, io, wake_tx));
                                    let _ = reply.send(Ok(()));
                                }
                                Err(e) => {
                                    log::warn!("[ASYNC] failed to connect to {}: {}", addr, e);
                                    let _ = reply.send(Err(e.to_string()));
                                }
                            }
                        });
                    }
                    #[cfg(feature = "tcp")]
                    ConnectRequest::TcpServer { addr } => {
                        log::info!("[ASYNC] tcp server listen on {}", addr);
                        tokio::spawn(async move {
                            match tokio::net::TcpListener::bind(&addr).await {
                                Ok(listener) => {
                                    log::info!("[ASYNC] listening on {}", addr);
                                    let _ = reply.send(Ok(()));
                                    loop {
                                        match listener.accept().await {
                                            Ok((stream, peer)) => {
                                                log::info!("Accepted connection from {}", peer);
                                                if let Err(e) = stream.set_nodelay(true) {
                                                    log::warn!("Failed to set TCP_NODELAY: {}", e);
                                                }
                                                let (transport, io) = AsyncTransport::new();
                                                let interface = Box::new(Interface::new(transport));
                                                let _ = command_tx
                                                    .send(Command::AddInterface { interface });
                                                let wake = wake_tx.clone();
                                                tokio::spawn(tcp_io_task(stream, io, wake));
                                            }
                                            Err(e) => {
                                                log::warn!("Accept error: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("[ASYNC] failed to listen on {}: {}", addr, e);
                                    let _ = reply.send(Err(e.to_string()));
                                }
                            }
                        });
                    }
                }
            }
        }
        self.poll(now);
    }
}

#[cfg(feature = "tcp")]
impl AsyncNode {
    pub fn add_tcp_stream(&mut self, stream: TcpStream) {
        log::info!("[ASYNC] adding TCP stream");
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("Failed to set TCP_NODELAY: {}", e);
        } else {
            log::debug!("[ASYNC] TCP_NODELAY set successfully");
        }
        let (transport, io) = AsyncTransport::new();
        self.node.add_interface(Interface::new(transport));
        let wake_tx = self.wake_tx.clone();
        log::info!("[ASYNC] spawning tcp_io_task");
        tokio::spawn(tcp_io_task(stream, io, wake_tx));
    }

    pub async fn connect(&mut self, addr: &str) -> std::io::Result<()> {
        let stream = TcpStream::connect(addr).await?;
        self.add_tcp_stream(stream);
        Ok(())
    }

    pub async fn listen(&mut self, addr: &str) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        log::info!("Listening on {}", local_addr);

        let command_tx = self.command_tx.clone();
        let wake_tx = self.wake_tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        log::info!("Accepted connection from {}", peer);
                        if let Err(e) = stream.set_nodelay(true) {
                            log::warn!("Failed to set TCP_NODELAY: {}", e);
                        }
                        let (transport, io) = AsyncTransport::new();
                        let interface = Box::new(Interface::new(transport));
                        let _ = command_tx.send(Command::AddInterface { interface });
                        let wake = wake_tx.clone();
                        tokio::spawn(tcp_io_task(stream, io, wake));
                    }
                    Err(e) => {
                        log::warn!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}

pub struct ServiceHandle {
    service_id: ServiceId,
    address: Address,
    command_tx: mpsc::UnboundedSender<Command>,
    request_rx: mpsc::UnboundedReceiver<IncomingRequest>,
    raw_rx: mpsc::UnboundedReceiver<IncomingRaw>,
    request_waiters: RequestWaiters,
    respond_waiters: RespondWaiters,
}

#[derive(Clone)]
pub struct Requester {
    service_id: ServiceId,
    command_tx: mpsc::UnboundedSender<Command>,
    request_waiters: RequestWaiters,
}

impl Requester {
    pub async fn request(
        &self,
        dest: Address,
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RequestError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Request {
            service: self.service_id,
            dest,
            path: path.to_string(),
            data: data.to_vec(),
            reply: reply_tx,
        });

        let request_id = reply_rx.await.map_err(|_| RequestError::LinkFailed)?;

        let (waiter_tx, waiter_rx) = oneshot::channel();
        self.request_waiters
            .lock()
            .unwrap()
            .insert(request_id, waiter_tx);

        waiter_rx.await.unwrap_or(Err(RequestError::LinkFailed))
    }

    pub async fn connect(&self, request: ConnectRequest) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Connect {
            request,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or(Err("channel closed".into()))
    }
}

impl ServiceHandle {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn service_id(&self) -> ServiceId {
        self.service_id
    }

    pub fn requester(&self) -> Requester {
        Requester {
            service_id: self.service_id,
            command_tx: self.command_tx.clone(),
            request_waiters: self.request_waiters.clone(),
        }
    }

    pub fn announce(&self) {
        let _ = self.command_tx.send(Command::Announce {
            service: self.service_id,
            app_data: None,
        });
    }

    pub fn announce_with_app_data(&self, app_data: &[u8]) {
        let _ = self.command_tx.send(Command::Announce {
            service: self.service_id,
            app_data: Some(app_data.to_vec()),
        });
    }

    pub async fn request(
        &self,
        dest: Address,
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RequestError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Request {
            service: self.service_id,
            dest,
            path: path.to_string(),
            data: data.to_vec(),
            reply: reply_tx,
        });

        let request_id = reply_rx.await.map_err(|_| RequestError::LinkFailed)?;

        let (waiter_tx, waiter_rx) = oneshot::channel();
        self.request_waiters
            .lock()
            .unwrap()
            .insert(request_id, waiter_tx);

        waiter_rx.await.unwrap_or(Err(RequestError::LinkFailed))
    }

    pub async fn respond(&self, request_id: RequestId, data: &[u8]) -> Result<(), RespondError> {
        let (waiter_tx, waiter_rx) = oneshot::channel();
        self.respond_waiters
            .lock()
            .unwrap()
            .insert(request_id, waiter_tx);

        let _ = self.command_tx.send(Command::Respond {
            request_id,
            data: data.to_vec(),
        });

        waiter_rx.await.unwrap_or(Err(RespondError::LinkClosed))
    }

    pub async fn recv_request(&mut self) -> Option<IncomingRequest> {
        self.request_rx.recv().await
    }

    pub async fn recv_raw(&mut self) -> Option<IncomingRaw> {
        self.raw_rx.recv().await
    }

    pub async fn stats(&self) -> StatsSnapshot {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::GetStats { reply: reply_tx });
        reply_rx.await.unwrap_or_default()
    }

    pub async fn connect(&self, request: ConnectRequest) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Connect {
            request,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or(Err("channel closed".into()))
    }
}

#[cfg(feature = "tcp")]
async fn tcp_io_task(stream: TcpStream, io: TransportIo, wake_tx: mpsc::Sender<()>) {
    let (mut reader, mut writer) = stream.into_split();
    let TransportIo {
        inbox,
        outbox,
        connected,
    } = io;

    let read_task = async {
        let mut buf = [0u8; 65536];
        let mut hdlc_buf = Vec::new();
        let mut read_count = 0u64;

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    read_count += n as u64;
                    hdlc_buf.extend_from_slice(&buf[..n]);

                    while let Some(frame) = hdlc_extract_frame(&mut hdlc_buf) {
                        inbox.lock().unwrap().push_back(frame);
                        let _ = wake_tx.try_send(());
                    }
                }
                Err(e) => {
                    log::warn!("TCP read error: {} (read {} bytes)", e, read_count);
                    break;
                }
            }
        }
    };

    let write_task = async {
        let mut interval = tokio::time::interval(Duration::from_micros(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut write_count = 0u64;

        loop {
            interval.tick().await;

            let packets: Vec<Vec<u8>> = outbox.lock().unwrap().drain(..).collect();
            for data in packets {
                let frame = hdlc_frame(&data);
                if let Err(e) = writer.write_all(&frame).await {
                    log::warn!("TCP write error: {} (wrote {} bytes)", e, write_count);
                    return;
                }
                write_count += frame.len() as u64;
            }

            if let Err(e) = writer.flush().await {
                log::warn!("TCP flush error: {} (wrote {} bytes)", e, write_count);
                return;
            }
        }
    };

    tokio::select! {
        _ = read_task => {
            log::info!("TCP read task ended");
        }
        _ = write_task => {
            log::info!("TCP write task ended");
        }
    }

    *connected.lock().unwrap() = false;
    let _ = wake_tx.try_send(());
}
