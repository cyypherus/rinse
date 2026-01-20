use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot};

use crate::handle::{Destination, RequestError, RespondError, ServiceEvent, ServiceId};
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

type Inbox = Arc<StdMutex<VecDeque<Vec<u8>>>>;
type Outbox = Arc<StdMutex<VecDeque<Vec<u8>>>>;

#[cfg(feature = "tcp")]
pub struct AsyncTcpTransport {
    addr: String,
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<StdMutex<bool>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

#[cfg(feature = "tcp")]
impl AsyncTcpTransport {
    pub async fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Self::from_stream(addr.to_string(), stream)
    }

    pub fn from_stream(addr: String, stream: TcpStream) -> std::io::Result<Self> {
        let inbox: Inbox = Arc::new(StdMutex::new(VecDeque::new()));
        let outbox: Outbox = Arc::new(StdMutex::new(VecDeque::new()));
        let connected = Arc::new(StdMutex::new(true));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        tokio::spawn(tcp_io_task(
            stream,
            inbox.clone(),
            outbox.clone(),
            connected.clone(),
            shutdown_rx,
        ));

        Ok(Self {
            addr,
            inbox,
            outbox,
            connected,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub async fn reconnect(&mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        let stream = TcpStream::connect(&self.addr).await?;
        stream.set_nodelay(true)?;

        *self.connected.lock().unwrap() = true;
        self.inbox.lock().unwrap().clear();
        self.outbox.lock().unwrap().clear();

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        tokio::spawn(tcp_io_task(
            stream,
            self.inbox.clone(),
            self.outbox.clone(),
            self.connected.clone(),
            shutdown_rx,
        ));

        Ok(())
    }

    pub fn addr(&self) -> &str {
        &self.addr
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
}

#[cfg(feature = "tcp")]
async fn tcp_io_task(
    stream: TcpStream,
    inbox: Inbox,
    outbox: Outbox,
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
                        inbox_clone.lock().unwrap().push_back(frame);
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

// Async interface extension for reconnect
impl Interface<AsyncTcpTransport> {
    pub async fn reconnect(&mut self) -> std::io::Result<()> {
        self.transport.reconnect().await
    }

    pub fn addr(&self) -> &str {
        self.transport.addr()
    }
}

type RequestWaiters =
    Arc<StdMutex<HashMap<RequestId, oneshot::Sender<Result<Vec<u8>, RequestError>>>>>;
type RespondWaiters = Arc<StdMutex<HashMap<RequestId, oneshot::Sender<Result<(), RespondError>>>>>;
type EventReceiver = Arc<TokioMutex<mpsc::UnboundedReceiver<ServiceEvent>>>;

#[derive(Clone)]
struct ServiceChannels {
    event_tx: mpsc::UnboundedSender<ServiceEvent>,
    event_rx: EventReceiver,
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
    HasDestination {
        dest: Address,
        reply: oneshot::Sender<bool>,
    },
    GetDestinations {
        reply: oneshot::Sender<Vec<Destination>>,
    },
    GetStats {
        reply: oneshot::Sender<StatsSnapshot>,
    },
}

struct AsyncNodeInner<T: Transport> {
    node: crate::Node<T, StdRng>,
    command_rx: mpsc::UnboundedReceiver<Command<T>>,
}

pub struct AsyncNode<T: Transport> {
    services: Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
    service_addresses: Arc<StdMutex<HashMap<ServiceId, Address>>>,
    command_tx: mpsc::UnboundedSender<Command<T>>,
    inner: Option<AsyncNodeInner<T>>,
}

impl<T: Transport> Clone for AsyncNode<T> {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            service_addresses: self.service_addresses.clone(),
            command_tx: self.command_tx.clone(),
            inner: None,
        }
    }
}

impl<T: Transport> AsyncNode<T> {
    pub fn new(transport: bool) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let rng = StdRng::from_entropy();

        Self {
            services: Arc::new(StdMutex::new(HashMap::new())),
            service_addresses: Arc::new(StdMutex::new(HashMap::new())),
            command_tx,
            inner: Some(AsyncNodeInner {
                node: crate::Node::with_rng(rng, transport),
                command_rx,
            }),
        }
    }

    pub fn add_interface(&self, interface: Interface<T>) {
        let _ = self.command_tx.send(Command::AddInterface {
            interface: Box::new(interface),
        });
    }

    pub fn add_service(&mut self, name: &str, paths: &[&str], identity: &Identity) -> ServiceId {
        let inner = self
            .inner
            .as_mut()
            .expect("add_service requires the original AsyncNode");

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(StdMutex::new(HashMap::new()));
        let respond_waiters: RespondWaiters = Arc::new(StdMutex::new(HashMap::new()));

        let service_id = inner.node.add_service(name, paths, identity);
        let address = inner.node.service_address(service_id).unwrap();

        self.services.lock().unwrap().insert(
            service_id,
            ServiceChannels {
                event_tx,
                event_rx: Arc::new(TokioMutex::new(event_rx)),
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

    pub fn send_raw(&self, dest: Address, data: &[u8]) {
        let _ = self.command_tx.send(Command::SendRaw {
            dest,
            data: data.to_vec(),
        });
    }

    pub async fn has_destination(&self, dest: &Address) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::HasDestination {
            dest: *dest,
            reply: reply_tx,
        });
        reply_rx.await.unwrap_or(false)
    }

    pub async fn known_destinations(&self) -> Vec<Destination> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .command_tx
            .send(Command::GetDestinations { reply: reply_tx });
        reply_rx.await.unwrap_or_else(|_| Vec::new())
    }

    pub async fn stats(&self) -> StatsSnapshot {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::GetStats { reply: reply_tx });
        reply_rx.await.unwrap_or_default()
    }

    pub async fn request(
        &self,
        service: ServiceId,
        dest: Address,
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RequestError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::Request {
            service,
            dest,
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

        waiter_rx.await.unwrap_or(Err(RequestError::LinkFailed))
    }

    pub async fn respond(
        &self,
        service: ServiceId,
        request_id: RequestId,
        data: &[u8],
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
        });

        waiter_rx.await.unwrap_or(Err(RespondError::LinkClosed))
    }

    pub async fn receive(&self, service: ServiceId) -> Option<ServiceEvent> {
        let event_rx = {
            let services = self.services.lock().unwrap();
            let channels = services
                .get(&service)
                .expect("invalid ServiceId - service not registered");
            channels.event_rx.clone()
        };
        event_rx.lock().await.recv().await
    }

    pub async fn run(mut self) {
        let Some(mut inner) = self.inner.take() else {
            panic!("run() can only be called on the original AsyncNode, not a clone");
        };

        let mut tick_interval = tokio::time::interval(Duration::from_millis(10));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                Some(cmd) = inner.command_rx.recv() => {
                    Self::handle_command(&mut inner, &self.services, cmd, Instant::now());
                }
                _ = tick_interval.tick() => {
                    Self::poll(&mut inner, &self.services);
                }
            }
        }
    }

    fn poll(
        inner: &mut AsyncNodeInner<T>,
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
    ) {
        let now = Instant::now();
        let events = inner.node.poll(now);
        Self::dispatch_events(services, events);
    }

    fn dispatch_events(
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
        events: Vec<ServiceEvent>,
    ) {
        let services = services.lock().unwrap();
        for event in events {
            match &event {
                ServiceEvent::Request { service, .. }
                | ServiceEvent::Raw { service, .. }
                | ServiceEvent::ResourceProgress { service, .. } => {
                    if let Some(channels) = services.get(service) {
                        let _ = channels.event_tx.send(event);
                    }
                }
                ServiceEvent::RequestResult {
                    service,
                    request_id,
                    result,
                } => {
                    if let Some(channels) = services.get(service) {
                        let mut waiters = channels.request_waiters.lock().unwrap();
                        if let Some(tx) = waiters.remove(request_id) {
                            let _ = tx.send(result.clone().map(|(_, data)| data));
                        }
                    }
                }
                ServiceEvent::RespondResult {
                    service,
                    request_id,
                    result,
                } => {
                    if let Some(channels) = services.get(service) {
                        let mut waiters = channels.respond_waiters.lock().unwrap();
                        if let Some(tx) = waiters.remove(request_id) {
                            let _ = tx.send(result.clone());
                        }
                    }
                }
                ServiceEvent::DestinationsChanged => {}
            }
        }
    }

    fn handle_command(
        inner: &mut AsyncNodeInner<T>,
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
        cmd: Command<T>,
        now: Instant,
    ) {
        match cmd {
            Command::AddInterface { interface } => {
                inner.node.add_interface(*interface);
            }
            Command::Announce { service, app_data } => {
                if let Some(data) = app_data {
                    inner.node.announce_with_app_data(service, Some(data));
                } else {
                    inner.node.announce(service);
                }
            }
            Command::Request {
                service,
                dest,
                path,
                data,
                reply,
            } => {
                let request_id = inner.node.request(service, dest, &path, &data, now);
                let _ = reply.send(request_id);
            }
            Command::Respond { request_id, data } => {
                inner.node.respond(request_id, &data);
            }
            Command::SendRaw { dest, data } => {
                inner.node.send_raw(dest, &data);
            }
            Command::HasDestination { dest, reply } => {
                let _ = reply.send(inner.node.has_destination(&dest));
            }
            Command::GetDestinations { reply } => {
                let _ = reply.send(inner.node.known_destinations());
            }
            Command::GetStats { reply } => {
                let _ = reply.send(inner.node.stats());
            }
        }
        Self::poll(inner, services);
    }
}
