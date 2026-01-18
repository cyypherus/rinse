use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::handle::{RequestError, RespondError};
use crate::packet::Address;
use crate::request::RequestId;
use crate::stats::StatsSnapshot;
use crate::transports::tcp::{HDLC_FLAG, hdlc_escape, hdlc_unescape};
use crate::{Identity, Interface, NodeHandle, Service, Transport};

fn hdlc_frame(data: &[u8]) -> Vec<u8> {
    let escaped = hdlc_escape(data);
    let mut result = Vec::with_capacity(escaped.len() + 2);
    result.push(HDLC_FLAG);
    result.extend(escaped);
    result.push(HDLC_FLAG);
    result
}

fn hdlc_extract_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let start = buf.iter().position(|&b| b == HDLC_FLAG)?;
    let end = buf[start + 1..]
        .iter()
        .position(|&b| b == HDLC_FLAG)
        .map(|p| p + start + 1)?;

    let frame_data = &buf[start + 1..end];
    let result = if !frame_data.is_empty() {
        let unescaped = hdlc_unescape(frame_data);
        if unescaped.len() >= 2 {
            Some(unescaped)
        } else {
            None
        }
    } else {
        None
    };

    *buf = buf[end..].to_vec();
    result
}

type Inbox = Arc<Mutex<VecDeque<Vec<u8>>>>;
type Outbox = Arc<Mutex<VecDeque<Vec<u8>>>>;

pub struct AsyncTransport {
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<Mutex<bool>>,
}

impl AsyncTransport {
    fn new_pair() -> (Self, Inbox, Outbox, Arc<Mutex<bool>>) {
        let inbox = Arc::new(Mutex::new(VecDeque::new()));
        let outbox = Arc::new(Mutex::new(VecDeque::new()));
        let connected = Arc::new(Mutex::new(true));

        let transport = Self {
            inbox: inbox.clone(),
            outbox: outbox.clone(),
            connected: connected.clone(),
        };

        (transport, inbox, outbox, connected)
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
    pub from: Address,
    pub path: String,
    pub data: Vec<u8>,
}

pub struct IncomingRaw {
    pub from: Address,
    pub data: Vec<u8>,
}

pub struct Destination {
    pub address: Address,
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
}

type RequestWaiters =
    Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<Vec<u8>, RequestError>>>>>;
type RespondWaiters = Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<(), RespondError>>>>>;

struct BridgeService {
    name: String,
    paths: Vec<String>,
    request_tx: mpsc::UnboundedSender<IncomingRequest>,
    raw_tx: mpsc::UnboundedSender<IncomingRaw>,
    request_waiters: RequestWaiters,
    respond_waiters: RespondWaiters,
    destinations_tx: mpsc::UnboundedSender<Vec<Destination>>,
}

impl Service for BridgeService {
    fn name(&self) -> &str {
        &self.name
    }

    fn paths(&self) -> Vec<&str> {
        self.paths.iter().map(|s| s.as_str()).collect()
    }

    fn on_request(
        &mut self,
        _handle: &mut NodeHandle,
        request_id: RequestId,
        from: Address,
        path: &str,
        data: &[u8],
    ) {
        let _ = self.request_tx.send(IncomingRequest {
            request_id,
            from,
            path: path.to_string(),
            data: data.to_vec(),
        });
    }

    fn on_request_result(
        &mut self,
        _handle: &mut NodeHandle,
        request_id: RequestId,
        result: Result<(Address, Vec<u8>), RequestError>,
    ) {
        let mut waiters = self.request_waiters.lock().unwrap();
        if let Some(tx) = waiters.remove(&request_id) {
            let _ = tx.send(result.map(|(_, data)| data));
        }
    }

    fn on_respond_result(
        &mut self,
        _handle: &mut NodeHandle,
        request_id: RequestId,
        result: Result<(), RespondError>,
    ) {
        let mut waiters = self.respond_waiters.lock().unwrap();
        if let Some(tx) = waiters.remove(&request_id) {
            let _ = tx.send(result);
        }
    }

    fn on_raw(&mut self, _handle: &mut NodeHandle, from: Address, data: &[u8]) {
        let _ = self.raw_tx.send(IncomingRaw {
            from,
            data: data.to_vec(),
        });
    }

    fn on_destinations_changed(&mut self, handle: &mut NodeHandle) {
        let destinations: Vec<Destination> = handle
            .destinations()
            .map(|d| Destination {
                address: d.address,
                app_data: d.app_data.clone(),
                hops: d.hops,
            })
            .collect();
        let _ = self.destinations_tx.send(destinations);
    }
}

enum Command {
    Announce {
        service_addr: Address,
        app_data: Option<Vec<u8>>,
    },
    Request {
        service_addr: Address,
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
}

pub struct AsyncNode {
    node: crate::Node<AsyncTransport, BridgeService, StdRng>,
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
        let (destinations_tx, destinations_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(Mutex::new(HashMap::new()));
        let respond_waiters: RespondWaiters = Arc::new(Mutex::new(HashMap::new()));

        let service = BridgeService {
            name: name.to_string(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            request_tx,
            raw_tx,
            request_waiters: request_waiters.clone(),
            respond_waiters: respond_waiters.clone(),
            destinations_tx,
        };

        let service_addr = self.node.add_service(service, identity);

        ServiceHandle {
            address: service_addr,
            command_tx: self.command_tx.clone(),
            request_rx,
            raw_rx,
            destinations_rx,
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

    pub fn add_tcp_stream(&mut self, stream: TcpStream) {
        let (transport, inbox, outbox, connected) = AsyncTransport::new_pair();
        self.node.add_interface(Interface::new(transport));
        let wake_tx = self.wake_tx.clone();
        tokio::spawn(tcp_io_task(stream, inbox, outbox, connected, wake_tx));
    }

    pub async fn connect(&mut self, addr: &str) -> std::io::Result<()> {
        let stream = TcpStream::connect(addr).await?;
        self.add_tcp_stream(stream);
        Ok(())
    }

    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(10));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let now = Instant::now();
            self.node.poll(now);

            tokio::select! {
                biased;
                Some(cmd) = self.command_rx.recv() => {
                    self.handle_command(cmd, Instant::now());
                }
                _ = self.wake_rx.recv() => {
                    // Drain any extra wakes to prevent backup
                    while self.wake_rx.try_recv().is_ok() {}
                }
                _ = tick_interval.tick() => {
                    // Periodic tick ensures we poll regularly even without events
                }
            }
        }
    }

    fn handle_command(&mut self, cmd: Command, now: Instant) {
        match cmd {
            Command::Announce {
                service_addr,
                app_data,
            } => {
                if let Some(data) = app_data {
                    self.node
                        .announce_with_app_data(service_addr, Some(data), now);
                } else {
                    self.node.announce(service_addr, now);
                }
            }
            Command::Request {
                service_addr,
                dest,
                path,
                data,
                reply,
            } => {
                let request_id = self.node.request(service_addr, dest, &path, &data, now);
                let _ = reply.send(request_id);
            }
            Command::Respond { request_id, data } => {
                self.node.respond(request_id, &data, now);
            }
            Command::SendRaw { dest, data } => {
                self.node.send_raw(dest, &data, now);
            }
            Command::GetDestinations { reply } => {
                let destinations: Vec<Destination> = self
                    .node
                    .known_destinations()
                    .iter()
                    .map(|addr| Destination {
                        address: *addr,
                        app_data: None,
                        hops: 0,
                    })
                    .collect();
                let _ = reply.send(destinations);
            }
            Command::GetStats { reply } => {
                let _ = reply.send(self.node.stats());
            }
        }
    }
}

pub struct ServiceHandle {
    address: Address,
    command_tx: mpsc::UnboundedSender<Command>,
    request_rx: mpsc::UnboundedReceiver<IncomingRequest>,
    raw_rx: mpsc::UnboundedReceiver<IncomingRaw>,
    destinations_rx: mpsc::UnboundedReceiver<Vec<Destination>>,
    request_waiters: RequestWaiters,
    respond_waiters: RespondWaiters,
}

#[derive(Clone)]
pub struct Requester {
    address: Address,
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
            service_addr: self.address,
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
}

impl ServiceHandle {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn requester(&self) -> Requester {
        Requester {
            address: self.address,
            command_tx: self.command_tx.clone(),
            request_waiters: self.request_waiters.clone(),
        }
    }

    pub fn announce(&self) {
        let _ = self.command_tx.send(Command::Announce {
            service_addr: self.address,
            app_data: None,
        });
    }

    pub fn announce_with_app_data(&self, app_data: &[u8]) {
        let _ = self.command_tx.send(Command::Announce {
            service_addr: self.address,
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
            service_addr: self.address,
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

    pub async fn recv_destinations_changed(&mut self) -> Option<Vec<Destination>> {
        self.destinations_rx.recv().await
    }

    pub async fn stats(&self) -> StatsSnapshot {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.command_tx.send(Command::GetStats { reply: reply_tx });
        reply_rx.await.unwrap_or_default()
    }
}

async fn tcp_io_task(
    stream: TcpStream,
    inbox: Inbox,
    outbox: Outbox,
    connected: Arc<Mutex<bool>>,
    wake_tx: mpsc::Sender<()>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let outbox_writer = outbox.clone();

    let read_task = async {
        let mut buf = [0u8; 65536];
        let mut hdlc_buf = Vec::new();

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    log::trace!("[TCP IN] {} bytes raw", n);
                    hdlc_buf.extend_from_slice(&buf[..n]);

                    while let Some(frame) = hdlc_extract_frame(&mut hdlc_buf) {
                        log::debug!(
                            "[TCP IN] frame {} bytes: {}",
                            frame.len(),
                            hex::encode(&frame[..frame.len().min(32)])
                        );
                        inbox.lock().unwrap().push_back(frame);
                    }
                    // Wake the node once after processing all frames (non-blocking)
                    let _ = wake_tx.try_send(());
                }
                Err(e) => {
                    log::debug!("[TCP IN] read error: {}", e);
                    break;
                }
            }
        }
        log::debug!("[TCP IN] read task ended");
    };

    let write_task = async {
        loop {
            let data = outbox_writer.lock().unwrap().pop_front();
            if let Some(data) = data {
                log::debug!(
                    "[TCP OUT] frame {} bytes: {}",
                    data.len(),
                    hex::encode(&data[..data.len().min(32)])
                );
                let framed = hdlc_frame(&data);
                if writer.write_all(&framed).await.is_err() {
                    log::debug!("[TCP OUT] write error");
                    break;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        log::debug!("[TCP OUT] write task ended");
    };

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
    }

    *connected.lock().unwrap() = false;
    let _ = wake_tx.send(()).await;
}
