use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{mpsc, oneshot};

use crate::aspect::AspectHash;
use crate::handle::{RequestError, RespondError};
use crate::packet::Address;
use crate::request::RequestId;
use crate::stats::StatsSnapshot;
use crate::{Identity, Interface, NodeHandle, Service, Transport};

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
        let len = data.len();
        self.outbox.lock().unwrap().push_back(data.to_vec());
        log::trace!(
            "[TRANSPORT] send queued {} bytes, outbox len={}",
            len,
            self.outbox.lock().unwrap().len()
        );
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        let result = self.inbox.lock().unwrap().pop_front();
        if let Some(ref data) = result {
            log::trace!(
                "[TRANSPORT] recv {} bytes, inbox len={}",
                data.len(),
                self.inbox.lock().unwrap().len()
            );
        }
        result
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
    pub aspect: AspectHash,
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
                aspect: d.aspect,
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
    AddInterface {
        interface: Box<Interface<AsyncTransport>>,
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

    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(10));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_poll = Instant::now();
        let mut poll_count = 0u64;
        let run_start = Instant::now();
        log::info!("[ASYNC] node.run() starting");

        loop {
            let now = Instant::now();
            let since_last = now.duration_since(last_poll);
            if since_last > Duration::from_secs(1) {
                log::warn!(
                    "[ASYNC] poll gap: {:?} - something blocked the event loop",
                    since_last
                );
            }
            last_poll = now;
            poll_count += 1;

            if poll_count.is_multiple_of(1000) {
                log::debug!(
                    "[ASYNC] poll #{}, uptime {:?}",
                    poll_count,
                    run_start.elapsed()
                );
            }

            let poll_start = Instant::now();
            self.node.poll(now);
            let poll_duration = poll_start.elapsed();
            if poll_duration > Duration::from_millis(100) {
                log::warn!("[ASYNC] poll() took {:?}", poll_duration);
            }

            tokio::select! {
                biased;
                Some(cmd) = self.command_rx.recv() => {
                    log::trace!("[ASYNC] select: command received");
                    self.handle_command(cmd, Instant::now());
                }
                _ = self.wake_rx.recv() => {
                    log::trace!("[ASYNC] select: wake received");
                    // Drain any extra wakes to prevent backup
                    while self.wake_rx.try_recv().is_ok() {}
                }
                _ = tick_interval.tick() => {
                    // log::trace!("[ASYNC] select: tick");
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
        }
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

#[cfg(feature = "tcp")]
async fn tcp_io_task(stream: TcpStream, io: TransportIo, wake_tx: mpsc::Sender<()>) {
    log::info!("[TCP] io task starting");
    let (mut reader, mut writer) = stream.into_split();
    let TransportIo {
        inbox,
        outbox,
        connected,
    } = io;

    let read_task = async {
        log::info!("[TCP IN] read task starting");
        let mut buf = [0u8; 65536];
        let mut hdlc_buf = Vec::new();
        let mut read_count = 0u64;

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    log::info!("[TCP IN] connection closed (read 0)");
                    break;
                }
                Ok(n) => {
                    read_count += 1;
                    log::trace!(
                        "[TCP IN] #{} {} bytes raw, hdlc_buf now {} bytes",
                        read_count,
                        n,
                        hdlc_buf.len() + n
                    );
                    hdlc_buf.extend_from_slice(&buf[..n]);

                    let mut frame_count = 0;
                    while let Some(frame) = hdlc_extract_frame(&mut hdlc_buf) {
                        frame_count += 1;
                        log::debug!(
                            "[TCP IN] frame {} bytes: {}",
                            frame.len(),
                            hex::encode(&frame[..frame.len().min(32)])
                        );
                        inbox.lock().unwrap().push_back(frame);
                    }
                    if frame_count > 0 {
                        log::trace!(
                            "[TCP IN] extracted {} frames, {} bytes remaining in hdlc_buf",
                            frame_count,
                            hdlc_buf.len()
                        );
                    } else if !hdlc_buf.is_empty() {
                        // No frames extracted but buffer has data - log for debugging
                        let flag_positions: Vec<usize> = hdlc_buf
                            .iter()
                            .enumerate()
                            .filter(|&(_, b)| *b == HDLC_FLAG)
                            .map(|(i, _)| i)
                            .collect();
                        log::debug!(
                            "[TCP IN] no frames extracted, buf {} bytes, FLAG positions: {:?}, first 16: {}",
                            hdlc_buf.len(),
                            &flag_positions[..flag_positions.len().min(10)],
                            hex::encode(&hdlc_buf[..hdlc_buf.len().min(16)])
                        );
                    }
                    // Wake the node once after processing all frames (non-blocking)
                    match wake_tx.try_send(()) {
                        Ok(()) => log::trace!("[TCP IN] wake sent"),
                        Err(_) => log::trace!("[TCP IN] wake channel full"),
                    }
                }
                Err(e) => {
                    log::info!("[TCP IN] read error: {}", e);
                    break;
                }
            }
        }
        log::info!("[TCP IN] read task ended after {} reads", read_count);
    };

    let write_task = async {
        log::info!("[TCP OUT] write task starting");
        let mut write_count = 0u64;
        let mut idle_count = 0u64;

        loop {
            let data = outbox.lock().unwrap().pop_front();
            if let Some(data) = data {
                write_count += 1;
                let framed = hdlc_frame(&data);
                log::debug!(
                    "[TCP OUT] #{} frame {} bytes (framed {}): {}",
                    write_count,
                    data.len(),
                    framed.len(),
                    hex::encode(&data[..data.len().min(32)])
                );
                let write_start = Instant::now();
                if writer.write_all(&framed).await.is_err() {
                    log::info!("[TCP OUT] write error");
                    break;
                }
                if writer.flush().await.is_err() {
                    log::info!("[TCP OUT] flush error");
                    break;
                }
                let write_duration = write_start.elapsed();
                if write_duration > Duration::from_millis(100) {
                    log::warn!("[TCP OUT] write+flush took {:?}", write_duration);
                }
                idle_count = 0;
            } else {
                idle_count += 1;
                if idle_count == 1000 {
                    log::trace!("[TCP OUT] idle for 1s (1000 iterations)");
                    idle_count = 0;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        log::info!("[TCP OUT] write task ended after {} writes", write_count);
    };

    tokio::select! {
        _ = read_task => {
            log::info!("[TCP] read task finished first");
        }
        _ = write_task => {
            log::info!("[TCP] write task finished first");
        }
    }

    *connected.lock().unwrap() = false;
    let _ = wake_tx.send(()).await;
    log::info!("[TCP] io task ended");
}

#[cfg(all(test, feature = "tcp"))]
mod tests {
    use super::*;
    use crate::transports::tcp::HDLC_ESC;

    #[test]
    fn hdlc_single_frame() {
        let data = vec![0x01, 0x02, 0x03];
        let framed = hdlc_frame(&data);

        let mut buf = framed;
        let extracted = hdlc_extract_frame(&mut buf);

        assert_eq!(extracted, Some(data));
        assert_eq!(buf, vec![HDLC_FLAG]); // ending FLAG remains
    }

    #[test]
    fn hdlc_two_frames_shared_flag() {
        // Two frames where ending FLAG of first = starting FLAG of second
        let d1 = vec![0x01, 0x02];
        let d2 = vec![0x03, 0x04];

        let mut buf = Vec::new();
        buf.push(HDLC_FLAG);
        buf.extend(hdlc_escape(&d1));
        buf.push(HDLC_FLAG); // shared
        buf.extend(hdlc_escape(&d2));
        buf.push(HDLC_FLAG);

        let f1 = hdlc_extract_frame(&mut buf);
        assert_eq!(f1, Some(d1));

        let f2 = hdlc_extract_frame(&mut buf);
        assert_eq!(f2, Some(d2));

        // Only trailing FLAG remains
        assert_eq!(buf, vec![HDLC_FLAG]);
    }

    #[test]
    fn hdlc_consecutive_flags_extracts_in_single_call() {
        // FLAG FLAG data FLAG - single call should extract data
        // This tests the real-world usage where we have a while loop:
        //   while let Some(frame) = hdlc_extract_frame(&mut buf) { ... }
        // If consecutive FLAGs cause None to be returned, the loop exits
        // without extracting the valid frame that follows.
        let data = vec![0x01, 0x02];

        let mut buf = vec![HDLC_FLAG, HDLC_FLAG];
        buf.extend(hdlc_escape(&data));
        buf.push(HDLC_FLAG);

        // Single call must extract the frame, not return None
        let result = hdlc_extract_frame(&mut buf);
        assert_eq!(result, Some(data));
        assert_eq!(buf, vec![HDLC_FLAG]); // only trailing FLAG remains
    }

    #[test]
    fn hdlc_partial_frame_not_consumed() {
        // Incomplete frame - should return None and NOT modify buffer
        let mut buf = vec![HDLC_FLAG, 0x01, 0x02, 0x03];
        let original = buf.clone();

        let result = hdlc_extract_frame(&mut buf);

        assert_eq!(result, None);
        assert_eq!(buf, original); // buffer unchanged
    }

    #[test]
    fn hdlc_garbage_before_frame() {
        let data = vec![0x01, 0x02];

        let mut buf = vec![0xFF, 0xAA, 0xBB]; // garbage
        buf.push(HDLC_FLAG);
        buf.extend(hdlc_escape(&data));
        buf.push(HDLC_FLAG);

        let result = hdlc_extract_frame(&mut buf);
        assert_eq!(result, Some(data));
    }

    #[test]
    fn hdlc_escaped_flag_in_data() {
        // Data contains FLAG byte - must be escaped
        let data = vec![0x01, HDLC_FLAG, 0x02];
        let framed = hdlc_frame(&data);

        let mut buf = framed;
        let extracted = hdlc_extract_frame(&mut buf);

        assert_eq!(extracted, Some(data));
    }

    #[test]
    fn hdlc_escaped_esc_in_data() {
        // Data contains ESC byte - must be escaped
        let data = vec![0x01, HDLC_ESC, 0x02];
        let framed = hdlc_frame(&data);

        let mut buf = framed;
        let extracted = hdlc_extract_frame(&mut buf);

        assert_eq!(extracted, Some(data));
    }

    #[test]
    fn hdlc_roundtrip_many_frames() {
        let frames: Vec<Vec<u8>> = vec![
            vec![0x00, 0x01],
            vec![HDLC_FLAG, HDLC_ESC, 0xFF],
            vec![0x10, 0x20, 0x30, 0x40],
        ];

        // Build buffer with all frames (shared FLAGs)
        let mut buf = Vec::new();
        for (i, data) in frames.iter().enumerate() {
            if i == 0 {
                buf.push(HDLC_FLAG);
            }
            buf.extend(hdlc_escape(data));
            buf.push(HDLC_FLAG);
        }

        // Extract all
        for expected in &frames {
            let extracted = hdlc_extract_frame(&mut buf);
            assert_eq!(extracted.as_ref(), Some(expected));
        }

        // Nothing left but trailing FLAG
        assert_eq!(buf, vec![HDLC_FLAG]);
        assert_eq!(hdlc_extract_frame(&mut buf), None);
    }

    #[test]
    fn hdlc_frame_too_short_rejected() {
        // Frame with only 1 byte of content (< 2) should be rejected
        let mut buf = vec![HDLC_FLAG, 0x01, HDLC_FLAG];

        let result = hdlc_extract_frame(&mut buf);
        assert_eq!(result, None);
        // Buffer should advance past the invalid frame
        assert_eq!(buf, vec![HDLC_FLAG]);
    }

    #[test]
    fn hdlc_incremental_receive() {
        // Simulate receiving a frame in chunks
        let data = vec![0x01, 0x02, 0x03];
        let framed = hdlc_frame(&data);

        let mut buf = Vec::new();

        // Receive first half
        buf.extend_from_slice(&framed[..framed.len() / 2]);
        assert_eq!(hdlc_extract_frame(&mut buf), None);

        // Receive second half
        buf.extend_from_slice(&framed[framed.len() / 2..]);
        let extracted = hdlc_extract_frame(&mut buf);

        assert_eq!(extracted, Some(data));
    }
}
