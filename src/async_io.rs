use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::handle::RequestError;
use crate::packet::Address;
use crate::request::RequestId;
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

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct PathTimeout;

type RequestWaiters =
    Arc<Mutex<HashMap<RequestId, oneshot::Sender<Result<Vec<u8>, RequestError>>>>>;
type PathWaiters = Arc<Mutex<HashMap<Address, oneshot::Sender<()>>>>;

struct ChannelService {
    name: String,
    paths: Vec<String>,
    request_tx: mpsc::UnboundedSender<IncomingRequest>,
    request_waiters: RequestWaiters,
    path_waiters: PathWaiters,
}

impl Service for ChannelService {
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
    ) -> Option<Vec<u8>> {
        let _ = self.request_tx.send(IncomingRequest {
            request_id,
            from,
            path: path.to_string(),
            data: data.to_vec(),
        });
        None
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

    fn on_raw(&mut self, _handle: &mut NodeHandle, _from: Address, _data: &[u8]) {}

    fn on_destinations_changed(&mut self, handle: &mut NodeHandle) {
        let mut waiters = self.path_waiters.lock().unwrap();
        let known: std::collections::HashSet<Address> =
            handle.destinations().map(|d| d.address).collect();
        let found: Vec<Address> = waiters
            .keys()
            .filter(|addr| known.contains(*addr))
            .copied()
            .collect();
        for addr in found {
            if let Some(tx) = waiters.remove(&addr) {
                let _ = tx.send(());
            }
        }
    }
}

pub struct AsyncNode {
    node: crate::Node<AsyncTransport, ChannelService>,
    service_addr: Address,
    wake_tx: mpsc::Sender<()>,
    wake_rx: mpsc::Receiver<()>,
    request_rx: mpsc::UnboundedReceiver<IncomingRequest>,
    request_waiters: RequestWaiters,
    path_waiters: PathWaiters,
}

impl AsyncNode {
    pub fn new(name: &str, paths: &[&str], identity: &Identity, transport_enabled: bool) -> Self {
        let (wake_tx, wake_rx) = mpsc::channel(16);
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(Mutex::new(HashMap::new()));
        let path_waiters: PathWaiters = Arc::new(Mutex::new(HashMap::new()));

        let mut node = crate::Node::new(transport_enabled);

        let service = ChannelService {
            name: name.to_string(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            request_tx,
            request_waiters: request_waiters.clone(),
            path_waiters: path_waiters.clone(),
        };
        let service_addr = node.add_service(service, identity);

        Self {
            node,
            service_addr,
            wake_tx,
            wake_rx,
            request_rx,
            request_waiters,
            path_waiters,
        }
    }

    pub fn service_addr(&self) -> Address {
        self.service_addr
    }

    pub fn destinations(&self) -> Vec<Address> {
        self.node.known_destinations()
    }

    pub fn announce(&mut self) {
        self.node.announce(self.service_addr, Instant::now());
    }

    pub async fn request(
        &mut self,
        destination: Address,
        path: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, RequestError> {
        let request_id =
            self.node
                .request(self.service_addr, destination, path, data, Instant::now());

        let (tx, rx) = oneshot::channel();
        self.request_waiters.lock().unwrap().insert(request_id, tx);

        tokio::pin!(rx);

        loop {
            let now = Instant::now();
            let timeout = self.node.poll(now);
            let sleep_duration = timeout.unwrap_or(Duration::from_secs(60));

            tokio::select! {
                biased;
                result = &mut rx => {
                    return result.unwrap_or(Err(RequestError::LinkFailed));
                }
                _ = self.wake_rx.recv() => {}
                _ = tokio::time::sleep(sleep_duration) => {}
            }
        }
    }

    pub async fn recv_request(&mut self) -> IncomingRequest {
        loop {
            let now = Instant::now();
            let timeout = self.node.poll(now);
            let sleep_duration = timeout.unwrap_or(Duration::from_secs(60));

            tokio::select! {
                biased;
                Some(req) = self.request_rx.recv() => {
                    return req;
                }
                _ = self.wake_rx.recv() => {}
                _ = tokio::time::sleep(sleep_duration) => {}
            }
        }
    }

    pub async fn connect(&mut self, addr: &str) -> std::io::Result<()> {
        let stream = TcpStream::connect(addr).await?;
        self.add_stream(stream);
        Ok(())
    }

    pub fn add_stream(&mut self, stream: TcpStream) {
        let (transport, inbox, outbox, connected) = AsyncTransport::new_pair();
        self.node.add_interface(Interface::new(transport));

        let wake_tx = self.wake_tx.clone();
        tokio::spawn(tcp_io_task(stream, inbox, outbox, connected, wake_tx));
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
                    hdlc_buf.extend_from_slice(&buf[..n]);

                    while let Some(frame) = hdlc_extract_frame(&mut hdlc_buf) {
                        inbox.lock().unwrap().push_back(frame);
                        let _ = wake_tx.send(()).await;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let write_task = async {
        loop {
            let data = outbox_writer.lock().unwrap().pop_front();
            if let Some(data) = data {
                let framed = hdlc_frame(&data);
                if writer.write_all(&framed).await.is_err() {
                    break;
                }
            } else {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    };

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
    }

    *connected.lock().unwrap() = false;
    let _ = wake_tx.send(()).await;
}
