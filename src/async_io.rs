use std::collections::HashMap;
#[cfg(feature = "tcp")]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot, watch};

use crate::handle::{
    Destination, IncomingRequest, LinkError, RequestError, ResourceError, RespondError, Response,
    ServiceEvent, ServiceId,
};
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
type Inbox = Arc<StdMutex<VecDeque<Vec<u8>>>>;
#[cfg(feature = "tcp")]
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
type LinkWaiters = HashMap<crate::LinkHandle, Vec<oneshot::Sender<Result<(), LinkError>>>>;
type PathWaiters = HashMap<Address, Vec<oneshot::Sender<bool>>>;
type IncomingRequestReceiver = Arc<TokioMutex<mpsc::UnboundedReceiver<IncomingRequest>>>;
type RawReceiver = Arc<TokioMutex<mpsc::UnboundedReceiver<Vec<u8>>>>;
type ResourceReceiver = Arc<TokioMutex<mpsc::UnboundedReceiver<(crate::LinkHandle, Vec<u8>)>>>;
type ProgressReceiver = Arc<TokioMutex<mpsc::UnboundedReceiver<crate::handle::Progress>>>;

#[derive(Clone)]
struct ServiceChannels {
    request_tx: mpsc::UnboundedSender<IncomingRequest>,
    request_rx: IncomingRequestReceiver,
    raw_tx: mpsc::UnboundedSender<Vec<u8>>,
    raw_rx: RawReceiver,
    resource_tx: mpsc::UnboundedSender<(crate::LinkHandle, Vec<u8>)>,
    resource_rx: ResourceReceiver,
    progress_tx: mpsc::UnboundedSender<crate::handle::Progress>,
    progress_rx: ProgressReceiver,
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
    GetDestinations {
        reply: oneshot::Sender<Vec<Destination>>,
    },
    GetStats {
        reply: oneshot::Sender<StatsSnapshot>,
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
}

struct AsyncNodeInner<T: Transport> {
    node: crate::node::Node<T, StdRng>,
    command_rx: mpsc::UnboundedReceiver<Command<T>>,
    link_waiters: LinkWaiters,
    path_waiters: PathWaiters,
}

pub struct AsyncNode<T: Transport> {
    services: Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
    service_addresses: Arc<StdMutex<HashMap<ServiceId, Address>>>,
    command_tx: mpsc::UnboundedSender<Command<T>>,
    destinations_changed_rx: watch::Receiver<()>,
    inner: Option<(AsyncNodeInner<T>, watch::Sender<()>)>,
}

impl<T: Transport> Clone for AsyncNode<T> {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            service_addresses: self.service_addresses.clone(),
            command_tx: self.command_tx.clone(),
            destinations_changed_rx: self.destinations_changed_rx.clone(),
            inner: None,
        }
    }
}

impl<T: Transport> AsyncNode<T> {
    pub fn new(transport: bool) -> Self {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (destinations_tx, destinations_rx) = watch::channel(());
        let rng = StdRng::from_entropy();

        Self {
            services: Arc::new(StdMutex::new(HashMap::new())),
            service_addresses: Arc::new(StdMutex::new(HashMap::new())),
            command_tx,
            destinations_changed_rx: destinations_rx,
            inner: Some((
                AsyncNodeInner {
                    node: crate::node::Node::with_rng(rng, transport),
                    command_rx,
                    link_waiters: HashMap::new(),
                    path_waiters: HashMap::new(),
                },
                destinations_tx,
            )),
        }
    }

    pub fn add_interface(&self, interface: Interface<T>) {
        let _ = self.command_tx.send(Command::AddInterface {
            interface: Box::new(interface),
        });
    }

    pub fn add_service(&mut self, name: &str, paths: &[&str], identity: &Identity) -> ServiceId {
        let (inner, _) = self
            .inner
            .as_mut()
            .expect("add_service requires the original AsyncNode");

        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        let (resource_tx, resource_rx) = mpsc::unbounded_channel();
        let (progress_tx, progress_rx) = mpsc::unbounded_channel();
        let request_waiters: RequestWaiters = Arc::new(StdMutex::new(HashMap::new()));
        let respond_waiters: RespondWaiters = Arc::new(StdMutex::new(HashMap::new()));

        let service_id = inner.node.add_service(name, paths, identity);
        let address = inner.node.service_address(service_id).unwrap();

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

    pub async fn run(mut self) {
        let Some((mut inner, destinations_tx)) = self.inner.take() else {
            panic!("run() can only be called on the original AsyncNode, not a clone");
        };

        let mut tick_interval = tokio::time::interval(Duration::from_millis(10));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                Some(cmd) = inner.command_rx.recv() => {
                    Self::handle_command(&mut inner, &self.services, &destinations_tx, cmd, Instant::now());
                }
                _ = tick_interval.tick() => {
                    Self::poll(&mut inner, &self.services, &destinations_tx);
                }
            }
        }
    }

    fn poll(
        inner: &mut AsyncNodeInner<T>,
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
        destinations_tx: &watch::Sender<()>,
    ) {
        let now = Instant::now();
        let events = inner.node.poll(now);

        for event in &events {
            if let ServiceEvent::PathRequestResult { destination, found } = event
                && let Some(waiters) = inner.path_waiters.remove(destination)
            {
                for tx in waiters {
                    let _ = tx.send(*found);
                }
            }
        }

        Self::dispatch_events(services, destinations_tx, events);

        inner.link_waiters.retain(|link, waiters| {
            let status = inner.node.link_status(*link);
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

    fn handle_command(
        inner: &mut AsyncNodeInner<T>,
        services: &Arc<StdMutex<HashMap<ServiceId, ServiceChannels>>>,
        destinations_tx: &watch::Sender<()>,
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
                link,
                path,
                data,
                reply,
            } => {
                if let Some(request_id) = inner.node.request(service, link, &path, &data) {
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
                    .node
                    .respond(request_id, &data, metadata.as_deref(), compress);
            }
            Command::SendRaw { dest, data, reply } => {
                let _ = reply.send(inner.node.send_raw(dest, &data));
            }
            Command::SendLinkData { link, data } => {
                inner.node.send_link_data(link, &data);
            }
            Command::GetDestinations { reply } => {
                let _ = reply.send(inner.node.known_destinations());
            }
            Command::GetStats { reply } => {
                let _ = reply.send(inner.node.stats());
            }
            Command::CreateLink {
                service,
                destination,
                reply,
            } => {
                let _ = reply.send(inner.node.create_link(service, destination, now));
            }
            Command::LinkStatus { link, reply } => {
                let _ = reply.send(inner.node.link_status(link));
            }
            Command::LinkRtt { link, reply } => {
                let _ = reply.send(inner.node.link_rtt(link));
            }
            Command::CloseLink { link } => {
                inner.node.close_link(link);
            }
            Command::SelfIdentify { link, identity } => {
                inner.node.self_identify(link, &identity);
            }
            Command::LinkRequest {
                link,
                path,
                data,
                reply,
            } => {
                let _ = reply.send(inner.node.link_request(link, &path, &data, now));
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
                        .node
                        .advertise_resource(link, data, metadata, compress),
                );
            }
            Command::AwaitLinkActive { link, reply } => {
                if inner.node.link_status(link) == crate::LinkStatus::Active {
                    let _ = reply.send(Ok(()));
                } else if inner.node.link_status(link) == crate::LinkStatus::Closed {
                    let _ = reply.send(Err(LinkError::Timeout));
                } else {
                    inner.link_waiters.entry(link).or_default().push(reply);
                }
            }
            Command::RequestPath { destination, reply } => {
                if inner.node.path_table.contains_key(&destination) {
                    let _ = reply.send(true);
                } else {
                    inner.node.request_path(destination, now);
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
                inner.node.prove_packet(service, &packet_data);
            }
        }
        Self::poll(inner, services, destinations_tx);
    }
}
