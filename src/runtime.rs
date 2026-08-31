use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use futures_channel::oneshot;
use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, StreamExt};
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroize;

use crate::api::*;
use crate::channel::QueueChannelError;
use crate::interface::{AttachedInterface, OutboundPacket};
use crate::model::*;
use crate::timer::{TimerEvent, TimerQueue};
use crate::{MonoTime, PrivateIdentity};

const LINK_HANDSHAKE_TIMEOUT: crate::TimeSpan = crate::TimeSpan::from_secs(15);
const REQUEST_TIMEOUT: crate::TimeSpan = crate::TimeSpan::from_secs(30);
const SHUTDOWN_GRACE: crate::TimeSpan = crate::TimeSpan::from_secs(5);
const KEEP_STREAM_OPEN: bool = false;
const FINISH_STREAM: bool = true;
const COMMAND_CAPACITY: usize = 256;
const INBOUND_PACKET_CAPACITY: usize = 64;
const EVENT_CAPACITY: usize = 128;
const CHANNEL_QUEUE_CAPACITY: usize = 64;
const MAXIMUM_INTERFACES: usize = 16;
const MAXIMUM_LINKS: usize = 256;
const MAXIMUM_SERVICES: usize = 64;
const DUPLICATE_PACKET_HASHES: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct InterfaceId(pub(crate) usize);

struct ReceivedPacket {
    interface: InterfaceId,
    bytes: Vec<u8>,
}

pub struct NodeBuilder {
    config: NodeConfig,
    interfaces: Vec<(AttachedInterface, InterfaceLimits)>,
}

impl NodeBuilder {
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            interfaces: Vec::new(),
        }
    }

    pub fn interface<I>(mut self, interface: I, limits: InterfaceLimits) -> Self
    where
        I: crate::Interface + Send + 'static,
    {
        self.interfaces.push((Arc::new(interface), limits));
        self
    }

    pub fn build(self) -> Result<(NodeHandle, NodeTask), BuildError> {
        if self.interfaces.len() > MAXIMUM_INTERFACES {
            return Err(BuildError(()));
        }
        let mut seed = [0; 32];
        if rand_core::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut seed).is_err() {
            seed.zeroize();
            return Err(BuildError(()));
        }
        if seed == [0; 32] {
            seed.zeroize();
            return Err(BuildError(()));
        }
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        let relay = matches!(self.config.mode, NodeMode::Relay);
        let mut relay_address = [0; 16];
        rng.fill_bytes(&mut relay_address);
        log::info!(
            "Node started with relay_address <{}>",
            hex::encode(relay_address)
        );
        let interfaces = self
            .interfaces
            .into_iter()
            .map(|(interface, limits)| InterfaceSlot::new(interface, limits))
            .collect();
        let (command_sender, command_receiver) = async_channel::bounded(COMMAND_CAPACITY);
        let commands_for_new_clients = command_sender.downgrade();
        let (resource_drop_sender, resource_drop_receiver) =
            async_channel::bounded(MAXIMUM_SERVICES + MAXIMUM_LINKS * 2);
        let resource_drops_for_new_clients = resource_drop_sender.downgrade();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown = async move {
            let _ = shutdown_rx.await;
        }
        .boxed()
        .shared();
        let handle = NodeHandle {
            client: NodeClient {
                commands: command_sender,
                resource_drops: resource_drop_sender,
            },
            shutdown,
        };
        let (inbound_packet_sender, inbound_packets) =
            async_channel::bounded(INBOUND_PACKET_CAPACITY);
        let pending_inbound_packets = Arc::new(AtomicUsize::new(0));
        let interface_tasks = FuturesUnordered::new();
        let task = NodeTask {
            started: tokio::time::Instant::now(),
            owner: NodeOwner {
                rng,
                relays_packets: relay,
                relay_address,
                path_table: HashMap::new(),
                pending_announces: Vec::new(),
                seen_packets: crate::packet_hashlist::PacketHashlist::new(DUPLICATE_PACKET_HASHES),
                reverse_table: HashMap::new(),
                receipts: Vec::new(),
                pending_outbound_links: HashMap::new(),
                pending_inbound_links: HashMap::new(),
                established_links: HashMap::new(),
                link_table: HashMap::new(),
                outbound_resources: HashMap::new(),
                inbound_resources: HashMap::new(),
                destination_links: HashMap::new(),
                pending_path_requests: HashMap::new(),
                discovery_path_requests: HashMap::new(),
                pending_resource_requests: HashSet::new(),
                command_receiver: Some(command_receiver),
                commands_for_new_clients,
                resource_drop_receiver: Some(resource_drop_receiver),
                resource_drops_for_new_clients,
                interfaces,
                send_operations: FuturesUnordered::new(),
                close_operations: FuturesUnordered::new(),
                interface_tasks,
                inbound_packet_sender,
                inbound_packets,
                pending_inbound_packets,
                timers: TimerQueue::default(),
                shutdown_tx: Some(shutdown_tx),
                phase: NodePhase::Running,
                services: Vec::new(),
                outbound_request_replies: HashMap::new(),
                route_waits: HashMap::new(),
            },
        };
        Ok((handle, task))
    }
}

pub struct NodeTask {
    started: tokio::time::Instant,
    owner: NodeOwner,
}

enum NodePhase {
    Running,
    Closing { deadline_expired: bool },
}

pub(crate) struct InterfaceSlot {
    interface: AttachedInterface,
    limits: InterfaceLimits,
    outbound: VecDeque<(u8, OutboundPacket)>,
    outbound_bytes: usize,
    phase: InterfacePhase,
}

enum InterfacePhase {
    Active { reading: bool, sending: bool },
    Draining { sending: bool },
    Failed,
    Closing,
    Closed,
}

pub(crate) struct ReceiveQueue<T, E> {
    queued: VecDeque<(T, usize)>,
    queued_bytes: usize,
    waiting_receiver_reply: Option<oneshot::Sender<Result<T, E>>>,
    terminal_error: Option<E>,
    item_limit: usize,
    max_queued_bytes: usize,
}

pub(crate) struct LinkEvents {
    events: ReceiveQueue<LinkEvent, NodeError>,
    inbound_requests: BTreeMap<[u8; 16], InboundRequestPhase>,
    requests_awaiting_delivery: VecDeque<[u8; 16]>,
}

enum InboundRequestPhase {
    AwaitingDelivery {
        path: RequestPath,
        body: bytes::Bytes,
    },
    AwaitingResponse,
}

impl LinkEvents {
    fn new(capacity: usize) -> Self {
        Self {
            events: ReceiveQueue::new(capacity, usize::MAX),
            inbound_requests: BTreeMap::new(),
            requests_awaiting_delivery: VecDeque::new(),
        }
    }
}

pub(crate) enum EventPushError<T> {
    Full(T),
    Closed(T),
}

impl<T> EventPushError<T> {
    fn link_close_reason(&self) -> LinkCloseReason {
        match self {
            Self::Full(_) => LinkCloseReason::CapacityReached,
            Self::Closed(_) => LinkCloseReason::LocalClosed,
        }
    }
}

enum OutboundAdmissionError {
    Busy,
    InterfaceFailed,
}

impl OutboundAdmissionError {
    fn into_node_error(self) -> NodeError {
        match self {
            Self::Busy | Self::InterfaceFailed => NodeError::InterfaceUnavailable,
        }
    }
}

impl<T, E: Clone> ReceiveQueue<T, E> {
    fn new(item_limit: usize, max_queued_bytes: usize) -> Self {
        Self {
            queued: VecDeque::new(),
            queued_bytes: 0,
            waiting_receiver_reply: None,
            terminal_error: None,
            item_limit,
            max_queued_bytes,
        }
    }

    pub(crate) fn push(&mut self, mut item: T, bytes: usize) -> Result<(), EventPushError<T>> {
        if self.terminal_error.is_some() {
            return Err(EventPushError::Closed(item));
        }
        if let Some(waiting) = self.waiting_receiver_reply.take() {
            match waiting.send(Ok(item)) {
                Ok(()) => return Ok(()),
                Err(Ok(returned)) => item = returned,
                Err(Err(_)) => unreachable!(),
            }
        }
        if self.queued.len() >= self.item_limit
            || self.queued_bytes.saturating_add(bytes) > self.max_queued_bytes
        {
            return Err(EventPushError::Full(item));
        }
        self.queued_bytes += bytes;
        self.queued.push_back((item, bytes));
        Ok(())
    }

    fn receive(&mut self, reply: oneshot::Sender<Result<T, E>>) {
        if let Some(waiting) = self.waiting_receiver_reply.take()
            && !waiting.is_canceled()
        {
            unreachable!("one receiver cannot have two live waits")
        }
        if let Some((item, bytes)) = self.queued.pop_front() {
            match reply.send(Ok(item)) {
                Ok(()) => {
                    self.queued_bytes -= bytes;
                    return;
                }
                Err(Ok(item)) => self.queued.push_front((item, bytes)),
                Err(Err(_)) => unreachable!(),
            }
            return;
        }
        if let Some(reason) = &self.terminal_error {
            let _ = reply.send(Err(reason.clone()));
        } else {
            self.waiting_receiver_reply = Some(reply);
        }
    }

    pub(crate) fn close(&mut self, reason: E) {
        if self.terminal_error.is_some() {
            return;
        }
        if self.queued.is_empty()
            && let Some(waiting) = self.waiting_receiver_reply.take()
        {
            let _ = waiting.send(Err(reason.clone()));
        }
        self.terminal_error = Some(reason);
    }
}

impl InterfaceSlot {
    fn new(interface: AttachedInterface, limits: InterfaceLimits) -> Self {
        Self {
            interface,
            limits,
            outbound: VecDeque::new(),
            outbound_bytes: 0,
            phase: InterfacePhase::Active {
                reading: false,
                sending: false,
            },
        }
    }

    pub(crate) fn enqueue_outbound(
        &mut self,
        priority: u8,
        packet: OutboundPacket,
    ) -> Result<(), OutboundPacket> {
        let bytes = packet.byte_len();
        if bytes > self.limits.maximum_packet_bytes
            || self.outbound.len() >= self.limits.outbound_packets
            || self.outbound_bytes + bytes > self.limits.outbound_bytes
        {
            return Err(packet);
        }
        self.outbound_bytes += bytes;
        let position = self
            .outbound
            .iter()
            .position(|(queued, _)| *queued > priority)
            .unwrap_or(self.outbound.len());
        self.outbound.insert(position, (priority, packet));
        Ok(())
    }

    pub(crate) fn enqueue_protocol_packet(
        &mut self,
        priority: u8,
        packet: &crate::packet::Packet,
    ) -> bool {
        self.accepts_outbound()
            && self
                .enqueue_outbound(priority, OutboundPacket::new(packet.to_bytes()))
                .is_ok()
    }

    pub(crate) fn accepts_outbound(&self) -> bool {
        matches!(self.phase, InterfacePhase::Active { .. })
    }

    fn fail(&mut self) {
        if matches!(
            self.phase,
            InterfacePhase::Failed | InterfacePhase::Closing | InterfacePhase::Closed
        ) {
            return;
        }
        self.phase = InterfacePhase::Failed;
        self.outbound.clear();
        self.outbound_bytes = 0;
    }
}

type InterfaceOperation = BoxFuture<'static, (InterfaceId, Result<(), crate::InterfaceError>)>;
type InterfaceTask = BoxFuture<'static, InterfaceId>;

pub(crate) struct NodeOwner {
    pub(crate) rng: rand_chacha::ChaCha20Rng,
    pub(crate) relays_packets: bool,
    pub(crate) relay_address: crate::packet::DestinationAddress,
    pub(crate) path_table: HashMap<crate::packet::DestinationAddress, crate::node::PathEntry>,
    pub(crate) pending_announces: Vec<crate::node::PendingAnnounce>,
    pub(crate) seen_packets: crate::packet_hashlist::PacketHashlist,
    pub(crate) reverse_table:
        HashMap<crate::packet::DestinationAddress, crate::node::ReverseTableEntry>,
    pub(crate) receipts: Vec<crate::node::Receipt>,
    pub(crate) pending_outbound_links: HashMap<[u8; 16], crate::link::PendingLink>,
    pub(crate) pending_inbound_links: HashMap<[u8; 16], crate::node::PendingInboundLink>,
    pub(crate) established_links: HashMap<[u8; 16], crate::link::EstablishedLink>,
    pub(crate) link_table: HashMap<[u8; 16], crate::node::LinkTableEntry>,
    pub(crate) outbound_resources: HashMap<[u8; 32], ([u8; 16], crate::resource::OutboundResource)>,
    pub(crate) inbound_resources: HashMap<[u8; 32], ([u8; 16], crate::resource::InboundResource)>,
    pub(crate) destination_links: HashMap<crate::packet::DestinationAddress, [u8; 16]>,
    pub(crate) pending_path_requests: HashMap<crate::packet::DestinationAddress, MonoTime>,
    pub(crate) discovery_path_requests: HashMap<crate::packet::DestinationAddress, usize>,
    pub(crate) pending_resource_requests: HashSet<([u8; 16], [u8; 32])>,
    command_receiver: Option<async_channel::Receiver<Command>>,
    commands_for_new_clients: async_channel::WeakSender<Command>,
    resource_drop_receiver: Option<async_channel::Receiver<RegisteredResource>>,
    resource_drops_for_new_clients: async_channel::WeakSender<RegisteredResource>,
    pub(crate) interfaces: Vec<InterfaceSlot>,
    send_operations: FuturesUnordered<InterfaceOperation>,
    close_operations: FuturesUnordered<InterfaceOperation>,
    interface_tasks: FuturesUnordered<InterfaceTask>,
    inbound_packet_sender: async_channel::Sender<ReceivedPacket>,
    inbound_packets: async_channel::Receiver<ReceivedPacket>,
    pending_inbound_packets: Arc<AtomicUsize>,
    pub(crate) timers: TimerQueue,
    shutdown_tx: Option<oneshot::Sender<()>>,
    phase: NodePhase,
    pub(crate) services: Vec<Option<crate::node::ServiceState>>,
    outbound_request_replies: HashMap<[u8; 16], oneshot::Sender<Result<Bytes, NodeError>>>,
    route_waits: HashMap<[u8; 16], Vec<oneshot::Sender<Result<Link, NodeError>>>>,
}

pub(crate) struct PendingOpenLink {
    reply: oneshot::Sender<Result<Link, NodeError>>,
    events: LinkEvents,
}

pub(crate) struct RuntimeChannel {
    pub(crate) protocol_state: crate::channel::ChannelState,
    events: ReceiveQueue<ChannelReceive, NodeError>,
    blocked_channel_ops: VecDeque<WaitingChannelOperation>,
    outgoing_streams: HashSet<StreamId>,
    ended_incoming_streams: HashSet<StreamId>,
    pending_delivery_replies: HashMap<[u8; 32], oneshot::Sender<Result<(), NodeError>>>,
}

impl RuntimeChannel {
    pub(crate) fn new() -> Self {
        let capacity = CHANNEL_QUEUE_CAPACITY;
        Self {
            protocol_state: crate::channel::ChannelState::new(),
            events: ReceiveQueue::new(capacity, capacity * crate::buffer::MAX_INPUT_BYTES),
            blocked_channel_ops: VecDeque::new(),
            outgoing_streams: HashSet::new(),
            ended_incoming_streams: HashSet::new(),
            pending_delivery_replies: HashMap::new(),
        }
    }
}

enum WaitingChannelOperation {
    Message {
        message: ChannelMessage,
        reply: oneshot::Sender<Result<(), NodeError>>,
    },
    BufferWrite {
        stream: StreamId,
        input: Bytes,
        finish_stream: bool,
        reply: oneshot::Sender<Result<BufferQueued, NodeError>>,
    },
}

enum RuntimeEvent {
    Command(Result<Command, async_channel::RecvError>),
    ResourceDropped(Result<RegisteredResource, async_channel::RecvError>),
    Sent((InterfaceId, Result<(), crate::InterfaceError>)),
    Closed((InterfaceId, Result<(), crate::InterfaceError>)),
    InterfaceStopped(InterfaceId),
    Inbound(Result<ReceivedPacket, async_channel::RecvError>),
    Timer,
}

async fn receive_packets(
    interface_id: InterfaceId,
    interface: AttachedInterface,
    inbound_packet_sender: async_channel::Sender<ReceivedPacket>,
    pending_inbound_packets: Arc<AtomicUsize>,
) -> InterfaceId {
    loop {
        let packet = match interface.receive().await {
            Ok(packet) => packet,
            Err(_) => return interface_id,
        };
        let packet = ReceivedPacket {
            interface: interface_id,
            bytes: packet.into_bytes(),
        };
        pending_inbound_packets.fetch_add(1, Ordering::AcqRel);
        if inbound_packet_sender.send(packet).await.is_err() {
            pending_inbound_packets.fetch_sub(1, Ordering::AcqRel);
            return interface_id;
        }
    }
}

async fn next_operation<T>(operations: &mut FuturesUnordered<BoxFuture<'static, T>>) -> T {
    match operations.next().await {
        Some(result) => result,
        None => std::future::pending().await,
    }
}

async fn receive_if_present<T>(
    receiver: Option<&async_channel::Receiver<T>>,
) -> Result<T, async_channel::RecvError> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

impl NodeTask {
    pub async fn run(self) -> Result<(), NodeRunError> {
        let NodeTask { started, mut owner } = self;
        loop {
            owner.schedule_readers();
            owner.schedule_sends();
            owner.schedule_closes();
            if let Some(result) = owner.shutdown_if_complete() {
                return result;
            }
            let deadline = owner.timers.next_deadline();
            let event = {
                let command = receive_if_present(owner.command_receiver.as_ref()).fuse();
                let resource_dropped =
                    receive_if_present(owner.resource_drop_receiver.as_ref()).fuse();
                let send = next_operation(&mut owner.send_operations).fuse();
                let close = next_operation(&mut owner.close_operations).fuse();
                let interface = next_operation(&mut owner.interface_tasks).fuse();
                let inbound = owner.inbound_packets.recv().fuse();
                let timer = async {
                    match deadline {
                        Some(deadline) => {
                            let now = MonoTime::from_micros(started.elapsed().as_micros() as u64);
                            tokio::time::sleep(
                                deadline.checked_duration_since(now).unwrap_or_default(),
                            )
                            .await
                        }
                        None => std::future::pending().await,
                    }
                }
                .fuse();
                futures_util::pin_mut!(
                    command,
                    resource_dropped,
                    send,
                    close,
                    interface,
                    inbound,
                    timer
                );
                futures_util::select_biased! {
                    command = command => RuntimeEvent::Command(command),
                    dropped = resource_dropped => RuntimeEvent::ResourceDropped(dropped),
                    send = send => RuntimeEvent::Sent(send),
                    close = close => RuntimeEvent::Closed(close),
                    interface = interface => RuntimeEvent::InterfaceStopped(interface),
                    inbound = inbound => RuntimeEvent::Inbound(inbound),
                    _ = timer => RuntimeEvent::Timer,
                }
            };
            let now = MonoTime::from_micros(started.elapsed().as_micros() as u64);
            match event {
                RuntimeEvent::Command(Ok(command)) => owner.handle_command(command, now),
                RuntimeEvent::Command(Err(_)) => {
                    owner.command_receiver = None;
                    if matches!(owner.phase, NodePhase::Running) {
                        owner.begin_shutdown(now);
                    }
                }
                RuntimeEvent::ResourceDropped(Ok(resource)) => {
                    owner.handle_dropped_resource(resource)
                }
                RuntimeEvent::ResourceDropped(Err(_)) => owner.resource_drop_receiver = None,
                RuntimeEvent::Sent(result) => owner.handle_send_completion(result)?,
                RuntimeEvent::Closed(result) => owner.handle_close_completion(result)?,
                RuntimeEvent::InterfaceStopped(interface) => {
                    let slot = owner
                        .interfaces
                        .get_mut(interface.0)
                        .ok_or(NodeRunError(()))?;
                    slot.fail();
                }
                RuntimeEvent::Inbound(Ok(inbound)) => {
                    owner
                        .pending_inbound_packets
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            count.checked_sub(1)
                        })
                        .map_err(|_| NodeRunError(()))?;
                    if let Some(packet) =
                        crate::node::PreparedInbound::parse(inbound.bytes, inbound.interface.0)
                    {
                        owner.handle_packet(now, packet);
                    }
                }
                RuntimeEvent::Inbound(Err(_)) => return Err(NodeRunError(())),
                RuntimeEvent::Timer => owner.expire_timers(now),
            }
        }
    }
}

impl NodeOwner {
    fn new_client(&self) -> Option<NodeClient> {
        Some(NodeClient {
            commands: self.commands_for_new_clients.upgrade()?,
            resource_drops: self.resource_drops_for_new_clients.upgrade()?,
        })
    }

    pub(crate) fn outbound_interfaces(
        interfaces: &[InterfaceSlot],
    ) -> impl Iterator<Item = usize> + '_ {
        interfaces
            .iter()
            .enumerate()
            .filter_map(|(id, interface)| interface.accepts_outbound().then_some(id))
    }

    fn handle_dropped_resource(&mut self, resource: RegisteredResource) {
        match resource {
            RegisteredResource::Service(service) => {
                for link in self.remove_service(service) {
                    self.close_link(link, LinkCloseReason::LocalClosed);
                }
            }
            RegisteredResource::Link(link) => self.close_link(link.0, LinkCloseReason::LocalClosed),
            RegisteredResource::Channel(link) => {
                self.close_link_channel(link.0, NodeError::ResourceClosed)
            }
        }
    }

    fn schedule_readers(&mut self) {
        if !matches!(self.phase, NodePhase::Running) {
            return;
        }
        for (id, slot) in self.interfaces.iter_mut().enumerate() {
            let InterfacePhase::Active { reading, .. } = &mut slot.phase else {
                continue;
            };
            if *reading {
                continue;
            }
            *reading = true;
            let interface = slot.interface.clone();
            let id = InterfaceId(id);
            self.interface_tasks.push(
                receive_packets(
                    id,
                    interface,
                    self.inbound_packet_sender.clone(),
                    self.pending_inbound_packets.clone(),
                )
                .boxed(),
            );
        }
    }

    fn schedule_sends(&mut self) {
        for (id, slot) in self.interfaces.iter_mut().enumerate() {
            let sending = match &mut slot.phase {
                InterfacePhase::Active { sending, .. } | InterfacePhase::Draining { sending } => {
                    sending
                }
                _ => continue,
            };
            if *sending {
                continue;
            }
            let Some((_priority, packet)) = slot.outbound.pop_front() else {
                continue;
            };
            slot.outbound_bytes -= packet.byte_len();
            *sending = true;
            let interface = slot.interface.clone();
            let id = InterfaceId(id);
            self.send_operations
                .push(async move { (id, interface.send(packet).await) }.boxed());
        }
    }

    fn handle_send_completion(
        &mut self,
        (interface, send_result): (InterfaceId, Result<(), crate::InterfaceError>),
    ) -> Result<(), NodeRunError> {
        let slot = self
            .interfaces
            .get_mut(interface.0)
            .ok_or(NodeRunError(()))?;
        match &mut slot.phase {
            InterfacePhase::Active { sending, .. } | InterfacePhase::Draining { sending } => {
                *sending = false;
            }
            _ => return Ok(()),
        }
        if send_result.is_err() {
            slot.fail();
        }
        Ok(())
    }

    fn schedule_closes(&mut self) {
        for (id, slot) in self.interfaces.iter_mut().enumerate() {
            match slot.phase {
                InterfacePhase::Failed => {}
                InterfacePhase::Draining { sending: false } if slot.outbound.is_empty() => {}
                _ => continue,
            }
            slot.phase = InterfacePhase::Closing;
            let interface = slot.interface.clone();
            let id = InterfaceId(id);
            self.close_operations
                .push(async move { (id, interface.close().await) }.boxed());
        }
    }

    fn handle_close_completion(
        &mut self,
        (interface, _close_result): (InterfaceId, Result<(), crate::InterfaceError>),
    ) -> Result<(), NodeRunError> {
        let slot = self
            .interfaces
            .get_mut(interface.0)
            .ok_or(NodeRunError(()))?;
        let InterfacePhase::Closing = slot.phase else {
            return Ok(());
        };
        slot.phase = InterfacePhase::Closed;
        Ok(())
    }

    fn deliver_waiting_request(&mut self, link: [u8; 16]) {
        let Some(client) = self.new_client() else {
            return;
        };
        let mut event_queue_closed = false;
        let Some(events) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
        else {
            return;
        };
        while let Some(request) = events.requests_awaiting_delivery.pop_front() {
            let Some(state) = events.inbound_requests.remove(&request) else {
                continue;
            };
            let InboundRequestPhase::AwaitingDelivery { path, body } = state else {
                events.inbound_requests.insert(request, state);
                continue;
            };
            let incoming = IncomingRequest {
                link: LinkId(link),
                id: IncomingRequestId(request),
                path,
                body,
                client: client.clone(),
            };
            match events.events.push(LinkEvent::Request(incoming), 0) {
                Ok(()) => {
                    events
                        .inbound_requests
                        .insert(request, InboundRequestPhase::AwaitingResponse);
                }
                Err(EventPushError::Full(LinkEvent::Request(incoming))) => {
                    events.inbound_requests.insert(
                        request,
                        InboundRequestPhase::AwaitingDelivery {
                            path: incoming.path,
                            body: incoming.body,
                        },
                    );
                    events.requests_awaiting_delivery.push_front(request);
                    break;
                }
                Err(EventPushError::Closed(_)) => {
                    event_queue_closed = true;
                    break;
                }
                Err(EventPushError::Full(_)) => unreachable!(),
            }
        }
        if event_queue_closed {
            self.close_link(link, LinkCloseReason::LocalClosed);
        }
    }

    fn expire_timers(&mut self, now: MonoTime) {
        for _ in 0..COMMAND_CAPACITY {
            let Some(timer) = self.timers.pop_due(now) else {
                break;
            };
            match timer {
                TimerEvent::Protocol(timer) => {
                    self.handle_timer(now, timer);
                }
                TimerEvent::InboundRequest { link, request } => {
                    let state = self
                        .established_links
                        .get_mut(&link)
                        .and_then(|link| link.events.as_mut())
                        .and_then(|events| events.inbound_requests.remove(&request));
                    if matches!(state, Some(InboundRequestPhase::AwaitingDelivery { .. })) {
                        self.close_link(link, LinkCloseReason::CapacityReached);
                    }
                }
                TimerEvent::Shutdown => {
                    if let NodePhase::Closing { deadline_expired } = &mut self.phase {
                        *deadline_expired = true;
                    }
                }
            }
        }
    }

    fn handle_command(&mut self, command: Command, now: MonoTime) {
        if !matches!(self.phase, NodePhase::Running) {
            return;
        }
        match command {
            Command::AttachInterface {
                interface,
                limits,
                reply,
            } => {
                if self.interfaces.len() >= MAXIMUM_INTERFACES {
                    let _ = reply.send(Err(NodeError::CapacityReached));
                } else {
                    self.interfaces.push(InterfaceSlot::new(interface, limits));
                    let _ = reply.send(Ok(()));
                }
            }
            Command::GenerateIdentity { reply } => {
                let _ = reply.send(Ok(PrivateIdentity::generate(&mut self.rng)));
            }
            Command::RegisterService { config, reply } => {
                let ServiceConfig {
                    name,
                    identity,
                    accepted_request_paths: paths,
                    restart_ratchet,
                } = *config;
                if self.services.iter().flatten().count() >= MAXIMUM_SERVICES {
                    let _ = reply.send(Err(NodeError::CapacityReached));
                    return;
                }
                let destination = identity.destination(&name);
                let path_values: Vec<_> = paths.iter().map(|path| path.as_str()).collect();
                let events = ReceiveQueue::new(EVENT_CAPACITY, usize::MAX);
                let id = self.add_service(
                    name.as_str(),
                    &path_values,
                    &identity,
                    restart_ratchet,
                    events,
                );
                let client = self
                    .new_client()
                    .expect("node client disappeared while registering service");
                let _ = reply.send(Ok(Service {
                    id,
                    destination,
                    registration: ResourceRegistration::new(
                        client,
                        RegisteredResource::Service(id),
                    ),
                }));
            }
            Command::ReceiveService { service, reply } => {
                if let Some(service) = self.services.get_mut(service.0).and_then(Option::as_mut) {
                    service.events.receive(reply);
                } else {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                }
            }
            Command::Announce {
                service,
                application_data: data,
                ratchet,
                reply,
            } => {
                let announcement_uses_ratchet = matches!(ratchet, RatchetAction::Rotate)
                    || self.services[service.0]
                        .as_ref()
                        .is_some_and(|service| !service.ratchets.is_empty());
                if self.interfaces.iter().all(|slot| !slot.accepts_outbound()) {
                    let _ = reply.send(Err(NodeError::InterfaceUnavailable));
                } else if announcement_uses_ratchet
                    && data.len() > Service::MAX_RATCHET_ANNOUNCEMENT_BYTES
                {
                    let _ = reply.send(Err(NodeError::InvalidInput));
                } else if let Some(prepared) =
                    self.prepare_announcement(service, data.to_vec(), ratchet)
                {
                    let mut admitted = 0;
                    for outbound in &prepared.outbounds {
                        admitted += usize::from(self.admit_outbound(outbound).is_ok());
                    }
                    if admitted > 0 {
                        let restart = self.commit_announcement(prepared);
                        let _ = reply.send(Ok(restart));
                    } else {
                        let _ = reply.send(Err(NodeError::InterfaceUnavailable));
                    }
                } else {
                    let _ = reply.send(Err(NodeError::InterfaceUnavailable));
                }
            }
            Command::SendDestination {
                destination,
                body,
                reply,
            } => {
                let destination = destination.into_bytes();
                if self.has_path(destination) {
                    self.send_destination(destination, body, reply);
                } else {
                    let _ = reply.send(Err(NodeError::NoRoute));
                }
            }
            Command::OpenLink { destination, reply } => {
                let destination = destination.into_bytes();
                if self.has_path(destination) {
                    self.open_link(destination, reply, now);
                } else if self.has_route_wait_capacity() {
                    self.route_waits.entry(destination).or_default().push(reply);
                    self.request_path(destination, now);
                } else {
                    let _ = reply.send(Err(NodeError::CapacityReached));
                }
            }
            Command::AcceptLink { offer, reply } => {
                if self.established_links.len() >= MAXIMUM_LINKS {
                    let _ = reply.send(Err(NodeError::CapacityReached));
                } else if self.accept_incoming_link(offer.0, now) {
                    let events = LinkEvents::new(EVENT_CAPACITY);
                    self.established_links
                        .get_mut(&offer.0)
                        .expect("accepted link disappeared")
                        .events = Some(events);
                    let client = self
                        .new_client()
                        .expect("node client disappeared while accepting link");
                    let _ = reply.send(Ok(Link {
                        id: LinkId(offer.0),
                        registration: ResourceRegistration::new(
                            client,
                            RegisteredResource::Link(LinkId(offer.0)),
                        ),
                    }));
                } else {
                    let _ = reply.send(Err(NodeError::Rejected));
                }
            }
            Command::RejectLink { offer, reply } => {
                let result = self
                    .reject_incoming_link(offer.0)
                    .then_some(())
                    .ok_or(NodeError::Rejected);
                let _ = reply.send(result);
            }
            Command::CloseLink { link, reply } => {
                self.terminate_link_handles(link.0, LinkCloseReason::LocalClosed);
                if let Some(requests) = self.remove_link_state(link.0) {
                    self.fail_outbound_requests(requests, NodeError::ResourceClosed);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                }
            }
            Command::ReceiveLink { link, reply } => {
                if let Some(events) = self
                    .established_links
                    .get_mut(&link.0)
                    .and_then(|link| link.events.as_mut())
                {
                    events.events.receive(reply);
                    self.deliver_waiting_request(link.0);
                } else {
                    let _ = reply.send(Err(NodeError::LinkClosed(LinkCloseReason::LocalClosed)));
                }
            }
            Command::SendLinkDatagram { link, body, reply } => {
                let result = match self.prepare_link_datagram(link.0, &body) {
                    Ok(outbound) => match self.admit_outbound(&outbound) {
                        Ok(()) => Ok(()),
                        Err(error) => Err(error.into_node_error()),
                    },
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Command::Request {
                link,
                path,
                body,
                reply,
            } => match self.prepare_request(link.0, path.as_str(), &body, now, REQUEST_TIMEOUT) {
                Ok(prepared) => match self.admit_outbound(&prepared.outbound) {
                    Ok(()) => {
                        let request = self.commit_request(prepared);
                        self.outbound_request_replies.insert(request.0, reply);
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error.into_node_error()));
                    }
                },
                Err(_) => {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                }
            },
            Command::Respond {
                link,
                request,
                response,
                reply,
            } => {
                let request_awaits_response = self
                    .established_links
                    .get(&link.0)
                    .and_then(|link| link.events.as_ref())
                    .is_some_and(|events| {
                        matches!(
                            events.inbound_requests.get(&request.0),
                            Some(InboundRequestPhase::AwaitingResponse)
                        )
                    });
                let result = if !request_awaits_response {
                    Err(
                        if self
                            .established_links
                            .get(&link.0)
                            .is_some_and(|link| link.events.is_some())
                        {
                            NodeError::TimedOut
                        } else {
                            NodeError::ResourceClosed
                        },
                    )
                } else {
                    match self.prepare_response(link.0, crate::WireRequestId(request.0), &response)
                    {
                        Ok(prepared) => match self.admit_outbound(&prepared.outbound) {
                            Ok(()) => {
                                self.commit_response(prepared);
                                self.established_links
                                    .get_mut(&link.0)
                                    .expect("responding link disappeared")
                                    .events
                                    .as_mut()
                                    .expect("responding events disappeared")
                                    .inbound_requests
                                    .remove(&request.0);
                                self.timers.cancel_inbound_request(link.0, request.0);
                                Ok(())
                            }
                            Err(error) => Err(error.into_node_error()),
                        },
                        Err(error) => Err(error),
                    }
                };
                let _ = reply.send(result);
            }
            Command::Identify {
                link,
                service,
                reply,
            } => match self.prepare_identify(link.0, service) {
                Ok(prepared) => {
                    let result = match self.admit_outbound(&prepared.outbound) {
                        Ok(()) => {
                            self.commit_identify(link.0, &prepared);
                            Ok(())
                        }
                        Err(
                            OutboundAdmissionError::Busy | OutboundAdmissionError::InterfaceFailed,
                        ) => Err(NodeError::InterfaceUnavailable),
                    };
                    let _ = reply.send(result);
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::OpenChannel { link, reply } => {
                if let Some(established) = self.established_links.get_mut(&link.0) {
                    if established.channel.is_none() {
                        established.channel = Some(RuntimeChannel::new());
                    }
                    let client = self
                        .new_client()
                        .expect("node client disappeared while opening channel");
                    let _ = reply.send(Ok(Channel {
                        link,
                        registration: ResourceRegistration::new(
                            client,
                            RegisteredResource::Channel(link),
                        ),
                    }));
                } else {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                }
            }
            Command::ReceiveChannel { link, reply } => {
                if let Some(channel) = self
                    .established_links
                    .get_mut(&link.0)
                    .and_then(|link| link.channel.as_mut())
                {
                    channel.events.receive(reply);
                } else {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                }
            }
            Command::SendChannel {
                link,
                message,
                reply,
            } => match self.try_queue_channel_message(link.0, &message, now) {
                Ok(packet) => {
                    self.established_links
                        .get_mut(&link.0)
                        .and_then(|link| link.channel.as_mut())
                        .expect("sending channel disappeared")
                        .pending_delivery_replies
                        .insert(packet, reply);
                }
                Err(QueueChannelError::WindowFull) => {
                    self.enqueue_window_waiter(
                        link.0,
                        WaitingChannelOperation::Message { message, reply },
                    );
                }
                Err(QueueChannelError::LinkNotFound | QueueChannelError::LinkNotActive) => {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                }
            },
            Command::OpenBuffer {
                link,
                stream,
                reply,
            } => {
                let Some(channel) = self
                    .established_links
                    .get_mut(&link.0)
                    .and_then(|link| link.channel.as_mut())
                else {
                    let _ = reply.send(Err(NodeError::ResourceClosed));
                    return;
                };
                if !channel.outgoing_streams.insert(stream) {
                    let _ = reply.send(Err(NodeError::Conflict));
                } else {
                    let _ = reply.send(Ok(()));
                }
            }
            Command::WriteBuffer {
                link,
                stream,
                input,
                reply,
            } => {
                self.queue_buffer(link, stream, input, KEEP_STREAM_OPEN, reply, now);
            }
            Command::FinishBuffer {
                link,
                stream,
                input,
                reply,
            } => {
                self.queue_buffer(link, stream, input, FINISH_STREAM, reply, now);
            }
            Command::Shutdown => self.begin_shutdown(now),
        }
    }

    fn has_route_wait_capacity(&self) -> bool {
        self.route_waits.values().map(Vec::len).sum::<usize>() < COMMAND_CAPACITY
    }

    pub(crate) fn at_link_capacity(&self) -> bool {
        self.pending_outbound_links.len()
            + self.pending_inbound_links.len()
            + self.established_links.len()
            >= MAXIMUM_LINKS
    }

    fn send_destination(
        &mut self,
        destination: [u8; 16],
        body: Bytes,
        reply: oneshot::Sender<Result<(), NodeError>>,
    ) {
        let result = match self.prepare_destination_datagram(destination, &body) {
            Ok(outbound) => match self.admit_outbound(&outbound) {
                Ok(()) => Ok(()),
                Err(OutboundAdmissionError::Busy | OutboundAdmissionError::InterfaceFailed) => {
                    Err(NodeError::InterfaceUnavailable)
                }
            },
            Err(error) => Err(error),
        };
        let _ = reply.send(result);
    }

    fn open_link(
        &mut self,
        destination: [u8; 16],
        reply: oneshot::Sender<Result<Link, NodeError>>,
        now: MonoTime,
    ) {
        if reply.is_canceled() {
            return;
        }
        if self.at_link_capacity() {
            let _ = reply.send(Err(NodeError::CapacityReached));
        } else if self.interfaces.iter().all(|slot| !slot.accepts_outbound()) {
            let _ = reply.send(Err(NodeError::InterfaceUnavailable));
        } else {
            let events = LinkEvents::new(EVENT_CAPACITY);
            self.begin_outbound_link(
                destination,
                now,
                LINK_HANDSHAKE_TIMEOUT,
                PendingOpenLink { reply, events },
            );
        }
    }

    fn admit_outbound(
        &mut self,
        outbound: &crate::node::ProtocolOutbound,
    ) -> Result<(), OutboundAdmissionError> {
        let Some(slot) = self.interfaces.get_mut(outbound.interface) else {
            return Err(OutboundAdmissionError::InterfaceFailed);
        };
        let packet = OutboundPacket::new(outbound.packet.to_bytes());
        if !slot.accepts_outbound() || packet.byte_len() > slot.limits.maximum_packet_bytes {
            return Err(OutboundAdmissionError::InterfaceFailed);
        }
        slot.enqueue_outbound(outbound.priority, packet)
            .map_err(|_| OutboundAdmissionError::Busy)?;
        Ok(())
    }

    fn queue_buffer(
        &mut self,
        link: LinkId,
        stream: StreamId,
        input: bytes::Bytes,
        finish_stream: bool,
        reply: oneshot::Sender<Result<BufferQueued, NodeError>>,
        now: MonoTime,
    ) {
        if !self
            .established_links
            .get(&link.0)
            .and_then(|link| link.channel.as_ref())
            .is_some_and(|channel| channel.outgoing_streams.contains(&stream))
        {
            let _ = reply.send(Err(NodeError::ResourceClosed));
            return;
        }
        let (encoded, input_bytes) = crate::buffer::encode(stream, &input, finish_stream);
        let stream_end_queued = finish_stream && input_bytes == input.len();
        match self.send_buffer_data(link.0, &encoded, now) {
            Ok(_) => {
                if stream_end_queued {
                    self.established_links
                        .get_mut(&link.0)
                        .and_then(|link| link.channel.as_mut())
                        .expect("channel disappeared")
                        .outgoing_streams
                        .remove(&stream);
                }
                let _ = reply.send(Ok(BufferQueued {
                    input_bytes,
                    end_queued: stream_end_queued,
                }));
            }
            Err(QueueChannelError::WindowFull) => {
                self.enqueue_window_waiter(
                    link.0,
                    WaitingChannelOperation::BufferWrite {
                        stream,
                        input,
                        finish_stream,
                        reply,
                    },
                );
            }
            Err(QueueChannelError::LinkNotFound | QueueChannelError::LinkNotActive) => {
                let _ = reply.send(Err(NodeError::ResourceClosed));
            }
        }
    }

    fn retry_waiting_operations(&mut self, link: [u8; 16], now: MonoTime) {
        let Some(channel) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
        else {
            return;
        };
        let waiting = std::mem::take(&mut channel.blocked_channel_ops);
        for operation in waiting {
            match operation {
                WaitingChannelOperation::Message { message, reply } => self.handle_command(
                    Command::SendChannel {
                        link: LinkId(link),
                        message,
                        reply,
                    },
                    now,
                ),
                WaitingChannelOperation::BufferWrite {
                    stream,
                    input,
                    finish_stream,
                    reply,
                } => self.queue_buffer(LinkId(link), stream, input, finish_stream, reply, now),
            }
        }
    }

    pub(crate) fn handle_channel_delivery(
        &mut self,
        link: [u8; 16],
        packet_id: [u8; 32],
        delivery_confirmed: bool,
        now: MonoTime,
    ) {
        let reply = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
            .and_then(|channel| channel.pending_delivery_replies.remove(&packet_id));
        if let Some(reply) = reply {
            let _ = reply.send(if delivery_confirmed {
                Ok(())
            } else {
                Err(NodeError::TimedOut)
            });
            if delivery_confirmed {
                self.retry_waiting_operations(link, now);
            }
        }
    }

    pub(crate) fn enqueue_link_datagram(&mut self, link: [u8; 16], data: Vec<u8>) {
        let Some(events) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
        else {
            return;
        };
        if let Err(error) = events.events.push(LinkEvent::Datagram(data.into()), 0) {
            self.close_link(link, error.link_close_reason());
        }
    }

    pub(crate) fn enqueue_incoming_link(&mut self, service: ServiceId, link: [u8; 16]) {
        let Some(client) = self.new_client() else {
            self.reject_incoming_link(link);
            return;
        };
        let incoming = IncomingLink {
            offer: LinkOfferId(link),
            client,
        };
        let queued = self
            .services
            .get_mut(service.0)
            .and_then(Option::as_mut)
            .is_some_and(|service| {
                service
                    .events
                    .push(ServiceEvent::IncomingLink(incoming), 0)
                    .is_ok()
            });
        if !queued {
            self.reject_incoming_link(link);
        }
    }

    pub(crate) fn complete_link_open(
        &mut self,
        link: [u8; 16],
        pending: PendingOpenLink,
        result: Result<(), NodeError>,
    ) {
        if let Err(error) = result {
            let _ = pending.reply.send(Err(error));
            return;
        }
        self.established_links
            .get_mut(&link)
            .expect("established link disappeared")
            .events = Some(pending.events);
        if let Some(client) = self.new_client() {
            let _ = pending.reply.send(Ok(Link {
                id: LinkId(link),
                registration: ResourceRegistration::new(
                    client,
                    RegisteredResource::Link(LinkId(link)),
                ),
            }));
        } else {
            self.close_link(link, LinkCloseReason::LocalClosed);
        }
    }

    pub(crate) fn complete_request(
        &mut self,
        request: crate::RequestId,
        result: Result<Vec<u8>, NodeError>,
    ) {
        if let Some(reply) = self.outbound_request_replies.remove(&request.0) {
            let result = result.map(Into::into);
            let _ = reply.send(result);
        }
    }

    pub(crate) fn handle_incoming_request(
        &mut self,
        link: [u8; 16],
        request: crate::RequestId,
        path: String,
        body: Vec<u8>,
        now: MonoTime,
    ) {
        let Some(path) = RequestPath::new(path) else {
            self.close_link(link, LinkCloseReason::ProtocolViolation);
            return;
        };
        let Some(events) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
        else {
            return;
        };
        if events.inbound_requests.len() >= EVENT_CAPACITY
            || events.inbound_requests.contains_key(&request.0)
        {
            self.close_link(link, LinkCloseReason::CapacityReached);
            return;
        }
        let deadline = now
            .checked_add(REQUEST_TIMEOUT)
            .expect("inbound request deadline overflow");
        events.inbound_requests.insert(
            request.0,
            InboundRequestPhase::AwaitingDelivery {
                path,
                body: body.into(),
            },
        );
        events.requests_awaiting_delivery.push_back(request.0);
        self.timers
            .schedule_inbound_request(deadline, link, request.0);
        self.deliver_waiting_request(link);
    }

    pub(crate) fn complete_identification(
        &mut self,
        link: [u8; 16],
        result: Result<[u8; 16], LinkCloseReason>,
    ) {
        let identity = match result {
            Ok(identity) => identity,
            Err(reason) => {
                self.close_link(link, reason);
                return;
            }
        };
        let result = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
            .map(|events| {
                events
                    .events
                    .push(LinkEvent::Identified(IdentityHash::from_bytes(identity)), 0)
            });
        match result {
            Some(Ok(())) => self.commit_remote_identity(link, identity),
            Some(Err(error)) => self.close_link(link, error.link_close_reason()),
            None => {}
        }
    }

    pub(crate) fn resolve_route(
        &mut self,
        destination: [u8; 16],
        route_found: bool,
        now: MonoTime,
    ) {
        if let Some(waiters) = self.route_waits.remove(&destination) {
            for reply in waiters {
                if route_found {
                    self.open_link(destination, reply, now);
                } else {
                    let _ = reply.send(Err(NodeError::NoRoute));
                }
            }
        }
    }

    fn enqueue_window_waiter(&mut self, link: [u8; 16], operation: WaitingChannelOperation) {
        let Some(channel) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
        else {
            Self::reply_to_failed_waiter(operation, NodeError::ResourceClosed);
            return;
        };
        if channel.blocked_channel_ops.len() < CHANNEL_QUEUE_CAPACITY {
            channel.blocked_channel_ops.push_back(operation);
            return;
        }
        Self::reply_to_failed_waiter(operation, NodeError::CapacityReached);
    }

    fn reply_to_failed_waiter(operation: WaitingChannelOperation, error: NodeError) {
        match operation {
            WaitingChannelOperation::Message { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            WaitingChannelOperation::BufferWrite { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }

    pub(crate) fn close_link(&mut self, link: [u8; 16], reason: LinkCloseReason) {
        self.terminate_link_handles(link, reason);
        if let Some(requests) = self.remove_link_state(link) {
            self.fail_outbound_requests(requests, NodeError::ResourceClosed);
        }
    }

    pub(crate) fn terminate_link_handles(&mut self, link: [u8; 16], reason: LinkCloseReason) {
        if let Some(mut events) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.take())
        {
            for request in events.inbound_requests.keys() {
                self.timers.cancel_inbound_request(link, *request);
            }
            events.events.close(NodeError::LinkClosed(reason));
        }
        self.close_link_channel(link, NodeError::ResourceClosed);
    }

    fn fail_outbound_requests(
        &mut self,
        requests: impl IntoIterator<Item = crate::RequestId>,
        error: NodeError,
    ) {
        for request in requests {
            if let Some(reply) = self.outbound_request_replies.remove(&request.0) {
                let _ = reply.send(Err(error));
            }
        }
    }

    pub(crate) fn close_link_channel(&mut self, link: [u8; 16], reason: NodeError) {
        if let Some(mut channel) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.take())
        {
            channel.events.close(reason);
            while let Some(operation) = channel.blocked_channel_ops.pop_front() {
                Self::reply_to_failed_waiter(operation, NodeError::ResourceClosed);
            }
            for (_, reply) in channel.pending_delivery_replies.drain() {
                let _ = reply.send(Err(NodeError::ResourceClosed));
            }
        }
    }

    pub(crate) fn enqueue_channel_event(&mut self, link: [u8; 16], event: ChannelReceive) {
        if let ChannelReceive::Buffer { stream, chunk } = &event {
            let Some(channel) = self
                .established_links
                .get_mut(&link)
                .and_then(|link| link.channel.as_mut())
            else {
                self.close_link(link, LinkCloseReason::ProtocolViolation);
                return;
            };
            if channel.ended_incoming_streams.contains(stream) {
                self.close_link(link, LinkCloseReason::ProtocolViolation);
                return;
            }
            if matches!(chunk, BufferChunk::End(_)) {
                channel.ended_incoming_streams.insert(*stream);
            }
        }
        let bytes = match &event {
            ChannelReceive::Message(message) => message.body().len(),
            ChannelReceive::Buffer { chunk, .. } => match chunk {
                BufferChunk::Data(data) | BufferChunk::End(data) => data.len(),
            },
        };
        let result = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
            .map(|channel| channel.events.push(event, bytes));
        match result {
            Some(Ok(())) => {}
            Some(Err(error)) => self.close_link(link, error.link_close_reason()),
            None => self.close_link(link, LinkCloseReason::ProtocolViolation),
        }
    }

    fn begin_shutdown(&mut self, now: MonoTime) {
        if !matches!(self.phase, NodePhase::Running) {
            return;
        }
        if let Some(commands) = self.command_receiver.take() {
            commands.close();
        }
        for service in self.services.iter_mut().flatten() {
            service.events.close(NodeError::ResourceClosed);
        }
        let links = self
            .established_links
            .iter()
            .filter_map(|(id, link)| link.events.is_some().then_some(*id))
            .collect::<Vec<_>>();
        for link in &links {
            self.terminate_link_handles(*link, LinkCloseReason::LocalClosed);
            if let Some(requests) = self.remove_link_state(*link) {
                self.fail_outbound_requests(requests, NodeError::NodeStopping);
            }
        }
        for slot in &mut self.interfaces {
            if let InterfacePhase::Active { sending, .. } = slot.phase {
                slot.phase = InterfacePhase::Draining { sending };
            }
        }
        let deadline = now
            .checked_add(SHUTDOWN_GRACE)
            .expect("shutdown deadline overflow");
        self.timers.schedule_shutdown(deadline);
        self.phase = NodePhase::Closing {
            deadline_expired: false,
        };
    }

    fn shutdown_if_complete(&mut self) -> Option<Result<(), NodeRunError>> {
        let NodePhase::Closing { deadline_expired } = self.phase else {
            return None;
        };
        let drained = self.pending_inbound_packets.load(Ordering::Acquire) == 0
            && self
                .interfaces
                .iter()
                .all(|slot| matches!(slot.phase, InterfacePhase::Closed));
        if !drained && !deadline_expired {
            return None;
        }
        if let Some(shutdown) = self.shutdown_tx.take() {
            let _ = shutdown.send(());
        }
        Some(Ok(()))
    }
}
