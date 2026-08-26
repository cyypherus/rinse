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
use crate::entropy::{CryptoEntropy, ProtocolRng};
use crate::interface::{AttachedInterface, OutboundPacket};
use crate::model::*;
use crate::timer::{TimerEvent, TimerQueue};
use crate::work::{InterfaceId, PacketWork, PreparePacket};
use crate::{Clock, MonoTime, PrivateIdentity};

const LINK_HANDSHAKE_TIMEOUT: crate::TimeSpan = crate::TimeSpan::from_secs(15);
const REQUEST_TIMEOUT: crate::TimeSpan = crate::TimeSpan::from_secs(30);
const SHUTDOWN_GRACE: crate::TimeSpan = crate::TimeSpan::from_secs(5);

pub struct NodeBuilder<C, W, E> {
    config: NodeConfig,
    clock: C,
    packet_work: W,
    entropy: E,
    interfaces: Vec<(AttachedInterface, InterfaceLimits)>,
}

impl<C, W, E> NodeBuilder<C, W, E>
where
    C: Clock,
    W: PacketWork + 'static,
    E: CryptoEntropy,
{
    pub fn new(config: NodeConfig, clock: C, packet_work: W, entropy: E) -> Self {
        Self {
            config,
            clock,
            packet_work,
            entropy,
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

    pub fn build(mut self) -> Result<(NodeHandle, NodeTask<C>), BuildError> {
        if self.interfaces.len() > self.config.limits.maximum_interfaces {
            return Err(BuildError::TooManyInitialInterfaces);
        }
        let mut seed = [0; 32];
        if self.entropy.fill_seed(&mut seed).is_err() {
            seed.zeroize();
            return Err(BuildError::EntropyUnavailable);
        }
        if seed == [0; 32] {
            seed.zeroize();
            return Err(BuildError::InvalidEntropy);
        }
        let mut rng = ProtocolRng::from_seed(seed);
        seed.zeroize();
        let relay = matches!(self.config.mode, NodeMode::Relay);
        let duplicate_packet_hashes = self.config.limits.duplicate_packet_hashes;
        let mut transport_id = [0; 16];
        rng.fill_bytes(&mut transport_id);
        log::info!(
            "Node started with transport_id <{}>",
            hex::encode(transport_id)
        );
        let interfaces = self
            .interfaces
            .into_iter()
            .map(|(interface, limits)| InterfaceSlot::new(interface, limits))
            .collect();
        let (command_tx, command_rx) = async_channel::bounded(self.config.limits.command_capacity);
        let command_handles = command_tx.downgrade();
        let (lifecycle_tx, lifecycle_rx) = async_channel::bounded(
            self.config.limits.maximum_services + self.config.limits.maximum_links * 2,
        );
        let lifecycle_handles = lifecycle_tx.downgrade();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown = async move {
            shutdown_rx.await.unwrap_or(ShutdownReport {
                reason: ShutdownReason::TaskDropped,
                links_closed: 0,
                links_abandoned: 0,
                interfaces_closed: 0,
                interfaces_failed: 0,
            })
        }
        .boxed()
        .shared();
        let handle = NodeHandle {
            commands: command_tx,
            _resource_lifecycle: lifecycle_tx,
            shutdown,
        };
        let packet_work = Arc::new(self.packet_work);
        let (work_tx, work_rx) = async_channel::bounded(self.config.limits.preparation_in_flight);
        let (prepared_tx, prepared_rx) = async_channel::bounded(1);
        let preparing = Arc::new(AtomicUsize::new(0));
        let pipelines = FuturesUnordered::new();
        pipelines.push(
            prepare_packets(
                work_rx,
                prepared_tx,
                packet_work.clone(),
                self.config.limits.preparation_in_flight,
            )
            .boxed(),
        );
        let task = NodeTask {
            clock: self.clock,
            owner: NodeOwner {
                config: self.config,
                rng,
                transport: relay,
                transport_id,
                path_table: HashMap::new(),
                pending_announces: Vec::new(),
                seen_packets: crate::packet_hashlist::PacketHashlist::new(duplicate_packet_hashes),
                reverse_table: HashMap::new(),
                receipts: Vec::new(),
                pending_outbound_links: HashMap::new(),
                pending_inbound_links: HashMap::new(),
                established_links: HashMap::new(),
                link_table: HashMap::new(),
                outbound_resources: HashMap::new(),
                inbound_resources: HashMap::new(),
                multi_segment_transfers: HashMap::new(),
                outbound_multi_segments: HashMap::new(),
                destination_links: HashMap::new(),
                pending_path_requests: HashMap::new(),
                discovery_path_requests: HashMap::new(),
                pending_resource_requests: HashSet::new(),
                commands: Some(command_rx),
                command_handles,
                lifecycle: Some(lifecycle_rx),
                lifecycle_handles,
                interfaces,
                sends: FuturesUnordered::new(),
                closes: FuturesUnordered::new(),
                pipelines,
                work: work_tx,
                prepared: prepared_rx,
                preparing,
                timers: TimerQueue::default(),
                shutdown_tx: Some(shutdown_tx),
                phase: NodePhase::Running,
                services: Vec::new(),
                pending_requests: HashMap::new(),
                route_waits: HashMap::new(),
                interfaces_failed: 0,
            },
        };
        Ok((handle, task))
    }
}

pub struct NodeTask<C> {
    clock: C,
    owner: NodeOwner,
}

enum NodePhase {
    Running,
    Closing {
        reason: ShutdownReason,
        links: usize,
        deadline_expired: bool,
    },
}

pub(crate) struct InterfaceSlot {
    interface: AttachedInterface,
    limits: InterfaceLimits,
    outbound: VecDeque<(u8, OutboundPacket)>,
    outbound_bytes: usize,
    phase: InterfacePhase,
    next_apply: u64,
    completed: BTreeMap<u64, crate::work::PreparedPacket>,
}

enum InterfacePhase {
    Active { reading: bool, sending: bool },
    Draining { sending: bool },
    Failed,
    Closing { failed: bool },
    Closed,
}

pub(crate) struct Events<T, E> {
    queued: VecDeque<(T, usize)>,
    queued_bytes: usize,
    waiting_receive: Option<oneshot::Sender<Result<T, E>>>,
    terminal: Option<E>,
    item_limit: usize,
    byte_limit: usize,
}

pub(crate) struct LinkEvents {
    events: Events<LinkEvent, LinkReceiveError>,
    inbound_requests: BTreeMap<[u8; 16], InboundRequestState>,
    requests_awaiting_delivery: VecDeque<[u8; 16]>,
}

struct InboundRequestState {
    phase: InboundRequestPhase,
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
            events: Events::new(capacity, 0),
            inbound_requests: BTreeMap::new(),
            requests_awaiting_delivery: VecDeque::new(),
        }
    }
}

pub(crate) enum EventPushError<T> {
    Full(T),
    Closed(T),
}

enum OutboundAdmissionError {
    Busy,
    InterfaceFailed,
}

impl OutboundAdmissionError {
    fn link(self) -> LinkError {
        match self {
            Self::Busy => LinkError::InterfaceBusy,
            Self::InterfaceFailed => LinkError::InterfaceFailed,
        }
    }
}

impl<T, E: Clone> Events<T, E> {
    fn new(item_limit: usize, byte_limit: usize) -> Self {
        Self {
            queued: VecDeque::new(),
            queued_bytes: 0,
            waiting_receive: None,
            terminal: None,
            item_limit,
            byte_limit,
        }
    }

    pub(crate) fn push(&mut self, mut item: T, bytes: usize) -> Result<(), EventPushError<T>> {
        if self.terminal.is_some() {
            return Err(EventPushError::Closed(item));
        }
        if let Some(waiting) = self.waiting_receive.take() {
            match waiting.send(Ok(item)) {
                Ok(()) => return Ok(()),
                Err(Ok(returned)) => item = returned,
                Err(Err(_)) => unreachable!(),
            }
        }
        if self.queued.len() >= self.item_limit
            || self.byte_limit != 0 && self.queued_bytes + bytes > self.byte_limit
        {
            return Err(EventPushError::Full(item));
        }
        self.queued_bytes += bytes;
        self.queued.push_back((item, bytes));
        Ok(())
    }

    fn receive(&mut self, reply: oneshot::Sender<Result<T, E>>) -> bool {
        if let Some(waiting) = self.waiting_receive.take()
            && !waiting.is_canceled()
        {
            unreachable!("one receiver cannot have two live waits")
        }
        if let Some((item, bytes)) = self.queued.pop_front() {
            match reply.send(Ok(item)) {
                Ok(()) => {
                    self.queued_bytes -= bytes;
                    return true;
                }
                Err(Ok(item)) => self.queued.push_front((item, bytes)),
                Err(Err(_)) => unreachable!(),
            }
            return false;
        }
        if let Some(reason) = &self.terminal {
            let _ = reply.send(Err(reason.clone()));
        } else {
            self.waiting_receive = Some(reply);
        }
        false
    }

    pub(crate) fn terminate(&mut self, reason: E) {
        if self.terminal.is_some() {
            return;
        }
        if self.queued.is_empty()
            && let Some(waiting) = self.waiting_receive.take()
        {
            let _ = waiting.send(Err(reason.clone()));
        }
        self.terminal = Some(reason);
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
            next_apply: 0,
            completed: BTreeMap::new(),
        }
    }

    pub(crate) fn admit(
        &mut self,
        priority: u8,
        packet: OutboundPacket,
    ) -> Result<(), OutboundPacket> {
        let bytes = packet.len();
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

    pub(crate) fn admit_protocol(&mut self, priority: u8, packet: &crate::packet::Packet) -> bool {
        self.accepting()
            && self
                .admit(priority, OutboundPacket::new(packet.to_bytes()))
                .is_ok()
    }

    pub(crate) fn accepting(&self) -> bool {
        matches!(self.phase, InterfacePhase::Active { .. })
    }

    fn fail(&mut self) -> bool {
        if matches!(
            self.phase,
            InterfacePhase::Failed | InterfacePhase::Closing { .. } | InterfacePhase::Closed
        ) {
            return false;
        }
        self.phase = InterfacePhase::Failed;
        self.outbound.clear();
        self.outbound_bytes = 0;
        true
    }

    fn begin_close(&mut self) {
        if let InterfacePhase::Active { sending, .. } = self.phase {
            self.phase = InterfacePhase::Draining { sending };
        }
    }
}

type SendOperation = BoxFuture<'static, (InterfaceId, Result<(), crate::InterfaceError>)>;
type CloseOperation = BoxFuture<'static, (InterfaceId, Result<(), crate::InterfaceError>)>;
type PipelineOperation = BoxFuture<'static, PipelineStopped>;

enum PipelineStopped {
    Interface(InterfaceId),
    Preparation,
}

pub(crate) struct NodeOwner {
    config: NodeConfig,
    pub(crate) rng: ProtocolRng,
    pub(crate) transport: bool,
    pub(crate) transport_id: crate::packet::DestinationAddress,
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
    pub(crate) multi_segment_transfers: HashMap<[u8; 32], crate::node::MultiSegmentTransfer>,
    pub(crate) outbound_multi_segments: HashMap<[u8; 32], crate::node::OutboundMultiSegment>,
    pub(crate) destination_links: HashMap<crate::packet::DestinationAddress, [u8; 16]>,
    pub(crate) pending_path_requests: HashMap<crate::packet::DestinationAddress, MonoTime>,
    pub(crate) discovery_path_requests: HashMap<crate::packet::DestinationAddress, usize>,
    pub(crate) pending_resource_requests: HashSet<([u8; 16], [u8; 32])>,
    commands: Option<async_channel::Receiver<Command>>,
    command_handles: async_channel::WeakSender<Command>,
    lifecycle: Option<async_channel::Receiver<DroppedResource>>,
    lifecycle_handles: async_channel::WeakSender<DroppedResource>,
    pub(crate) interfaces: Vec<InterfaceSlot>,
    sends: FuturesUnordered<SendOperation>,
    closes: FuturesUnordered<CloseOperation>,
    pipelines: FuturesUnordered<PipelineOperation>,
    work: async_channel::Sender<PreparePacket>,
    prepared:
        async_channel::Receiver<Vec<Result<crate::work::PreparedPacket, crate::PacketWorkError>>>,
    preparing: Arc<AtomicUsize>,
    pub(crate) timers: TimerQueue,
    shutdown_tx: Option<oneshot::Sender<ShutdownReport>>,
    phase: NodePhase,
    pub(crate) services: Vec<Option<crate::node::ServiceState>>,
    pending_requests: HashMap<[u8; 16], oneshot::Sender<Result<Bytes, LinkError>>>,
    route_waits: HashMap<[u8; 16], Vec<PendingRoute>>,
    interfaces_failed: usize,
}

pub(crate) struct PendingOpenLink {
    reply: oneshot::Sender<Result<Link, LinkError>>,
    events: LinkEvents,
}

enum PendingRoute {
    Send {
        body: Bytes,
        reply: oneshot::Sender<Result<(), SendError>>,
    },
    OpenLink {
        reply: oneshot::Sender<Result<Link, LinkError>>,
    },
}

pub(crate) struct RuntimeChannel {
    pub(crate) protocol: crate::channel::ChannelState,
    events: Events<ChannelReceive, ChannelReceiveError>,
    waiting_sends: VecDeque<WaitingChannelOperation>,
    outgoing_streams: HashSet<StreamId>,
    ended_incoming_streams: HashSet<StreamId>,
    delivery_replies: HashMap<[u8; 32], oneshot::Sender<Result<(), ChannelError>>>,
}

enum WaitingChannelOperation {
    Message {
        message: ChannelMessage,
        reply: oneshot::Sender<Result<(), ChannelError>>,
    },
    Buffer {
        stream: StreamId,
        input: Bytes,
        finish: bool,
        reply: oneshot::Sender<Result<BufferQueued, BufferError>>,
    },
}

enum RuntimeEvent {
    Command(Result<Command, async_channel::RecvError>),
    Lifecycle(Result<DroppedResource, async_channel::RecvError>),
    Sent((InterfaceId, Result<(), crate::InterfaceError>)),
    Closed((InterfaceId, Result<(), crate::InterfaceError>)),
    PipelineStopped(PipelineStopped),
    Prepared(
        Result<
            Vec<Result<crate::work::PreparedPacket, crate::PacketWorkError>>,
            async_channel::RecvError,
        >,
    ),
    Timer,
}

async fn receive_packets(
    interface_id: InterfaceId,
    interface: AttachedInterface,
    work: async_channel::Sender<PreparePacket>,
    preparing: Arc<AtomicUsize>,
) -> PipelineStopped {
    let mut sequence = 0u64;
    loop {
        let packet = match interface.receive().await {
            Ok(packet) => packet,
            Err(_) => return PipelineStopped::Interface(interface_id),
        };
        let job = PreparePacket::new(interface_id, sequence, packet.into_bytes());
        let Some(next) = sequence.checked_add(1) else {
            return PipelineStopped::Interface(interface_id);
        };
        sequence = next;
        preparing.fetch_add(1, Ordering::AcqRel);
        if work.send(job).await.is_err() {
            preparing.fetch_sub(1, Ordering::AcqRel);
            return PipelineStopped::Interface(interface_id);
        }
    }
}

async fn prepare_packets<W: PacketWork>(
    work: async_channel::Receiver<PreparePacket>,
    prepared: async_channel::Sender<
        Vec<Result<crate::work::PreparedPacket, crate::PacketWorkError>>,
    >,
    packet_work: Arc<W>,
    concurrency: usize,
) -> PipelineStopped {
    let results = work
        .map(move |job| {
            let packet_work = packet_work.clone();
            async move { packet_work.prepare(job).await }
        })
        .buffer_unordered(concurrency)
        .ready_chunks(concurrency);
    futures_util::pin_mut!(results);
    while let Some(results) = results.next().await {
        let failed = results.iter().any(Result::is_err);
        if prepared.send(results).await.is_err() || failed {
            break;
        }
    }
    PipelineStopped::Preparation
}

async fn next_operation<T>(operations: &mut FuturesUnordered<BoxFuture<'static, T>>) -> T {
    match operations.next().await {
        Some(result) => result,
        None => std::future::pending().await,
    }
}

async fn receive_channel<T>(
    receiver: Option<&async_channel::Receiver<T>>,
) -> Result<T, async_channel::RecvError> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

impl<C> NodeTask<C>
where
    C: Clock + Sync,
{
    pub async fn run(self) -> Result<ShutdownReport, NodeRunError> {
        let NodeTask { clock, mut owner } = self;
        loop {
            owner.schedule_readers();
            owner.schedule_sends();
            owner.schedule_closes();
            if let Some(report) = owner.shutdown_if_complete() {
                return Ok(report);
            }
            let deadline = owner.timers.next_deadline();
            let event = {
                let command = receive_channel(owner.commands.as_ref()).fuse();
                let lifecycle = receive_channel(owner.lifecycle.as_ref()).fuse();
                let send = next_operation(&mut owner.sends).fuse();
                let close = next_operation(&mut owner.closes).fuse();
                let pipeline = next_operation(&mut owner.pipelines).fuse();
                let prepared = owner.prepared.recv().fuse();
                let timer = async {
                    match deadline {
                        Some(deadline) => clock.sleep_until(deadline).await,
                        None => std::future::pending().await,
                    }
                }
                .fuse();
                futures_util::pin_mut!(command, lifecycle, send, close, pipeline, prepared, timer);
                futures_util::select_biased! {
                    command = command => RuntimeEvent::Command(command),
                    lifecycle = lifecycle => RuntimeEvent::Lifecycle(lifecycle),
                    send = send => RuntimeEvent::Sent(send),
                    close = close => RuntimeEvent::Closed(close),
                    pipeline = pipeline => RuntimeEvent::PipelineStopped(pipeline),
                    prepared = prepared => RuntimeEvent::Prepared(prepared),
                    _ = timer => RuntimeEvent::Timer,
                }
            };
            let now = clock.now();
            match event {
                RuntimeEvent::Command(Ok(command)) => owner.handle_command(command, now),
                RuntimeEvent::Command(Err(_)) => {
                    owner.commands = None;
                    if matches!(owner.phase, NodePhase::Running) {
                        owner.begin_shutdown(ShutdownReason::LastHandleDropped, now);
                    }
                }
                RuntimeEvent::Lifecycle(Ok(resource)) => owner.release(resource),
                RuntimeEvent::Lifecycle(Err(_)) => owner.lifecycle = None,
                RuntimeEvent::Sent(sent) => owner.sent(sent)?,
                RuntimeEvent::Closed(closed) => owner.closed(closed)?,
                RuntimeEvent::PipelineStopped(PipelineStopped::Interface(interface)) => {
                    let slot = owner
                        .interfaces
                        .get_mut(interface.0)
                        .ok_or(NodeRunError::ProtocolInvariant)?;
                    owner.interfaces_failed += usize::from(slot.fail());
                }
                RuntimeEvent::PipelineStopped(PipelineStopped::Preparation) => {
                    return Err(NodeRunError::PacketWorkFailed);
                }
                RuntimeEvent::Prepared(Ok(prepared)) => {
                    for prepared in prepared {
                        owner.finished_preparing()?;
                        match prepared {
                            Ok(prepared) => owner.prepared(prepared, now)?,
                            Err(_) => return Err(NodeRunError::PacketWorkFailed),
                        }
                    }
                }
                RuntimeEvent::Prepared(Err(_)) => return Err(NodeRunError::PacketWorkFailed),
                RuntimeEvent::Timer => owner.expire_timers(now),
            }
        }
    }
}

impl NodeOwner {
    pub(crate) fn active_interfaces(
        interfaces: &[InterfaceSlot],
    ) -> impl Iterator<Item = usize> + '_ {
        interfaces
            .iter()
            .enumerate()
            .filter_map(|(id, interface)| interface.accepting().then_some(id))
    }

    fn release(&mut self, resource: DroppedResource) {
        match resource {
            DroppedResource::Service(service) => {
                for link in self.remove_service(service) {
                    self.close_protocol_link(link, LinkCloseReason::LocalClosed);
                }
            }
            DroppedResource::Link(link) => {
                self.close_protocol_link(link.0, LinkCloseReason::LocalClosed);
            }
            DroppedResource::Channel(link) => {
                self.close_runtime_channel(link.0, ChannelReceiveError::ChannelClosed);
            }
        }
    }

    fn prepared(
        &mut self,
        prepared: crate::work::PreparedPacket,
        now: MonoTime,
    ) -> Result<(), NodeRunError> {
        let slot = self
            .interfaces
            .get_mut(prepared.interface.0)
            .ok_or(NodeRunError::ProtocolInvariant)?;
        if slot.completed.insert(prepared.sequence, prepared).is_some() {
            return Err(NodeRunError::ProtocolInvariant);
        }
        let mut ready = Vec::new();
        while let Some(prepared) = slot.completed.remove(&slot.next_apply) {
            slot.next_apply = slot
                .next_apply
                .checked_add(1)
                .ok_or(NodeRunError::ProtocolInvariant)?;
            if let Some(packet) = prepared.packet {
                ready.push(packet);
            }
        }
        if !ready.is_empty() {
            self.process(now, ready);
        }
        Ok(())
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
            self.pipelines.push(
                receive_packets(id, interface, self.work.clone(), self.preparing.clone()).boxed(),
            );
        }
    }

    fn finished_preparing(&self) -> Result<(), NodeRunError> {
        self.preparing
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            })
            .map(|_| ())
            .map_err(|_| NodeRunError::ProtocolInvariant)
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
            slot.outbound_bytes -= packet.len();
            *sending = true;
            let interface = slot.interface.clone();
            let id = InterfaceId(id);
            self.sends
                .push(async move { (id, interface.send(packet).await) }.boxed());
        }
    }

    fn sent(
        &mut self,
        (interface, sent): (InterfaceId, Result<(), crate::InterfaceError>),
    ) -> Result<(), NodeRunError> {
        let slot = self
            .interfaces
            .get_mut(interface.0)
            .ok_or(NodeRunError::ProtocolInvariant)?;
        let sending = match &mut slot.phase {
            InterfacePhase::Active { sending, .. } | InterfacePhase::Draining { sending } => {
                sending
            }
            _ => return Ok(()),
        };
        *sending = false;
        if sent.is_err() {
            self.interfaces_failed += usize::from(slot.fail());
        }
        Ok(())
    }

    fn schedule_closes(&mut self) {
        for (id, slot) in self.interfaces.iter_mut().enumerate() {
            let failed = match slot.phase {
                InterfacePhase::Failed => true,
                InterfacePhase::Draining { sending: false } if slot.outbound.is_empty() => false,
                _ => continue,
            };
            slot.phase = InterfacePhase::Closing { failed };
            let interface = slot.interface.clone();
            let id = InterfaceId(id);
            self.closes
                .push(async move { (id, interface.close().await) }.boxed());
        }
    }

    fn closed(
        &mut self,
        (interface, closed): (InterfaceId, Result<(), crate::InterfaceError>),
    ) -> Result<(), NodeRunError> {
        let slot = self
            .interfaces
            .get_mut(interface.0)
            .ok_or(NodeRunError::ProtocolInvariant)?;
        let InterfacePhase::Closing { failed } = slot.phase else {
            return Ok(());
        };
        if closed.is_err() && !failed {
            self.interfaces_failed += 1;
        }
        slot.phase = InterfacePhase::Closed;
        Ok(())
    }

    fn deliver_waiting_request(&mut self, link: [u8; 16]) {
        let Some(commands) = self.command_handles.upgrade() else {
            return;
        };
        let mut receiver_closed = false;
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
            let InboundRequestPhase::AwaitingDelivery { path, body } = state.phase else {
                events.inbound_requests.insert(request, state);
                continue;
            };
            let incoming = IncomingRequest {
                link: LinkId(link),
                id: IncomingRequestId(request),
                path,
                body,
                commands: commands.clone(),
            };
            match events.events.push(LinkEvent::Request(incoming), 0) {
                Ok(()) => {
                    events.inbound_requests.insert(
                        request,
                        InboundRequestState {
                            phase: InboundRequestPhase::AwaitingResponse,
                        },
                    );
                }
                Err(EventPushError::Full(LinkEvent::Request(incoming))) => {
                    events.inbound_requests.insert(
                        request,
                        InboundRequestState {
                            phase: InboundRequestPhase::AwaitingDelivery {
                                path: incoming.path,
                                body: incoming.body,
                            },
                        },
                    );
                    events.requests_awaiting_delivery.push_front(request);
                    break;
                }
                Err(EventPushError::Closed(_)) => {
                    receiver_closed = true;
                    break;
                }
                Err(EventPushError::Full(_)) => unreachable!(),
            }
        }
        if receiver_closed {
            self.close_protocol_link(link, LinkCloseReason::CapacityReached);
        }
    }

    fn expire_timers(&mut self, now: MonoTime) {
        for _ in 0..64 {
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
                    if matches!(
                        state.map(|state| state.phase),
                        Some(InboundRequestPhase::AwaitingDelivery { .. })
                    ) {
                        self.close_protocol_link(link, LinkCloseReason::CapacityReached);
                    }
                }
                TimerEvent::Shutdown => {
                    if let NodePhase::Closing {
                        deadline_expired, ..
                    } = &mut self.phase
                    {
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
                if self.interfaces.len() >= self.config.limits.maximum_interfaces {
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
                if self.services.iter().flatten().count() >= self.config.limits.maximum_services {
                    let _ = reply.send(Err(NodeError::CapacityReached));
                    return;
                }
                let destination = identity.destination(&name);
                let path_values: Vec<_> = paths.iter().map(|path| path.as_str()).collect();
                let events = Events::new(self.config.limits.event_capacity, 0);
                let id = self.add_service(
                    name.as_str(),
                    &path_values,
                    &identity,
                    restart_ratchet,
                    events,
                );
                let commands = self
                    .command_handles
                    .upgrade()
                    .expect("command sender disappeared while registering service");
                let lifecycle = self
                    .lifecycle_handles
                    .upgrade()
                    .expect("lifecycle sender disappeared while registering service");
                let _ = reply.send(Ok(Service {
                    id,
                    destination,
                    commands,
                    _drop_notice: DropNotice::new(lifecycle, DroppedResource::Service(id)),
                }));
            }
            Command::ReceiveService { service, reply } => {
                if let Some(service) = self.services.get_mut(service.0).and_then(Option::as_mut) {
                    service.events.receive(reply);
                } else {
                    let _ = reply.send(Err(ServiceReceiveError::ServiceClosed));
                }
            }
            Command::Announce {
                service,
                application_data: data,
                ratchet,
                reply,
            } => {
                let has_ratchet = matches!(ratchet, RatchetAction::Rotate)
                    || self.services[service.0]
                        .as_ref()
                        .is_some_and(|service| !service.ratchets.is_empty());
                if self.interfaces.iter().all(|slot| !slot.accepting()) {
                    let _ = reply.send(Err(AnnounceError::NoUsableInterface));
                } else if has_ratchet && data.len() > 301 {
                    let _ = reply.send(Err(AnnounceError::ApplicationDataTooLarge));
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
                        let _ = reply.send(Err(AnnounceError::InterfaceBusy));
                    }
                } else {
                    let _ = reply.send(Err(AnnounceError::InterfaceFailed));
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
                } else if self.can_wait_for_route() {
                    self.route_waits
                        .entry(destination)
                        .or_default()
                        .push(PendingRoute::Send { body, reply });
                    self.request_path(destination, now);
                } else {
                    let _ = reply.send(Err(SendError::CapacityReached));
                }
            }
            Command::OpenLink { destination, reply } => {
                let destination = destination.into_bytes();
                if self.has_path(destination) {
                    self.open_link(destination, reply, now);
                } else if self.can_wait_for_route() {
                    self.route_waits
                        .entry(destination)
                        .or_default()
                        .push(PendingRoute::OpenLink { reply });
                    self.request_path(destination, now);
                } else {
                    let _ = reply.send(Err(LinkError::CapacityReached));
                }
            }
            Command::AcceptLink { offer, reply } => {
                if self.established_links.len() >= self.config.limits.maximum_links {
                    let _ = reply.send(Err(LinkError::CapacityReached));
                } else if self.accept_incoming_link(offer.0, now) {
                    let events = LinkEvents::new(self.config.limits.event_capacity);
                    self.established_links
                        .get_mut(&offer.0)
                        .expect("accepted link disappeared")
                        .events = Some(events);
                    let commands = self
                        .command_handles
                        .upgrade()
                        .expect("command sender disappeared while accepting link");
                    let lifecycle = self
                        .lifecycle_handles
                        .upgrade()
                        .expect("lifecycle sender disappeared while accepting link");
                    let _ = reply.send(Ok(Link {
                        sender: LinkSender {
                            id: LinkId(offer.0),
                            commands,
                        },
                        _drop_notice: DropNotice::new(
                            lifecycle,
                            DroppedResource::Link(LinkId(offer.0)),
                        ),
                    }));
                } else {
                    let _ = reply.send(Err(LinkError::Rejected));
                }
            }
            Command::RejectLink { offer, reply } => {
                let result = self
                    .reject_incoming_link(offer.0)
                    .then_some(())
                    .ok_or(LinkError::Rejected);
                let _ = reply.send(result);
            }
            Command::CloseLink { link, reply } => {
                self.finish_link_close(link.0, LinkCloseReason::LocalClosed);
                if let Some(requests) = self.close_link(link.0) {
                    self.fail_outbound_requests(requests, LinkError::LinkClosed);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(LinkError::LinkClosed));
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
                    let _ = reply.send(Err(LinkReceiveError::LinkClosed(
                        LinkCloseReason::LocalClosed,
                    )));
                }
            }
            Command::SendLinkDatagram { link, body, reply } => {
                let result = match self.prepare_link_datagram(link.0, &body) {
                    Ok(outbound) => match self.admit_outbound(&outbound) {
                        Ok(()) => Ok(()),
                        Err(error) => Err(error.link()),
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
                        self.pending_requests.insert(request.0, reply);
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error.link()));
                    }
                },
                Err(_) => {
                    let _ = reply.send(Err(LinkError::LinkClosed));
                }
            },
            Command::Respond {
                link,
                request,
                response,
                reply,
            } => {
                let ready = self
                    .established_links
                    .get(&link.0)
                    .and_then(|link| link.events.as_ref())
                    .is_some_and(|events| {
                        matches!(
                            events
                                .inbound_requests
                                .get(&request.0)
                                .map(|state| &state.phase),
                            Some(InboundRequestPhase::AwaitingResponse)
                        )
                    });
                let result = if !ready {
                    Err(
                        if self
                            .established_links
                            .get(&link.0)
                            .is_some_and(|link| link.events.is_some())
                        {
                            LinkError::TimedOut
                        } else {
                            LinkError::LinkClosed
                        },
                    )
                } else {
                    match self.prepare_response(
                        link.0,
                        crate::WireRequestId(request.0),
                        &response,
                        None,
                        true,
                    ) {
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
                            Err(error) => Err(error.link()),
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
                        Err(OutboundAdmissionError::Busy) => Err(IdentifyError::InterfaceBusy),
                        Err(OutboundAdmissionError::InterfaceFailed) => {
                            Err(IdentifyError::InterfaceFailed)
                        }
                    };
                    let _ = reply.send(result);
                }
                Err(error) => {
                    let _ = reply.send(Err(error));
                }
            },
            Command::OpenChannel { link, reply } => match self.open_channel(link.0) {
                Ok(()) => {
                    let capacity = self.config.limits.channel_queue_capacity;
                    let events = Events::new(capacity, capacity * crate::buffer::MAX_INPUT_BYTES);
                    self.established_links
                        .get_mut(&link.0)
                        .expect("opened channel link disappeared")
                        .channel = Some(RuntimeChannel {
                        protocol: crate::channel::ChannelState::new(),
                        events,
                        waiting_sends: VecDeque::new(),
                        outgoing_streams: HashSet::new(),
                        ended_incoming_streams: HashSet::new(),
                        delivery_replies: HashMap::new(),
                    });
                    let commands = self
                        .command_handles
                        .upgrade()
                        .expect("command sender disappeared while opening channel");
                    let lifecycle = self
                        .lifecycle_handles
                        .upgrade()
                        .expect("lifecycle sender disappeared while opening channel");
                    let _ = reply.send(Ok(Channel {
                        sender: ChannelSender { link, commands },
                        _drop_notice: DropNotice::new(lifecycle, DroppedResource::Channel(link)),
                    }));
                }
                Err(QueueChannelError::AlreadyOpen) => {
                    let _ = reply.send(Err(ChannelError::AlreadyOpen));
                }
                Err(QueueChannelError::LinkNotFound | QueueChannelError::LinkNotActive) => {
                    let _ = reply.send(Err(ChannelError::LinkClosed));
                }
                Err(QueueChannelError::WindowFull) => unreachable!(),
            },
            Command::ReceiveChannel { link, reply } => {
                if let Some(channel) = self
                    .established_links
                    .get_mut(&link.0)
                    .and_then(|link| link.channel.as_mut())
                {
                    channel.events.receive(reply);
                } else {
                    let _ = reply.send(Err(ChannelReceiveError::ChannelClosed));
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
                        .delivery_replies
                        .insert(packet, reply);
                }
                Err(QueueChannelError::WindowFull) => {
                    self.wait_for_reliable(
                        link.0,
                        WaitingChannelOperation::Message { message, reply },
                    );
                }
                Err(QueueChannelError::LinkNotFound | QueueChannelError::LinkNotActive) => {
                    let _ = reply.send(Err(ChannelError::LinkClosed));
                }
                Err(QueueChannelError::AlreadyOpen) => unreachable!(),
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
                    let _ = reply.send(Err(BufferError::Channel(ChannelError::ChannelClosed)));
                    return;
                };
                if !channel.outgoing_streams.insert(stream) {
                    let _ = reply.send(Err(BufferError::StreamAlreadyOpen));
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
                self.queue_buffer(link, stream, input, false, reply, now);
            }
            Command::FinishBuffer {
                link,
                stream,
                input,
                reply,
            } => {
                self.queue_buffer(link, stream, input, true, reply, now);
            }
            Command::Shutdown => self.begin_shutdown(ShutdownReason::Requested, now),
        }
    }

    fn can_wait_for_route(&self) -> bool {
        self.route_waits.values().map(Vec::len).sum::<usize>() < self.config.limits.command_capacity
    }

    pub(crate) fn at_link_capacity(&self) -> bool {
        self.pending_outbound_links.len()
            + self.pending_inbound_links.len()
            + self.established_links.len()
            >= self.config.limits.maximum_links
    }

    fn send_destination(
        &mut self,
        destination: [u8; 16],
        body: Bytes,
        reply: oneshot::Sender<Result<(), SendError>>,
    ) {
        let result = match self.prepare_destination_datagram(destination, &body) {
            Ok(outbound) => match self.admit_outbound(&outbound) {
                Ok(()) => Ok(()),
                Err(OutboundAdmissionError::Busy) => Err(SendError::InterfaceBusy),
                Err(OutboundAdmissionError::InterfaceFailed) => Err(SendError::InterfaceFailed),
            },
            Err(error) => Err(error),
        };
        let _ = reply.send(result);
    }

    fn open_link(
        &mut self,
        destination: [u8; 16],
        reply: oneshot::Sender<Result<Link, LinkError>>,
        now: MonoTime,
    ) {
        if reply.is_canceled() {
            return;
        }
        if self.at_link_capacity() {
            let _ = reply.send(Err(LinkError::CapacityReached));
        } else if self.interfaces.iter().all(|slot| !slot.accepting()) {
            let _ = reply.send(Err(LinkError::InterfaceFailed));
        } else {
            let events = LinkEvents::new(self.config.limits.event_capacity);
            self.link(
                None,
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
        if !slot.accepting() || packet.len() > slot.limits.maximum_packet_bytes {
            return Err(OutboundAdmissionError::InterfaceFailed);
        }
        slot.admit(outbound.priority, packet)
            .map_err(|_| OutboundAdmissionError::Busy)?;
        Ok(())
    }

    fn queue_buffer(
        &mut self,
        link: LinkId,
        stream: StreamId,
        input: bytes::Bytes,
        finish: bool,
        reply: oneshot::Sender<Result<BufferQueued, BufferError>>,
        now: MonoTime,
    ) {
        if !self
            .established_links
            .get(&link.0)
            .and_then(|link| link.channel.as_ref())
            .is_some_and(|channel| channel.outgoing_streams.contains(&stream))
        {
            let _ = reply.send(Err(BufferError::Channel(ChannelError::ChannelClosed)));
            return;
        }
        let (raw, input_bytes) = crate::buffer::encode(stream, &input, finish);
        let end_queued = finish && input_bytes == input.len();
        match self.send_buffer_data(link.0, &raw, now) {
            Ok(_) => {
                if end_queued {
                    self.established_links
                        .get_mut(&link.0)
                        .and_then(|link| link.channel.as_mut())
                        .expect("channel disappeared")
                        .outgoing_streams
                        .remove(&stream);
                }
                let _ = reply.send(Ok(BufferQueued {
                    input_bytes,
                    end_queued,
                }));
            }
            Err(QueueChannelError::WindowFull) => {
                self.wait_for_reliable(
                    link.0,
                    WaitingChannelOperation::Buffer {
                        stream,
                        input,
                        finish,
                        reply,
                    },
                );
            }
            Err(QueueChannelError::LinkNotFound | QueueChannelError::LinkNotActive) => {
                let _ = reply.send(Err(BufferError::Channel(ChannelError::LinkClosed)));
            }
            Err(QueueChannelError::AlreadyOpen) => unreachable!(),
        }
    }

    fn retry_reliable(&mut self, link: [u8; 16], now: MonoTime) {
        let Some(channel) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
        else {
            return;
        };
        let count = channel.waiting_sends.len().min(32);
        let waiting = channel.waiting_sends.drain(..count).collect::<Vec<_>>();
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
                WaitingChannelOperation::Buffer {
                    stream,
                    input,
                    finish,
                    reply,
                } => self.queue_buffer(LinkId(link), stream, input, finish, reply, now),
            }
        }
    }

    pub(crate) fn complete_channel_send(
        &mut self,
        link: [u8; 16],
        packet: [u8; 32],
        delivered: bool,
        now: MonoTime,
    ) {
        let reply = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
            .and_then(|channel| channel.delivery_replies.remove(&packet));
        if let Some(reply) = reply {
            let _ = reply.send(if delivered {
                Ok(())
            } else {
                Err(ChannelError::RetryLimitReached)
            });
            if delivered {
                self.retry_reliable(link, now);
            }
        }
    }

    pub(crate) fn deliver_link_datagram(&mut self, link: [u8; 16], data: Vec<u8>) {
        let delivered = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
            .is_some_and(|events| {
                events
                    .events
                    .push(LinkEvent::Datagram(data.into()), 0)
                    .is_ok()
            });
        if !delivered {
            self.close_protocol_link(link, LinkCloseReason::CapacityReached);
        }
    }

    pub(crate) fn deliver_incoming_link(&mut self, service: ServiceId, link: [u8; 16]) {
        let Some(commands) = self.command_handles.upgrade() else {
            self.reject_incoming_link(link);
            return;
        };
        let incoming = IncomingLink {
            offer: LinkOfferId(link),
            commands,
        };
        let delivered = self
            .services
            .get_mut(service.0)
            .and_then(Option::as_mut)
            .is_some_and(|service| {
                service
                    .events
                    .push(ServiceEvent::IncomingLink(incoming), 0)
                    .is_ok()
            });
        if !delivered {
            self.reject_incoming_link(link);
        }
    }

    pub(crate) fn finish_link_establishment(
        &mut self,
        link: [u8; 16],
        pending: PendingOpenLink,
        result: Result<(), LinkError>,
    ) {
        if let Err(error) = result {
            let _ = pending.reply.send(Err(error));
            return;
        }
        self.established_links
            .get_mut(&link)
            .expect("established link disappeared")
            .events = Some(pending.events);
        if let Some(commands) = self.command_handles.upgrade() {
            let lifecycle = self
                .lifecycle_handles
                .upgrade()
                .expect("lifecycle sender disappeared while opening link");
            let _ = pending.reply.send(Ok(Link {
                sender: LinkSender {
                    id: LinkId(link),
                    commands,
                },
                _drop_notice: DropNotice::new(lifecycle, DroppedResource::Link(LinkId(link))),
            }));
        } else {
            self.close_protocol_link(link, LinkCloseReason::LocalClosed);
        }
    }

    pub(crate) fn finish_request(
        &mut self,
        request: crate::RequestId,
        result: Result<(Vec<u8>, Option<Vec<u8>>), LinkError>,
    ) {
        if let Some(reply) = self.pending_requests.remove(&request.0) {
            let result = result.map(|(data, _)| data.into());
            let _ = reply.send(result);
        }
    }

    pub(crate) fn receive_request(
        &mut self,
        link: [u8; 16],
        request: crate::RequestId,
        path: String,
        data: Vec<u8>,
        now: MonoTime,
    ) {
        let Ok(path) = RequestPath::new(path) else {
            return;
        };
        let Some(events) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
        else {
            return;
        };
        if events.inbound_requests.len() >= self.config.limits.event_capacity
            || events.inbound_requests.contains_key(&request.0)
        {
            self.close_protocol_link(link, LinkCloseReason::CapacityReached);
            return;
        }
        let deadline = now
            .checked_add(REQUEST_TIMEOUT)
            .expect("inbound request deadline overflow");
        events.inbound_requests.insert(
            request.0,
            InboundRequestState {
                phase: InboundRequestPhase::AwaitingDelivery {
                    path,
                    body: data.into(),
                },
            },
        );
        events.requests_awaiting_delivery.push_back(request.0);
        self.timers
            .schedule_inbound_request(deadline, link, request.0);
        self.deliver_waiting_request(link);
    }

    pub(crate) fn finish_link_identification(
        &mut self,
        link: [u8; 16],
        identity: Result<[u8; 16], LinkCloseReason>,
    ) {
        let identity = match identity {
            Ok(identity) => identity,
            Err(reason) => {
                self.close_protocol_link(link, reason);
                return;
            }
        };
        let delivered = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.as_mut())
            .is_some_and(|events| {
                events
                    .events
                    .push(LinkEvent::Identified(IdentityHash::from_bytes(identity)), 0)
                    .is_ok()
            });
        if delivered {
            self.commit_remote_identity(link, identity);
        } else {
            self.close_protocol_link(link, LinkCloseReason::CapacityReached);
        }
    }

    pub(crate) fn resolve_route(&mut self, destination: [u8; 16], found: bool, now: MonoTime) {
        if let Some(waiters) = self.route_waits.remove(&destination) {
            for waiter in waiters {
                match waiter {
                    PendingRoute::Send { body, reply } => {
                        if found {
                            self.send_destination(destination, body, reply);
                        } else {
                            let _ = reply.send(Err(SendError::NoRoute));
                        }
                    }
                    PendingRoute::OpenLink { reply } => {
                        if found {
                            self.open_link(destination, reply, now);
                        } else {
                            let _ = reply.send(Err(LinkError::NoRoute));
                        }
                    }
                }
            }
        }
    }

    fn wait_for_reliable(&mut self, link: [u8; 16], operation: WaitingChannelOperation) {
        let Some(channel) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
        else {
            Self::fail_waiting(operation, ChannelError::ChannelClosed);
            return;
        };
        if channel.waiting_sends.len() < self.config.limits.channel_queue_capacity {
            channel.waiting_sends.push_back(operation);
            return;
        }
        Self::fail_waiting(operation, ChannelError::CapacityReached);
    }

    fn fail_waiting(operation: WaitingChannelOperation, error: ChannelError) {
        match operation {
            WaitingChannelOperation::Message { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            WaitingChannelOperation::Buffer { reply, .. } => {
                let _ = reply.send(Err(BufferError::Channel(error)));
            }
        }
    }

    pub(crate) fn close_protocol_link(&mut self, link: [u8; 16], reason: LinkCloseReason) {
        self.finish_link_close(link, reason);
        if let Some(requests) = self.close_link(link) {
            self.fail_outbound_requests(requests, LinkError::LinkClosed);
        }
    }

    pub(crate) fn finish_link_close(&mut self, link: [u8; 16], reason: LinkCloseReason) {
        if let Some(mut events) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.events.take())
        {
            for request in events.inbound_requests.keys() {
                self.timers.cancel_inbound_request(link, *request);
            }
            events
                .events
                .terminate(LinkReceiveError::LinkClosed(reason));
        }
        self.close_runtime_channel(link, ChannelReceiveError::LinkClosed);
    }

    fn fail_outbound_requests(
        &mut self,
        requests: impl IntoIterator<Item = crate::RequestId>,
        error: LinkError,
    ) {
        for request in requests {
            if let Some(reply) = self.pending_requests.remove(&request.0) {
                let _ = reply.send(Err(error));
            }
        }
    }

    pub(crate) fn close_runtime_channel(&mut self, link: [u8; 16], reason: ChannelReceiveError) {
        if let Some(mut channel) = self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.take())
        {
            channel.events.terminate(reason);
            while let Some(operation) = channel.waiting_sends.pop_front() {
                Self::fail_waiting(operation, ChannelError::ChannelClosed);
            }
            for (_, reply) in channel.delivery_replies.drain() {
                let _ = reply.send(Err(ChannelError::ChannelClosed));
            }
        }
    }

    pub(crate) fn deliver_channel_receive(&mut self, link: [u8; 16], item: ChannelReceive) {
        if let ChannelReceive::Buffer { stream, chunk } = &item {
            let Some(channel) = self
                .established_links
                .get_mut(&link)
                .and_then(|link| link.channel.as_mut())
            else {
                self.close_protocol_link(link, LinkCloseReason::ProtocolViolation);
                return;
            };
            if channel.ended_incoming_streams.contains(stream) {
                self.close_protocol_link(link, LinkCloseReason::ProtocolViolation);
                return;
            }
            if matches!(chunk, BufferChunk::End(_)) {
                channel.ended_incoming_streams.insert(*stream);
            }
        }
        let bytes = match &item {
            ChannelReceive::Message(message) => message.body().len(),
            ChannelReceive::Buffer { chunk, .. } => match chunk {
                BufferChunk::Data(data) | BufferChunk::End(data) => data.len(),
            },
        };
        if !self
            .established_links
            .get_mut(&link)
            .and_then(|link| link.channel.as_mut())
            .is_some_and(|channel| channel.events.push(item, bytes).is_ok())
        {
            self.close_protocol_link(link, LinkCloseReason::ProtocolViolation);
        }
    }

    fn begin_shutdown(&mut self, reason: ShutdownReason, now: MonoTime) {
        if !matches!(self.phase, NodePhase::Running) {
            return;
        }
        if let Some(commands) = self.commands.take() {
            commands.close();
            while commands.try_recv().is_ok() {}
        }
        for service in self.services.iter_mut().flatten() {
            service.events.terminate(ServiceReceiveError::ServiceClosed);
        }
        let links = self
            .established_links
            .iter()
            .filter_map(|(id, link)| link.events.is_some().then_some(*id))
            .collect::<Vec<_>>();
        for link in &links {
            self.finish_link_close(*link, LinkCloseReason::LocalClosed);
            if let Some(requests) = self.close_link(*link) {
                self.fail_outbound_requests(requests, LinkError::NodeStopping);
            }
        }
        for slot in &mut self.interfaces {
            slot.begin_close();
        }
        let deadline = now
            .checked_add(SHUTDOWN_GRACE)
            .expect("shutdown deadline overflow");
        self.timers.schedule_shutdown(deadline);
        self.phase = NodePhase::Closing {
            reason,
            links: links.len(),
            deadline_expired: false,
        };
    }

    fn shutdown_if_complete(&mut self) -> Option<ShutdownReport> {
        let NodePhase::Closing {
            reason,
            links,
            deadline_expired,
        } = self.phase
        else {
            return None;
        };
        let complete = self.preparing.load(Ordering::Acquire) == 0
            && self
                .interfaces
                .iter()
                .all(|slot| matches!(slot.phase, InterfacePhase::Closed));
        if !complete && !deadline_expired {
            return None;
        }
        let reason = if complete {
            reason
        } else {
            ShutdownReason::DeadlineExpired
        };
        let report = ShutdownReport {
            reason,
            links_closed: if complete { links } else { 0 },
            links_abandoned: if complete { 0 } else { links },
            interfaces_closed: self.interfaces.len() - self.interfaces_failed,
            interfaces_failed: self.interfaces_failed,
        };
        if let Some(shutdown) = self.shutdown_tx.take() {
            let _ = shutdown.send(report.clone());
        }
        Some(report)
    }
}
