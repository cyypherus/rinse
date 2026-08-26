use bytes::Bytes;
use futures_channel::oneshot;
use std::sync::Arc;

use crate::PrivateIdentity;
use crate::interface::{AttachedInterface, Interface};
use crate::model::*;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ServiceId(pub(crate) usize);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct LinkId(pub(crate) [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct LinkOfferId(pub(crate) [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct IncomingRequestId(pub(crate) [u8; 16]);

type Reply<T> = oneshot::Sender<T>;

pub(crate) enum Command {
    AttachInterface {
        interface: AttachedInterface,
        limits: InterfaceLimits,
        reply: Reply<Result<(), NodeError>>,
    },
    GenerateIdentity {
        reply: Reply<Result<PrivateIdentity, NodeError>>,
    },
    RegisterService {
        config: Box<ServiceConfig>,
        reply: Reply<Result<Service, NodeError>>,
    },
    ReceiveService {
        service: ServiceId,
        reply: Reply<Result<ServiceEvent, ServiceReceiveError>>,
    },
    Announce {
        service: ServiceId,
        application_data: Bytes,
        ratchet: RatchetAction,
        reply: Reply<Result<Option<RatchetSecret>, AnnounceError>>,
    },
    SendDestination {
        destination: Destination,
        body: Bytes,
        reply: Reply<Result<(), SendError>>,
    },
    OpenLink {
        destination: Destination,
        reply: Reply<Result<Link, LinkError>>,
    },
    AcceptLink {
        offer: LinkOfferId,
        reply: Reply<Result<Link, LinkError>>,
    },
    RejectLink {
        offer: LinkOfferId,
        reply: Reply<Result<(), LinkError>>,
    },
    CloseLink {
        link: LinkId,
        reply: Reply<Result<(), LinkError>>,
    },
    ReceiveLink {
        link: LinkId,
        reply: Reply<Result<LinkEvent, LinkReceiveError>>,
    },
    SendLinkDatagram {
        link: LinkId,
        body: Bytes,
        reply: Reply<Result<(), LinkError>>,
    },
    Request {
        link: LinkId,
        path: RequestPath,
        body: Bytes,
        reply: Reply<Result<Bytes, LinkError>>,
    },
    Respond {
        link: LinkId,
        request: IncomingRequestId,
        response: Bytes,
        reply: Reply<Result<(), LinkError>>,
    },
    Identify {
        link: LinkId,
        service: ServiceId,
        reply: Reply<Result<(), IdentifyError>>,
    },
    OpenChannel {
        link: LinkId,
        reply: Reply<Result<Channel, ChannelError>>,
    },
    ReceiveChannel {
        link: LinkId,
        reply: Reply<Result<ChannelReceive, ChannelReceiveError>>,
    },
    SendChannel {
        link: LinkId,
        message: ChannelMessage,
        reply: Reply<Result<(), ChannelError>>,
    },
    OpenBuffer {
        link: LinkId,
        stream: StreamId,
        reply: Reply<Result<(), BufferError>>,
    },
    WriteBuffer {
        link: LinkId,
        stream: StreamId,
        input: Bytes,
        reply: Reply<Result<BufferQueued, BufferError>>,
    },
    FinishBuffer {
        link: LinkId,
        stream: StreamId,
        input: Bytes,
        reply: Reply<Result<BufferQueued, BufferError>>,
    },
    Shutdown,
}

async fn ask<T>(
    commands: &async_channel::Sender<Command>,
    command: impl FnOnce(Reply<T>) -> Command,
) -> Option<T> {
    let (reply, result) = oneshot::channel();
    commands.send(command(reply)).await.ok()?;
    result.await.ok()
}

#[derive(Clone, Copy)]
pub(crate) enum DroppedResource {
    Service(ServiceId),
    Link(LinkId),
    Channel(LinkId),
}

pub(crate) struct DropNotice {
    lifecycle: async_channel::Sender<DroppedResource>,
    dropped: DroppedResource,
}

impl DropNotice {
    pub(crate) fn new(
        lifecycle: async_channel::Sender<DroppedResource>,
        dropped: DroppedResource,
    ) -> Self {
        Self { lifecycle, dropped }
    }
}

impl Drop for DropNotice {
    fn drop(&mut self) {
        match self.lifecycle.try_send(self.dropped) {
            Ok(()) | Err(async_channel::TrySendError::Closed(_)) => {}
            Err(async_channel::TrySendError::Full(_)) => {
                unreachable!("lifecycle capacity covers every live resource")
            }
        }
    }
}

pub(crate) type ShutdownFuture =
    futures_util::future::Shared<futures_util::future::BoxFuture<'static, ShutdownReport>>;

#[derive(Clone)]
pub struct NodeHandle {
    pub(crate) commands: async_channel::Sender<Command>,
    pub(crate) _resource_lifecycle: async_channel::Sender<DroppedResource>,
    pub(crate) shutdown: ShutdownFuture,
}

impl NodeHandle {
    pub const MAX_DATAGRAM_BYTES: usize = 383;

    pub async fn attach_interface<I>(
        &self,
        interface: I,
        limits: InterfaceLimits,
    ) -> Result<(), NodeError>
    where
        I: Interface + Send + 'static,
    {
        ask(&self.commands, |reply| Command::AttachInterface {
            interface: Arc::new(interface),
            limits,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn generate_identity(&self) -> Result<PrivateIdentity, NodeError> {
        ask(&self.commands, |reply| Command::GenerateIdentity { reply })
            .await
            .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn register_service(&self, config: ServiceConfig) -> Result<Service, NodeError> {
        ask(&self.commands, |reply| Command::RegisterService {
            config: Box::new(config),
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn send(&self, destination: Destination, body: Bytes) -> Result<(), SendError> {
        if body.len() > Self::MAX_DATAGRAM_BYTES {
            return Err(SendError::PayloadTooLarge);
        }
        ask(&self.commands, |reply| Command::SendDestination {
            destination,
            body,
            reply,
        })
        .await
        .unwrap_or(Err(SendError::NodeStopping))
    }

    pub async fn open_link(&self, destination: Destination) -> Result<Link, LinkError> {
        ask(&self.commands, |reply| Command::OpenLink {
            destination,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }

    pub async fn shutdown(&self) -> ShutdownReport {
        let _ = self.commands.send(Command::Shutdown).await;
        self.shutdown.clone().await
    }
}

pub struct Service {
    pub(crate) id: ServiceId,
    pub(crate) destination: Destination,
    pub(crate) commands: async_channel::Sender<Command>,
    pub(crate) _drop_notice: DropNotice,
}

impl Service {
    pub const MAX_ANNOUNCEMENT_BYTES: usize = 333;
    pub const MAX_RATCHET_ANNOUNCEMENT_BYTES: usize = 301;

    pub const fn destination(&self) -> Destination {
        self.destination
    }

    pub async fn announce(
        &self,
        application_data: Bytes,
        ratchet: RatchetAction,
    ) -> Result<Option<RatchetSecret>, AnnounceError> {
        if application_data.len() > Self::MAX_ANNOUNCEMENT_BYTES {
            return Err(AnnounceError::ApplicationDataTooLarge);
        }
        ask(&self.commands, |reply| Command::Announce {
            service: self.id,
            application_data,
            ratchet,
            reply,
        })
        .await
        .unwrap_or(Err(AnnounceError::NodeStopping))
    }

    pub async fn receive(&mut self) -> Result<ServiceEvent, ServiceReceiveError> {
        ask(&self.commands, |reply| Command::ReceiveService {
            service: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(ServiceReceiveError::NodeStopped))
    }
}

pub enum ServiceEvent {
    Announce(DiscoveredService),
    Datagram(Bytes),
    IncomingLink(IncomingLink),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredService {
    pub(crate) destination: Destination,
    pub(crate) service_hash: crate::ServiceHash,
    pub(crate) application_data: Bytes,
}

impl DiscoveredService {
    pub const fn destination(&self) -> Destination {
        self.destination
    }
    pub const fn service_hash(&self) -> crate::ServiceHash {
        self.service_hash
    }
    pub fn application_data(&self) -> &[u8] {
        &self.application_data
    }
}

pub struct IncomingLink {
    pub(crate) offer: LinkOfferId,
    pub(crate) commands: async_channel::Sender<Command>,
}

impl IncomingLink {
    pub async fn accept(self) -> Result<Link, LinkError> {
        ask(&self.commands, |reply| Command::AcceptLink {
            offer: self.offer,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }

    pub async fn reject(self) -> Result<(), LinkError> {
        ask(&self.commands, |reply| Command::RejectLink {
            offer: self.offer,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }
}

pub struct Link {
    pub(crate) sender: LinkSender,
    pub(crate) _drop_notice: DropNotice,
}

impl Link {
    pub fn send_handle(&self) -> LinkSender {
        self.sender.clone()
    }

    pub async fn receive(&mut self) -> Result<LinkEvent, LinkReceiveError> {
        ask(&self.sender.commands, |reply| Command::ReceiveLink {
            link: self.sender.id,
            reply,
        })
        .await
        .unwrap_or(Err(LinkReceiveError::NodeStopped))
    }

    pub async fn close(self) -> Result<(), LinkError> {
        ask(&self.sender.commands, |reply| Command::CloseLink {
            link: self.sender.id,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }
}

#[derive(Clone)]
pub struct LinkSender {
    pub(crate) id: LinkId,
    pub(crate) commands: async_channel::Sender<Command>,
}

impl LinkSender {
    pub const MAX_DATAGRAM_BYTES: usize = crate::node::LINK_MDU;
    pub const MAX_REQUEST_BODY_BYTES: usize = 400;

    pub async fn send(&self, body: Bytes) -> Result<(), LinkError> {
        if body.len() > Self::MAX_DATAGRAM_BYTES {
            return Err(LinkError::PayloadTooLarge);
        }
        ask(&self.commands, |reply| Command::SendLinkDatagram {
            link: self.id,
            body,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }

    pub async fn request(&self, path: RequestPath, body: Bytes) -> Result<Bytes, LinkError> {
        if body.len() > Self::MAX_REQUEST_BODY_BYTES {
            return Err(LinkError::PayloadTooLarge);
        }
        ask(&self.commands, |reply| Command::Request {
            link: self.id,
            path,
            body,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }

    pub async fn open_channel(&self) -> Result<Channel, ChannelError> {
        ask(&self.commands, |reply| Command::OpenChannel {
            link: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(ChannelError::NodeStopping))
    }
}

impl Service {
    pub async fn identify_on(&self, link: &LinkSender) -> Result<(), IdentifyError> {
        if !self.commands.same_channel(&link.commands) {
            return Err(IdentifyError::DifferentNode);
        }
        ask(&self.commands, |reply| Command::Identify {
            link: link.id,
            service: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(IdentifyError::NodeStopping))
    }
}

pub enum LinkEvent {
    Identified(IdentityHash),
    Datagram(Bytes),
    Request(IncomingRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkCloseReason {
    LocalClosed,
    RemoteClosed,
    IdleTimeout,
    AuthenticationFailed,
    InterfaceFailed,
    CapacityReached,
    ProtocolViolation,
}

pub struct IncomingRequest {
    pub(crate) link: LinkId,
    pub(crate) id: IncomingRequestId,
    pub(crate) path: RequestPath,
    pub(crate) body: Bytes,
    pub(crate) commands: async_channel::Sender<Command>,
}

impl IncomingRequest {
    pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

    pub fn path(&self) -> &RequestPath {
        &self.path
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub async fn respond(self, response: Bytes) -> Result<(), LinkError> {
        if response.len() > Self::MAX_RESPONSE_BYTES {
            return Err(LinkError::PayloadTooLarge);
        }
        ask(&self.commands, |reply| Command::Respond {
            link: self.link,
            request: self.id,
            response,
            reply,
        })
        .await
        .unwrap_or(Err(LinkError::NodeStopping))
    }
}

pub struct Channel {
    pub(crate) sender: ChannelSender,
    pub(crate) _drop_notice: DropNotice,
}

impl Channel {
    pub fn send_handle(&self) -> ChannelSender {
        self.sender.clone()
    }
    pub async fn receive(&mut self) -> Result<ChannelReceive, ChannelReceiveError> {
        ask(&self.sender.commands, |reply| Command::ReceiveChannel {
            link: self.sender.link,
            reply,
        })
        .await
        .unwrap_or(Err(ChannelReceiveError::NodeStopped))
    }
}

#[derive(Clone)]
pub struct ChannelSender {
    pub(crate) link: LinkId,
    pub(crate) commands: async_channel::Sender<Command>,
}

impl ChannelSender {
    pub async fn send(&self, message: ChannelMessage) -> Result<(), ChannelError> {
        ask(&self.commands, |reply| Command::SendChannel {
            link: self.link,
            message,
            reply,
        })
        .await
        .unwrap_or(Err(ChannelError::NodeStopping))
    }

    pub async fn open_buffer(&self, stream: StreamId) -> Result<BufferSender, BufferError> {
        ask(&self.commands, |reply| Command::OpenBuffer {
            link: self.link,
            stream,
            reply,
        })
        .await
        .unwrap_or(Err(BufferError::Channel(ChannelError::NodeStopping)))?;
        Ok(BufferSender {
            link: self.link,
            stream,
            commands: self.commands.clone(),
        })
    }
}

pub enum ChannelReceive {
    Message(ChannelMessage),
    Buffer {
        stream: StreamId,
        chunk: BufferChunk,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BufferChunk {
    Data(Bytes),
    End(Bytes),
}

pub struct BufferSender {
    link: LinkId,
    stream: StreamId,
    commands: async_channel::Sender<Command>,
}

impl BufferSender {
    pub async fn write(&mut self, input: Bytes) -> Result<usize, BufferError> {
        if input.is_empty() {
            return Err(BufferError::EmptyInput);
        }
        if input.len() > crate::buffer::MAX_INPUT_BYTES {
            return Err(BufferError::InputTooLarge);
        }
        ask(&self.commands, |reply| Command::WriteBuffer {
            link: self.link,
            stream: self.stream,
            input,
            reply,
        })
        .await
        .unwrap_or(Err(BufferError::Channel(ChannelError::NodeStopping)))
        .map(|queued| queued.input_bytes)
    }

    pub async fn finish(self, input: Bytes) -> Result<usize, BufferError> {
        if input.len() > crate::buffer::MAX_INPUT_BYTES {
            return Err(BufferError::InputTooLarge);
        }
        let mut queued = 0;
        while queued < input.len() {
            let remaining = input.slice(queued..);
            let result = ask(&self.commands, |reply| Command::FinishBuffer {
                link: self.link,
                stream: self.stream,
                input: remaining,
                reply,
            })
            .await
            .unwrap_or(Err(BufferError::Channel(ChannelError::NodeStopping)))?;
            queued += result.input_bytes;
            if result.end_queued {
                return Ok(queued);
            }
        }
        let result = ask(&self.commands, |reply| Command::FinishBuffer {
            link: self.link,
            stream: self.stream,
            input: Bytes::new(),
            reply,
        })
        .await
        .unwrap_or(Err(BufferError::Channel(ChannelError::NodeStopping)))?;
        debug_assert!(result.end_queued);
        Ok(queued)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BufferQueued {
    pub(crate) input_bytes: usize,
    pub(crate) end_queued: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    pub reason: ShutdownReason,
    pub links_closed: usize,
    pub links_abandoned: usize,
    pub interfaces_closed: usize,
    pub interfaces_failed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownReason {
    Requested,
    LastHandleDropped,
    DeadlineExpired,
    TaskDropped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    TooManyInitialInterfaces,
    EntropyUnavailable,
    InvalidEntropy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRunError {
    PacketWorkFailed,
    ProtocolInvariant,
}

macro_rules! errors {
    ($($name:ident { $($variant:ident $(($value:ty))?),* $(,)? })*) => {$(
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name { $($variant $(($value))?),* }
    )*};
}

errors! {
    NodeError { NodeStopping, CapacityReached }
    SendError { NodeStopping, NoRoute, PayloadTooLarge, InterfaceBusy, InterfaceFailed, CapacityReached }
    AnnounceError { NodeStopping, NoUsableInterface, ApplicationDataTooLarge, InterfaceBusy, InterfaceFailed }
    LinkError { NodeStopping, NoRoute, LinkClosed, TimedOut, Rejected, PayloadTooLarge, InterfaceBusy, InterfaceFailed, CapacityReached }
    IdentifyError { NodeStopping, DifferentNode, ServiceClosed, LinkClosed, BoundToDifferentIdentity, InterfaceBusy, InterfaceFailed }
    ChannelError { NodeStopping, LinkClosed, ChannelClosed, AlreadyOpen, CapacityReached, RetryLimitReached }
    ServiceReceiveError { NodeStopped, ServiceClosed }
    LinkReceiveError { NodeStopped, LinkClosed(LinkCloseReason) }
    ChannelReceiveError { NodeStopped, LinkClosed, ChannelClosed, ProtocolViolation }
    BufferError { EmptyInput, InputTooLarge, StreamAlreadyOpen, Channel(ChannelError) }
}
