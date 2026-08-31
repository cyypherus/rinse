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
        reply: Reply<Result<ServiceEvent, NodeError>>,
    },
    Announce {
        service: ServiceId,
        application_data: Bytes,
        ratchet: RatchetAction,
        reply: Reply<Result<Option<RatchetSecret>, NodeError>>,
    },
    SendDestination {
        destination: Destination,
        body: Bytes,
        reply: Reply<Result<(), NodeError>>,
    },
    OpenLink {
        destination: Destination,
        reply: Reply<Result<Link, NodeError>>,
    },
    AcceptLink {
        offer: LinkOfferId,
        reply: Reply<Result<Link, NodeError>>,
    },
    RejectLink {
        offer: LinkOfferId,
        reply: Reply<Result<(), NodeError>>,
    },
    CloseLink {
        link: LinkId,
        reply: Reply<Result<(), NodeError>>,
    },
    ReceiveLink {
        link: LinkId,
        reply: Reply<Result<LinkEvent, NodeError>>,
    },
    SendLinkDatagram {
        link: LinkId,
        body: Bytes,
        reply: Reply<Result<(), NodeError>>,
    },
    Request {
        link: LinkId,
        path: RequestPath,
        body: Bytes,
        reply: Reply<Result<Bytes, NodeError>>,
    },
    Respond {
        link: LinkId,
        request: IncomingRequestId,
        response: Bytes,
        reply: Reply<Result<(), NodeError>>,
    },
    Identify {
        link: LinkId,
        service: ServiceId,
        reply: Reply<Result<(), NodeError>>,
    },
    OpenChannel {
        link: LinkId,
        reply: Reply<Result<Channel, NodeError>>,
    },
    ReceiveChannel {
        link: LinkId,
        reply: Reply<Result<ChannelReceive, NodeError>>,
    },
    SendChannel {
        link: LinkId,
        message: ChannelMessage,
        reply: Reply<Result<(), NodeError>>,
    },
    OpenBuffer {
        link: LinkId,
        stream: StreamId,
        reply: Reply<Result<(), NodeError>>,
    },
    WriteBuffer {
        link: LinkId,
        stream: StreamId,
        input: Bytes,
        reply: Reply<Result<BufferQueued, NodeError>>,
    },
    FinishBuffer {
        link: LinkId,
        stream: StreamId,
        input: Bytes,
        reply: Reply<Result<BufferQueued, NodeError>>,
    },
    Shutdown,
}

#[derive(Clone, Copy)]
pub(crate) enum RegisteredResource {
    Service(ServiceId),
    Link(LinkId),
    Channel(LinkId),
}

#[derive(Clone)]
pub(crate) struct NodeClient {
    pub(crate) commands: async_channel::Sender<Command>,
    pub(crate) resource_drops: async_channel::Sender<RegisteredResource>,
}

impl NodeClient {
    fn resource_dropped(&self, resource: RegisteredResource) {
        if let Err(async_channel::TrySendError::Full(_)) = self.resource_drops.try_send(resource) {
            unreachable!("lifecycle capacity covers every live resource");
        }
    }
}

pub(crate) struct ResourceRegistration {
    client: NodeClient,
    resource: RegisteredResource,
}

impl ResourceRegistration {
    pub(crate) fn new(client: NodeClient, resource: RegisteredResource) -> Self {
        Self { client, resource }
    }
}

impl Drop for ResourceRegistration {
    fn drop(&mut self) {
        self.client.resource_dropped(self.resource);
    }
}

async fn ask<T>(client: &NodeClient, command: impl FnOnce(Reply<T>) -> Command) -> Option<T> {
    let (reply, result) = oneshot::channel();
    client.commands.send(command(reply)).await.ok()?;
    result.await.ok()
}

pub(crate) type ShutdownFuture =
    futures_util::future::Shared<futures_util::future::BoxFuture<'static, ()>>;

#[derive(Clone)]
pub struct NodeHandle {
    pub(crate) client: NodeClient,
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
        ask(&self.client, |reply| Command::AttachInterface {
            interface: Arc::new(interface),
            limits,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn generate_identity(&self) -> Result<PrivateIdentity, NodeError> {
        ask(&self.client, |reply| Command::GenerateIdentity { reply })
            .await
            .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn register_service(&self, config: ServiceConfig) -> Result<Service, NodeError> {
        ask(&self.client, |reply| Command::RegisterService {
            config: Box::new(config),
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn send(&self, destination: Destination, body: Bytes) -> Result<(), NodeError> {
        if body.len() > Self::MAX_DATAGRAM_BYTES {
            return Err(NodeError::InvalidInput);
        }
        ask(&self.client, |reply| Command::SendDestination {
            destination,
            body,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn open_link(&self, destination: Destination) -> Result<Link, NodeError> {
        ask(&self.client, |reply| Command::OpenLink {
            destination,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn shutdown(&self) {
        let _ = self.client.commands.send(Command::Shutdown).await;
        self.shutdown.clone().await
    }
}

pub struct Service {
    pub(crate) id: ServiceId,
    pub(crate) destination: Destination,
    pub(crate) registration: ResourceRegistration,
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
    ) -> Result<Option<RatchetSecret>, NodeError> {
        if application_data.len() > Self::MAX_ANNOUNCEMENT_BYTES {
            return Err(NodeError::InvalidInput);
        }
        ask(&self.registration.client, |reply| Command::Announce {
            service: self.id,
            application_data,
            ratchet,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn receive(&mut self) -> Result<ServiceEvent, NodeError> {
        ask(&self.registration.client, |reply| Command::ReceiveService {
            service: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
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
    pub(crate) client: NodeClient,
}

impl IncomingLink {
    pub async fn accept(self) -> Result<Link, NodeError> {
        ask(&self.client, |reply| Command::AcceptLink {
            offer: self.offer,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn reject(self) -> Result<(), NodeError> {
        ask(&self.client, |reply| Command::RejectLink {
            offer: self.offer,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }
}

pub struct Link {
    pub(crate) id: LinkId,
    pub(crate) registration: ResourceRegistration,
}

impl Link {
    pub const fn id(&self) -> [u8; 16] {
        self.id.0
    }

    pub fn send_handle(&self) -> LinkSender {
        LinkSender {
            id: self.id,
            client: self.registration.client.clone(),
        }
    }

    pub async fn receive(&mut self) -> Result<LinkEvent, NodeError> {
        ask(&self.registration.client, |reply| Command::ReceiveLink {
            link: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn close(self) -> Result<(), NodeError> {
        ask(&self.registration.client, |reply| Command::CloseLink {
            link: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }
}

#[derive(Clone)]
pub struct LinkSender {
    pub(crate) id: LinkId,
    pub(crate) client: NodeClient,
}

impl LinkSender {
    pub const MAX_DATAGRAM_BYTES: usize = crate::node::LINK_MDU;
    pub const MAX_REQUEST_BODY_BYTES: usize = 400;

    pub async fn send(&self, body: Bytes) -> Result<(), NodeError> {
        if body.len() > Self::MAX_DATAGRAM_BYTES {
            return Err(NodeError::InvalidInput);
        }
        ask(&self.client, |reply| Command::SendLinkDatagram {
            link: self.id,
            body,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn request(&self, path: RequestPath, body: Bytes) -> Result<Bytes, NodeError> {
        if body.len() > Self::MAX_REQUEST_BODY_BYTES {
            return Err(NodeError::InvalidInput);
        }
        ask(&self.client, |reply| Command::Request {
            link: self.id,
            path,
            body,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn open_channel(&self) -> Result<Channel, NodeError> {
        ask(&self.client, |reply| Command::OpenChannel {
            link: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }
}

impl Service {
    pub async fn identify_on(&self, link: &LinkSender) -> Result<(), NodeError> {
        if !self
            .registration
            .client
            .commands
            .same_channel(&link.client.commands)
        {
            return Err(NodeError::Conflict);
        }
        ask(&self.registration.client, |reply| Command::Identify {
            link: link.id,
            service: self.id,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
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
    CapacityReached,
    ProtocolViolation,
}

pub struct IncomingRequest {
    pub(crate) link: LinkId,
    pub(crate) id: IncomingRequestId,
    pub(crate) path: RequestPath,
    pub(crate) body: Bytes,
    pub(crate) client: NodeClient,
}

impl IncomingRequest {
    pub const MAX_RESPONSE_BYTES: usize = 1_048_543;

    pub fn path(&self) -> &RequestPath {
        &self.path
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub async fn respond(self, response: Bytes) -> Result<(), NodeError> {
        if response.len() > Self::MAX_RESPONSE_BYTES {
            return Err(NodeError::InvalidInput);
        }
        ask(&self.client, |reply| Command::Respond {
            link: self.link,
            request: self.id,
            response,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }
}

pub struct Channel {
    pub(crate) link: LinkId,
    pub(crate) registration: ResourceRegistration,
}

impl Channel {
    pub fn send_handle(&self) -> ChannelSender {
        ChannelSender {
            link: self.link,
            client: self.registration.client.clone(),
        }
    }
    pub async fn receive(&mut self) -> Result<ChannelReceive, NodeError> {
        ask(&self.registration.client, |reply| Command::ReceiveChannel {
            link: self.link,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }
}

#[derive(Clone)]
pub struct ChannelSender {
    pub(crate) link: LinkId,
    pub(crate) client: NodeClient,
}

impl ChannelSender {
    pub async fn send(&self, message: ChannelMessage) -> Result<(), NodeError> {
        ask(&self.client, |reply| Command::SendChannel {
            link: self.link,
            message,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
    }

    pub async fn open_buffer(&self, stream: StreamId) -> Result<BufferSender, NodeError> {
        ask(&self.client, |reply| Command::OpenBuffer {
            link: self.link,
            stream,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))?;
        Ok(BufferSender {
            link: self.link,
            stream,
            client: self.client.clone(),
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
    client: NodeClient,
}

impl BufferSender {
    pub async fn write(&mut self, input: Bytes) -> Result<usize, NodeError> {
        if input.is_empty() {
            return Err(NodeError::InvalidInput);
        }
        if input.len() > crate::buffer::MAX_INPUT_BYTES {
            return Err(NodeError::InvalidInput);
        }
        ask(&self.client, |reply| Command::WriteBuffer {
            link: self.link,
            stream: self.stream,
            input,
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))
        .map(|queued| queued.input_bytes)
    }

    pub async fn finish(self, input: Bytes) -> Result<usize, NodeError> {
        if input.len() > crate::buffer::MAX_INPUT_BYTES {
            return Err(NodeError::InvalidInput);
        }
        let mut queued = 0;
        while queued < input.len() {
            let remaining = input.slice(queued..);
            let result = ask(&self.client, |reply| Command::FinishBuffer {
                link: self.link,
                stream: self.stream,
                input: remaining,
                reply,
            })
            .await
            .unwrap_or(Err(NodeError::NodeStopping))?;
            queued += result.input_bytes;
            if result.end_queued {
                return Ok(queued);
            }
        }
        let result = ask(&self.client, |reply| Command::FinishBuffer {
            link: self.link,
            stream: self.stream,
            input: Bytes::new(),
            reply,
        })
        .await
        .unwrap_or(Err(NodeError::NodeStopping))?;
        debug_assert!(result.end_queued);
        Ok(queued)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BufferQueued {
    pub(crate) input_bytes: usize,
    pub(crate) end_queued: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildError(pub(crate) ());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeRunError(pub(crate) ());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeError {
    NodeStopping,
    ResourceClosed,
    LinkClosed(LinkCloseReason),
    CapacityReached,
    NoRoute,
    InvalidInput,
    InterfaceUnavailable,
    TimedOut,
    Rejected,
    Conflict,
}
