mod announce;
mod aspect;
mod buffer;
mod channel;
mod crypto;
mod handle;
mod identity;
mod interface;
mod link;
mod link_handle;
mod node;
mod packet;
mod packet_hashlist;
mod request;
mod resource;
mod stats;

mod async_io;

#[cfg(feature = "tcp")]
mod transports;

#[cfg(feature = "config")]
pub mod config;

pub use aspect::ServiceNameHash;
pub use buffer::{
    InvalidLinkBufferStreamId, LinkBufferStreamChunk, LinkBufferStreamId,
    QueuedLinkBufferStreamData,
};
pub use channel::{
    ChannelMessage, ChannelMessageTooLarge, ChannelMessageType, ChannelSendError,
    InvalidChannelMessageType,
};
pub use handle::{
    AnnounceError, DecryptLaterDeliveredPayloadError, DestinationCiphertext,
    EncryptForLaterDeliveryError, EstablishLinkError, IncomingRequest,
    InvalidDestinationCiphertext, KnownDestination, LinkLookupError, LinkPeerAuthenticationError,
    LinkRttError, LocalServiceId, RatchetConfigurationError, RatchetKeysForRestart,
    RatchetKeysForRestartError, ReceiveError, ReceivedDatagram, RegisteredLocalService,
    RequestError, RespondError, Response, RouteDiscoveryError, RuntimeStopped,
    SendDestinationDatagramError, SendLinkDatagramError,
};
pub use identity::{InvalidPrivateIdentityBytes, PrivateIdentity};
pub use interface::{Interface, InterfaceAccessCode, InterfaceAccessCodeError, Transport};
pub use link_handle::{LinkHandle, LinkStatus};
pub use packet::DestinationAddress;
pub use request::RequestId;
pub(crate) use request::WireRequestId;
pub use stats::LifetimeStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityAddress([u8; 16]);

impl IdentityAddress {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl AsRef<[u8]> for IdentityAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub use async_io::{Node, NodeBuilder, NodeRuntime, OutboundLinkBufferStream};

#[cfg(feature = "tcp")]
pub use async_io::AsyncTcpTransport as TcpTransport;
