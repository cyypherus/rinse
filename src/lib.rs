#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

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
pub use buffer::{BufferStreamChunk, BufferStreamError};
pub use channel::{LinkChannelError, LinkChannelMessage};
pub use handle::{
    AppDecryptError, AppEncryptError, Destination, EstablishLinkError, IncomingRequest,
    LinkRttError, RatchetSnapshotError, ReceiveError, RequestError, ResourceError, RespondError,
    Response, ResponseTransferProgress, RouteDiscoveryError, SendError, SendUnreliableError,
    ServiceId, ServiceRegistrationError,
};
pub use identity::PrivateIdentity;
pub use interface::{Interface, InterfaceAccessCode, InterfaceAccessCodeError, Transport};
pub use link_handle::{LinkHandle, LinkStatus};
pub use packet::DestinationAddress;
pub use request::RequestId;
pub(crate) use request::WireRequestId;
pub use stats::LifetimeStats;

pub type IdentityAddress = [u8; 16];

pub use async_io::Node;

#[cfg(feature = "tcp")]
pub use async_io::AsyncTcpTransport as TcpTransport;
