#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

mod announce;
mod aspect;
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

pub use aspect::AspectHash;
pub use handle::{
    Destination, IncomingRequest, LinkError, PathNotFound, Progress, RequestError, ResourceError,
    RespondError, Response, ServiceId,
};
pub use identity::Identity;
pub use interface::{Interface, Transport};
pub use link_handle::{LinkHandle, LinkStatus, ResourceHandle};
pub use packet::Address;
pub use request::RequestId;
pub(crate) use request::WireRequestId;
pub use stats::StatsSnapshot;

pub use async_io::AsyncNode as Node;

#[cfg(feature = "tcp")]
pub use async_io::AsyncTcpTransport as TcpTransport;
