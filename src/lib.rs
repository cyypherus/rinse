#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

mod announce;
mod aspect;
mod crypto;
mod handle;
mod identity;
mod interface;
mod link;
mod node;
mod packet;
mod packet_hashlist;
mod request;
mod resource;
mod stats;
pub mod transports;

#[cfg(feature = "tokio")]
mod async_io;

#[cfg(feature = "config")]
pub mod config;

pub use aspect::AspectHash;
pub use handle::{Destination, NodeHandle, RequestError, RespondError, Service};
pub use identity::Identity;
pub use interface::{Interface, Transport};
pub use link::LinkId;
pub use node::Node;
pub use packet::Address;
pub use request::RequestId;
pub(crate) use request::WireRequestId;
pub use stats::StatsSnapshot;

#[cfg(feature = "tokio")]
pub use async_io::{
    AsyncNode, AsyncTransport, ConnectRequest, Destination as AsyncDestination, IncomingRaw,
    IncomingRequest, Requester, ServiceHandle,
};
