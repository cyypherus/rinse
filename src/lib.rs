#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]

mod announce;
mod crypto;
mod handle;
mod identity;
mod interface;
mod link;
mod node;
mod packet;
mod packet_hashlist;
mod path_request;
mod request;
mod resource;
pub mod transports;

#[cfg(feature = "tokio")]
mod async_io;

pub use handle::{Destination, NodeHandle, RequestError, RespondError, Service};
pub use identity::Identity;
pub use interface::{Interface, Transport};
pub use link::LinkId;
pub use node::Node;
pub use packet::Address;
pub use request::RequestId;
pub(crate) use request::WireRequestId;

#[cfg(feature = "tokio")]
pub use async_io::{
    AsyncNode, AsyncTransport, Destination as AsyncDestination, IncomingRaw, IncomingRequest,
    ServiceHandle,
};
