#[cfg(not(target_os = "macos"))]
compile_error!("rinse currently supports only macOS");

mod announce;
mod api;
mod aspect;
mod buffer;
mod channel;
mod crypto;
mod identity;
mod interface;
mod link;
mod model;
mod node;
mod packet;
mod packet_hashlist;
mod request;
mod resource;
mod runtime;
#[cfg(feature = "tcp")]
mod tcp;
mod time;
mod timer;

#[cfg(feature = "config")]
pub mod config;

pub use api::*;
pub use aspect::ServiceHash;
pub use identity::PrivateIdentity;
pub use interface::{
    AccessControlledInterface, InboundPacket, Interface, InterfaceAccessCode, InterfaceError,
    OutboundPacket,
};
pub use model::{
    ChannelMessage, Destination, IdentityHash, InterfaceLimits, MessageType, NodeConfig,
    RatchetAction, RatchetSecret, RequestPath, ServiceConfig, ServiceName, StreamId,
};
pub(crate) use request::RequestId;
pub(crate) use request::WireRequestId;
pub use runtime::{NodeBuilder, NodeTask};
#[cfg(feature = "tcp")]
pub use tcp::TcpHdlcInterface;
pub(crate) use time::{MonoTime, TimeSpan};
