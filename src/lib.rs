#[cfg(not(target_has_atomic = "ptr"))]
compile_error!("rinse requires pointer-width atomics");

#[cfg(all(target_arch = "xtensa", not(target_os = "espidf")))]
compile_error!("Xtensa is supported only through an ESP-IDF std target");

mod announce;
mod api;
mod aspect;
mod buffer;
mod channel;
mod crypto;
mod entropy;
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
mod work;

#[cfg(feature = "config")]
pub mod config;

pub use api::*;
pub use aspect::ServiceHash;
#[cfg(feature = "std-clock")]
pub use entropy::SystemEntropy;
pub use entropy::{CryptoEntropy, EntropyUnavailable};
pub use identity::{IdentityError, PrivateIdentity};
pub use interface::{
    AccessControlledInterface, InboundPacket, Interface, InterfaceAccessCode,
    InterfaceAccessCodeError, InterfaceError, OutboundPacket,
};
pub use model::{
    ChannelMessage, ChannelMessageTooLarge, Destination, EmptyRequestPath, EmptyServiceName,
    IdentityHash, InterfaceLimits, InterfaceLimitsError, InvalidRatchetSecret, MessageType,
    NodeConfig, NodeLimits, RatchetAction, RatchetSecret, RequestPath, ReservedMessageType,
    ServiceConfig, ServiceName, StreamId, StreamIdOutOfRange, TooManyRequestPaths,
};
pub(crate) use request::RequestId;
pub(crate) use request::WireRequestId;
pub use runtime::{NodeBuilder, NodeTask};
#[cfg(feature = "tcp")]
pub use tcp::TcpHdlcInterface;
#[cfg(feature = "embassy-clock")]
pub use time::EmbassyClock;
pub use time::{Clock, MonoTime, TimeSpan};
pub use work::{InlinePacketWork, PacketWork, PacketWorkError, PreparePacket, PreparedPacket};
