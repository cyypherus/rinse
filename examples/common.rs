pub use rinse::TcpHdlcInterface as TcpHdlc;
use rinse::{InterfaceLimits, NodeBuilder, NodeConfig};

pub fn node_builder(relay: bool) -> NodeBuilder {
    NodeBuilder::new(if relay {
        NodeConfig::relay()
    } else {
        NodeConfig::endpoint()
    })
}

pub fn interface_limits() -> InterfaceLimits {
    InterfaceLimits::new(65_535, 256, 1_048_576).unwrap()
}
