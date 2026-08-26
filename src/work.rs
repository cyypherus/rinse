use core::future::Future;

use crate::node::PreparedInbound;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct InterfaceId(pub(crate) usize);

pub struct PreparePacket {
    interface: InterfaceId,
    sequence: u64,
    bytes: Vec<u8>,
}

impl PreparePacket {
    pub(crate) fn new(interface: InterfaceId, sequence: u64, bytes: Vec<u8>) -> Self {
        Self {
            interface,
            sequence,
            bytes,
        }
    }

    pub fn prepare(self) -> PreparedPacket {
        PreparedPacket {
            interface: self.interface,
            sequence: self.sequence,
            packet: PreparedInbound::parse(self.bytes, self.interface.0),
        }
    }
}

pub struct PreparedPacket {
    pub(crate) interface: InterfaceId,
    pub(crate) sequence: u64,
    pub(crate) packet: Option<PreparedInbound>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketWorkError;

pub trait PacketWork: Send + Sync {
    fn prepare(
        &self,
        job: PreparePacket,
    ) -> impl Future<Output = Result<PreparedPacket, PacketWorkError>> + Send;
}

pub struct InlinePacketWork;

impl PacketWork for InlinePacketWork {
    async fn prepare(&self, job: PreparePacket) -> Result<PreparedPacket, PacketWorkError> {
        Ok(job.prepare())
    }
}
