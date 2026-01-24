use crate::link::LinkId;
use crate::packet::Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkHandle(pub(crate) LinkId);

impl LinkHandle {
    pub fn id(&self) -> &LinkId {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelHandle {
    pub(crate) link_id: LinkId,
}

impl ChannelHandle {
    pub fn link(&self) -> LinkHandle {
        LinkHandle(self.link_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceHandle(pub(crate) [u8; 32]);

impl ResourceHandle {
    pub fn hash(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Pending,
    Active,
    Stale,
    Closed,
}

pub struct LinkInfo {
    pub handle: LinkHandle,
    pub destination: Address,
    pub status: LinkStatus,
    pub rtt_ms: Option<u64>,
}
