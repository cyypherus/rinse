use crate::link::LinkId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkHandle(pub(crate) LinkId);

impl LinkHandle {
    pub fn id(&self) -> &LinkId {
        &self.0
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
