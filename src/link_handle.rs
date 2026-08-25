use crate::link::LinkId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkHandle(pub(crate) LinkId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ResourceHandle(pub(crate) [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Pending,
    Active,
    Stale,
    Closed,
}
