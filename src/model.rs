use std::collections::BTreeSet;

use bytes::Bytes;

use crate::identity::PrivateIdentity;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Destination([u8; 16]);

impl Destination {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityHash([u8; 16]);

impl IdentityHash {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceName(String);

impl ServiceName {
    pub fn new(value: impl Into<String>) -> Result<Self, EmptyServiceName> {
        let value = value.into();
        if value.is_empty() {
            return Err(EmptyServiceName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyServiceName;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestPath(String);

impl RequestPath {
    pub fn new(value: impl Into<String>) -> Result<Self, EmptyRequestPath> {
        let value = value.into();
        if value.is_empty() {
            return Err(EmptyRequestPath);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyRequestPath;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeMode {
    Endpoint,
    Relay,
}

pub struct NodeConfig {
    pub(crate) mode: NodeMode,
}

impl NodeConfig {
    pub fn endpoint() -> Self {
        Self {
            mode: NodeMode::Endpoint,
        }
    }

    pub fn relay() -> Self {
        Self {
            mode: NodeMode::Relay,
        }
    }
}

pub struct InterfaceLimits {
    pub(crate) outbound_packets: usize,
    pub(crate) outbound_bytes: usize,
    pub(crate) maximum_packet_bytes: usize,
}

impl InterfaceLimits {
    pub fn new(
        maximum_packet_bytes: usize,
        outbound_packets: usize,
        outbound_bytes: usize,
    ) -> Result<Self, InterfaceLimitsError> {
        if outbound_packets == 0 || outbound_bytes == 0 || maximum_packet_bytes == 0 {
            return Err(InterfaceLimitsError::Zero);
        }
        if outbound_bytes < maximum_packet_bytes {
            return Err(InterfaceLimitsError::QueueCannotHoldPacket);
        }
        Ok(Self {
            outbound_packets,
            outbound_bytes,
            maximum_packet_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterfaceLimitsError {
    Zero,
    QueueCannotHoldPacket,
}

pub struct ServiceConfig {
    pub(crate) name: ServiceName,
    pub(crate) identity: PrivateIdentity,
    pub(crate) accepted_request_paths: BTreeSet<RequestPath>,
    pub(crate) restart_ratchet: Option<RatchetSecret>,
}

impl ServiceConfig {
    pub fn new(
        name: ServiceName,
        identity: PrivateIdentity,
        accepted_request_paths: impl IntoIterator<Item = RequestPath>,
        restart_ratchet: Option<RatchetSecret>,
    ) -> Result<Self, TooManyRequestPaths> {
        let mut paths = BTreeSet::new();
        for path in accepted_request_paths {
            paths.insert(path);
            if paths.len() > 256 {
                return Err(TooManyRequestPaths);
            }
        }
        Ok(Self {
            name,
            identity,
            accepted_request_paths: paths,
            restart_ratchet,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TooManyRequestPaths;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageType(u16);

impl MessageType {
    pub const RESERVED_START: u16 = 0xf000;
    pub fn new(value: u16) -> Result<Self, ReservedMessageType> {
        (value < Self::RESERVED_START)
            .then_some(Self(value))
            .ok_or(ReservedMessageType)
    }
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedMessageType;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StreamId(u16);

impl StreamId {
    pub const MAX: u16 = 0x3fff;
    pub fn new(value: u16) -> Result<Self, StreamIdOutOfRange> {
        (value <= Self::MAX)
            .then_some(Self(value))
            .ok_or(StreamIdOutOfRange)
    }
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamIdOutOfRange;

pub struct ChannelMessage {
    message_type: MessageType,
    body: Bytes,
}

impl ChannelMessage {
    pub const MAX_BODY_BYTES: usize = 425;
    pub fn new(message_type: MessageType, body: Bytes) -> Result<Self, ChannelMessageTooLarge> {
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(ChannelMessageTooLarge);
        }
        Ok(Self { message_type, body })
    }
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelMessageTooLarge;

pub struct RatchetSecret([u8; 32]);

impl RatchetSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidRatchetSecret> {
        if bytes == [0; 32] {
            return Err(InvalidRatchetSecret);
        }
        Ok(Self(bytes))
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Drop for RatchetSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidRatchetSecret;

pub enum RatchetAction {
    Keep,
    Rotate,
}
