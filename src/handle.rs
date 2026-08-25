use std::time::Instant;

use crate::aspect::AspectHash;
use crate::packet::Address;
use crate::request::RequestId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId(pub(crate) usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Timeout,
    LinkFailed,
    LinkClosed,
    TransferFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondError {
    LinkClosed,
    TransferFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    DestinationUnreachable,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    LinkClosed,
    InvalidLink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathNotFound;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    PayloadTooLarge { size: usize, max: usize },
    DestinationUnknown,
}

pub struct IncomingRequest {
    pub request_id: RequestId,
    pub path: String,
    pub data: Vec<u8>,
    pub remote_identity: Option<Address>,
}

pub struct Response {
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
}

pub struct Progress {
    pub request_id: RequestId,
    pub received_parts: usize,
    pub total_parts: usize,
    pub received_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Clone)]
pub struct Destination {
    pub address: Address,
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub aspect: AspectHash,
    pub last_seen: Instant,
}

pub(crate) enum ServiceEvent {
    Request {
        service: ServiceId,
        request_id: RequestId,
        path: String,
        data: Vec<u8>,
        remote_identity: Option<Address>,
    },
    RequestResult {
        service: ServiceId,
        request_id: RequestId,
        result: Result<(Address, Vec<u8>, Option<Vec<u8>>), RequestError>,
    },
    RespondResult {
        service: ServiceId,
        request_id: RequestId,
        result: Result<(), RespondError>,
    },
    ResourceProgress {
        service: ServiceId,
        request_id: RequestId,
        received_parts: usize,
        total_parts: usize,
        received_bytes: usize,
        total_bytes: usize,
    },
    Raw {
        service: ServiceId,
        data: Vec<u8>,
    },
    Channel {
        service: ServiceId,
        link: crate::LinkHandle,
        message: crate::ChannelMessage,
    },
    Buffer {
        service: ServiceId,
        link: crate::LinkHandle,
        chunk: crate::BufferChunk,
    },
    Resource {
        service: ServiceId,
        link: crate::LinkHandle,
        data: Vec<u8>,
    },
    DestinationsChanged,
    PathRequestResult {
        destination: Address,
        found: bool,
    },
}
