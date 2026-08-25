use std::time::Instant;

use crate::aspect::ServiceNameHash;
use crate::packet::DestinationAddress;
use crate::request::RequestId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceId(pub(crate) usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Timeout,
    LinkEstablishmentFailed,
    RuntimeStopped,
    ServiceNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondError {
    LinkClosed,
    TransferFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstablishLinkError {
    DestinationUnreachable,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRttError {
    LinkNotFound,
    NotMeasured,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetSnapshotError {
    ServiceNotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEncryptError {
    DestinationUnknown,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppDecryptError {
    ServiceNotFound,
    InvalidCiphertext,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    ServiceNotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceRegistrationError {
    RuntimeStarted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    LinkClosed,
    InvalidLink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDiscoveryError {
    NotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    PayloadTooLarge { size: usize, max: usize },
    DestinationUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendUnreliableError {
    LinkNotFound,
    LinkNotActive,
    PayloadTooLarge { size: usize, max: usize },
    RuntimeStopped,
}

pub struct IncomingRequest {
    pub request_id: RequestId,
    pub path: String,
    pub data: Vec<u8>,
    pub authenticated_remote_identity: Option<crate::IdentityAddress>,
}

pub struct Response {
    pub data: Vec<u8>,
    pub metadata: Option<Vec<u8>>,
}

pub struct ResponseTransferProgress {
    pub request_id: RequestId,
    pub received_parts: usize,
    pub total_parts: usize,
    pub received_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Clone)]
pub struct Destination {
    pub address: DestinationAddress,
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub service_name_hash: ServiceNameHash,
    pub last_seen: Instant,
}

pub(crate) enum ServiceEvent {
    Request {
        service: ServiceId,
        request_id: RequestId,
        path: String,
        data: Vec<u8>,
        remote_identity: Option<DestinationAddress>,
    },
    RequestResult {
        service: ServiceId,
        request_id: RequestId,
        result: Result<(DestinationAddress, Vec<u8>, Option<Vec<u8>>), RequestError>,
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
        message: crate::LinkChannelMessage,
    },
    Buffer {
        service: ServiceId,
        link: crate::LinkHandle,
        chunk: crate::BufferStreamChunk,
    },
    Resource {
        service: ServiceId,
        link: crate::LinkHandle,
        data: Vec<u8>,
    },
    DestinationsChanged,
    PathRequestResult {
        destination: DestinationAddress,
        found: bool,
    },
}
