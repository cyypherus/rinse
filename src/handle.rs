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

pub struct Destination {
    pub address: Address,
    pub app_data: Option<Vec<u8>>,
    pub hops: u8,
    pub aspect: AspectHash,
    pub last_seen: Instant,
}

pub enum ServiceEvent {
    Request {
        service: ServiceId,
        request_id: RequestId,
        path: String,
        data: Vec<u8>,
    },
    RequestResult {
        service: ServiceId,
        request_id: RequestId,
        result: Result<(Address, Vec<u8>), RequestError>,
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
    DestinationsChanged,
}
