use std::time::Instant;

use crate::aspect::ServiceNameHash;
use crate::packet::DestinationAddress;
use crate::request::RequestId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalServiceId(pub(crate) usize);

pub struct RegisteredLocalService {
    pub id: LocalServiceId,
    pub destination_address: DestinationAddress,
}

pub(crate) use LocalServiceId as ServiceId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnounceError {
    ServiceNotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Timeout,
    LinkNotFound,
    LinkClosed,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespondError {
    RequestNotFound,
    LinkClosed,
    TransferFailed,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstablishLinkError {
    DestinationUnreachable,
    Timeout,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRttError {
    LinkNotFound,
    NotMeasured,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkLookupError {
    LinkNotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkPeerAuthenticationError {
    LinkNotFound,
    LinkNotActive,
    LocalNodeDidNotInitiateLink,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetKeysForRestartError {
    ServiceNotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetKeysForRestart(pub(crate) Vec<[u8; 32]>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetConfigurationError {
    ServiceNotFound,
    RuntimeStopped,
    ZeroRotationInterval,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptForLaterDeliveryError {
    DestinationUnknown,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptLaterDeliveredPayloadError {
    ServiceNotFound,
    InvalidCiphertext,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationCiphertext(Vec<u8>);

impl DestinationCiphertext {
    pub(crate) fn from_validated_bytes(bytes: Vec<u8>) -> Self {
        debug_assert!(bytes.len() >= 32);
        Self(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, InvalidDestinationCiphertext> {
        if bytes.len() < 32 {
            return Err(InvalidDestinationCiphertext);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDestinationCiphertext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError {
    ServiceNotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStopped;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDiscoveryError {
    NotFound,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDestinationDatagramError {
    PayloadTooLarge { size: usize, max: usize },
    DestinationUnknown,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendLinkDatagramError {
    LinkNotFound,
    LinkNotActive,
    PayloadTooLarge { size: usize, max: usize },
    RuntimeStopped,
}

pub enum ReceivedDatagram {
    Destination {
        data: Vec<u8>,
    },
    Link {
        link: crate::LinkHandle,
        data: Vec<u8>,
    },
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

#[derive(Clone, PartialEq, Eq)]
pub struct KnownDestination {
    pub address: DestinationAddress,
    pub announcement_data: Option<Vec<u8>>,
    pub hop_count: u8,
    pub service_name_hash: ServiceNameHash,
    pub route_refreshed_at: Instant,
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
        request_id: RequestId,
        result: Result<(Vec<u8>, Option<Vec<u8>>), RequestError>,
    },
    RespondResult {
        request_id: RequestId,
        result: Result<(), RespondError>,
    },
    #[cfg(test)]
    ResourceProgress {
        request_id: RequestId,
        total_parts: usize,
        received_bytes: usize,
        total_bytes: usize,
    },
    Raw {
        service: ServiceId,
        link: Option<crate::LinkHandle>,
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
        chunk: crate::LinkBufferStreamChunk,
    },
    DestinationsChanged,
    PathRequestResult {
        destination: DestinationAddress,
        found: bool,
    },
}
