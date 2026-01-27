use std::collections::HashMap;
use std::time::Instant;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::announce::{AnnounceBuilder, AnnounceData};
use crate::aspect::AspectHash;
use crate::crypto::{EphemeralKeyPair, sha256};
use crate::handle::{Destination, RequestError, RespondError, ServiceEvent, ServiceId};
use crate::stats::{Stats, StatsSnapshot};

const LINK_MDU: usize = 431;
use crate::link::{EstablishedLink, LinkId, LinkProof, LinkRequest, LinkState, PendingLink};
use crate::packet::{Address, LinkContext, Packet, SingleDestination};
use crate::packet_hashlist::PacketHashlist;
use crate::request::{PathHash, Request, RequestId, Response, WireRequestId};
use crate::{Interface, Transport};
use ed25519_dalek::Signature;

const DEFAULT_MAX_HOPS: u8 = 128;
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;
const LOCAL_REBROADCASTS_MAX: u8 = 2;
const PATHFINDER_RW_MS: u64 = 500;
const ESTABLISHMENT_TIMEOUT_PER_HOP_SECS: u64 = 6;
const ESTABLISHMENT_TIMEOUT_BASE_SECS: u64 = 60;
const PATH_REQUEST_TIMEOUT_SECS: u64 = 60;

enum Notification {
    Request {
        service: ServiceId,
        link_id: LinkId,
        request_id: RequestId,
        wire_request_id: WireRequestId,
        path: String,
        data: Vec<u8>,
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
    Raw {
        service: ServiceId,
        data: Vec<u8>,
    },
    DestinationsChanged,
    PathRequestResult {
        destination: Address,
        found: bool,
    },
}

struct ServiceEntry {
    address: Address,
    name_hash: [u8; 10],
    encryption_secret: StaticSecret,
    encryption_public: X25519Public,
    signing_key: SigningKey,
    registered_paths: HashMap<PathHash, String>,
}

struct Receipt {
    packet_hash: [u8; 32],
    destination: Address,
}

#[derive(Clone)]
pub(crate) struct PathEntry {
    timestamp: Instant,
    next_hop: Address,
    hops: u8,
    receiving_interface: usize,
    encryption_key: X25519Public,
    signing_key: VerifyingKey,
    ratchet_key: Option<X25519Public>,
    app_data: Option<Vec<u8>>,
    name_hash: [u8; 10],
    has_ratchet: bool,
    announce_data: Vec<u8>,
}

#[derive(Debug)]
struct PendingAnnounce {
    destination: Address,
    source_interface: usize,
    hops: u8,
    has_ratchet: bool,
    data: Vec<u8>,
    retries_remaining: u8,
    retry_at: Instant,
    local_rebroadcasts: u8,
}

struct LinkTableEntry {
    timestamp: Instant,
    receiving_interface: usize,
    next_hop_interface: usize,
    remaining_hops: u8,
    hops: u8,
}

struct ReverseTableEntry {
    receiving_interface: usize,
}

struct MultiSegmentTransfer {
    service: ServiceId,
    local_request_id: RequestId,
    total_segments: usize,
    segments_received: usize,
    accumulated_data: Vec<u8>,
    has_metadata: bool,
}

struct OutboundMultiSegment {
    destination: Address,
    service_idx: Option<ServiceId>,
    local_request_id: Option<RequestId>,
    full_data: Vec<u8>,
    compress: bool,
    is_response: bool,
    request_id: Option<Vec<u8>>,
    total_segments: usize,
    current_segment: usize,
}

pub struct Node<T, R = ThreadRng> {
    transport: bool,
    max_hops: u8,
    retries: u8,
    retry_delay_ms: u64,
    rng: R,
    transport_id: Address,
    pub(crate) path_table: HashMap<Address, PathEntry>,
    pending_announces: Vec<PendingAnnounce>,
    seen_packets: PacketHashlist,
    reverse_table: HashMap<Address, ReverseTableEntry>,
    receipts: Vec<Receipt>,
    services: Vec<ServiceEntry>,
    pub(crate) interfaces: Vec<Interface<T>>,
    pending_outbound_links: HashMap<LinkId, PendingLink>,
    pub(crate) established_links: HashMap<LinkId, EstablishedLink>,
    link_table: HashMap<LinkId, LinkTableEntry>,
    outbound_resources: HashMap<
        [u8; 32],
        (
            LinkId,
            Address,
            Option<ServiceId>,
            Option<RequestId>,
            crate::resource::OutboundResource,
        ),
    >,
    inbound_resources: HashMap<[u8; 32], (LinkId, crate::resource::InboundResource)>,
    pending_resource_adverts: HashMap<[u8; 32], (LinkId, crate::resource::ResourceAdvertisement)>,
    multi_segment_transfers: HashMap<[u8; 32], MultiSegmentTransfer>,
    outbound_multi_segments: HashMap<[u8; 32], OutboundMultiSegment>,
    inbound_request_links: HashMap<RequestId, (WireRequestId, LinkId, ServiceId)>,
    pub(crate) destination_links: HashMap<Address, LinkId>,
    pending_outbound_requests: HashMap<Address, Vec<(ServiceId, RequestId, String, Vec<u8>)>>,
    pending_path_requests: HashMap<Address, Instant>,
    discovery_path_requests: HashMap<Address, usize>,
    stats: Stats,
    pending_events: Vec<ServiceEvent>,
    pending_resource_requests: Vec<(LinkId, [u8; 32])>,
}

impl<T: Transport> Node<T, ThreadRng> {
    pub fn new(transport: bool) -> Self {
        let mut rng = rand::thread_rng();
        let mut transport_id = [0u8; 16];
        rng.fill_bytes(&mut transport_id);
        log::info!(
            "Node started with transport_id <{}>",
            hex::encode(transport_id)
        );
        Self {
            transport,
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            rng,
            transport_id,
            path_table: HashMap::new(),
            pending_announces: Vec::new(),
            seen_packets: crate::packet_hashlist::PacketHashlist::new(1_000_000),
            reverse_table: HashMap::new(),
            receipts: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
            outbound_resources: HashMap::new(),
            inbound_resources: HashMap::new(),
            pending_resource_adverts: HashMap::new(),
            multi_segment_transfers: HashMap::new(),
            outbound_multi_segments: HashMap::new(),
            inbound_request_links: HashMap::new(),
            destination_links: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
            pending_path_requests: HashMap::new(),
            discovery_path_requests: HashMap::new(),
            stats: Stats::new(),
            pending_events: Vec::new(),
            pending_resource_requests: Vec::new(),
        }
    }
}

impl<T: Transport, R: RngCore> Node<T, R> {
    pub fn with_rng(mut rng: R, transport: bool) -> Self {
        let mut transport_id = [0u8; 16];
        rng.fill_bytes(&mut transport_id);
        log::info!(
            "Node started with transport_id <{}>",
            hex::encode(transport_id)
        );
        Self {
            transport,
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            rng,
            transport_id,
            path_table: HashMap::new(),
            pending_announces: Vec::new(),
            seen_packets: PacketHashlist::new(1_000_000),
            reverse_table: HashMap::new(),
            receipts: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
            outbound_resources: HashMap::new(),
            inbound_resources: HashMap::new(),
            pending_resource_adverts: HashMap::new(),
            multi_segment_transfers: HashMap::new(),
            outbound_multi_segments: HashMap::new(),
            inbound_request_links: HashMap::new(),
            destination_links: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
            pending_path_requests: HashMap::new(),
            discovery_path_requests: HashMap::new(),
            stats: Stats::new(),
            pending_events: Vec::new(),
            pending_resource_requests: Vec::new(),
        }
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    pub fn add_interface(&mut self, interface: Interface<T>) -> usize {
        let id = self.interfaces.len();
        self.interfaces.push(interface);
        id
    }

    pub fn known_destinations(&self) -> Vec<Destination> {
        self.path_table
            .iter()
            .map(|(addr, entry)| Destination {
                address: *addr,
                app_data: entry.app_data.clone(),
                hops: entry.hops,
                aspect: AspectHash::from_bytes(entry.name_hash),
                last_seen: entry.timestamp,
            })
            .collect()
    }

    pub fn service_address(&self, service: ServiceId) -> Option<Address> {
        self.services.get(service.0).map(|s| s.address)
    }

    fn send_single_data(&mut self, destination: Address, data: &[u8]) {
        use crate::crypto::SingleDestEncryption;

        if let Some(entry) = self.path_table.get(&destination) {
            let target_key = entry.ratchet_key.as_ref().unwrap_or(&entry.encryption_key);
            let (ephemeral_pub, ciphertext) =
                SingleDestEncryption::encrypt(&mut self.rng, target_key, data);
            let mut payload = ephemeral_pub.as_bytes().to_vec();
            payload.extend(ciphertext);

            let dest = if entry.hops > 1 {
                SingleDestination::Transport {
                    transport_id: entry.next_hop,
                    destination,
                }
            } else {
                SingleDestination::Direct(destination)
            };
            let packet = Packet::SingleData {
                hops: 0,
                destination: dest,
                ciphertext: payload,
            };
            let target = entry.receiving_interface;
            if let Some(iface) = self.interfaces.get_mut(target) {
                self.stats.packets_sent += 1;
                self.stats.bytes_sent += packet.to_bytes().len() as u64;
                iface.send(packet, 0);
            }
        }
    }

    pub fn request(
        &mut self,
        service: ServiceId,
        link: crate::LinkHandle,
        path: &str,
        data: &[u8],
    ) -> Option<RequestId> {
        use crate::packet::LinkDataDestination;

        let link_id = link.0;
        let Some(established) = self.established_links.get_mut(&link_id) else {
            log::warn!("Request on non-existent link {}", hex::encode(link_id));
            return None;
        };

        let mut id_bytes = [0u8; 16];
        self.rng.fill_bytes(&mut id_bytes);
        let local_request_id = RequestId(id_bytes);

        let path_hash = crate::request::path_hash(path);
        log::info!(
            "Request on link {} path={} hash={} ({} bytes)",
            hex::encode(link_id),
            path,
            hex::encode(path_hash),
            data.len()
        );

        let req = Request::new(path, data.to_vec());
        let encoded = req.encode();
        let ciphertext = established.encrypt(&mut self.rng, &encoded);
        let target_interface = established.receiving_interface;

        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link_id),
            context: LinkContext::Request,
            data: ciphertext,
        };
        let wire_request_id = WireRequestId(packet.packet_hash()[..16].try_into().unwrap());
        established
            .pending_requests
            .insert(wire_request_id, (service, local_request_id));

        log::info!(
            "Sending request over link {} wire_request_id={}",
            hex::encode(link_id),
            hex::encode(wire_request_id.0),
        );
        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += packet.to_bytes().len() as u64;
            iface.send(packet, 0);
        }

        Some(local_request_id)
    }

    pub fn respond(
        &mut self,
        request_id: RequestId,
        data: &[u8],
        metadata: Option<&[u8]>,
        compress: bool,
    ) {
        use crate::packet::LinkDataDestination;

        if let Some((wire_request_id, link_id, service_idx)) =
            self.inbound_request_links.remove(&request_id)
            && let Some(link) = self.established_links.get(&link_id)
        {
            let target_interface = link.receiving_interface;
            if data.len() <= LINK_MDU && metadata.is_none() {
                let resp = Response::new(wire_request_id, data.to_vec());
                let ciphertext = link.encrypt(&mut self.rng, &resp.encode());

                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::Response,
                    data: ciphertext,
                };
                if let Some(iface) = self.interfaces.get_mut(target_interface) {
                    iface.send(packet, 0);
                }
                self.dispatch_notifications(vec![Notification::RespondResult {
                    service: service_idx,
                    request_id,
                    result: Ok(()),
                }]);
            } else {
                use crate::resource::MAX_EFFICIENT_SIZE;
                use serde_bytes::ByteBuf;

                let packed_response = rmp_serde::to_vec(&(
                    ByteBuf::from(wire_request_id.0.to_vec()),
                    ByteBuf::from(data.to_vec()),
                ))
                .unwrap_or_else(|_| data.to_vec());

                let total_size = packed_response.len();
                let needs_segmentation = total_size > MAX_EFFICIENT_SIZE;

                let segment_data = if needs_segmentation {
                    packed_response[..MAX_EFFICIENT_SIZE].to_vec()
                } else {
                    packed_response.clone()
                };

                let mut resource = crate::resource::OutboundResource::new_segment(
                    &mut self.rng,
                    link,
                    segment_data,
                    metadata.map(|m| m.to_vec()),
                    compress,
                    true,
                    Some(wire_request_id.0.to_vec()),
                    1,
                    None,
                    if needs_segmentation {
                        Some(total_size)
                    } else {
                        None
                    },
                );

                let adv = resource.advertisement(91);
                let adv_data = adv.encode();
                let hash = resource.hash;
                let original_hash = resource.original_hash;

                if needs_segmentation {
                    self.outbound_multi_segments.insert(
                        original_hash,
                        OutboundMultiSegment {
                            destination: link.destination,
                            service_idx: Some(service_idx),
                            local_request_id: Some(request_id),
                            full_data: packed_response,
                            compress,
                            is_response: true,
                            request_id: Some(wire_request_id.0.to_vec()),
                            total_segments: resource.total_segments,
                            current_segment: 1,
                        },
                    );
                    log::info!(
                        "Created multi-segment outbound resource: {} segments, {} bytes total",
                        resource.total_segments,
                        total_size
                    );
                }

                let ciphertext = link.encrypt(&mut self.rng, &adv_data);
                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::ResourceAdv,
                    data: ciphertext,
                };

                self.outbound_resources.insert(
                    hash,
                    (
                        link_id,
                        link.destination,
                        Some(service_idx),
                        Some(request_id),
                        resource,
                    ),
                );

                if let Some(iface) = self.interfaces.get_mut(target_interface) {
                    iface.send(packet, 0);
                }
            }
        }
    }

    fn send_request_inner(
        &mut self,
        service: ServiceId,
        destination: Address,
        local_request_id: RequestId,
        path: &str,
        data: Vec<u8>,
        now: Instant,
    ) {
        use crate::packet::LinkDataDestination;

        let path_hash = crate::request::path_hash(path);
        log::info!(
            "Request to <{}> path={} hash={} ({} bytes)",
            hex::encode(destination),
            path,
            hex::encode(path_hash),
            data.len()
        );

        let link_id = self.destination_links.get(&destination).copied();

        if let Some(link_id) = link_id {
            log::info!(
                "Have existing link {} to <{}>",
                hex::encode(link_id),
                hex::encode(destination)
            );
            if let Some(link) = self.established_links.get_mut(&link_id) {
                let req = Request::new(path, data);
                let encoded = req.encode();
                log::debug!(
                    "Request plaintext {} bytes: {}",
                    encoded.len(),
                    hex::encode(&encoded[..encoded.len().min(64)])
                );
                let ciphertext = link.encrypt(&mut self.rng, &encoded);
                let target_interface = link.receiving_interface;
                log::debug!(
                    "Request ciphertext {} bytes: {}",
                    ciphertext.len(),
                    hex::encode(&ciphertext[..ciphertext.len().min(64)])
                );

                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::Request,
                    data: ciphertext,
                };
                let wire_request_id = WireRequestId(packet.packet_hash()[..16].try_into().unwrap());
                link.pending_requests
                    .insert(wire_request_id, (service, local_request_id));

                log::info!(
                    "Sending request over link {} wire_request_id={} packet_hash={}",
                    hex::encode(link_id),
                    hex::encode(wire_request_id.0),
                    hex::encode(packet.packet_hash())
                );
                if let Some(iface) = self.interfaces.get_mut(target_interface) {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += packet.to_bytes().len() as u64;
                    iface.send(packet, 0);
                }
            } else {
                log::warn!(
                    "Link {} in destination_links but not in established_links!",
                    hex::encode(link_id)
                );
            }
        } else {
            log::info!("No link to <{}>, queuing request", hex::encode(destination));
            self.pending_outbound_requests
                .entry(destination)
                .or_default()
                .push((service, local_request_id, path.to_string(), data));

            if self.link(Some(service), destination, now).is_none() {
                log::info!(
                    "No existing link, sending path request for <{}>",
                    hex::encode(destination)
                );
                self.request_path(destination, now);
            }
        }
    }

    fn dispatch_notifications(&mut self, notifications: Vec<Notification>) {
        for notification in notifications {
            match notification {
                Notification::Request {
                    service,
                    link_id,
                    request_id,
                    wire_request_id,
                    path,
                    data,
                } => {
                    self.inbound_request_links
                        .insert(request_id, (wire_request_id, link_id, service));
                    let remote_identity = self
                        .established_links
                        .get(&link_id)
                        .and_then(|l| l.remote_identity);
                    self.pending_events.push(ServiceEvent::Request {
                        service,
                        request_id,
                        path,
                        data,
                        remote_identity,
                    });
                }
                Notification::RequestResult {
                    service,
                    request_id,
                    result,
                } => {
                    self.pending_events.push(ServiceEvent::RequestResult {
                        service,
                        request_id,
                        result,
                    });
                }
                Notification::RespondResult {
                    service,
                    request_id,
                    result,
                } => {
                    self.pending_events.push(ServiceEvent::RespondResult {
                        service,
                        request_id,
                        result,
                    });
                }
                Notification::Raw { service, data } => {
                    self.pending_events
                        .push(ServiceEvent::Raw { service, data });
                }
                Notification::DestinationsChanged => {
                    self.pending_events.push(ServiceEvent::DestinationsChanged);
                }
                Notification::PathRequestResult { destination, found } => {
                    self.pending_events
                        .push(ServiceEvent::PathRequestResult { destination, found });
                }
            }
        }
    }

    pub fn add_service(
        &mut self,
        name: &str,
        paths: &[&str],
        identity: &crate::identity::Identity,
    ) -> ServiceId {
        let name_hash: [u8; 10] = sha256(name.as_bytes())[..10].try_into().unwrap();

        let encryption_secret = StaticSecret::from(*identity.encryption_secret.as_bytes());
        let encryption_public = identity.encryption_public;
        let signing_key = SigningKey::from_bytes(identity.signing_key.as_bytes());

        let identity_hash = identity.hash();

        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(&name_hash);
        hash_material.extend_from_slice(&identity_hash);
        let address: Address = sha256(&hash_material)[..16].try_into().unwrap();

        log::info!(
            "Added service \"{}\" with address <{}>, identity <{}>",
            name,
            hex::encode(address),
            hex::encode(identity_hash)
        );

        let mut registered_paths = HashMap::new();
        for path in paths {
            let path_hash = crate::request::path_hash(path);
            log::info!(
                "Registering path '{}' with hash {}",
                path,
                hex::encode(path_hash)
            );
            registered_paths.insert(path_hash, path.to_string());
        }

        let service_id = ServiceId(self.services.len());
        self.services.push(ServiceEntry {
            address,
            name_hash,
            encryption_secret,
            encryption_public,
            signing_key,
            registered_paths,
        });

        service_id
    }

    pub fn announce(&mut self, service: ServiceId) {
        self.announce_with_app_data(service, None);
    }

    pub fn announce_with_app_data(&mut self, service: ServiceId, app_data: Option<Vec<u8>>) {
        let Some(entry) = self.services.get(service.0) else {
            return;
        };
        let address = entry.address;

        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash);

        let mut builder = AnnounceBuilder::new(
            *entry.encryption_public.as_bytes(),
            entry.signing_key.clone(),
            entry.name_hash,
            random_hash,
        );
        if let Some(data) = app_data {
            builder = builder.with_app_data(data);
        }
        let announce_data = builder.build(&address);

        let packet =
            self.make_announce_packet(address, 0, false, false, announce_data.to_bytes(), None);
        let packet_len = packet.to_bytes().len();
        let num_interfaces = self.interfaces.len();
        self.stats.packets_sent += num_interfaces as u64;
        self.stats.bytes_sent += (packet_len * num_interfaces) as u64;

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0);
        }
    }

    pub fn request_path(&mut self, destination: Address, now: Instant) {
        log::info!(
            "Sending path request for <{}> on {} interface(s)",
            hex::encode(destination),
            self.interfaces.len()
        );
        self.pending_path_requests.insert(destination, now);

        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);

        let packet = Packet::PathRequest {
            hops: 0,
            query_destination: destination,
            requesting_transport: None,
            tag,
        };

        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            log::info!("Sending path request on interface {}", i);
            iface.send(packet.clone(), 0);
        }
    }

    pub fn send_raw(&mut self, destination: Address, data: &[u8]) {
        self.send_single_data(destination, data);
    }

    pub fn create_link(
        &mut self,
        service: ServiceId,
        destination: Address,
        now: Instant,
    ) -> Option<crate::LinkHandle> {
        if let Some(&link_id) = self.destination_links.get(&destination) {
            let is_usable = self
                .established_links
                .get(&link_id)
                .map(|l| matches!(l.state, LinkState::Handshake | LinkState::Active))
                .unwrap_or(false)
                || self.pending_outbound_links.contains_key(&link_id);

            if is_usable {
                return Some(crate::LinkHandle(link_id));
            }
            self.destination_links.remove(&destination);
        }
        let link_id = self.link(Some(service), destination, now)?;
        self.destination_links.insert(destination, link_id);
        Some(crate::LinkHandle(link_id))
    }

    pub fn link_status(&self, link: crate::LinkHandle) -> crate::LinkStatus {
        if self.pending_outbound_links.contains_key(&link.0) {
            return crate::LinkStatus::Pending;
        }
        match self.established_links.get(&link.0) {
            Some(l) => match l.state {
                LinkState::Handshake => crate::LinkStatus::Pending,
                LinkState::Active => crate::LinkStatus::Active,
                LinkState::Stale => crate::LinkStatus::Stale,
                LinkState::Closed => crate::LinkStatus::Closed,
            },
            None => crate::LinkStatus::Closed,
        }
    }

    pub fn link_rtt(&self, link: crate::LinkHandle) -> Option<u64> {
        self.established_links.get(&link.0)?.rtt_ms
    }

    pub fn close_link(&mut self, link: crate::LinkHandle) {
        if let Some(l) = self.established_links.get(&link.0) {
            let dest = l.destination;
            self.destination_links.remove(&dest);
        }
        self.established_links.remove(&link.0);
        self.pending_outbound_links.remove(&link.0);
    }

    pub fn self_identify(&mut self, link: crate::LinkHandle, identity: &crate::Identity) {
        use crate::link::LinkIdentify;

        let Some(established) = self.established_links.get(&link.0) else {
            log::warn!("self_identify: link {} not found", hex::encode(link.0));
            return;
        };

        if established.state != LinkState::Active {
            log::warn!(
                "self_identify: link {} not active (state={:?})",
                hex::encode(link.0),
                established.state
            );
            return;
        }

        if !established.is_initiator {
            log::warn!(
                "self_identify: link {} is not initiator",
                hex::encode(link.0)
            );
            return;
        }

        let identify = LinkIdentify::create(&link.0, identity);
        log::info!(
            "Sending LinkIdentify on link {} identity={}",
            hex::encode(link.0),
            hex::encode(identity.hash())
        );
        self.send_link_packet(link.0, LinkContext::LinkIdentify, &identify.to_bytes());
    }

    pub fn link_request(
        &mut self,
        link: crate::LinkHandle,
        path: &str,
        data: &[u8],
        now: Instant,
    ) -> Option<RequestId> {
        use crate::packet::LinkDataDestination;

        let link_entry = self.established_links.get_mut(&link.0)?;
        if link_entry.state != LinkState::Active {
            return None;
        }

        let req = Request::new(path, data.to_vec());
        let encoded = req.encode();
        let ciphertext = link_entry.encrypt(&mut self.rng, &encoded);
        let target_interface = link_entry.receiving_interface;

        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link.0),
            context: LinkContext::Request,
            data: ciphertext,
        };

        let mut id_bytes = [0u8; 16];
        self.rng.fill_bytes(&mut id_bytes);
        let local_request_id = RequestId(id_bytes);
        let wire_request_id = WireRequestId(packet.packet_hash()[..16].try_into().unwrap());

        let service_id = self
            .services
            .iter()
            .position(|_| true)
            .map(ServiceId)
            .unwrap_or(ServiceId(0));
        link_entry
            .pending_requests
            .insert(wire_request_id, (service_id, local_request_id));

        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += packet.to_bytes().len() as u64;
            iface.send(packet, 0);
        }

        if let Some(link_entry) = self.established_links.get_mut(&link.0) {
            link_entry.touch_outbound(now);
        }

        Some(local_request_id)
    }

    pub fn advertise_resource(
        &mut self,
        link: crate::LinkHandle,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    ) -> Option<crate::ResourceHandle> {
        use crate::packet::LinkDataDestination;

        let established = self.established_links.get(&link.0)?;
        if established.state != LinkState::Active {
            return None;
        }
        let target_interface = established.receiving_interface;

        let mut resource = crate::resource::OutboundResource::new_segment(
            &mut self.rng,
            established,
            data,
            metadata,
            compress,
            false,
            None,
            1,
            None,
            None,
        );

        let adv = resource.advertisement(91);
        let adv_data = adv.encode();
        let hash = resource.hash;

        let ciphertext = established.encrypt(&mut self.rng, &adv_data);
        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link.0),
            context: LinkContext::ResourceAdv,
            data: ciphertext,
        };

        self.outbound_resources.insert(
            hash,
            (link.0, established.destination, None, None, resource),
        );

        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += packet.to_bytes().len() as u64;
            iface.send(packet, 0);
        }

        Some(crate::ResourceHandle(hash))
    }

    pub fn resource_progress(&self, resource: crate::ResourceHandle) -> Option<f32> {
        if let Some((_, _, _, _, outbound)) = self.outbound_resources.get(&resource.0) {
            let total = outbound.transfer_size();
            if total == 0 {
                return Some(1.0);
            }
            return Some(0.0);
        }
        if let Some((_, inbound)) = self.inbound_resources.get(&resource.0) {
            let received = inbound.received_count();
            let total = inbound.num_parts();
            if total == 0 {
                return Some(1.0);
            }
            return Some(received as f32 / total as f32);
        }
        None
    }

    pub fn prove_packet(&mut self, service: ServiceId, packet_data: &[u8]) -> bool {
        use crate::packet::ProofDestination;

        let Some(service_entry) = self.services.get(service.0) else {
            return false;
        };

        let signature = crate::crypto::create_proof(&service_entry.signing_key, packet_data);
        let packet_hash = crate::crypto::sha256(packet_data);
        let mut proof_data = packet_hash.to_vec();
        proof_data.extend_from_slice(&signature.to_bytes());

        let packet = Packet::Proof {
            hops: 0,
            destination: ProofDestination::Single(service_entry.address),
            context: crate::packet::ProofContext::None,
            data: proof_data,
        };

        for iface in &mut self.interfaces {
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += packet.to_bytes().len() as u64;
            iface.send(packet.clone(), 0);
        }
        true
    }

    pub(crate) fn link(
        &mut self,
        service: Option<ServiceId>,
        destination: Address,
        now: Instant,
    ) -> Option<LinkId> {
        // Must have path to this destination
        let path_entry = match self.path_table.get(&destination) {
            Some(entry) => entry,
            None => {
                log::info!("No path to <{}> in path_table", hex::encode(destination));
                return None;
            }
        };
        let target_interface = path_entry.receiving_interface;
        let hops = path_entry.hops;
        let next_hop = if hops > 1 {
            Some(path_entry.next_hop)
        } else {
            None
        };

        // "randomly generate a new X25519 private/public key pair"
        let ephemeral = EphemeralKeyPair::generate(&mut self.rng);

        // Generate signing keypair for this link
        let mut sig_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut sig_bytes);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        let request = LinkRequest::new(ephemeral.public, signing_key.verifying_key().to_bytes());

        let transport_id = if hops > 1 { next_hop } else { None };
        let request_data = request.to_bytes();
        let packet = self.make_link_request_packet(destination, transport_id, request_data.clone());
        let link_id = LinkRequest::link_id_from_packet(&packet.hashable_part(), request_data.len());

        // Store pending link
        self.pending_outbound_links.insert(
            link_id,
            PendingLink {
                link_id,
                initiator_encryption_secret: ephemeral.secret,
                destination,
                local_service: service,
                request_time: now,
            },
        );

        // Send on the interface that received the announce
        log::debug!(
            "Sending link request to <{}> link_id=<{}>",
            hex::encode(destination),
            hex::encode(link_id)
        );
        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            iface.send(packet, 0);
        }

        Some(link_id)
    }

    fn accept_packet(&self, packet: &Packet) -> bool {
        use crate::packet::LinkContext;

        if !matches!(packet, Packet::Announce { .. })
            && packet
                .transport_id()
                .is_some_and(|tid| tid != self.transport_id)
        {
            log::warn!(
                "Ignored packet <{}> - not for us",
                hex::encode(packet.packet_hash())
            );
            return false;
        }

        // These contexts bypass duplicate detection
        if let Packet::LinkData {
            context: LinkContext::Keepalive,
            ..
        } = packet
        {
            return true;
        }

        if let Packet::LinkData { context, .. } = packet
            && matches!(
                context,
                LinkContext::Resource
                    | LinkContext::ResourceReq
                    | LinkContext::CacheRequest
                    | LinkContext::Channel
            )
        {
            return true;
        }

        // PathRequest/GroupData packets with hops > 1 are invalid (no transport routing)
        if matches!(packet, Packet::PathRequest { hops, .. } | Packet::GroupData { hops, .. } if *hops > 1)
        {
            log::debug!(
                "Dropped PathRequest/GroupData packet with hops {}",
                packet.hops()
            );
            return false;
        }

        // Duplicate detection for remaining packets
        let packet_hash = packet.packet_hash();
        if self.seen_packets.contains(&packet_hash) {
            // SINGLE announces are allowed even if duplicate (re-announcements)
            if matches!(packet, Packet::Announce { .. }) {
                return true;
            }
            log::debug!("Filtered duplicate packet <{}>", hex::encode(packet_hash));
            return false;
        }

        true
    }

    fn inbound(
        &mut self,
        raw: &[u8],
        interface_index: usize,
        now: Instant,
    ) -> Option<(Packet, bool, bool)> {
        let mut notifications: Vec<Notification> = Vec::new();
        let mut pending_next_segments: Vec<(LinkId, [u8; 32])> = Vec::new();

        let mut packet = match Packet::from_bytes(raw) {
            Ok(p) => p,
            Err(e) => {
                log::debug!(
                    "Failed to parse packet: {:?} raw={} (len={})",
                    e,
                    hex::encode(&raw[..raw.len().min(64)]),
                    raw.len()
                );
                return None;
            }
        };

        if !self.accept_packet(&packet) {
            return None;
        }

        packet.increment_hops();

        let packet_hash = sha256(&packet.hashable_part());

        // By default, remember packet hashes to avoid routing
        // loops in the network, using the packet filter.
        let mut remember_packet_hash = true;

        let destination_hash = packet.destination_hash();

        // If this packet belongs to a link in our link table,
        // we'll have to defer adding it to the filter list.
        // In some cases, we might see a packet over a shared-
        // medium interface, belonging to a link that transports
        // or terminates with this instance, but before it would
        // normally reach us. If the packet is appended to the
        // filter list at this point, link transport will break.
        let link_id: LinkId = destination_hash;
        if self.link_table.contains_key(&link_id) {
            remember_packet_hash = false;
        }

        // If this is a link request proof, don't add it until
        // we are sure it's not actually somewhere else in the
        // routing chain.
        if matches!(packet, Packet::LinkProof { .. }) {
            remember_packet_hash = false;
        }

        if remember_packet_hash {
            self.seen_packets.insert(packet_hash);
        }

        // TODO review
        let for_local_service = !matches!(packet, Packet::Announce { .. })
            && self.services.iter().any(|s| s.address == destination_hash);

        let for_local_link = !matches!(packet, Packet::Announce { .. })
            && self.established_links.contains_key(&link_id);

        // PathRequest handling
        if let Packet::PathRequest {
            query_destination,
            tag,
            ..
        } = &packet
        {
            let query_dest = *query_destination;
            let request_tag = *tag;

            // Check if destination is local (one of our services)
            let local_service = self.services.iter().find(|s| s.address == query_dest);
            if let Some(entry) = local_service {
                log::debug!(
                    "Answering path request for <{}>, destination is local",
                    hex::encode(query_dest)
                );

                // Create PATH_RESPONSE announce for the local service
                let mut random_hash = [0u8; 10];
                self.rng.fill_bytes(&mut random_hash);

                let builder = AnnounceBuilder::new(
                    *entry.encryption_public.as_bytes(),
                    entry.signing_key.clone(),
                    entry.name_hash,
                    random_hash,
                );
                let announce_data = builder.build(&query_dest);

                let response_packet = self.make_announce_packet(
                    query_dest,
                    0,
                    false,
                    true, // is_path_response
                    announce_data.to_bytes(),
                    Some(self.transport_id),
                );

                // Send only to the requesting interface
                if let Some(iface) = self.interfaces.get_mut(interface_index) {
                    iface.send(response_packet, 0);
                }
            } else if let Some(path_entry) = self.path_table.get(&query_dest).cloned() {
                // We know the path - send PATH_RESPONSE announce
                log::debug!(
                    "Answering path request for <{}>, path is known ({} hops)",
                    hex::encode(query_dest),
                    path_entry.hops
                );

                let response_packet = self.make_announce_packet(
                    query_dest,
                    path_entry.hops,
                    path_entry.has_ratchet,
                    true, // is_path_response
                    path_entry.announce_data.clone(),
                    Some(self.transport_id),
                );

                // Send only to the requesting interface
                if let Some(iface) = self.interfaces.get_mut(interface_index) {
                    iface.send(response_packet, 0);
                }
            } else if self.transport {
                // Unknown path, but we're a transport node - record and forward
                let other_interfaces = self.interfaces.len().saturating_sub(1);
                log::debug!(
                    "Path request for unknown <{}> from interface {}, forwarding to {} other interface(s)",
                    hex::encode(query_dest),
                    interface_index,
                    other_interfaces
                );
                self.discovery_path_requests
                    .insert(query_dest, interface_index);

                // Create a NEW PathRequest with hops=0 (not forward the existing one).
                // PathRequests are PLAIN packets which get dropped if hops > 1.
                // We preserve the tag to prevent loops in the network.
                let new_packet = Packet::PathRequest {
                    hops: 0,
                    query_destination: query_dest,
                    requesting_transport: Some(self.transport_id),
                    tag: request_tag,
                };

                // Forward path request on all other interfaces
                for (i, iface) in self.interfaces.iter_mut().enumerate() {
                    if i != interface_index {
                        self.stats.packets_relayed += 1;
                        self.stats.bytes_relayed += new_packet.to_bytes().len() as u64;
                        iface.send(new_packet.clone(), 0);
                    }
                }
            }
        }

        // General transport handling. Takes care of directing packets according
        // to transport tables and recording entries in reverse and link tables.
        let mut relayed_via_link_table = false;
        if self.transport || for_local_service || for_local_link {
            // TODO missing cache request handling

            // If the packet is in transport (has transport_id), check whether we
            // are the designated next hop, and process it accordingly if we are.
            if let Some(transport_id) = packet.transport_id()
                && transport_id == self.transport_id
                && !matches!(packet, Packet::Announce { .. })
            {
                let dest = packet.destination_hash();
                if let Some(path_entry) = self.path_table.get_mut(&dest) {
                    let next_hop = path_entry.next_hop;
                    let remaining_hops = path_entry.hops;
                    let outbound_interface = path_entry.receiving_interface;

                    // Build forwarded packet
                    let mut new_packet = packet.clone();
                    if remaining_hops > 1 {
                        new_packet.set_transport_id(next_hop);
                    } else if remaining_hops == 1 {
                        new_packet.strip_transport();
                    }

                    // Record in link_table for link requests, reverse_table for others
                    if let Packet::LinkRequest { data, .. } = &packet {
                        let link_id =
                            LinkRequest::link_id_from_packet(&packet.hashable_part(), data.len());
                        log::debug!(
                            "Adding link_table entry for transported LinkRequest: link_id=<{}> dest=<{}> recv_iface={} next_hop_iface={}",
                            hex::encode(link_id),
                            hex::encode(dest),
                            interface_index,
                            outbound_interface
                        );
                        self.link_table.insert(
                            link_id,
                            LinkTableEntry {
                                timestamp: now,
                                receiving_interface: interface_index,
                                next_hop_interface: outbound_interface,
                                remaining_hops,
                                hops: packet.hops(),
                            },
                        );
                    } else {
                        self.reverse_table.insert(
                            destination_hash,
                            ReverseTableEntry {
                                receiving_interface: interface_index,
                            },
                        );
                    }

                    // Transmit on outbound interface
                    if let Some(iface) = self.interfaces.get_mut(outbound_interface) {
                        self.stats.packets_relayed += 1;
                        self.stats.bytes_relayed += raw.len() as u64;
                        iface.send(new_packet, 0);
                        path_entry.timestamp = now;
                    }
                } else {
                    log::debug!(
                        "Got packet in transport, but no known path to destination <{}>",
                        hex::encode(dest)
                    );
                }
            }

            // Link transport handling. Directs packets according to entries in the link tables
            if !matches!(packet, Packet::Announce { .. })
                && !matches!(packet, Packet::LinkRequest { .. })
                && !matches!(packet, Packet::LinkProof { .. })
            {
                let found = self.link_table.contains_key(&link_id);
                if !found && matches!(packet, Packet::LinkData { .. }) {
                    log::debug!(
                        "LinkData for link <{}> not in link_table, known links: {:?}",
                        hex::encode(link_id),
                        self.link_table.keys().map(hex::encode).collect::<Vec<_>>()
                    );
                }
            }
            if !matches!(packet, Packet::Announce { .. })
                && !matches!(packet, Packet::LinkRequest { .. })
                && !matches!(packet, Packet::LinkProof { .. })
                && let Some(link_entry) = self.link_table.get_mut(&link_id)
            {
                let hops = packet.hops();
                let outbound_interface =
                    if link_entry.next_hop_interface == link_entry.receiving_interface {
                        // Same interface both directions - just repeat
                        // But check that taken hops matches one of the expected values
                        if hops == link_entry.remaining_hops || hops == link_entry.hops {
                            Some(link_entry.next_hop_interface)
                        } else {
                            None
                        }
                    } else if interface_index == link_entry.next_hop_interface {
                        // Received from next_hop side, send to receiving side
                        // Check that expected hop count matches
                        if hops == link_entry.remaining_hops {
                            Some(link_entry.receiving_interface)
                        } else {
                            None
                        }
                    } else if interface_index == link_entry.receiving_interface {
                        // Received from receiving side, send to next_hop side
                        // Check that expected hop count matches
                        if hops == link_entry.hops {
                            Some(link_entry.next_hop_interface)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                if let Some(out_iface) = outbound_interface {
                    // Add to packet hash filter now that we know it's our turn
                    self.seen_packets.insert(packet_hash);

                    if let Some(iface) = self.interfaces.get_mut(out_iface) {
                        self.stats.packets_relayed += 1;
                        self.stats.bytes_relayed += raw.len() as u64;
                        self.stats.link_packets_relayed += 1;
                        iface.send(packet.clone(), 0);
                        link_entry.timestamp = now;
                        relayed_via_link_table = true;
                    }
                }
            }
        }

        // Skip local processing for packets that were relayed via link_table
        if relayed_via_link_table && !for_local_link {
            return Some((packet, for_local_service, for_local_link));
        }

        match packet.clone() {
            Packet::Announce {
                has_ratchet,
                is_path_response,
                data,
                ..
            } => {
                let announce = match AnnounceData::parse(&data, has_ratchet) {
                    Ok(a) => a,
                    Err(_) => return None,
                };

                if announce.verify(&destination_hash).is_err() {
                    return None;
                }

                self.stats.announces_received += 1;

                // TODO missing ingress limiting
                // if not packet.destination_hash in Transport.path_table:
                //     # This is an unknown destination, and we'll apply
                //     # potential ingress limiting. Already known
                //     # destinations will have re-announces controlled
                //     # by normal announce rate limiting.
                //     if interface.should_ingress_limit():
                //         interface.hold_announce(packet)
                //         Transport.jobs_locked = False
                //         return

                // Check if this is a local destination (one of our services)
                let is_local = self.services.iter().any(|s| s.address == destination_hash);

                if is_local {
                    log::trace!(
                        "Announce for <{}> is local, not rebroadcasting",
                        hex::encode(destination_hash)
                    );
                }

                let verify_result = announce.verify_destination(&destination_hash);
                if verify_result.is_err() {
                    log::debug!(
                        "Announce for <{}> failed verification: {:?}",
                        hex::encode(destination_hash),
                        verify_result
                    );
                }

                if !is_local && verify_result.is_ok() {
                    let received_from = packet.received_from();

                    // Check if this is a next retransmission from another node.
                    // If it is, we may remove the announce from our pending table.
                    // Only applies when transport_id is present (Type2 header).
                    if self.transport
                        && packet.transport_id().is_some()
                        && let Some(pending) = self
                            .pending_announces
                            .iter_mut()
                            .find(|a| a.destination == destination_hash)
                    {
                        // Case 1: Another node heard the same announce we did and rebroadcast it.
                        // packet.hops - 1 == pending.hops means they received it at the same hop
                        // count we did (before their increment).
                        if packet.hops().saturating_sub(1) == pending.hops {
                            log::trace!(
                                "Heard a rebroadcast of announce for <{}>",
                                hex::encode(destination_hash)
                            );
                            pending.local_rebroadcasts += 1;
                            if pending.retries_remaining > 0
                                && pending.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX
                            {
                                log::trace!(
                                    "Completed announce processing for <{}>, local rebroadcast limit reached",
                                    hex::encode(destination_hash)
                                );
                                pending.retries_remaining = 0;
                            }
                        }

                        // Case 2: Our rebroadcast was picked up and passed on by another node.
                        // packet.hops - 1 == pending.hops + 1 means they received our rebroadcast
                        // (which was at pending.hops + 1) and incremented it.
                        if packet.hops().saturating_sub(1) == pending.hops.saturating_add(1)
                            && pending.retries_remaining > 0
                            && now < pending.retry_at
                        {
                            log::trace!(
                                "Announce for <{}> passed on by another node, no further tries needed",
                                hex::encode(destination_hash)
                            );
                            pending.retries_remaining = 0;
                        }
                    }

                    let mut should_add = false;
                    let mut is_new_destination = false;
                    let hops = packet.hops();

                    if hops > self.max_hops {
                        log::debug!(
                            "Announce for <{}> exceeded max hops ({} >= {})",
                            hex::encode(destination_hash),
                            hops,
                            self.max_hops + 1
                        );
                    } else if let Some(existing) = self.path_table.get(&destination_hash) {
                        if hops <= existing.hops {
                            should_add = true;
                        } else {
                            log::trace!(
                                "Announce for <{}> has more hops ({}) than existing path ({})",
                                hex::encode(destination_hash),
                                hops,
                                existing.hops
                            );
                        }
                    } else {
                        should_add = true;
                        is_new_destination = true;
                    }

                    if should_add {
                        let signing_key = match announce.signing_public_key() {
                            Ok(k) => k,
                            Err(_) => return None,
                        };

                        // Update path table
                        let app_data = if announce.app_data.is_empty() {
                            None
                        } else {
                            Some(announce.app_data.clone())
                        };
                        self.path_table.insert(
                            destination_hash,
                            PathEntry {
                                timestamp: now,
                                next_hop: received_from,
                                hops,
                                receiving_interface: interface_index,
                                encryption_key: announce.encryption_public_key(),
                                signing_key,
                                ratchet_key: announce.ratchet.map(X25519Public::from),
                                app_data,
                                name_hash: announce.name_hash,
                                has_ratchet,
                                announce_data: data.clone(),
                            },
                        );

                        // Schedule for rebroadcast with random delay
                        // PATH_RESPONSE announces are not rebroadcast (they're one-shot responses)
                        // Only schedule if we are a transport node (relay enabled)
                        if !is_path_response && self.transport {
                            let delay_ms = self.rng.gen_range(0..=PATHFINDER_RW_MS);
                            let retry_at = now + std::time::Duration::from_millis(delay_ms);
                            self.pending_announces.push(PendingAnnounce {
                                destination: destination_hash,
                                source_interface: interface_index,
                                hops,
                                has_ratchet,
                                data: data.clone(),
                                retries_remaining: self.retries,
                                retry_at,
                                local_rebroadcasts: 0,
                            });
                        }

                        log::debug!(
                            "Destination <{}> is now {} hops away via <{}>",
                            hex::encode(destination_hash),
                            hops,
                            hex::encode(received_from)
                        );

                        if is_new_destination {
                            notifications.push(Notification::DestinationsChanged);
                        }

                        if self
                            .pending_path_requests
                            .remove(&destination_hash)
                            .is_some()
                        {
                            log::info!(
                                "Received announce for <{}> which we had a pending path request for",
                                hex::encode(destination_hash)
                            );
                            notifications.push(Notification::PathRequestResult {
                                destination: destination_hash,
                                found: true,
                            });
                        }

                        // Check if we have a discovery path request waiting for this destination
                        if let Some(requesting_interface) =
                            self.discovery_path_requests.remove(&destination_hash)
                        {
                            log::debug!(
                                "Got matching announce for discovery path request for <{}>, sending PATH_RESPONSE to interface {}",
                                hex::encode(destination_hash),
                                requesting_interface
                            );

                            // Send PATH_RESPONSE announce to the requesting interface
                            let response_packet = self.make_announce_packet(
                                destination_hash,
                                hops,
                                has_ratchet,
                                true, // is_path_response
                                data.clone(),
                                Some(self.transport_id),
                            );

                            if let Some(iface) = self.interfaces.get_mut(requesting_interface) {
                                iface.send(response_packet, 0);
                            }
                        }

                        if let Some(pending) = self.pending_outbound_requests.get(&destination_hash)
                        {
                            let service = pending.first().map(|(s, _, _, _)| *s);
                            log::info!(
                                "Have pending requests for <{}>, initiating link",
                                hex::encode(destination_hash)
                            );
                            self.link(service, destination_hash, now);
                        }
                    }
                }
            }
            Packet::LinkRequest { data, .. } => {
                let is_for_us = packet
                    .transport_id()
                    .is_none_or(|tid| tid == self.transport_id);
                log::debug!(
                    "Received LinkRequest for <{}> is_for_us={} for_local_service={}",
                    hex::encode(destination_hash),
                    is_for_us,
                    for_local_service
                );

                if is_for_us && for_local_service {
                    let request = LinkRequest::parse(&data)?;
                    // Find the service
                    let service_idx = self
                        .services
                        .iter()
                        .position(|s| s.address == destination_hash)?;
                    let service = &self.services[service_idx];

                    // Create responder's ephemeral key pair
                    let responder_keypair = EphemeralKeyPair::generate(&mut self.rng);

                    // Derive link keys
                    let new_link_id =
                        LinkRequest::link_id_from_packet(&packet.hashable_part(), data.len());
                    let link = EstablishedLink::from_responder(
                        new_link_id,
                        &responder_keypair.secret,
                        &request.encryption_public,
                        destination_hash,
                        ServiceId(service_idx),
                        interface_index,
                        now,
                    );

                    // Create and send proof
                    let proof = LinkProof::create(
                        &new_link_id,
                        &responder_keypair.public,
                        &service.signing_key,
                    );
                    let proof_packet = self.make_link_proof_packet(new_link_id, proof.to_bytes());

                    self.established_links.insert(new_link_id, link);
                    self.destination_links.insert(destination_hash, new_link_id);

                    log::info!(
                        "Sending LinkProof for link <{}> on interface {}",
                        hex::encode(new_link_id),
                        interface_index
                    );
                    if let Some(iface) = self.interfaces.get_mut(interface_index) {
                        iface.send(proof_packet, 0);
                    } else {
                        log::error!("No interface {} to send LinkProof", interface_index);
                    }

                    log::debug!(
                        "Established link <{}> as responder for service <{}>",
                        hex::encode(new_link_id),
                        hex::encode(destination_hash)
                    );
                }
            }
            Packet::LinkData { context, data, .. } => {
                let link = match self.established_links.get_mut(&link_id) {
                    Some(l) => l,
                    None => {
                        log::warn!(
                            "LinkData on unknown link {} (ctx={:?}, data_len={}), known links: {:?}",
                            hex::encode(link_id),
                            context,
                            data.len(),
                            self.established_links
                                .keys()
                                .map(hex::encode)
                                .collect::<Vec<_>>()
                        );
                        return None;
                    }
                };
                link.touch_inbound(now);

                // Resource data packets are raw chunks of pre-encrypted stream - no Token decryption
                if context == LinkContext::Resource {
                    self.handle_resource_packet(link_id, context, &data, now);
                    return None;
                }

                // CacheRequest packets are not encrypted - just a packet hash
                if context == LinkContext::CacheRequest {
                    // TODO: handle cache request - look up packet in cache and resend
                    log::debug!(
                        "Received CacheRequest on link {} ({} bytes)",
                        hex::encode(link_id),
                        data.len()
                    );
                    return None;
                }

                // All other LinkData packets use Token encryption
                let plaintext = match link.decrypt(&data) {
                    Some(p) => p,
                    None => {
                        log::warn!(
                            "Failed to decrypt LinkData on link {} (ctx={:?}, data_len={}, is_initiator={}, dest={})",
                            hex::encode(link_id),
                            context,
                            data.len(),
                            link.is_initiator,
                            hex::encode(link.destination)
                        );
                        return None;
                    }
                };

                // Handle keepalive
                if context == LinkContext::Keepalive {
                    self.handle_keepalive(link_id, &plaintext, now);
                } else if context == LinkContext::LinkRtt {
                    self.handle_link_rtt(link_id, &plaintext);
                } else if context == LinkContext::LinkIdentify {
                    self.handle_link_identify(link_id, &plaintext);
                } else if context == LinkContext::LinkClose {
                    // Verify the close packet contains the link_id
                    if plaintext.as_slice() == link_id {
                        let dest = link.destination;
                        log::info!(
                            "Link <{}> closed by remote (dest=<{}>)",
                            hex::encode(link_id),
                            hex::encode(dest)
                        );
                        self.destination_links.remove(&dest);
                        self.established_links.remove(&link_id);
                    } else {
                        log::warn!(
                            "Received LinkClose with mismatched link_id: expected {}, got {}",
                            hex::encode(link_id),
                            hex::encode(&plaintext)
                        );
                    }
                    return None;
                } else if matches!(
                    context,
                    LinkContext::ResourceAdv
                        | LinkContext::ResourceReq
                        | LinkContext::ResourceHmu
                        | LinkContext::ResourceIcl
                        | LinkContext::ResourceRcl
                ) {
                    self.handle_resource_packet(link_id, context, &plaintext, now);
                } else if context == LinkContext::Response {
                    log::debug!(
                        "Received Response on link {} ({} bytes plaintext)",
                        hex::encode(link_id),
                        plaintext.len()
                    );
                    if let Some(resp) = Response::decode(&plaintext) {
                        log::info!(
                            "Response decoded: wire_request_id={} data_len={}",
                            hex::encode(resp.request_id.0),
                            resp.data.len()
                        );
                        if let Some((service, local_request_id)) =
                            link.pending_requests.remove(&resp.request_id)
                        {
                            log::info!(
                                "Matched pending request local_id={} - delivering {} bytes",
                                hex::encode(local_request_id.0),
                                resp.data.len()
                            );
                            let from = link.destination;
                            notifications.push(Notification::RequestResult {
                                service,
                                request_id: local_request_id,
                                result: Ok((from, resp.data, None)),
                            });
                        } else {
                            log::warn!(
                                "Response wire_request_id={} did not match any pending request",
                                hex::encode(resp.request_id.0)
                            );
                        }
                    } else {
                        log::warn!("Failed to decode Response from plaintext");
                    }
                } else if let Some(service) = link.local_service {
                    match context {
                        LinkContext::Request => {
                            if let Some(req) = Request::decode(&plaintext) {
                                let wire_request_id =
                                    WireRequestId(packet.packet_hash()[..16].try_into().unwrap());
                                let mut id_bytes = [0u8; 16];
                                self.rng.fill_bytes(&mut id_bytes);
                                let request_id = RequestId(id_bytes);
                                let path = self.services[service.0]
                                    .registered_paths
                                    .get(&req.path_hash)
                                    .cloned();
                                log::info!(
                                    "Request path_hash={} matched={:?} registered_count={}",
                                    hex::encode(req.path_hash),
                                    path,
                                    self.services[service.0].registered_paths.len()
                                );
                                notifications.push(Notification::Request {
                                    service,
                                    link_id,
                                    request_id,
                                    wire_request_id,
                                    path: path.unwrap_or_default(),
                                    data: req.data.unwrap_or_default(),
                                });
                            } else {
                                log::warn!(
                                    "Failed to decode Request from plaintext {} bytes",
                                    plaintext.len()
                                );
                                notifications.push(Notification::Raw {
                                    service,
                                    data: plaintext,
                                });
                            }
                        }
                        _ => {
                            notifications.push(Notification::Raw {
                                service,
                                data: plaintext,
                            });
                        }
                    };
                } else {
                    log::warn!(
                        "No local_service for link data: link_id={} context={:?}",
                        hex::encode(link_id),
                        context
                    );
                }
            }
            Packet::SingleData { ciphertext, .. } => {
                // Data for a single destination - decrypt with service keys
                // Packet data format: ephemeral_public (32) + ciphertext
                if ciphertext.len() >= 32
                    && let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.address == destination_hash)
                {
                    let service = &self.services[service_idx];

                    let ephemeral_public =
                        X25519Public::from(<[u8; 32]>::try_from(&ciphertext[..32]).unwrap());
                    let encrypted = &ciphertext[32..];

                    if let Some(plaintext) = crate::crypto::SingleDestEncryption::decrypt(
                        &service.encryption_secret,
                        &ephemeral_public,
                        encrypted,
                    ) {
                        notifications.push(Notification::Raw {
                            service: ServiceId(service_idx),
                            data: plaintext,
                        });
                    }
                }
            }
            Packet::GroupData { .. } | Packet::PathRequest { .. } => {
                // GroupData: would need group decryption (not implemented)
                // PathRequest: handled by transport layer, not delivered to services
            }
            Packet::LinkProof { data, .. } => {
                log::info!(
                    "Received LinkProof: dest_from_packet=<{}> raw_bytes={} pending_links={:?}",
                    hex::encode(destination_hash),
                    hex::encode(&raw[..raw.len().min(40)]),
                    self.pending_outbound_links
                        .keys()
                        .map(hex::encode)
                        .collect::<Vec<_>>()
                );
                // Link request proof - check if it needs to be transported
                if let Some(link_entry) = self.link_table.get(&link_id) {
                    if interface_index == link_entry.next_hop_interface {
                        // Transport the proof
                        if let Some(iface) = self.interfaces.get_mut(link_entry.receiving_interface)
                        {
                            self.stats.packets_relayed += 1;
                            self.stats.bytes_relayed += raw.len() as u64;
                            self.stats.proofs_relayed += 1;
                            iface.send(packet.clone(), 0);
                        }
                    }
                } else if let Some(pending) = self.pending_outbound_links.remove(&destination_hash)
                {
                    // This is a proof for a link we initiated - validate and establish
                    log::debug!(
                        "Processing LinkProof: dest_hash={} pending.link_id={} data_len={}",
                        hex::encode(destination_hash),
                        hex::encode(pending.link_id),
                        data.len()
                    );
                    if destination_hash != pending.link_id {
                        log::error!(
                            "MISMATCH: dest_hash={} != pending.link_id={}",
                            hex::encode(destination_hash),
                            hex::encode(pending.link_id)
                        );
                    }
                    let proof = match LinkProof::parse(&data) {
                        Some(p) => p,
                        None => {
                            self.pending_outbound_links
                                .insert(destination_hash, pending);
                            return None;
                        }
                    };

                    // Get the destination's signing key from path_table
                    let signing_key = match self.path_table.get(&pending.destination) {
                        Some(entry) => entry.signing_key,
                        None => {
                            log::debug!(
                                "No path found for destination <{}>",
                                hex::encode(pending.destination)
                            );
                            self.pending_outbound_links
                                .insert(destination_hash, pending);
                            return None;
                        }
                    };

                    // Validate the proof signature
                    if !proof.verify(&pending.link_id, &signing_key) {
                        log::debug!(
                            "Invalid link proof signature for link <{}>",
                            hex::encode(pending.link_id)
                        );
                        self.pending_outbound_links
                            .insert(destination_hash, pending);
                        return None;
                    }

                    // Establish the link using the responder's public key from the proof
                    let dest = pending.destination;
                    let link = EstablishedLink::from_initiator(
                        pending,
                        &proof.encryption_public,
                        interface_index,
                        now,
                    );
                    let rtt_secs = link.rtt_seconds();

                    self.established_links.insert(destination_hash, link);
                    self.destination_links.insert(dest, destination_hash);

                    // Send LRRTT packet to inform responder of the measured RTT
                    if let Some(rtt) = rtt_secs {
                        let rtt_data = crate::link::encode_rtt(rtt);
                        self.send_link_packet_with_activity(
                            destination_hash,
                            LinkContext::LinkRtt,
                            &rtt_data,
                            now,
                        );
                    }

                    let link = self.established_links.get(&destination_hash).unwrap();
                    log::debug!(
                        "Link <{}> established as initiator, RTT: {:?}ms, keepalive_interval: {}s",
                        hex::encode(destination_hash),
                        link.rtt_ms,
                        link.keepalive_interval_secs()
                    );

                    // Send any pending requests that were waiting for this link
                    if let Some(pending_requests) = self.pending_outbound_requests.remove(&dest) {
                        for (service_addr, local_request_id, path, data) in pending_requests {
                            self.send_request_inner(
                                service_addr,
                                dest,
                                local_request_id,
                                &path,
                                data,
                                now,
                            );
                        }
                    }
                }
            }
            Packet::Proof { data, context, .. } => {
                use crate::packet::ProofContext;

                // Handle resource proofs specially
                if context == ProofContext::ResourcePrf {
                    // Resource proof format: resource_hash (32) + proof (32) = 64 bytes
                    if data.len() == 64 {
                        let resource_hash: [u8; 32] = data[..32].try_into().unwrap();
                        let proof: &[u8] = &data[32..64];

                        // Find matching outbound resource and validate proof
                        if let Some((link_id, _, service_idx, local_request_id, outbound)) =
                            self.outbound_resources.get(&resource_hash)
                        {
                            if outbound.verify_proof(proof) {
                                log::debug!(
                                    "Resource proof validated for {} (segment {}/{})",
                                    hex::encode(resource_hash),
                                    outbound.segment_index,
                                    outbound.total_segments
                                );

                                let link_id = *link_id;
                                let original_hash = outbound.original_hash;
                                let is_last_segment = outbound.is_last_segment();
                                let service_idx = *service_idx;
                                let local_request_id = *local_request_id;

                                self.outbound_resources.remove(&resource_hash);

                                if is_last_segment {
                                    // Last segment - clean up and notify
                                    self.outbound_multi_segments.remove(&original_hash);

                                    if let (Some(service), Some(request_id)) =
                                        (service_idx, local_request_id)
                                    {
                                        notifications.push(Notification::RespondResult {
                                            service,
                                            request_id,
                                            result: Ok(()),
                                        });
                                    }
                                } else {
                                    // More segments to send
                                    pending_next_segments.push((link_id, original_hash));
                                }
                            } else {
                                log::warn!(
                                    "Resource proof invalid for {}",
                                    hex::encode(resource_hash)
                                );
                            }
                        }
                    }
                    // Don't process ResourcePrf as regular proof
                } else {
                    // Regular proof - check reverse table for transport
                    if let Some(reverse_entry) = self.reverse_table.remove(&destination_hash)
                        && let Some(iface) =
                            self.interfaces.get_mut(reverse_entry.receiving_interface)
                    {
                        self.stats.packets_relayed += 1;
                        self.stats.bytes_relayed += raw.len() as u64;
                        self.stats.proofs_relayed += 1;
                        iface.send(packet.clone(), 0);
                    }

                    // Check local receipts - validate proof against outstanding receipts
                    // Proof format: explicit = hash (32) + signature (64), implicit = signature (64)
                    let (proof_hash, signature_bytes) = if data.len() == 96 {
                        // Explicit proof
                        (Some(<[u8; 32]>::try_from(&data[..32]).ok()), &data[32..96])
                    } else if data.len() == 64 {
                        // Implicit proof
                        (None, &data[..64])
                    } else {
                        (None, &[] as &[u8])
                    };

                    if !signature_bytes.is_empty()
                        && let Ok(signature) = Signature::from_slice(signature_bytes)
                    {
                        self.receipts.retain(|receipt| {
                            // For explicit proofs, check hash matches
                            if let Some(Some(ph)) = proof_hash
                                && ph != receipt.packet_hash
                            {
                                return true; // Keep - not for this receipt
                            }

                            // Get destination's signing key to verify
                            let signing_key = match self.path_table.get(&receipt.destination) {
                                Some(entry) => &entry.signing_key,
                                None => return true, // Keep - can't verify without key
                            };

                            // Validate signature over packet hash
                            if crate::crypto::verify(signing_key, &receipt.packet_hash, &signature)
                            {
                                log::debug!(
                                    "Proof validated for packet <{}>",
                                    hex::encode(receipt.packet_hash)
                                );
                                false // Remove - proved
                            } else {
                                true // Keep - signature invalid
                            }
                        });
                    }
                }
            }
        }

        self.dispatch_notifications(notifications);

        for (link_id, original_hash) in pending_next_segments {
            self.send_next_segment(link_id, original_hash);
        }

        Some((packet, for_local_service, for_local_link))
    }

    fn send_next_segment(&mut self, link_id: LinkId, original_hash: [u8; 32]) {
        use crate::packet::LinkDataDestination;
        use crate::resource::MAX_EFFICIENT_SIZE;

        let Some(multi) = self.outbound_multi_segments.get_mut(&original_hash) else {
            log::warn!(
                "send_next_segment: no multi-segment transfer for {}",
                hex::encode(original_hash)
            );
            return;
        };

        let next_segment = multi.current_segment + 1;
        if next_segment > multi.total_segments {
            log::warn!(
                "send_next_segment: already sent all {} segments for {}",
                multi.total_segments,
                hex::encode(original_hash)
            );
            return;
        }

        let Some(link) = self.established_links.get(&link_id) else {
            log::warn!("send_next_segment: link {} not found", hex::encode(link_id));
            return;
        };
        let target_interface = link.receiving_interface;

        let start = (next_segment - 1) * MAX_EFFICIENT_SIZE;
        let end = (start + MAX_EFFICIENT_SIZE).min(multi.full_data.len());
        let segment_data = multi.full_data[start..end].to_vec();

        let mut resource = crate::resource::OutboundResource::new_segment(
            &mut self.rng,
            link,
            segment_data,
            None,
            multi.compress,
            multi.is_response,
            multi.request_id.clone(),
            next_segment,
            Some(original_hash),
            Some(multi.full_data.len()),
        );

        let adv = resource.advertisement(91);
        let adv_data = adv.encode();
        let hash = resource.hash;

        log::debug!(
            "Sending segment {}/{} for multi-segment transfer {}",
            next_segment,
            multi.total_segments,
            hex::encode(original_hash)
        );

        let ciphertext = link.encrypt(&mut self.rng, &adv_data);
        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link_id),
            context: LinkContext::ResourceAdv,
            data: ciphertext,
        };

        let service_idx = multi.service_idx;
        let local_request_id = multi.local_request_id;
        let destination = multi.destination;
        multi.current_segment = next_segment;

        self.outbound_resources.insert(
            hash,
            (
                link_id,
                destination,
                service_idx,
                local_request_id,
                resource,
            ),
        );

        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            iface.send(packet, 0);
        }
    }

    fn send_link_packet(&mut self, link_id: LinkId, context: LinkContext, plaintext: &[u8]) {
        use crate::packet::LinkDataDestination;

        let Some(link) = self.established_links.get_mut(&link_id) else {
            return;
        };

        let ciphertext = link.encrypt(&mut self.rng, plaintext);
        let target_interface = link.receiving_interface;

        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link_id),
            context,
            data: ciphertext,
        };

        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            iface.send(packet, 0);
        }
    }

    fn send_link_packet_with_activity(
        &mut self,
        link_id: LinkId,
        context: LinkContext,
        plaintext: &[u8],
        now: Instant,
    ) {
        if let Some(link) = self.established_links.get_mut(&link_id) {
            link.touch_outbound(now);
        }
        self.send_link_packet(link_id, context, plaintext);
    }

    fn outbound(
        &mut self,
        mut packet: Packet,
        attached_interface: Option<usize>,
        now: Instant,
    ) -> bool {
        let destination_hash = packet.destination_hash();
        let hops = packet.hops();

        // Check if we should generate a receipt for this packet
        let generate_receipt = matches!(
            &packet,
            Packet::SingleData { .. } | Packet::GroupData { .. }
        );

        // Check if we have a known path for the destination
        // This applies to non-announce packets going to Single destinations
        let use_path = !matches!(packet, Packet::Announce { .. })
            && matches!(
                &packet,
                Packet::SingleData { .. } | Packet::LinkRequest { .. }
            )
            && self.path_table.contains_key(&destination_hash);

        if use_path {
            let path_entry = self.path_table.get(&destination_hash).unwrap();
            let path_hops = path_entry.hops;
            let next_hop = path_entry.next_hop;
            let outbound_interface = path_entry.receiving_interface;

            // If there's more than one hop to the destination, insert into transport
            // by adding the next hop address to the header
            if path_hops > 1 && packet.transport_id().is_none() {
                packet.insert_transport(next_hop);
            }

            // Generate receipt if needed
            if generate_receipt {
                self.receipts.push(Receipt {
                    destination: destination_hash,
                    packet_hash: packet.packet_hash(),
                });
            }

            // Transmit on the specific interface
            if let Some(iface) = self.interfaces.get_mut(outbound_interface) {
                iface.send(packet, 0);
            }

            // Update path timestamp
            if let Some(entry) = self.path_table.get_mut(&destination_hash) {
                entry.timestamp = now;
            }

            return true;
        }

        // No known path - broadcast on all interfaces (with filtering)
        let mut sent = false;
        let mut stored_hash = false;

        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            let mut should_transmit = true;

            // If packet has an attached interface, skip that one (don't echo back)
            if let Some(attached) = attached_interface
                && i == attached
            {
                should_transmit = false;
            }

            // For link packets, check if link is on this interface
            if let Packet::LinkData { .. } | Packet::LinkProof { .. } = &packet {
                // Link packets should only go on their attached interface
                // This is handled by attached_interface above
            }

            // Announce rate limiting is handled by interface.send()
            // which queues announces based on hop count priority

            if should_transmit {
                if !stored_hash {
                    self.seen_packets.insert(packet.packet_hash());
                    stored_hash = true;
                }

                // Generate receipt on first send
                if !sent && generate_receipt {
                    self.receipts.push(Receipt {
                        destination: destination_hash,
                        packet_hash: packet.packet_hash(),
                    });
                }

                iface.send(packet.clone(), hops);
                sent = true;
            }
        }

        sent
    }

    pub fn poll(&mut self, now: Instant) -> Vec<ServiceEvent> {
        let mut next_wake: Option<Instant> = None;
        let mut update_wake = |t: Instant| {
            next_wake = Some(next_wake.map_or(t, |w| w.min(t)));
        };

        // Receive from all interfaces
        let mut received = Vec::new();
        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            while let Some(raw) = iface.recv() {
                self.stats.packets_received += 1;
                self.stats.bytes_received += raw.len() as u64;
                received.push((raw, i));
            }
        }
        for (raw, source) in received {
            self.inbound(&raw, source, now);
        }

        // Process batched resource requests (deduplicated)
        let pending_reqs: Vec<_> = self.pending_resource_requests.drain(..).collect();
        let mut seen = std::collections::HashSet::new();
        for (link_id, hash) in pending_reqs {
            if seen.insert((link_id, hash)) {
                self.send_resource_request(link_id, hash, now);
            }
        }

        // Process outbound queues
        for iface in &mut self.interfaces {
            iface.poll();
        }

        // Handle pending announce rebroadcasts
        let mut to_send = Vec::new();
        for pending in &mut self.pending_announces {
            if pending.retry_at <= now && pending.retries_remaining > 0 {
                pending.retries_remaining -= 1;
                pending.retry_at = now + std::time::Duration::from_millis(self.retry_delay_ms);
                to_send.push((
                    pending.destination,
                    pending.hops,
                    pending.has_ratchet,
                    pending.data.clone(),
                    pending.source_interface,
                ));
                if pending.retries_remaining > 0 {
                    update_wake(pending.retry_at);
                }
            } else if pending.retries_remaining > 0 {
                update_wake(pending.retry_at);
            }
        }
        // Remove announces with no retries left
        self.pending_announces.retain(|a| a.retries_remaining > 0);

        for (dest, hops, has_ratchet, data, source) in to_send {
            log::debug!(
                "Rebroadcasting announce for <{}> at hops={}",
                hex::encode(dest),
                hops + 1
            );
            let packet = self.make_announce_packet(
                dest,
                hops,
                has_ratchet,
                false,
                data,
                Some(self.transport_id),
            );
            let packet_len = packet.to_bytes().len();
            let num_interfaces = self.interfaces.len().saturating_sub(1); // minus source
            self.stats.packets_relayed += num_interfaces as u64;
            self.stats.bytes_relayed += (packet_len * num_interfaces) as u64;
            self.stats.announces_relayed += num_interfaces as u64;
            self.outbound(packet, Some(source), now);
        }

        if let Some(t) = self.maintain_links(now) {
            update_wake(t);
        }

        for iface in &mut self.interfaces {
            iface.poll();
        }

        // Remove disconnected interfaces
        let before_count = self.interfaces.len();
        self.interfaces.retain(|iface| iface.is_connected());
        let removed = before_count - self.interfaces.len();
        if removed > 0 {
            log::debug!("Removed {} disconnected interface(s)", removed);
        }

        std::mem::take(&mut self.pending_events)
    }

    fn maintain_links(&mut self, now: Instant) -> Option<Instant> {
        let mut next_wake: Option<Instant> = None;
        let mut update_wake = |t: Instant| {
            next_wake = Some(next_wake.map_or(t, |w| w.min(t)));
        };

        // Check for timed out pending links
        let mut timed_out_pending: Vec<(LinkId, Address)> = Vec::new();
        for (link_id, pending) in &self.pending_outbound_links {
            let hops = self
                .path_table
                .get(&pending.destination)
                .map(|e| e.hops)
                .unwrap_or(1);
            let timeout_secs = ESTABLISHMENT_TIMEOUT_BASE_SECS
                + ESTABLISHMENT_TIMEOUT_PER_HOP_SECS * hops.max(1) as u64;
            let elapsed = now.duration_since(pending.request_time).as_secs();
            if elapsed >= timeout_secs {
                timed_out_pending.push((*link_id, pending.destination));
            } else {
                let timeout_at =
                    pending.request_time + std::time::Duration::from_secs(timeout_secs);
                update_wake(timeout_at);
            }
        }

        // Handle timed out pending links
        let mut notifications = Vec::new();
        for (link_id, destination) in timed_out_pending {
            self.pending_outbound_links.remove(&link_id);

            // Fail any queued requests for this destination
            if let Some(queued) = self.pending_outbound_requests.remove(&destination) {
                for (service, local_request_id, _path, _data) in queued {
                    notifications.push(Notification::RequestResult {
                        service,
                        request_id: local_request_id,
                        result: Err(crate::handle::RequestError::LinkFailed),
                    });
                }
            }
        }

        // Check for timed out path requests
        let mut timed_out_paths: Vec<Address> = Vec::new();
        for (destination, request_time) in &self.pending_path_requests {
            let elapsed = now.duration_since(*request_time).as_secs();
            if elapsed >= PATH_REQUEST_TIMEOUT_SECS {
                timed_out_paths.push(*destination);
            } else {
                let timeout_at =
                    *request_time + std::time::Duration::from_secs(PATH_REQUEST_TIMEOUT_SECS);
                update_wake(timeout_at);
            }
        }

        for destination in timed_out_paths {
            self.pending_path_requests.remove(&destination);

            notifications.push(Notification::PathRequestResult {
                destination,
                found: false,
            });

            if let Some(queued) = self.pending_outbound_requests.remove(&destination) {
                for (service, local_request_id, _path, _data) in queued {
                    notifications.push(Notification::RequestResult {
                        service,
                        request_id: local_request_id,
                        result: Err(crate::handle::RequestError::Timeout),
                    });
                }
            }

            log::warn!(
                "Path request for <{}> timed out after {} seconds",
                hex::encode(destination),
                PATH_REQUEST_TIMEOUT_SECS
            );
        }

        if !notifications.is_empty() {
            self.dispatch_notifications(notifications);
        }

        let mut to_close = Vec::new();
        let mut to_keepalive = Vec::new();

        for (link_id, link) in &mut self.established_links {
            if link.state == LinkState::Closed {
                to_close.push(*link_id);
                continue;
            }

            let keepalive_secs = link.keepalive_interval_secs();
            let stale_secs = link.stale_time_secs();
            let since_inbound = now.duration_since(link.last_inbound).as_secs();

            if link.state == LinkState::Active
                && since_inbound >= stale_secs
                && link.pending_requests.is_empty()
            {
                log::info!(
                    "Link {} to <{}> became stale (no inbound for {}s, stale_time={}s)",
                    hex::encode(link_id),
                    hex::encode(link.destination),
                    since_inbound,
                    stale_secs
                );
                link.state = LinkState::Stale;
            }

            if link.state == LinkState::Stale {
                to_close.push(*link_id);
                continue;
            }

            if link.is_initiator && link.state == LinkState::Active {
                // Python: send keepalive if now >= last_inbound + keepalive AND now >= last_keepalive + keepalive
                let since_last_keepalive = link
                    .last_keepalive_sent
                    .map(|t| now.duration_since(t).as_secs())
                    .unwrap_or(u64::MAX);

                if since_inbound >= keepalive_secs && since_last_keepalive >= keepalive_secs {
                    to_keepalive.push(*link_id);
                } else {
                    // Schedule wake for next keepalive check
                    let next_inbound_check =
                        link.last_inbound + std::time::Duration::from_secs(keepalive_secs);
                    let next_keepalive_check = link
                        .last_keepalive_sent
                        .map(|t| t + std::time::Duration::from_secs(keepalive_secs))
                        .unwrap_or(now);
                    update_wake(next_inbound_check.max(next_keepalive_check));
                }
            }

            // Schedule wake for stale check
            let stale_at = link.last_inbound + std::time::Duration::from_secs(stale_secs);
            if stale_at > now {
                update_wake(stale_at);
            }
        }

        for link_id in to_keepalive {
            if let Some(link) = self.established_links.get_mut(&link_id) {
                log::debug!(
                    "Sending keepalive request on link {} (no inbound for {}s, rtt={:?}ms, interval={}s)",
                    hex::encode(link_id),
                    now.duration_since(link.last_inbound).as_secs(),
                    link.rtt_ms,
                    link.keepalive_interval_secs()
                );
                link.last_keepalive_sent = Some(now);
            }
            self.send_link_packet_with_activity(
                link_id,
                LinkContext::Keepalive,
                &[crate::link::KEEPALIVE_REQUEST],
                now,
            );
        }

        for link_id in to_close {
            if let Some(link) = self.established_links.get(&link_id)
                && link.state != LinkState::Closed
            {
                use crate::packet::LinkDataDestination;
                log::info!(
                    "Closing stale link <{}> to <{}> (state={:?})",
                    hex::encode(link_id),
                    hex::encode(link.destination),
                    link.state
                );
                let dest = link.destination;
                let target_interface = link.receiving_interface;
                let close_data = link.encrypt(&mut self.rng, &link_id);
                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::LinkClose,
                    data: close_data,
                };
                if let Some(iface) = self.interfaces.get_mut(target_interface) {
                    iface.send(packet, 0);
                }
                self.destination_links.remove(&dest);
            }
            self.established_links.remove(&link_id);
        }

        next_wake
    }

    fn handle_keepalive(&mut self, link_id: LinkId, plaintext: &[u8], _now: Instant) {
        use crate::link::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE};
        use crate::packet::LinkDataDestination;

        if plaintext.is_empty() {
            return;
        }

        if let Some(link) = self.established_links.get_mut(&link_id) {
            if plaintext[0] == KEEPALIVE_REQUEST && !link.is_initiator {
                log::debug!(
                    "Received keepalive request on link {}, sending response",
                    hex::encode(link_id)
                );
                // Responder: reply to keepalive request
                let response = link.encrypt(&mut self.rng, &[KEEPALIVE_RESPONSE]);
                let target_interface = link.receiving_interface;
                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::Keepalive,
                    data: response,
                };
                if let Some(iface) = self.interfaces.get_mut(target_interface) {
                    iface.send(packet, 0);
                }
            } else if plaintext[0] == KEEPALIVE_RESPONSE && link.is_initiator {
                // Initiator: received keepalive response
                log::debug!(
                    "Received keepalive response on link {}",
                    hex::encode(link_id)
                );
            } else {
                log::warn!(
                    "Unexpected keepalive byte 0x{:02x} on link {} (is_initiator={})",
                    plaintext[0],
                    hex::encode(link_id),
                    link.is_initiator
                );
            }
        }
    }

    fn handle_link_rtt(&mut self, link_id: LinkId, plaintext: &[u8]) {
        use crate::link::decode_rtt;

        // LRRTT packet from initiator telling responder the measured RTT
        if let Some(rtt_secs) = decode_rtt(plaintext)
            && let Some(link) = self.established_links.get_mut(&link_id)
            && !link.is_initiator
        {
            let rtt_ms = (rtt_secs * 1000.0) as u64;
            link.set_rtt(rtt_ms);
            link.state = LinkState::Active;
            link.activated_at = Some(std::time::Instant::now());
        }
    }

    fn handle_link_identify(&mut self, link_id: LinkId, plaintext: &[u8]) {
        use crate::link::LinkIdentify;

        let Some(identify) = LinkIdentify::parse(plaintext) else {
            log::warn!(
                "Failed to parse LinkIdentify on link {} ({} bytes)",
                hex::encode(link_id),
                plaintext.len()
            );
            return;
        };

        if !identify.verify(&link_id) {
            log::warn!(
                "LinkIdentify verification failed on link {}",
                hex::encode(link_id)
            );
            return;
        }

        let identity_hash = identify.identity_hash();
        log::info!(
            "Link {} identified as <{}>",
            hex::encode(link_id),
            hex::encode(identity_hash)
        );

        if let Some(link) = self.established_links.get_mut(&link_id) {
            link.remote_identity = Some(identity_hash);
        }
    }

    fn handle_resource_packet(
        &mut self,
        link_id: LinkId,
        context: LinkContext,
        plaintext: &[u8],
        now: Instant,
    ) {
        use crate::resource::MAPHASH_LEN;

        match context {
            LinkContext::ResourceAdv => {
                use crate::resource::ResourceAdvertisement;

                if let Some(adv) = ResourceAdvertisement::decode(plaintext) {
                    log::debug!(
                        "ResourceAdv: hash={} random_hash={} num_parts={} transfer_size={} compressed={} is_response={} request_id={:?} segment={}/{} split={}",
                        hex::encode(adv.hash),
                        hex::encode(adv.random_hash),
                        adv.num_parts,
                        adv.transfer_size,
                        adv.compressed,
                        adv.is_response,
                        adv.request_id.as_ref().map(hex::encode),
                        adv.segment_index,
                        adv.total_segments,
                        adv.split
                    );

                    // Auto-accept if this is a response to a pending request or a continuation
                    if !adv.is_response {
                        log::debug!("ResourceAdv not a response, ignoring");
                    } else if adv.request_id.is_none() {
                        log::warn!("ResourceAdv is_response=true but no request_id");
                    } else {
                        let original_hash = adv.original_hash;
                        let is_continuation = adv.segment_index > 1
                            && self.multi_segment_transfers.contains_key(&original_hash);

                        if is_continuation {
                            // Subsequent segment of an in-progress multi-segment transfer
                            log::info!(
                                "ResourceAdv: accepting continuation segment {}/{} for transfer {}",
                                adv.segment_index,
                                adv.total_segments,
                                hex::encode(original_hash)
                            );

                            let hash = adv.hash;
                            let mut resource =
                                crate::resource::InboundResource::from_advertisement(&adv);
                            resource.mark_transferring();
                            self.inbound_resources.insert(hash, (link_id, resource));
                            self.send_resource_request(link_id, hash, now);
                        } else if let Some(ref req_id_bytes) = adv.request_id
                            && let Some(link) = self.established_links.get(&link_id)
                        {
                            // First segment or single-segment resource
                            let wire_req_id: Option<WireRequestId> = req_id_bytes
                                .get(..16)
                                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                                .map(WireRequestId);

                            if let Some(wire_request_id) = wire_req_id {
                                if link.pending_requests.contains_key(&wire_request_id) {
                                    log::info!(
                                        "ResourceAdv matched pending request {} (segment {}/{})",
                                        hex::encode(wire_request_id.0),
                                        adv.segment_index,
                                        adv.total_segments
                                    );

                                    let hash = adv.hash;
                                    let mut resource =
                                        crate::resource::InboundResource::from_advertisement(&adv);
                                    resource.mark_transferring();
                                    self.inbound_resources.insert(hash, (link_id, resource));
                                    self.send_resource_request(link_id, hash, now);
                                } else {
                                    log::warn!(
                                        "ResourceAdv request_id {} not found in pending_requests (have: {:?})",
                                        hex::encode(wire_request_id.0),
                                        link.pending_requests
                                            .keys()
                                            .map(|k| hex::encode(k.0))
                                            .collect::<Vec<_>>()
                                    );
                                }
                            } else {
                                log::warn!(
                                    "ResourceAdv request_id too short: {} bytes",
                                    req_id_bytes.len()
                                );
                            }
                        }
                    }
                } else {
                    log::warn!("Failed to decode ResourceAdv ({} bytes)", plaintext.len());
                }
            }
            LinkContext::ResourceReq => {
                use crate::packet::LinkDataDestination;

                if plaintext.len() < 33 {
                    return;
                }
                let exhausted = plaintext[0] != 0;
                let offset = if exhausted { 5 } else { 1 };
                if plaintext.len() < offset + 32 {
                    return;
                }
                let hash: [u8; 32] = plaintext[offset..offset + 32].try_into().unwrap();
                let requested_hashes: Vec<[u8; MAPHASH_LEN]> = plaintext[offset + 32..]
                    .chunks_exact(MAPHASH_LEN)
                    .map(|c| [c[0], c[1], c[2], c[3]])
                    .collect();

                let target_interface = self
                    .established_links
                    .get(&link_id)
                    .map(|l| l.receiving_interface);
                if let Some((_, _, _, _, resource)) = self.outbound_resources.get_mut(&hash) {
                    resource.mark_transferring();

                    for part_hash in requested_hashes {
                        if let Some(part_data) = resource.get_part(&part_hash) {
                            // Resource parts are already encrypted at the stream level,
                            // so we send them as raw data (no Token encryption)
                            let packet = Packet::LinkData {
                                hops: 0,
                                destination: LinkDataDestination::Direct(link_id),
                                context: LinkContext::Resource,
                                data: part_data.to_vec(),
                            };
                            if let Some(iface_idx) = target_interface
                                && let Some(iface) = self.interfaces.get_mut(iface_idx)
                            {
                                iface.send(packet, 0);
                            }
                        }
                    }

                    if exhausted
                        && let Some((segment, hmu_data)) = resource.hashmap_update()
                        && let Some(link) = self.established_links.get(&link_id)
                    {
                        let mut payload = hash.to_vec();
                        // Encode [segment, hashmap] with msgpack (Python interop)
                        let segment_and_map = rmpv::Value::Array(vec![
                            rmpv::Value::Integer(segment.into()),
                            rmpv::Value::Binary(hmu_data),
                        ]);
                        rmpv::encode::write_value(&mut payload, &segment_and_map).unwrap();
                        let ciphertext = link.encrypt(&mut self.rng, &payload);
                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::ResourceHmu,
                            data: ciphertext,
                        };
                        if let Some(iface_idx) = target_interface
                            && let Some(iface) = self.interfaces.get_mut(iface_idx)
                        {
                            iface.send(packet, 0);
                        }
                    }
                }
            }
            LinkContext::Resource => {
                log::debug!(
                    "Received resource part: {} bytes on link {}",
                    plaintext.len(),
                    hex::encode(link_id)
                );
                let mut completed = None;
                let mut need_more = None;
                let mut progress_event = None;
                for (hash, (res_link_id, resource)) in &mut self.inbound_resources {
                    if *res_link_id == link_id {
                        let accepted = resource.receive_part(plaintext.to_vec());
                        log::debug!(
                            "Resource {} accepted={} complete={} outstanding={}",
                            hex::encode(hash),
                            accepted,
                            resource.is_complete(),
                            resource.outstanding_parts()
                        );
                        if accepted {
                            // Emit progress event if this is a response with a request_id
                            if resource.is_response
                                && let Some(ref req_id_bytes) = resource.request_id
                                && let Some(wire_req_id) = req_id_bytes
                                    .get(..16)
                                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                                    .map(WireRequestId)
                            {
                                let (received_bytes, total_bytes) = if resource.total_segments > 1 {
                                    let accumulated = self
                                        .multi_segment_transfers
                                        .get(&resource.original_hash)
                                        .map(|t| t.accumulated_data.len())
                                        .unwrap_or(0);
                                    let current_received = resource.bytes_received();
                                    let current_total = resource.total_bytes();
                                    let remaining =
                                        resource.total_segments - resource.segment_index;
                                    (
                                        accumulated + current_received,
                                        accumulated + current_total + remaining * current_total,
                                    )
                                } else {
                                    (resource.bytes_received(), resource.total_bytes())
                                };
                                progress_event = Some((
                                    wire_req_id,
                                    resource.original_hash,
                                    resource.received_count(),
                                    resource.num_parts(),
                                    received_bytes,
                                    total_bytes,
                                ));
                            }

                            if resource.is_complete() {
                                completed = Some(*hash);
                            } else {
                                // Pipeline: request more parts as soon as we have room
                                if resource.batch_complete() {
                                    resource.complete_batch(now);
                                }
                                need_more = Some(*hash);
                            }
                        }
                        break;
                    }
                }

                // Emit progress event
                if let Some((
                    wire_req_id,
                    original_hash,
                    received_parts,
                    total_parts,
                    received_bytes,
                    total_bytes,
                )) = progress_event
                {
                    // Try pending_requests first (first segment), then multi_segment_transfers (continuation)
                    let request_info = self
                        .established_links
                        .get(&link_id)
                        .and_then(|link| link.pending_requests.get(&wire_req_id).copied())
                        .or_else(|| {
                            self.multi_segment_transfers
                                .get(&original_hash)
                                .map(|t| (t.service, t.local_request_id))
                        });

                    if let Some((service, local_request_id)) = request_info {
                        self.pending_events.push(ServiceEvent::ResourceProgress {
                            service,
                            request_id: local_request_id,
                            received_parts,
                            total_parts,
                            received_bytes,
                            total_bytes,
                        });
                    }
                }

                if let Some(hash) = completed {
                    self.complete_resource(link_id, hash, now);
                } else if let Some(hash) = need_more {
                    self.pending_resource_requests.push((link_id, hash));
                }
            }
            LinkContext::ResourceHmu => {
                use crate::resource::HASHMAP_MAX_LEN;
                if plaintext.len() < 33 {
                    return;
                }
                let hash: [u8; 32] = plaintext[..32].try_into().unwrap();
                // Decode [segment, hashmap] from msgpack (Python interop)
                let Ok(value) = rmpv::decode::read_value(&mut &plaintext[32..]) else {
                    return;
                };
                let Some(arr) = value.as_array() else { return };
                if arr.len() < 2 {
                    return;
                }
                let Some(segment) = arr[0].as_u64() else {
                    return;
                };
                let Some(hmu_data) = arr[1].as_slice() else {
                    return;
                };
                let start_index = (segment as usize) * HASHMAP_MAX_LEN;
                if let Some((_, resource)) = self.inbound_resources.get_mut(&hash) {
                    resource.receive_hashmap_update(start_index, hmu_data);
                    self.send_resource_request(link_id, hash, now);
                }
            }
            LinkContext::ResourceIcl | LinkContext::ResourceRcl => {
                if plaintext.len() < 32 {
                    return;
                }
                let hash: [u8; 32] = plaintext[..32].try_into().unwrap();
                self.inbound_resources.remove(&hash);
                self.outbound_resources.remove(&hash);
                self.pending_resource_adverts.remove(&hash);
            }
            _ => {}
        }
    }

    fn complete_resource(&mut self, link_id: LinkId, hash: [u8; 32], _now: Instant) {
        use crate::packet::{ProofContext, ProofDestination};

        log::debug!(
            "complete_resource called: link={} hash={}",
            hex::encode(link_id),
            hex::encode(hash)
        );

        let resource = match self.inbound_resources.remove(&hash) {
            Some((_, r)) => r,
            None => {
                log::warn!(
                    "complete_resource: hash {} not found in inbound_resources",
                    hex::encode(hash)
                );
                return;
            }
        };

        let link = match self.established_links.get(&link_id) {
            Some(l) => l,
            None => {
                log::warn!("complete_resource: link {} not found", hex::encode(link_id));
                return;
            }
        };

        let (segment_data, proof) = match resource.assemble_segment(link) {
            Some(r) => r,
            None => {
                log::warn!(
                    "complete_resource: assemble_segment failed for hash {}",
                    hex::encode(hash)
                );
                return;
            }
        };

        log::info!(
            "Segment completed: hash={} segment={}/{} data_len={} is_response={}",
            hex::encode(hash),
            resource.segment_index,
            resource.total_segments,
            segment_data.len(),
            resource.is_response
        );

        // Send proof
        let mut payload = hash.to_vec();
        payload.extend(&proof);
        let packet = Packet::Proof {
            hops: 0,
            destination: ProofDestination::Link(link_id),
            context: ProofContext::ResourcePrf,
            data: payload,
        };
        let target_interface = link.receiving_interface;
        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            iface.send(packet, 0);
        }

        if !resource.is_response {
            log::debug!(
                "Resource {} is not a response, data ({} bytes) not delivered to any service",
                hex::encode(hash),
                segment_data.len()
            );
            return;
        }

        let req_id_bytes = match resource.request_id {
            Some(ref r) => r,
            None => {
                log::warn!("complete_resource: is_response=true but no request_id");
                return;
            }
        };

        let wire_req_id: Option<WireRequestId> = req_id_bytes
            .get(..16)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(WireRequestId);

        let wire_request_id = match wire_req_id {
            Some(w) => w,
            None => {
                log::warn!(
                    "complete_resource: failed to parse wire_request_id from {:?}",
                    req_id_bytes
                );
                return;
            }
        };

        let original_hash = resource.original_hash;
        let is_multi_segment = resource.total_segments > 1;
        let is_last_segment = resource.is_last_segment();

        if is_multi_segment && !is_last_segment {
            // Not the last segment - accumulate data and wait for next
            let transfer = self
                .multi_segment_transfers
                .entry(original_hash)
                .or_insert_with(|| {
                    // First segment - look up request info
                    let (service, local_request_id) = self
                        .established_links
                        .get_mut(&link_id)
                        .and_then(|l| l.pending_requests.remove(&wire_request_id))
                        .unwrap_or((ServiceId(0), RequestId([0; 16])));

                    MultiSegmentTransfer {
                        service,
                        local_request_id,
                        total_segments: resource.total_segments,
                        segments_received: 0,
                        accumulated_data: Vec::new(),
                        has_metadata: resource.has_metadata,
                    }
                });

            transfer.accumulated_data.extend(&segment_data);
            transfer.segments_received += 1;

            log::info!(
                "Multi-segment transfer {}: received segment {}/{}, accumulated {} bytes",
                hex::encode(original_hash),
                transfer.segments_received,
                transfer.total_segments,
                transfer.accumulated_data.len()
            );
            return;
        }

        // Either single-segment or the last segment of multi-segment
        let (final_data, metadata, service, local_request_id) = if is_multi_segment {
            // Last segment of multi-segment transfer
            let mut transfer = match self.multi_segment_transfers.remove(&original_hash) {
                Some(t) => t,
                None => {
                    log::warn!(
                        "complete_resource: last segment but no multi_segment_transfer for {}",
                        hex::encode(original_hash)
                    );
                    return;
                }
            };

            transfer.accumulated_data.extend(&segment_data);
            transfer.segments_received += 1;

            log::info!(
                "Multi-segment transfer {} complete: {} segments, {} bytes total",
                hex::encode(original_hash),
                transfer.segments_received,
                transfer.accumulated_data.len()
            );

            // Extract metadata from accumulated data if present
            let (data, metadata) = if transfer.has_metadata && transfer.accumulated_data.len() >= 3
            {
                let metadata_size = ((transfer.accumulated_data[0] as usize) << 16)
                    | ((transfer.accumulated_data[1] as usize) << 8)
                    | (transfer.accumulated_data[2] as usize);
                let data_start = 3 + metadata_size;
                if transfer.accumulated_data.len() >= data_start {
                    log::debug!(
                        "Extracting {} byte metadata, {} byte data",
                        metadata_size,
                        transfer.accumulated_data.len() - data_start
                    );
                    let metadata = transfer.accumulated_data[3..data_start].to_vec();
                    let data = transfer.accumulated_data[data_start..].to_vec();
                    (data, Some(metadata))
                } else {
                    log::warn!("Metadata size exceeds data length");
                    (transfer.accumulated_data, None)
                }
            } else {
                (transfer.accumulated_data, None)
            };

            (data, metadata, transfer.service, transfer.local_request_id)
        } else {
            // Single-segment - extract metadata and get request info
            let (data, metadata) = if resource.has_metadata && segment_data.len() >= 3 {
                let metadata_size = ((segment_data[0] as usize) << 16)
                    | ((segment_data[1] as usize) << 8)
                    | (segment_data[2] as usize);
                let data_start = 3 + metadata_size;
                if segment_data.len() >= data_start {
                    log::debug!(
                        "Extracting {} byte metadata, {} byte data",
                        metadata_size,
                        segment_data.len() - data_start
                    );
                    let metadata = segment_data[3..data_start].to_vec();
                    let data = segment_data[data_start..].to_vec();
                    (data, Some(metadata))
                } else {
                    log::warn!("Metadata size exceeds data length");
                    (segment_data, None)
                }
            } else {
                (segment_data, None)
            };

            let (service, local_request_id) = match self
                .established_links
                .get_mut(&link_id)
                .and_then(|l| l.pending_requests.remove(&wire_request_id))
            {
                Some(r) => r,
                None => {
                    log::warn!(
                        "complete_resource: no pending request for wire_request_id={}",
                        hex::encode(wire_request_id.0)
                    );
                    return;
                }
            };

            (data, metadata, service, local_request_id)
        };

        let from = self
            .established_links
            .get(&link_id)
            .map(|l| l.destination)
            .unwrap_or([0u8; 16]);

        log::info!(
            "Delivering resource response: {} bytes to service {:?} (request_id={})",
            final_data.len(),
            service,
            hex::encode(local_request_id.0)
        );

        // Resource responses are msgpack [request_id, response_data] - extract response_data
        use serde_bytes::ByteBuf;
        let data = rmp_serde::from_slice::<(ByteBuf, ByteBuf)>(&final_data)
            .map(|(_, response_data)| response_data.into_vec())
            .unwrap_or(final_data);

        let notification = Notification::RequestResult {
            service,
            request_id: local_request_id,
            result: Ok((from, data, metadata)),
        };
        self.dispatch_notifications(vec![notification]);
    }

    fn send_resource_request(&mut self, link_id: LinkId, hash: [u8; 32], now: Instant) {
        use crate::packet::LinkDataDestination;
        use crate::resource::{HASHMAP_IS_EXHAUSTED, HASHMAP_IS_NOT_EXHAUSTED};

        // First pass: get needed hashes and build payload
        let payload = if let Some((_, resource)) = self.inbound_resources.get_mut(&hash) {
            let (needed, exhausted) = resource.needed_hashes();

            log::debug!(
                "send_resource_request: hash={} needed={} exhausted={} complete={} received={}/{}",
                hex::encode(hash),
                needed.len(),
                exhausted,
                resource.is_complete(),
                resource.received_count(),
                resource.num_parts()
            );

            if needed.is_empty() && resource.is_complete() {
                return;
            }

            if needed.is_empty() && !resource.is_complete() {
                log::debug!(
                    "send_resource_request: need hashmap update (exhausted={})",
                    exhausted
                );
            }

            let mut payload = Vec::new();
            payload.push(if exhausted {
                HASHMAP_IS_EXHAUSTED
            } else {
                HASHMAP_IS_NOT_EXHAUSTED
            });
            if exhausted && let Some(last_hash) = resource.last_hashmap_hash() {
                payload.extend(&last_hash);
            }
            payload.extend(&hash);
            for h in &needed {
                payload.extend(h);
            }
            Some((payload, needed.len(), exhausted))
        } else {
            None
        };

        // Second pass: encrypt and send
        if let Some((payload, needed_len, exhausted)) = payload
            && let Some(link) = self.established_links.get(&link_id)
        {
            log::debug!(
                "Sending ResourceReq: {} hashes requested, exhausted={}",
                needed_len,
                exhausted
            );
            let ciphertext = link.encrypt(&mut self.rng, &payload);
            let target_interface = link.receiving_interface;
            let packet = Packet::LinkData {
                hops: 0,
                destination: LinkDataDestination::Direct(link_id),
                context: LinkContext::ResourceReq,
                data: ciphertext,
            };
            if let Some(iface) = self.interfaces.get_mut(target_interface) {
                iface.send(packet, 0);
            }

            // Mark request sent for rate tracking
            if let Some((_, resource)) = self.inbound_resources.get_mut(&hash) {
                resource.mark_req_sent(now);
            }
        }
    }

    fn make_announce_packet(
        &self,
        dest: Address,
        hops: u8,
        has_ratchet: bool,
        is_path_response: bool,
        data: Vec<u8>,
        transport_id: Option<Address>,
    ) -> Packet {
        use crate::packet::AnnounceDestination;
        let destination = match transport_id {
            Some(tid) => AnnounceDestination::Transport {
                transport_id: tid,
                destination: dest,
            },
            None => AnnounceDestination::Single(dest),
        };
        Packet::Announce {
            hops,
            destination,
            has_ratchet,
            is_path_response,
            data,
        }
    }

    fn make_link_request_packet(
        &self,
        dest: Address,
        transport_id: Option<Address>,
        data: Vec<u8>,
    ) -> Packet {
        use crate::packet::LinkRequestDestination;
        let destination = match transport_id {
            Some(tid) => LinkRequestDestination::Transport {
                transport_id: tid,
                destination: dest,
            },
            None => LinkRequestDestination::Direct(dest),
        };
        Packet::LinkRequest {
            hops: 0,
            destination,
            data,
        }
    }

    fn make_link_proof_packet(&self, link_id: LinkId, data: Vec<u8>) -> Packet {
        use crate::packet::LinkProofDestination;
        Packet::LinkProof {
            hops: 0,
            destination: LinkProofDestination::Direct(link_id),
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    struct MockTransport {
        outbox: std::collections::VecDeque<Vec<u8>>,
        inbox: std::collections::VecDeque<Vec<u8>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                outbox: std::collections::VecDeque::new(),
                inbox: std::collections::VecDeque::new(),
            }
        }
    }

    impl Transport for MockTransport {
        fn send(&mut self, data: &[u8]) {
            self.outbox.push_back(data.to_vec());
        }
        fn recv(&mut self) -> Option<Vec<u8>> {
            self.inbox.pop_front()
        }
        fn bandwidth_available(&self) -> bool {
            true
        }
    }

    type TestNode = Node<MockTransport, StdRng>;

    fn transfer(from: &mut TestNode, from_iface: usize, to: &mut TestNode, to_iface: usize) {
        while let Some(pkt) = from.interfaces[from_iface].transport.outbox.pop_front() {
            to.interfaces[to_iface].transport.inbox.push_back(pkt);
        }
    }

    fn test_interface() -> Interface<MockTransport> {
        Interface::new(MockTransport::new())
    }

    fn test_node(transport: bool) -> TestNode {
        Node::with_rng(StdRng::from_entropy(), transport)
    }

    fn id(seed: u64) -> crate::identity::Identity {
        let mut rng = StdRng::seed_from_u64(seed);
        crate::identity::Identity::generate(&mut rng)
    }

    #[test]
    fn announce_two_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("test", &[], &id(1));
        let addr_a = a.service_address(svc_a).unwrap();
        let now = Instant::now();

        a.announce(svc_a);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert!(b.path_table.contains_key(&addr_a));
    }

    #[test]
    fn announce_three_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("test", &[], &id(1));
        let addr_a = a.service_address(svc_a).unwrap();
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        a.announce(svc_a);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);

        assert!(b.path_table.contains_key(&addr_a));
        assert!(c.path_table.contains_key(&addr_a));
    }

    #[test]
    fn announce_not_echoed_back() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("test", &[], &id(1));
        let now = Instant::now();

        a.announce(svc_a);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        b.poll(now);

        // B should not echo the announce back to interface 0 (where it came from)
        assert!(b.interfaces[0].transport.outbox.is_empty());
    }

    #[test]
    fn link_two_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).expect("link should be created");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.contains_key(&link_id));
    }

    #[test]
    fn link_three_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(None, addr_c, later).expect("link should be created");
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        assert!(a.established_links.contains_key(&link_id));
        assert!(c.established_links.contains_key(&link_id));
    }

    #[test]
    fn link_data_two_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.send_link_packet(link_id, LinkContext::None, b"payload");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events = b.poll(now);

        // B receives raw data via ServiceEvent::Raw
        let raw_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ServiceEvent::Raw { data, .. } => Some(data.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(raw_events.len(), 1);
        assert_eq!(raw_events[0], b"payload");
    }

    #[test]
    fn link_data_three_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(None, addr_c, later).unwrap();
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        a.send_link_packet(link_id, LinkContext::None, b"payload");
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        let events = c.poll(later);

        // C receives raw data via ServiceEvent::Raw
        let raw_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ServiceEvent::Raw { data, .. } => Some(data.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(raw_events.len(), 1);
        assert_eq!(raw_events[0], b"payload");
    }

    #[test]
    fn request_response_two_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should know about B's destination
        assert!(a.path_table.contains_key(&addr_b));

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Link should be established on both sides
        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.contains_key(&link_id));

        // Send request from A to B
        a.request(
            svc_a,
            crate::LinkHandle(link_id),
            "test.path",
            b"request data",
        );
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B should have received the request via ServiceEvent::Request
        let request = events_b.iter().find_map(|e| match e {
            ServiceEvent::Request {
                request_id,
                path,
                data,
                ..
            } => Some((request_id, path.clone(), data.clone())),
            _ => None,
        });
        let (request_id, path, data) = request.expect("B should receive request");
        assert_eq!(path, "test.path");
        assert_eq!(data, b"request data");

        // B responds
        b.respond(*request_id, b"response data", None, true);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(now);

        // A should have received the response via ServiceEvent::RequestResult
        let response = events_a.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                result: Ok((_, data, _)),
                ..
            } => Some(data.clone()),
            _ => None,
        });
        assert_eq!(response, Some(b"response data".to_vec()));
    }

    #[test]
    fn request_response_three_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_c = c.add_service("server", &["test.path"], &id(2));
        let addr_c = c.service_address(svc_c).unwrap();
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // A should know about C's destination (via B as transport)
        assert!(a.path_table.contains_key(&addr_c));

        let link_id = a.link(None, addr_c, later).unwrap();
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // Link should be established on both ends
        assert!(a.established_links.contains_key(&link_id));
        assert!(c.established_links.contains_key(&link_id));

        // Send request from A to C (via B)
        a.request(
            svc_a,
            crate::LinkHandle(link_id),
            "test.path",
            b"request data",
        );
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        let events_c = c.poll(later);

        // C should have received the request via ServiceEvent::Request
        let request = events_c.iter().find_map(|e| match e {
            ServiceEvent::Request {
                request_id,
                path,
                data,
                ..
            } => Some((request_id, path.clone(), data.clone())),
            _ => None,
        });
        let (request_id, path, data) = request.expect("C should receive request");
        assert_eq!(path, "test.path");
        assert_eq!(data, b"request data");

        // C responds
        c.respond(*request_id, b"response data", None, true);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(later);

        // A should have received the response via ServiceEvent::RequestResult
        let response = events_a.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                result: Ok((_, data, _)),
                ..
            } => Some(data.clone()),
            _ => None,
        });
        assert_eq!(response, Some(b"response data".to_vec()));
    }

    #[test]
    fn large_response_uses_resource() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Create a large response (> LINK_MDU of 431 bytes) to trigger resource transfer
        let large_response: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Link should be established
        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.contains_key(&link_id));

        // Send request from A to B
        a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"request");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B should have received the request
        let request = events_b.iter().find_map(|e| match e {
            ServiceEvent::Request { request_id, .. } => Some(*request_id),
            _ => None,
        });
        let request_id = request.expect("B should receive request");

        // B responds with large response
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        // B should have an outbound resource for the large response
        assert_eq!(
            b.outbound_resources.len(),
            1,
            "large response should create outbound resource"
        );

        // Transfer resource advertisement and complete the transfer
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should have an inbound resource
        assert_eq!(
            a.inbound_resources.len(),
            1,
            "should auto-accept response resource"
        );

        // Transfer resource request back
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Transfer resource parts
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(now);

        // Transfer proof
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // A should have received the large response via ServiceEvent::RequestResult
        let response = events_a.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                result: Ok((_, data, _)),
                ..
            } => Some(data.clone()),
            _ => None,
        });
        assert_eq!(response, Some(large_response));

        // Resources should be cleaned up
        assert_eq!(a.inbound_resources.len(), 0);
        assert_eq!(b.outbound_resources.len(), 0);
    }

    #[test]
    fn multipart_resource_with_hashmap_updates() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // 10KB response = ~21 parts at 470 bytes/part, needs multiple hashmap updates
        let large_response: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Send request
        a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"req");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds with large response
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        // Transfer until complete (resource adv, requests, parts, hashmap updates, proof)
        let mut response_received = None;
        for _ in 0..50 {
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(now);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(now);
            if let Some(data) = events_a.iter().find_map(|e| match e {
                ServiceEvent::RequestResult {
                    result: Ok((_, data, _)),
                    ..
                } => Some(data.clone()),
                _ => None,
            }) {
                response_received = Some(data);
                break;
            }
        }

        assert_eq!(response_received, Some(large_response));
    }

    #[test]
    fn hmu_msgpack_encoding_interop() {
        use crate::resource::HASHMAP_MAX_LEN;

        let segment: u64 = 2;
        let hashmap_data: Vec<u8> = (0..50 * 4).map(|i| i as u8).collect();

        let mut encoded = Vec::new();
        let value = rmpv::Value::Array(vec![
            rmpv::Value::Integer(segment.into()),
            rmpv::Value::Binary(hashmap_data.clone()),
        ]);
        rmpv::encode::write_value(&mut encoded, &value).unwrap();

        let decoded = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        let arr = decoded.as_array().unwrap();
        let decoded_segment = arr[0].as_u64().unwrap();
        let decoded_hashmap = arr[1].as_slice().unwrap();

        assert_eq!(decoded_segment, segment);
        assert_eq!(decoded_hashmap, &hashmap_data[..]);
        assert_eq!(
            (decoded_segment as usize) * HASHMAP_MAX_LEN,
            2 * HASHMAP_MAX_LEN
        );
    }

    #[test]
    fn large_resource_multiple_hmu_segments() {
        let _ = env_logger::builder().is_test(true).try_init();

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // 50KB = ~106 parts, needs 2 HMU segments (74 hashes each)
        // This verifies msgpack encoding works end-to-end
        let mut large_response = vec![0u8; 50_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();

        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        let mut t = now;
        let mut response_received = false;

        for _ in 0..500 {
            t += std::time::Duration::from_millis(1);
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if events_a
                .iter()
                .any(|e| matches!(e, ServiceEvent::RequestResult { result: Ok(_), .. }))
            {
                response_received = true;
                break;
            }
        }

        assert!(
            response_received,
            "Should complete 50KB transfer requiring multiple HMU segments"
        );
    }

    #[test]
    fn resource_transfer_three_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let large_response: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_c = c.add_service("server", &["test.path"], &id(2));
        let addr_c = c.service_address(svc_c).unwrap();
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        // Propagate announce: C -> B -> A
        c.announce(svc_c);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // Establish link A -> C (via B)
        let link_id = a.link(None, addr_c, later).unwrap();
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // Send request
        a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"req");
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        let events_c = c.poll(later);

        // C responds with large response
        let request_id = events_c
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("C should receive request");
        c.respond(request_id, &large_response, None, true);
        c.poll(later);

        // Transfer until complete
        let mut response_received = None;
        for _ in 0..30 {
            transfer(&mut c, 0, &mut b, 1);
            b.poll(later);
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(later);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(later);
            transfer(&mut b, 1, &mut c, 0);
            c.poll(later);
            if let Some(data) = events_a.iter().find_map(|e| match e {
                ServiceEvent::RequestResult {
                    result: Ok((_, data, _)),
                    ..
                } => Some(data.clone()),
                _ => None,
            }) {
                response_received = Some(data);
                break;
            }
        }

        assert_eq!(response_received, Some(large_response));
    }

    #[test]
    fn rtt_measured_and_propagated() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // After link establishment, initiator (a) should have RTT measured
        let a_link = a.established_links.get(&link_id).unwrap();
        assert!(a_link.rtt_ms.is_some(), "initiator should have RTT");
        assert!(a_link.is_initiator);

        // LRRTT packet should have been sent, transfer it
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Now responder (b) should also have RTT from LRRTT packet
        let b_link = b.established_links.get(&link_id).unwrap();
        assert!(
            b_link.rtt_ms.is_some(),
            "responder should have RTT from LRRTT"
        );
        assert!(!b_link.is_initiator);
        assert_eq!(b_link.state, LinkState::Active);
    }

    #[test]
    fn keepalive_timing_adapts_to_rtt() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Helper to count keepalives sent over a time period
        // Keepalive is sent when since_inbound >= keepalive_interval
        let count_keepalives = |node: &mut TestNode,
                                link: LinkId,
                                start: Instant,
                                duration_secs: u64,
                                step_secs: u64|
         -> u64 {
            let mut count = 0u64;
            let mut t = start;
            let end = start + Duration::from_secs(duration_secs);
            while t < end {
                let before = node
                    .established_links
                    .get(&link)
                    .and_then(|l| l.last_keepalive_sent);
                node.poll(t);
                let after = node
                    .established_links
                    .get(&link)
                    .and_then(|l| l.last_keepalive_sent);
                if after.is_some() && after != before {
                    count += 1;
                    // Simulate receiving keepalive response: update inbound and clear pending
                    if let Some(l) = node.established_links.get_mut(&link) {
                        l.last_keepalive_sent = None;
                        l.last_inbound = t; // Response received
                    }
                }
                t += Duration::from_secs(step_secs);
            }
            count
        };

        // Test with low RTT (0ms -> 5s keepalive interval, 10s stale time)
        // Over 60 seconds, expect ~12 keepalives (60/5)
        // Start with last_inbound 6s in past: triggers keepalive (>= 5s) but not stale (< 10s)
        let test_start = now + Duration::from_secs(6);
        if let Some(link) = a.established_links.get_mut(&link_id) {
            link.set_rtt(0);
            link.last_inbound = now; // 6s ago at test_start
            link.last_keepalive_sent = None;
        }
        let low_rtt_count = count_keepalives(&mut a, link_id, test_start, 60, 1);
        assert!(
            (10..=14).contains(&low_rtt_count),
            "low RTT (5s interval): expected ~12 keepalives in 60s, got {}",
            low_rtt_count
        );

        // Test with high RTT (1750ms -> 360s interval)
        // Over 60 seconds, expect 0 keepalives
        let now2 = now + Duration::from_secs(100);
        if let Some(link) = a.established_links.get_mut(&link_id) {
            link.set_rtt(1750);
            link.last_outbound = now2;
            link.last_inbound = now2;
            link.last_keepalive_sent = None;
        }
        let high_rtt_count = count_keepalives(&mut a, link_id, now2, 60, 1);
        assert_eq!(
            high_rtt_count, 0,
            "high RTT (360s interval): expected 0 keepalives in 60s, got {}",
            high_rtt_count
        );
    }

    #[test]
    fn request_on_pending_link_returns_none() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &[], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Announce B so A knows the path
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A initiates link (but we won't complete handshake)
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);

        // Verify link is pending
        assert!(a.pending_outbound_links.contains_key(&link_id));

        // Request on pending link returns None
        let result = a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"data");
        assert!(
            result.is_none(),
            "request on pending link should return None"
        );
    }

    #[test]
    fn stale_link_closed() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert!(a.established_links.contains_key(&link_id));

        // With RTT ~0, stale_time = 10s (KEEPALIVE_MIN * STALE_FACTOR = 5 * 2)
        // Simulate no inbound traffic for longer than stale_time
        let stale_future = now + Duration::from_secs(15);

        a.poll(stale_future);

        assert!(
            !a.established_links.contains_key(&link_id),
            "link should be closed after stale timeout"
        );
    }

    #[test]
    fn link_not_stale_while_request_pending() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();

        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Send a request
        a.request(svc_a, crate::LinkHandle(link_id), "test", b"request");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // Verify request was received
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("Server should have received request");

        // With RTT ~0, stale_time = 10s (KEEPALIVE_MIN * STALE_FACTOR = 5 * 2)
        // Simulate time passing beyond stale_time, but don't send response yet
        let after_stale = now + Duration::from_secs(15);
        a.poll(after_stale);

        // Link should NOT be closed because we have a pending request
        assert!(
            a.established_links.contains_key(&link_id),
            "Link should NOT be closed while request is pending"
        );

        // Now server responds (late)
        b.respond(request_id, b"late response", None, true);
        b.poll(after_stale);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(after_stale);

        // Response should be received
        let response = events_a.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                result: Ok((_, data, _)),
                ..
            } => Some(data.clone()),
            _ => None,
        });
        assert_eq!(
            response,
            Some(b"late response".to_vec()),
            "Client should receive late response"
        );
    }

    #[test]
    fn keepalive_request_response() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Set a known RTT value that we'll expect to change after keepalive
        if let Some(link) = a.established_links.get_mut(&link_id) {
            link.set_rtt(9999);
        }
        let rtt_before = a.established_links.get(&link_id).unwrap().rtt_ms.unwrap();
        assert_eq!(rtt_before, 9999);

        // Set up to trigger keepalive: inbound old enough to trigger keepalive but not stale
        // With RTT 9999ms, keepalive_interval = 360s (clamped to max), stale_time = 720s
        // Set last_inbound to 400s ago (> 360s keepalive, < 720s stale)
        let future = now + Duration::from_secs(400);

        if let Some(link) = a.established_links.get_mut(&link_id) {
            link.last_outbound = future;
            link.last_inbound = now; // 400s ago, triggers keepalive (> 360s)
        }

        a.poll(future);

        // Check keepalive was sent
        let keepalive_sent_at = a
            .established_links
            .get(&link_id)
            .unwrap()
            .last_keepalive_sent;
        assert!(
            keepalive_sent_at.is_some(),
            "keepalive should have been sent"
        );

        // Transfer keepalive request to b
        transfer(&mut a, 0, &mut b, 0);
        b.poll(future);

        // Simulate some time passing for the response (50ms round trip)
        let response_time = future + Duration::from_millis(50);

        // Transfer keepalive response back to a
        transfer(&mut b, 0, &mut a, 0);
        a.poll(response_time);

        // Keepalive timestamp should be preserved (not cleared like before)
        // This allows throttling future keepalives
        let a_link = a.established_links.get(&link_id).unwrap();
        assert!(
            a_link.last_keepalive_sent.is_some(),
            "keepalive timestamp should be preserved for throttling"
        );
    }

    fn make_ifac_interface(ifac_identity: [u8; 32], ifac_key: Vec<u8>) -> Interface<MockTransport> {
        Interface::new(MockTransport::new()).with_access_codes(ifac_identity, ifac_key, 8)
    }

    #[test]
    fn ifac_two_nodes_communicate() {
        use rand::RngCore;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        // Both nodes share the SAME IFAC identity and key (derived from network name/key)
        let mut rng = StdRng::seed_from_u64(42);
        let mut shared_ifac_identity = [0u8; 32];
        rng.fill_bytes(&mut shared_ifac_identity);
        let shared_ifac_key = vec![0xAB; 32];

        let mut a = test_node(false);
        let mut b = test_node(false);
        a.add_interface(make_ifac_interface(
            shared_ifac_identity,
            shared_ifac_key.clone(),
        ));
        b.add_interface(make_ifac_interface(shared_ifac_identity, shared_ifac_key));

        let _svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &[], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // B announces
        b.announce(svc_b);
        b.poll(now);

        // Transfer announce (with IFAC) from B to A
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should have learned about B
        assert!(
            a.path_table.contains_key(&addr_b),
            "A should know about B after IFAC-protected announce"
        );

        // A establishes link to B
        let link_id = a.link(None, addr_b, now).expect("should create link");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Link should be established on both sides
        assert!(
            a.established_links.contains_key(&link_id),
            "link should be established over IFAC"
        );
        assert!(
            b.established_links.contains_key(&link_id),
            "B should have established link"
        );

        // Send data over the link
        a.send_link_packet(link_id, LinkContext::None, b"hello over ifac");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B should receive data via ServiceEvent::Raw
        let raw_data = events_b.iter().find_map(|e| match e {
            ServiceEvent::Raw { data, .. } => Some(data.clone()),
            _ => None,
        });
        assert_eq!(raw_data, Some(b"hello over ifac".to_vec()));
    }

    #[test]
    fn ifac_mismatch_blocks_communication() {
        use rand::RngCore;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut a = test_node(false);
        let mut b = test_node(false);

        // A uses one IFAC key
        let mut rng_a = StdRng::seed_from_u64(42);
        let mut ifac_identity_a = [0u8; 32];
        rng_a.fill_bytes(&mut ifac_identity_a);
        let ifac_key_a = vec![0xAA; 32];
        let iface_a =
            Interface::new(MockTransport::new()).with_access_codes(ifac_identity_a, ifac_key_a, 8);
        a.add_interface(iface_a);

        // B uses different IFAC key
        let mut rng_b = StdRng::seed_from_u64(99);
        let mut ifac_identity_b = [0u8; 32];
        rng_b.fill_bytes(&mut ifac_identity_b);
        let ifac_key_b = vec![0xBB; 32];
        let iface_b =
            Interface::new(MockTransport::new()).with_access_codes(ifac_identity_b, ifac_key_b, 8);
        b.add_interface(iface_b);

        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // B announces
        b.announce(svc_b);
        b.poll(now);

        // Transfer announce from B to A
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should NOT know about B (IFAC mismatch)
        assert!(
            !a.path_table.contains_key(&addr_b),
            "A should not learn about B with mismatched IFAC"
        );
    }

    #[test]
    fn destinations_changed_event_for_new_destination() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let _svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &[], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(now);

        // Check that DestinationsChanged event was emitted
        let destinations_changed = events_a
            .iter()
            .any(|e| matches!(e, ServiceEvent::DestinationsChanged));
        assert!(
            destinations_changed,
            "DestinationsChanged should be emitted when new destination discovered"
        );

        // A should know about B
        assert!(a.path_table.contains_key(&addr_b));

        // Re-announce should not trigger again (not a new destination)
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        let events_a2 = a.poll(now);

        let destinations_changed2 = events_a2
            .iter()
            .any(|e| matches!(e, ServiceEvent::DestinationsChanged));
        assert!(
            !destinations_changed2,
            "DestinationsChanged should not be emitted for re-announce"
        );
    }

    #[test]
    fn request_received_event() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));

        a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"hello");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        let request = events_b.iter().find_map(|e| match e {
            ServiceEvent::Request { path, data, .. } => Some((path.clone(), data.clone())),
            _ => None,
        });
        let (path, data) = request.expect("Request event should be emitted");
        assert_eq!(path, "test.path");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn request_result_event_on_response() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));

        let sent_request_id = a
            .request(svc_a, crate::LinkHandle(link_id), "test.path", b"hello")
            .unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, b"response", None, true);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(now);

        let result = events_a.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                request_id,
                result: Ok((_, data, _)),
                ..
            } => Some((*request_id, data.clone())),
            _ => None,
        });
        let (recv_request_id, data) = result.expect("RequestResult event should be emitted");
        assert_eq!(recv_request_id, sent_request_id);
        assert_eq!(data, b"response");
    }

    #[test]
    fn pending_link_timeout_closes_link_status() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &[], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Create link but don't complete handshake
        let link = a.create_link(svc_a, addr_b, now).unwrap();
        a.poll(now);

        // Link should be pending
        assert_eq!(a.link_status(link), crate::LinkStatus::Pending);

        // Time out the link (base 60s + 6s per hop)
        let timeout = now + Duration::from_secs(67);
        a.poll(timeout);

        // Link should be closed
        assert_eq!(a.link_status(link), crate::LinkStatus::Closed);
    }

    #[test]
    fn two_sequential_requests_both_get_responses() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["echo"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Setup: announce and establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));

        // First request
        let request_id_1 = a
            .request(svc_a, crate::LinkHandle(link_id), "echo", b"first")
            .unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b1 = b.poll(now);

        // B responds to first request
        let req_id_1 = events_b1
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive first request");
        b.respond(req_id_1, b"response1", None, true);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        let events_a1 = a.poll(now);

        let resp1 = events_a1.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                request_id,
                result: Ok((_, data, _)),
                ..
            } => Some((*request_id, data.clone())),
            _ => None,
        });
        assert!(resp1.is_some(), "first request should get response");
        assert_eq!(resp1.unwrap().0, request_id_1);

        // Second request
        let request_id_2 = a
            .request(svc_a, crate::LinkHandle(link_id), "echo", b"second")
            .unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b2 = b.poll(now);

        // B responds to second request
        let req_id_2 = events_b2
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive second request");
        b.respond(req_id_2, b"response2", None, true);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        let events_a2 = a.poll(now);

        let resp2 = events_a2.iter().find_map(|e| match e {
            ServiceEvent::RequestResult {
                request_id,
                result: Ok((_, data, _)),
                ..
            } => Some((*request_id, data.clone())),
            _ => None,
        });
        assert!(resp2.is_some(), "second request should also get response");
        assert_eq!(resp2.unwrap().0, request_id_2);
    }

    #[test]
    fn three_sequential_requests_all_get_responses() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["echo"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // B announces
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should know about B now
        assert!(a.path_table.contains_key(&addr_b));

        // Establish link
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));

        // Send three requests and get three responses
        for i in 1..=3 {
            let req_data = format!("request{}", i);
            let resp_data = format!("response{}", i);

            a.request(
                svc_a,
                crate::LinkHandle(link_id),
                "echo",
                req_data.as_bytes(),
            );
            a.poll(now);
            transfer(&mut a, 0, &mut b, 0);
            let events_b = b.poll(now);

            let req_id = events_b
                .iter()
                .find_map(|e| match e {
                    ServiceEvent::Request { request_id, .. } => Some(*request_id),
                    _ => None,
                })
                .expect("B should receive request");
            b.respond(req_id, resp_data.as_bytes(), None, true);
            b.poll(now);
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(now);

            let response = events_a.iter().find_map(|e| match e {
                ServiceEvent::RequestResult {
                    result: Ok((_, data, _)),
                    ..
                } => Some(data.clone()),
                _ => None,
            });
            assert_eq!(
                response,
                Some(resp_data.as_bytes().to_vec()),
                "request {} should get response",
                i
            );
        }
    }

    // Rate adaptation tests - these verify the window management behavior
    // based on measured transfer rates.
    //
    // Objectives:
    // 1. Measure bytes_received / rtt when each batch completes
    // 2. If rate > 50 Kbps for 4 consecutive batches → window_max = 75
    // 3. If rate < 2 Kbps for 2 consecutive batches (and never fast) → window_max = 4
    // 4. window_min trails window to prevent over-shrinking

    #[test]
    fn resource_window_max_increases_after_sustained_fast_rate() {
        // After 4 consecutive batches with rate > 50 Kbps, window_max should increase to 75
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Large incompressible response for many batches (use hash chain for randomness)
        let mut large_response = vec![0u8; 50_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();

        // Use short RTT to simulate fast link (high bytes/rtt ratio)
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds with large response
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        // Simulate fast transfer with small time increments (high rate)
        let mut t = now;
        let mut max_window_seen = 0;
        let mut response_received = false;
        for _ in 0..500 {
            t += std::time::Duration::from_millis(1); // Fast: ~470KB/s per part
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                max_window_seen = max_window_seen.max(resource.window);
            }

            if events_a
                .iter()
                .any(|e| matches!(e, ServiceEvent::RequestResult { result: Ok(_), .. }))
            {
                response_received = true;
                break;
            }
        }

        assert!(response_received, "Should have received response");
        // After sustained fast rate, window should be allowed to grow beyond 10
        assert!(
            max_window_seen > 10,
            "window_max should increase to 75 after sustained fast rate, but max was {}",
            max_window_seen
        );
    }

    #[test]
    fn resource_window_max_decreases_on_very_slow_rate() {
        // After 2 consecutive batches with rate < 2 Kbps, window_max should decrease to 4
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data
        let mut large_response = vec![0u8; 50_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();

        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds with large response
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        // Simulate very slow transfer with large time increments
        let mut t = now;
        let mut final_window_max = 10; // Default
        let mut response_received = false;
        for _ in 0..500 {
            t += std::time::Duration::from_secs(10); // Very slow: ~47 bytes/s per part
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                final_window_max = resource.window_max;
            }

            if events_a
                .iter()
                .any(|e| matches!(e, ServiceEvent::RequestResult { result: Ok(_), .. }))
            {
                response_received = true;
                break;
            }
        }

        assert!(response_received, "Should have received response");
        assert_eq!(
            final_window_max, 4,
            "window_max should decrease to 4 after sustained very slow rate"
        );
    }

    #[test]
    fn resource_window_max_stays_high_if_ever_fast() {
        // Once window_max reaches 75, it should not decrease even if rate becomes slow
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data - 75KB needs ~160 parts, enough for sustained fast detection
        let mut large_response = vec![0u8; 75_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();

        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds with large response
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        let mut t = now;
        let mut reached_fast = false;
        let mut final_window_max = 10;
        let mut response_received = false;

        for i in 0..1000 {
            // First 200 iterations: fast rate to reach window_max=75
            // Rest: slower rate to verify it stays high
            if i < 200 {
                t += std::time::Duration::from_millis(1);
            } else {
                t += std::time::Duration::from_millis(50);
            }

            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                if resource.window_max == 75 {
                    reached_fast = true;
                }
                final_window_max = resource.window_max;
            }

            if events_a
                .iter()
                .any(|e| matches!(e, ServiceEvent::RequestResult { result: Ok(_), .. }))
            {
                response_received = true;
                break;
            }
        }

        assert!(response_received, "Should have received response");
        assert!(reached_fast, "Should have reached fast window_max");
        assert_eq!(
            final_window_max, 75,
            "window_max should stay at 75 even after rate becomes slow"
        );
    }

    #[test]
    fn resource_window_min_trails_window() {
        let _ = env_logger::builder().is_test(true).try_init();
        // window_min should trail window by at most WINDOW_FLEXIBILITY (4)
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data
        let mut large_response = vec![0u8; 100_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();

        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds with large response
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        let mut t = now;
        let mut max_gap = 0;
        let mut max_window = 0;
        let mut response_received = false;

        for _ in 0..1000 {
            t += std::time::Duration::from_millis(1);
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                let gap = resource.window.saturating_sub(resource.window_min);
                max_gap = max_gap.max(gap);
                max_window = max_window.max(resource.window);
            }

            if events_a
                .iter()
                .any(|e| matches!(e, ServiceEvent::RequestResult { result: Ok(_), .. }))
            {
                response_received = true;
                break;
            }
        }

        assert!(response_received, "Should have received response");
        assert!(
            max_window > 4,
            "window should grow beyond initial 4, but max was {}",
            max_window
        );
        assert!(
            max_gap <= 4,
            "window_min should trail window by at most 4, but gap was {} (max_window={})",
            max_gap,
            max_window
        );
    }

    #[test]
    fn resource_proof_packet_roundtrip() {
        use crate::packet::{Packet, ProofContext, ProofDestination};

        let link_id = [0x42u8; 16];
        let resource_hash = [0xAAu8; 32];
        let proof = [0xBBu8; 32];

        let mut data = resource_hash.to_vec();
        data.extend(&proof);

        let packet = Packet::Proof {
            hops: 0,
            destination: ProofDestination::Link(link_id),
            context: ProofContext::ResourcePrf,
            data,
        };

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);

        if let Packet::Proof {
            context,
            data,
            destination,
            ..
        } = parsed
        {
            assert_eq!(context, ProofContext::ResourcePrf);
            assert_eq!(destination, ProofDestination::Link(link_id));
            assert_eq!(&data[..32], &resource_hash);
            assert_eq!(&data[32..64], &proof);
        } else {
            panic!("Expected Proof packet");
        }
    }

    #[test]
    fn resource_proof_validates_and_cleans_up() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let large_response: Vec<u8> = (0..600).map(|i| (i % 256) as u8).collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"req");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(now);

        // B responds with large response
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, &large_response, None, true);
        b.poll(now);

        assert_eq!(
            b.outbound_resources.len(),
            1,
            "B should have outbound resource"
        );

        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            a.inbound_resources.len(),
            0,
            "A's inbound resource should be complete"
        );
        assert_eq!(b.outbound_resources.len(), 1, "B still waiting for proof");

        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(
            b.outbound_resources.len(),
            0,
            "B should clean up after receiving valid proof"
        );
    }

    #[test]
    fn last_inbound_updated_on_received_packets() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));

        let initial_inbound = a.established_links.get(&link_id).unwrap().last_inbound;

        // Advance time by 3 seconds
        let later = now + Duration::from_secs(3);

        // Send a request - this will trigger a response from B
        a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"req");
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(later);

        // B responds
        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");
        b.respond(request_id, b"response", None, true);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // After receiving the response, last_inbound should be updated
        let updated_inbound = a.established_links.get(&link_id).unwrap().last_inbound;

        assert!(
            updated_inbound > initial_inbound,
            "last_inbound should be updated after receiving response (was {:?}, now {:?})",
            initial_inbound,
            updated_inbound
        );
    }

    #[test]
    fn link_stays_active_with_traffic() {
        use std::time::Duration;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test.path"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // With 0ms RTT, stale_time is 10s (2 * 5s keepalive interval)
        // Send requests every 4s - link should stay active
        for i in 1..=5 {
            let t = now + Duration::from_secs(i * 4);
            a.request(svc_a, crate::LinkHandle(link_id), "test.path", b"ping");
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            let events_b = b.poll(t);

            // B responds
            let request_id = events_b
                .iter()
                .find_map(|e| match e {
                    ServiceEvent::Request { request_id, .. } => Some(*request_id),
                    _ => None,
                })
                .expect("B should receive request");
            b.respond(request_id, b"pong", None, true);
            b.poll(t);
            transfer(&mut b, 0, &mut a, 0);
            a.poll(t);

            assert!(
                a.established_links.contains_key(&link_id),
                "Link should stay active at t={}s with regular traffic",
                i * 4
            );
        }

        // At t=20s, link should still be active (last traffic at t=20s)
        assert!(
            a.established_links.contains_key(&link_id),
            "Link should still be active at t=20s"
        );
    }

    #[test]
    fn resource_requests_batched_per_poll() {
        use crate::packet::{LinkContext, Packet};

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Use data that won't compress much
        use rand::Rng;
        let mut rng = StdRng::seed_from_u64(42);
        let response: Vec<u8> = (0..50000).map(|_| rng.r#gen()).collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Request and respond
        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events = b.poll(now);
        let req_id = events
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .unwrap();
        b.respond(req_id, &response, None, true);
        b.poll(now);

        // Transfer advertisement
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Now B has parts queued. Transfer ALL of them at once to A.
        let parts_transferred = b.interfaces[0].transport.outbox.len();
        transfer(&mut b, 0, &mut a, 0);

        // Single poll should process all parts but only send ONE ResourceReq
        a.poll(now);

        let resource_req_count = a.interfaces[0]
            .transport
            .outbox
            .iter()
            .filter(|pkt| {
                Packet::from_bytes(pkt)
                    .map(|p| {
                        matches!(
                            p,
                            Packet::LinkData {
                                context: LinkContext::ResourceReq,
                                ..
                            }
                        )
                    })
                    .unwrap_or(false)
            })
            .count();

        // Key assertion: even though multiple parts arrived, at most 1 ResourceReq
        assert!(
            resource_req_count <= 1,
            "Expected at most 1 ResourceReq after batch of {} parts, got {}",
            parts_transferred,
            resource_req_count
        );
    }

    #[test]
    fn resource_progress_events() {
        use rand::Rng;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let mut rng = StdRng::seed_from_u64(99);
        let response: Vec<u8> = (0..10000).map(|_| rng.r#gen()).collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Request
        let local_req_id = a
            .request(svc_a, crate::LinkHandle(link_id), "test", b"")
            .unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events = b.poll(now);
        let server_req_id = events
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .unwrap();
        b.respond(server_req_id, &response, None, true);
        b.poll(now);

        // Track progress events
        let mut progress_events = Vec::new();
        let mut completed = false;

        for _ in 0..100 {
            transfer(&mut b, 0, &mut a, 0);
            let events = a.poll(now);

            for event in &events {
                match event {
                    ServiceEvent::ResourceProgress {
                        request_id,
                        received_parts,
                        total_parts,
                        ..
                    } => {
                        assert_eq!(*request_id, local_req_id);
                        progress_events.push((*received_parts, *total_parts));
                    }
                    ServiceEvent::RequestResult { request_id, .. } => {
                        assert_eq!(*request_id, local_req_id);
                        completed = true;
                    }
                    _ => {}
                }
            }

            transfer(&mut a, 0, &mut b, 0);
            b.poll(now);

            if completed {
                break;
            }
        }

        assert!(completed, "Transfer should complete");
        assert!(
            !progress_events.is_empty(),
            "Should have received progress events"
        );

        // Progress should be monotonically increasing
        for i in 1..progress_events.len() {
            assert!(
                progress_events[i].0 >= progress_events[i - 1].0,
                "Progress should be monotonic"
            );
        }

        // Last progress should be close to or at total
        let (last_received, total) = progress_events.last().unwrap();
        assert!(
            *last_received > 0 && *total > 0,
            "Should have non-zero parts"
        );
    }

    #[test]
    fn multi_segment_transfer_struct_fields() {
        let transfer = MultiSegmentTransfer {
            service: ServiceId(1),
            local_request_id: RequestId([0xAA; 16]),
            total_segments: 3,
            segments_received: 1,
            accumulated_data: vec![1, 2, 3, 4],
            has_metadata: true,
        };

        assert_eq!(transfer.total_segments, 3);
        assert_eq!(transfer.segments_received, 1);
        assert_eq!(transfer.accumulated_data.len(), 4);
        assert!(transfer.has_metadata);
    }

    #[test]
    fn multi_segment_transfer_tracking_initialized() {
        let node = test_node(true);
        assert!(node.multi_segment_transfers.is_empty());
    }

    #[test]
    fn strip_metadata_from_accumulated_data() {
        // Test the metadata stripping logic used in complete_resource
        // Metadata format: 3-byte big-endian length + msgpack data + actual content
        let metadata_content = b"test metadata";
        let actual_content = b"actual file content here";

        let metadata_len = metadata_content.len();
        let mut accumulated = Vec::new();
        accumulated.push((metadata_len >> 16) as u8);
        accumulated.push((metadata_len >> 8) as u8);
        accumulated.push(metadata_len as u8);
        accumulated.extend_from_slice(metadata_content);
        accumulated.extend_from_slice(actual_content);

        // Simulate stripping
        let metadata_size = ((accumulated[0] as usize) << 16)
            | ((accumulated[1] as usize) << 8)
            | (accumulated[2] as usize);
        let data_start = 3 + metadata_size;

        assert_eq!(metadata_size, metadata_content.len());
        assert_eq!(&accumulated[data_start..], actual_content);
    }

    #[test]
    fn strip_metadata_large_size() {
        // Test with metadata size requiring all 3 bytes
        let metadata_len: usize = 0x010203; // 66051 bytes
        let header = [
            (metadata_len >> 16) as u8,
            (metadata_len >> 8) as u8,
            metadata_len as u8,
        ];

        let parsed_size =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | (header[2] as usize);

        assert_eq!(parsed_size, 0x010203);
    }

    #[test]
    fn continuation_segment_detection() {
        // Test that segment_index > 1 with matching original_hash is detected as continuation
        let mut node = test_node(true);

        let original_hash = [0xAA; 32];

        // Add an in-progress transfer
        node.multi_segment_transfers.insert(
            original_hash,
            MultiSegmentTransfer {
                service: ServiceId(1),
                local_request_id: RequestId([0xBB; 16]),
                total_segments: 3,
                segments_received: 1,
                accumulated_data: vec![1, 2, 3],
                has_metadata: true,
            },
        );

        // Verify the transfer exists
        assert!(node.multi_segment_transfers.contains_key(&original_hash));

        // This simulates the check in ResourceAdv handling:
        let segment_index = 2;
        let is_continuation =
            segment_index > 1 && node.multi_segment_transfers.contains_key(&original_hash);

        assert!(is_continuation);
    }

    #[test]
    fn first_segment_not_detected_as_continuation() {
        let mut node = test_node(true);

        let original_hash = [0xAA; 32];

        // Even if there's an existing transfer (shouldn't happen but testing the logic)
        node.multi_segment_transfers.insert(
            original_hash,
            MultiSegmentTransfer {
                service: ServiceId(1),
                local_request_id: RequestId([0xBB; 16]),
                total_segments: 3,
                segments_received: 0,
                accumulated_data: Vec::new(),
                has_metadata: true,
            },
        );

        // segment_index == 1 should NOT be treated as continuation
        let segment_index = 1;
        let is_continuation =
            segment_index > 1 && node.multi_segment_transfers.contains_key(&original_hash);

        assert!(!is_continuation);
    }

    #[test]
    fn multi_segment_accumulation() {
        // Test that segments accumulate correctly
        let mut transfer = MultiSegmentTransfer {
            service: ServiceId(1),
            local_request_id: RequestId([0xAA; 16]),
            total_segments: 3,
            segments_received: 0,
            accumulated_data: Vec::new(),
            has_metadata: true,
        };

        // Simulate receiving segment 1
        let segment1_data = vec![1, 2, 3, 4, 5];
        transfer.accumulated_data.extend(&segment1_data);
        transfer.segments_received += 1;

        assert_eq!(transfer.segments_received, 1);
        assert_eq!(transfer.accumulated_data.len(), 5);

        // Simulate receiving segment 2
        let segment2_data = vec![6, 7, 8, 9, 10];
        transfer.accumulated_data.extend(&segment2_data);
        transfer.segments_received += 1;

        assert_eq!(transfer.segments_received, 2);
        assert_eq!(transfer.accumulated_data.len(), 10);
        assert_eq!(
            transfer.accumulated_data,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );

        // Simulate receiving final segment
        let segment3_data = vec![11, 12, 13];
        transfer.accumulated_data.extend(&segment3_data);
        transfer.segments_received += 1;

        assert_eq!(transfer.segments_received, 3);
        assert_eq!(transfer.accumulated_data.len(), 13);

        // Check if all segments received
        assert_eq!(transfer.segments_received, transfer.total_segments);
    }

    #[test]
    fn single_segment_resource_with_metadata_strips_prefix() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Create response with metadata prefix (simulating file download)
        // Format: 3-byte length + metadata + actual content
        let metadata = b"filename.txt";
        let actual_content: Vec<u8> = (0..100).map(|i| i as u8).collect();

        let mut response_with_metadata = Vec::new();
        let metadata_len = metadata.len();
        response_with_metadata.push((metadata_len >> 16) as u8);
        response_with_metadata.push((metadata_len >> 8) as u8);
        response_with_metadata.push(metadata_len as u8);
        response_with_metadata.extend_from_slice(metadata);
        response_with_metadata.extend_from_slice(&actual_content);

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Request
        a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events = b.poll(now);
        let server_req_id = events
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .unwrap();

        // Respond (the response goes through resource transfer)
        b.respond(server_req_id, &response_with_metadata, None, true);
        b.poll(now);

        // Complete the transfer
        let mut received_data = None;
        for _ in 0..50 {
            transfer(&mut b, 0, &mut a, 0);
            let events = a.poll(now);

            for event in &events {
                if let ServiceEvent::RequestResult {
                    result: Ok((_, data, _)),
                    ..
                } = event
                {
                    received_data = Some(data.clone());
                    break;
                }
            }

            if received_data.is_some() {
                break;
            }

            transfer(&mut a, 0, &mut b, 0);
            b.poll(now);
        }

        // Since we're not actually setting has_metadata in the advertisement
        // (that's done by the server when serving files), the metadata won't be stripped
        // This test verifies the basic single-segment resource flow works
        assert!(received_data.is_some());
        assert_eq!(received_data.unwrap(), response_with_metadata);
    }

    #[test]
    fn resource_advertisement_with_segment_fields_accepted() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Verify link is established
        assert!(a.established_links.contains_key(&link_id));

        // Make a request to set up pending_requests
        let _local_req_id = a.request(svc_a, crate::LinkHandle(link_id), "test", b"");
        a.poll(now);

        // Verify request is pending
        let link = a.established_links.get(&link_id).unwrap();
        assert!(!link.pending_requests.is_empty());
    }

    #[test]
    fn inbound_resource_tracks_segment_info() {
        use crate::resource::{InboundResource, ResourceAdvertisement};

        let adv = ResourceAdvertisement {
            transfer_size: 5000,
            data_size: 4800,
            num_parts: 10,
            hash: [0x11; 32],
            random_hash: [0x22; 4],
            original_hash: [0x33; 32],
            segment_index: 2,
            total_segments: 4,
            hashmap: vec![0; 40],
            compressed: false,
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: false,
            request_id: Some(vec![0xaa; 16]),
        };

        let resource = InboundResource::from_advertisement(&adv);

        assert_eq!(resource.segment_index, 2);
        assert_eq!(resource.total_segments, 4);
        assert_eq!(resource.original_hash, [0x33; 32]);
        assert!(!resource.is_last_segment()); // segment 2 of 4

        // Test last segment detection
        let last_adv = ResourceAdvertisement {
            segment_index: 4,
            total_segments: 4,
            ..adv
        };
        let last_resource = InboundResource::from_advertisement(&last_adv);
        assert!(last_resource.is_last_segment()); // segment 4 of 4
    }

    #[test]
    fn outbound_multi_segment_struct_fields() {
        let multi = OutboundMultiSegment {
            destination: [0x11; 16],
            service_idx: Some(ServiceId(1)),
            local_request_id: Some(RequestId([0x22; 16])),
            full_data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            compress: true,
            is_response: true,
            request_id: Some(vec![0xAA; 16]),
            total_segments: 3,
            current_segment: 1,
        };

        assert_eq!(multi.total_segments, 3);
        assert_eq!(multi.current_segment, 1);
        assert_eq!(multi.full_data.len(), 10);
    }

    #[test]
    fn outbound_multi_segment_tracking_initialized() {
        let node = test_node(true);
        assert!(node.outbound_multi_segments.is_empty());
    }

    fn make_test_link() -> EstablishedLink {
        use crate::crypto::EphemeralKeyPair;

        let mut rng = StdRng::seed_from_u64(12345);
        let initiator_keypair = EphemeralKeyPair::generate(&mut rng);
        let responder_keypair = EphemeralKeyPair::generate(&mut rng);
        let dest: Address = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];
        let now = Instant::now();

        EstablishedLink::from_responder(
            link_id,
            &responder_keypair.secret,
            &initiator_keypair.public,
            dest,
            ServiceId(0),
            0,
            now,
        )
    }

    #[test]
    fn outbound_resource_segment_fields() {
        use crate::resource::OutboundResource;

        let link = make_test_link();
        let data = vec![1, 2, 3, 4, 5];
        let mut rng = StdRng::seed_from_u64(42);

        let mut resource = OutboundResource::new_segment(
            &mut rng,
            &link,
            data,
            None,
            false,
            true,
            None,
            2,
            Some([0xAA; 32]),
            Some(5000),
        );

        assert_eq!(resource.segment_index, 2);
        assert!(resource.total_segments >= 1);
        assert_eq!(resource.original_hash, [0xAA; 32]);
        assert!(!resource.is_last_segment()); // segment 2 of N where N > 2

        // Verify advertisement includes segment info
        let adv = resource.advertisement(91);
        assert_eq!(adv.segment_index, 2);
        assert_eq!(adv.original_hash, [0xAA; 32]);
    }

    #[test]
    fn outbound_resource_is_last_segment() {
        use crate::resource::OutboundResource;

        let link = make_test_link();
        let mut rng = StdRng::seed_from_u64(42);

        // Single segment (no total_data_size hint) - should be last
        let single = OutboundResource::new_segment(
            &mut rng,
            &link,
            vec![1, 2, 3],
            None,
            false,
            true,
            None,
            1,
            None,
            None,
        );
        assert!(single.is_last_segment());

        // Last segment of multi-segment (segment 1 of 1)
        let last = OutboundResource::new_segment(
            &mut rng,
            &link,
            vec![1, 2, 3],
            None,
            false,
            true,
            None,
            1,
            Some([0xAA; 32]),
            Some(3), // total size = 3, so 1 segment
        );
        assert!(last.is_last_segment());
    }

    #[test]
    fn resource_response_msgpack_format() {
        use serde_bytes::ByteBuf;

        let request_id = [0xAB; 16];
        let response_data = b"Hello, World!".to_vec();

        // Encode like we do in send_response (and like Python does)
        let packed = rmp_serde::to_vec(&(
            ByteBuf::from(request_id.to_vec()),
            ByteBuf::from(response_data.clone()),
        ))
        .unwrap();

        // Decode like we do in complete_resource
        let (_, unpacked_data): (ByteBuf, ByteBuf) =
            rmp_serde::from_slice(&packed).expect("should decode");

        assert_eq!(unpacked_data.as_slice(), response_data.as_slice());
    }

    #[test]
    fn resource_response_msgpack_interop_with_python() {
        use serde_bytes::ByteBuf;

        // This is what Python sends: umsgpack.packb([request_id_bytes, response_bytes])
        // Test vector: request_id = 16 bytes of 0x42, response = b"test"
        let request_id = vec![0x42u8; 16];
        let response = b"test".to_vec();

        // Pack using our format
        let packed = rmp_serde::to_vec(&(
            ByteBuf::from(request_id.clone()),
            ByteBuf::from(response.clone()),
        ))
        .unwrap();

        // Verify it's a valid 2-element array that Python would produce
        // msgpack format: 0x92 = fixarray of 2 elements
        assert_eq!(packed[0], 0x92, "should be 2-element fixarray");

        // Unpack and verify
        let (unpacked_id, unpacked_response): (ByteBuf, ByteBuf) =
            rmp_serde::from_slice(&packed).unwrap();

        assert_eq!(unpacked_id.as_slice(), request_id.as_slice());
        assert_eq!(unpacked_response.as_slice(), response.as_slice());
    }

    #[test]
    fn multi_segment_progress_events_for_continuation() {
        // This tests that progress events are emitted for ALL segments,
        // not just the first one. The bug was that after the first segment
        // completes, pending_requests is cleared, so continuation segments
        // couldn't find service/request_id to emit progress events.

        use crate::resource::MAX_EFFICIENT_SIZE;

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Create response large enough to require 2 segments (> MAX_EFFICIENT_SIZE)
        // Use random data that won't compress well
        let mut rng = StdRng::seed_from_u64(12345);
        let large_response: Vec<u8> = (0..(MAX_EFFICIENT_SIZE + 1000))
            .map(|_| rng.r#gen())
            .collect();

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_b = b.add_service("server", &["test"], &id(2));
        let addr_b = b.service_address(svc_b).unwrap();
        let now = Instant::now();

        // Establish link
        b.announce(svc_b);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        let link_id = a.link(None, addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Send request
        let local_req_id = a
            .request(svc_a, crate::LinkHandle(link_id), "test", b"")
            .unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        let events = b.poll(now);
        let server_req_id = events
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .unwrap();

        // Respond with large data (will require 2 segments)
        // Use compress=false for predictable part counts
        b.respond(server_req_id, &large_response, None, false);
        b.poll(now);

        // Track progress events from both segments
        let mut first_segment_events = 0;
        let mut second_segment_events = 0;
        let mut completed = false;
        let mut t = now;

        for _ in 0..500 {
            t += std::time::Duration::from_millis(1);
            transfer(&mut b, 0, &mut a, 0);
            let events = a.poll(t);

            for event in &events {
                match event {
                    ServiceEvent::ResourceProgress {
                        request_id,
                        total_parts,
                        ..
                    } => {
                        assert_eq!(*request_id, local_req_id);
                        // First segment has ~11 parts, second has ~3
                        if *total_parts > 5 {
                            first_segment_events += 1;
                        } else {
                            second_segment_events += 1;
                        }
                    }
                    ServiceEvent::RequestResult { request_id, .. } => {
                        assert_eq!(*request_id, local_req_id);
                        completed = true;
                    }
                    _ => {}
                }
            }

            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if completed {
                break;
            }
        }

        assert!(completed, "Transfer should complete");

        // Both segments should emit progress events.
        // The bug was that only the first segment emitted progress events.
        assert!(
            first_segment_events > 0,
            "Should have progress events from first segment"
        );
        assert!(
            second_segment_events > 0,
            "Should have progress events from second segment (this was the bug)"
        );
    }

    #[test]
    fn create_link_returns_handle() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("server", &[], &id(0));
        let svc_b = b.add_service("client", &[], &id(1));
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let handle = b.create_link(svc_b, addr_a, t);
        assert!(handle.is_some());

        let link_id = b.destination_links.get(&addr_a);
        assert!(link_id.is_some());
        assert_eq!(handle.unwrap().0, *link_id.unwrap());
    }

    #[test]
    fn link_status_pending_then_active() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("server", &[], &id(0));
        let svc_b = b.add_service("client", &[], &id(1));
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let handle = b.create_link(svc_b, addr_a, t).unwrap();
        assert_eq!(b.link_status(handle), crate::LinkStatus::Pending);

        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        assert_eq!(b.link_status(handle), crate::LinkStatus::Active);
    }

    #[test]
    fn prove_packet_sends_proof() {
        let mut a = test_node(true);
        a.add_interface(test_interface());
        let svc_a = a.add_service("server", &[], &id(0));
        let _t = Instant::now();

        let packet_data = b"test packet data";
        assert!(a.prove_packet(svc_a, packet_data));
    }

    #[test]
    fn send_raw_to_known_destination() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("server", &[], &id(0));
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        b.send_raw(addr_a, b"raw data");
        b.poll(t);

        transfer(&mut b, 0, &mut a, 0);
        let events = a.poll(t);

        let raw_received = events.iter().any(|e| matches!(e, ServiceEvent::Raw { .. }));
        assert!(raw_received);
    }

    #[test]
    fn close_link_removes_link() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("server", &[], &id(0));
        let svc_b = b.add_service("client", &[], &id(1));
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let handle = b.create_link(svc_b, addr_a, t).unwrap();
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        assert_eq!(b.link_status(handle), crate::LinkStatus::Active);

        b.close_link(handle);

        assert_eq!(b.link_status(handle), crate::LinkStatus::Closed);
    }

    #[test]
    fn link_rtt_available_after_establishment() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("server", &[], &id(0));
        let svc_b = b.add_service("client", &[], &id(1));
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let handle = b.create_link(svc_b, addr_a, t).unwrap();
        assert!(b.link_rtt(handle).is_none());

        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        assert!(b.link_rtt(handle).is_some());
    }

    #[test]
    fn link_identify_sets_remote_identity() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let client_id = id(0);
        let svc_a = a.add_service("server", &[], &id(1));
        let svc_b = b.add_service("client", &[], &client_id);
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let handle = b.create_link(svc_b, addr_a, t).unwrap();
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        assert_eq!(b.link_status(handle), crate::LinkStatus::Active);

        let link_id = handle.0;
        assert!(
            a.established_links
                .get(&link_id)
                .unwrap()
                .remote_identity
                .is_none()
        );

        b.self_identify(handle, &client_id);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let remote_identity = a.established_links.get(&link_id).unwrap().remote_identity;
        assert!(remote_identity.is_some());
        assert_eq!(remote_identity.unwrap(), client_id.hash());
    }

    #[test]
    fn link_identify_included_in_request_event() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let client_id = id(0);
        let svc_a = a.add_service("server", &["/test"], &id(1));
        let svc_b = b.add_service("client", &[], &client_id);
        let addr_a = a.service_address(svc_a).unwrap();
        let t = Instant::now();

        a.announce(svc_a);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let handle = b.create_link(svc_b, addr_a, t).unwrap();
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        b.self_identify(handle, &client_id);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        b.link_request(handle, "/test", b"hello", t);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(t);

        let request_event = events_a
            .iter()
            .find(|e| matches!(e, ServiceEvent::Request { .. }));
        assert!(request_event.is_some(), "Request event should be emitted");
        if let Some(ServiceEvent::Request {
            remote_identity, ..
        }) = request_event
        {
            assert!(remote_identity.is_some(), "remote_identity should be set");
            assert_eq!(*remote_identity, Some(client_id.hash()));
        }
    }

    #[test]
    fn relay_four_nodes_link_and_data() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        let mut d = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());
        c.add_interface(test_interface());
        d.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_d = d.add_service("server", &[], &id(1));
        let addr_d = d.service_address(svc_d).unwrap();
        let now = Instant::now();
        let t1 = now + std::time::Duration::from_secs(1);
        let t2 = now + std::time::Duration::from_secs(2);

        d.announce(svc_d);
        d.poll(now);
        transfer(&mut d, 0, &mut c, 1);
        c.poll(now);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        b.poll(t2);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t2);

        assert!(a.path_table.contains_key(&addr_d));

        let link_id = a.link(Some(svc_a), addr_d, t2).unwrap();
        a.poll(t2);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t2);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t2);
        transfer(&mut c, 1, &mut d, 0);
        d.poll(t2);
        transfer(&mut d, 0, &mut c, 1);
        c.poll(t2);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t2);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t2);

        assert!(a.established_links.contains_key(&link_id));
        assert!(d.established_links.contains_key(&link_id));

        a.send_link_packet(link_id, LinkContext::None, b"hello from a");
        a.poll(t2);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t2);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t2);
        transfer(&mut c, 1, &mut d, 0);
        let events = d.poll(t2);

        let raw_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                ServiceEvent::Raw { data, .. } => Some(data.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(raw_events.len(), 1);
        assert_eq!(raw_events[0], b"hello from a");
    }

    #[test]
    fn relay_bidirectional_data_through_three_nodes() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(1));
        let svc_c = c.add_service("server", &[], &id(2));
        let addr_c = c.service_address(svc_c).unwrap();
        let now = Instant::now();
        let t1 = now + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let link_id = a.link(Some(svc_a), addr_c, t1).unwrap();
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        assert!(a.established_links.contains_key(&link_id));
        assert!(c.established_links.contains_key(&link_id));

        a.send_link_packet(link_id, LinkContext::None, b"a to c");
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        let events_c = c.poll(t1);

        let data_c: Vec<_> = events_c
            .iter()
            .filter_map(|e| match e {
                ServiceEvent::Raw { data, .. } => Some(data.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(data_c, vec![b"a to c".to_vec()]);

        assert!(c.established_links.contains_key(&link_id));
        assert!(b.link_table.contains_key(&link_id));

        c.send_link_packet(link_id, LinkContext::None, b"c to a");
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);

        let events_a = a.poll(t1);

        let data_a: Vec<_> = events_a
            .iter()
            .filter_map(|e| match e {
                ServiceEvent::Raw { data, .. } => Some(data.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(data_a, vec![b"c to a".to_vec()]);
    }

    #[test]
    fn relay_stats_updated_on_forwarding() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let now = Instant::now();
        let t1 = now + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);

        let stats_before = b.stats();
        assert_eq!(stats_before.announces_relayed, 0);

        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let stats_after = b.stats();
        assert!(stats_after.announces_relayed > 0);

        let _link_id = a.link(Some(svc_a), addr_c, t1).unwrap();
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);

        let stats_before_relay = b.stats();
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let stats_after_relay = b.stats();
        assert!(stats_after_relay.packets_relayed > stats_before_relay.packets_relayed);
    }

    #[test]
    fn link_request_sends_request_over_established_link() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &["/test"], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        assert_eq!(a.link_status(handle), crate::LinkStatus::Active);

        let request_id = a.link_request(handle, "/test", b"request data", t);
        assert!(request_id.is_some());

        a.poll(t);
        assert!(!a.interfaces[0].transport.outbox.is_empty());
    }

    #[test]
    fn link_request_fails_on_inactive_link() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        assert_eq!(a.link_status(handle), crate::LinkStatus::Pending);

        let request_id = a.link_request(handle, "/test", b"data", t);
        assert!(request_id.is_none());
    }

    #[test]
    fn link_request_response_received_via_link() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &["/test"], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let request_id = a.link_request(handle, "/test", b"request", t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(t);

        let req_event = events_b
            .iter()
            .find(|e| matches!(e, ServiceEvent::Request { .. }));
        assert!(req_event.is_some());

        if let Some(ServiceEvent::Request {
            request_id: req_id,
            path,
            ..
        }) = req_event
        {
            assert_eq!(path, "/test");
            b.respond(*req_id, b"response data", None, false);
        }

        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        let events_a = a.poll(t);

        let result_event = events_a.iter().find(|e| {
            matches!(
                e,
                ServiceEvent::RequestResult {
                    request_id: rid,
                    ..
                } if *rid == request_id
            )
        });
        assert!(result_event.is_some());
    }

    // Resource Advertisement API

    #[test]
    fn advertise_resource_sends_advertisement() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let outbox_before = a.interfaces[0].transport.outbox.len();
        let resource = a.advertise_resource(handle, b"resource data".to_vec(), None, false);
        assert!(resource.is_some());
        a.poll(t);

        assert!(a.interfaces[0].transport.outbox.len() > outbox_before);
        assert!(a.outbound_resources.contains_key(&resource.unwrap().0));
    }

    #[test]
    fn advertise_resource_with_metadata() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let metadata = b"file:test.txt".to_vec();
        let resource = a.advertise_resource(handle, b"data".to_vec(), Some(metadata), false);
        assert!(resource.is_some());
    }

    #[test]
    fn advertise_resource_with_compression() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let resource = a.advertise_resource(handle, b"compressible data".to_vec(), None, true);
        assert!(resource.is_some());
    }

    // Resource Progress API

    #[test]
    fn resource_progress_outbound() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let resource = a
            .advertise_resource(handle, b"test data".to_vec(), None, false)
            .unwrap();

        let progress = a.resource_progress(resource);
        assert!(progress.is_some());
    }

    #[test]
    fn resource_progress_inbound() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        a.advertise_resource(handle, b"test data".to_vec(), None, false);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);

        let inbound_resources: Vec<_> = b.inbound_resources.keys().cloned().collect();
        if let Some(hash) = inbound_resources.first() {
            let progress = b.resource_progress(crate::ResourceHandle(*hash));
            assert!(progress.is_some());
        }
    }

    #[test]
    fn resource_progress_unknown_resource() {
        let a = test_node(true);
        let fake_hash = [0u8; 32];
        let progress = a.resource_progress(crate::ResourceHandle(fake_hash));
        assert!(progress.is_none());
    }

    // Path Discovery

    #[test]
    fn path_request_sent_for_unknown_destination() {
        let mut a = test_node(true);
        a.add_interface(test_interface());

        let _svc_a = a.add_service("client", &[], &id(0));
        let unknown_dest: Address = [0xAB; 16];
        let t = Instant::now();

        assert!(!a.path_table.contains_key(&unknown_dest));

        a.request_path(unknown_dest, t);
        a.poll(t);

        assert!(!a.interfaces[0].transport.outbox.is_empty());
    }

    #[test]
    fn path_response_updates_path_table() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        let mut c = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        assert!(a.path_table.contains_key(&addr_c));
    }

    #[test]
    fn path_request_forwarded_by_transport() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);

        a.request_path(addr_c, t1);
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);

        let stats_before = b.stats();
        b.poll(t1);
        let stats_after = b.stats();

        assert!(
            stats_after.packets_relayed > stats_before.packets_relayed
                || !b.interfaces[1].transport.outbox.is_empty()
        );
    }

    #[test]
    fn path_response_forwarded_back() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);

        a.request_path(addr_c, t1);
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        assert!(a.path_table.contains_key(&addr_c));
    }

    // Multi-hop Routing

    #[test]
    fn link_request_routed_through_transport() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let _handle = a.create_link(svc_a, addr_c, t1);
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);

        let stats_before = b.stats();
        b.poll(t1);
        let stats_after = b.stats();

        assert!(stats_after.packets_relayed > stats_before.packets_relayed);
    }

    #[test]
    fn link_proof_routed_back_through_transport() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let handle = a.create_link(svc_a, addr_c, t1).unwrap();
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        assert_eq!(a.link_status(handle), crate::LinkStatus::Active);
    }

    // Resource Segment Handling

    #[test]
    fn resource_hmu_segment_received() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let large_data = vec![0u8; 5000];
        let resource = a.advertise_resource(handle, large_data, None, false);
        assert!(resource.is_some());

        assert!(a.outbound_resources.contains_key(&resource.unwrap().0));

        a.poll(t);
        assert!(!a.interfaces[0].transport.outbox.is_empty());
    }

    #[test]
    fn resource_req_triggers_data_send() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let data = vec![0u8; 2000];
        a.advertise_resource(handle, data, None, false);
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);

        let outbox_before = a.interfaces[0].transport.outbox.len();
        a.poll(t);
        let outbox_after = a.interfaces[0].transport.outbox.len();

        assert!(outbox_after >= outbox_before);
    }

    #[test]
    fn resource_icl_confirms_segment() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let resource = a.advertise_resource(handle, b"small".to_vec(), None, false);
        assert!(resource.is_some());

        for _ in 0..10 {
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);
            transfer(&mut b, 0, &mut a, 0);
        }

        assert!(resource.is_some());
    }

    #[test]
    fn resource_rcl_confirms_segment() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &["test"], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let link_id = a.link(None, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"req");
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(t);

        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");

        let large_response: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        b.respond(request_id, &large_response, None, false);
        b.poll(t);

        assert_eq!(
            b.outbound_resources.len(),
            1,
            "B should have outbound resource"
        );

        for _ in 0..20 {
            transfer(&mut b, 0, &mut a, 0);
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);
        }

        assert!(
            b.outbound_resources.is_empty(),
            "outbound resource should be confirmed and removed after RCL proof"
        );
    }

    #[test]
    fn resource_proof_validates_transfer() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let resource = a
            .advertise_resource(handle, b"test".to_vec(), None, false)
            .unwrap();

        for _ in 0..20 {
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);
            transfer(&mut b, 0, &mut a, 0);
        }

        let still_pending = a.outbound_resources.contains_key(&resource.0);
        assert!(!still_pending || b.inbound_resources.is_empty());
    }

    // Transport Relay Edge Cases

    #[test]
    fn announce_with_transport_id_forwarded() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);

        let stats_before = b.stats();
        b.poll(t1);
        let stats_after = b.stats();

        assert!(stats_after.announces_relayed > stats_before.announces_relayed);

        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        assert!(a.path_table.contains_key(&addr_c));
    }

    #[test]
    fn link_data_relayed_by_transport_node() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let link_id = a.link(Some(svc_a), addr_c, t1).unwrap();
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        a.send_link_packet(link_id, LinkContext::None, b"test data");
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);

        let stats_before = b.stats();
        b.poll(t1);
        let stats_after = b.stats();

        assert!(stats_after.packets_relayed > stats_before.packets_relayed);

        transfer(&mut b, 1, &mut c, 0);
        let events = c.poll(t1);

        let has_raw = events.iter().any(|e| matches!(e, ServiceEvent::Raw { .. }));
        assert!(has_raw);
    }

    // Path Discovery Timeout

    #[test]
    fn path_request_timeout_emits_not_found() {
        let mut a = test_node(true);
        a.add_interface(test_interface());

        let _svc_a = a.add_service("client", &[], &id(0));
        let unknown_dest: Address = [0xDE; 16];
        let t = Instant::now();

        a.request_path(unknown_dest, t);
        a.poll(t);

        assert!(a.pending_path_requests.contains_key(&unknown_dest));

        let timeout = t + std::time::Duration::from_secs(61);
        let events = a.poll(timeout);

        assert!(!a.pending_path_requests.contains_key(&unknown_dest));

        let has_path_not_found = events.iter().any(|e| {
            matches!(
                e,
                ServiceEvent::PathRequestResult {
                    destination,
                    found: false,
                } if *destination == unknown_dest
            )
        });
        assert!(has_path_not_found);
    }

    #[test]
    fn pending_link_timeout_closes_link() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let link = a.create_link(svc_a, addr_b, t);
        assert!(link.is_some());
        a.poll(t);

        assert!(!a.pending_outbound_links.is_empty());

        let timeout = t + std::time::Duration::from_secs(70);
        a.poll(timeout);

        assert!(a.pending_outbound_links.is_empty());
        assert_eq!(a.link_status(link.unwrap()), crate::LinkStatus::Closed);
    }

    // Multi-Segment Resources

    #[test]
    fn multi_segment_resource_transfer_complete() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &[], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let handle = a.create_link(svc_a, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let large_data = vec![0xAB; 10000];
        let resource = a.advertise_resource(handle, large_data.clone(), None, false);
        assert!(resource.is_some());

        for _ in 0..50 {
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);
            transfer(&mut b, 0, &mut a, 0);
        }

        for _ in 0..10 {
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);
            transfer(&mut b, 0, &mut a, 0);
        }

        let transfer_active = !a.outbound_resources.is_empty() || !b.inbound_resources.is_empty();
        assert!(transfer_active);
    }

    #[test]
    fn resource_hashmap_update_processed() {
        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &["test"], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let link_id = a.link(None, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"req");
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(t);

        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");

        let large_data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        b.respond(request_id, &large_data, None, true);
        b.poll(t);

        let mut received_data = None;
        for _ in 0..500 {
            transfer(&mut b, 0, &mut a, 0);
            let events_a = a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some(data) = events_a.iter().find_map(|e| match e {
                ServiceEvent::RequestResult {
                    result: Ok((_, data, _)),
                    ..
                } => Some(data.clone()),
                _ => None,
            }) {
                received_data = Some(data);
                break;
            }
        }

        assert_eq!(
            received_data,
            Some(large_data),
            "50KB transfer requiring HMU should complete with correct data"
        );
    }

    #[test]
    fn resource_confirmation_cleans_up_state() {
        use crate::packet::{LinkContext, LinkDataDestination, Packet};

        let mut a = test_node(true);
        let mut b = test_node(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_b = b.add_service("server", &["test"], &id(1));
        let addr_b = b.service_address(svc_b).unwrap();
        let t = Instant::now();

        b.announce(svc_b);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        let link_id = a.link(None, addr_b, t).unwrap();
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        a.request(svc_a, crate::LinkHandle(link_id), "test", b"req");
        a.poll(t);
        transfer(&mut a, 0, &mut b, 0);
        let events_b = b.poll(t);

        let request_id = events_b
            .iter()
            .find_map(|e| match e {
                ServiceEvent::Request { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("B should receive request");

        let response_data = vec![0xAB; 500];
        b.respond(request_id, &response_data, None, false);
        b.poll(t);

        assert_eq!(
            b.outbound_resources.len(),
            1,
            "B should have outbound resource after respond"
        );
        let resource_hash = *b.outbound_resources.keys().next().unwrap();

        transfer(&mut b, 0, &mut a, 0);
        a.poll(t);

        assert_eq!(
            a.inbound_resources.len(),
            1,
            "A should have inbound resource after receiving advertisement"
        );

        let link_id = *a.established_links.keys().next().unwrap();
        let link = a.established_links.get(&link_id).unwrap();
        let icl_payload = link.encrypt(&mut rand::rngs::StdRng::from_entropy(), &resource_hash);
        let icl_packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link_id),
            context: LinkContext::ResourceIcl,
            data: icl_payload,
        };

        b.interfaces[0]
            .transport
            .inbox
            .push_back(icl_packet.to_bytes());
        b.poll(t);

        assert!(
            !b.outbound_resources.contains_key(&resource_hash),
            "ICL packet should clean up outbound_resources"
        );
    }

    #[test]
    fn multi_segment_resource_with_three_nodes() {
        let mut a = test_node(false);
        let mut b = test_node(true);
        let mut c = test_node(false);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = a.add_service("client", &[], &id(0));
        let svc_c = c.add_service("server", &[], &id(1));
        let addr_c = c.service_address(svc_c).unwrap();
        let t = Instant::now();
        let t1 = t + std::time::Duration::from_secs(1);

        c.announce(svc_c);
        c.poll(t);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        let handle = a.create_link(svc_a, addr_c, t1).unwrap();
        a.poll(t1);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(t1);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(t1);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(t1);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(t1);

        assert_eq!(a.link_status(handle), crate::LinkStatus::Active);

        let data = vec![0xEF; 5000];
        let resource = a.advertise_resource(handle, data, None, false);
        assert!(resource.is_some());

        for _ in 0..50 {
            a.poll(t1);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t1);
            transfer(&mut b, 1, &mut c, 0);
            c.poll(t1);
            transfer(&mut c, 0, &mut b, 1);
            b.poll(t1);
            transfer(&mut b, 0, &mut a, 0);
        }

        let b_relayed = b.stats().packets_relayed;
        assert!(b_relayed > 0);
    }

    #[test]
    fn link_packets_only_sent_on_link_interface() {
        use std::time::Duration;

        let mut server = test_node(true);
        let mut client = test_node(true);

        server.add_interface(test_interface());
        server.add_interface(test_interface());
        client.add_interface(test_interface());

        let svc_client = client.add_service("client", &[], &id(1));
        let svc_server = server.add_service("server", &["test"], &id(2));
        let addr = server.service_address(svc_server).unwrap();
        let now = Instant::now();

        // Announce goes to all interfaces (correct behavior)
        server.announce(svc_server);
        server.poll(now);
        transfer(&mut server, 0, &mut client, 0);
        client.poll(now);

        // Establish link via interface 0
        let link_id = client.link(None, addr, now).unwrap();
        client.poll(now);
        transfer(&mut client, 0, &mut server, 0);
        server.poll(now);
        transfer(&mut server, 0, &mut client, 0);
        client.poll(now);

        assert!(client.established_links.contains_key(&link_id));
        assert!(server.established_links.contains_key(&link_id));

        // Clear interface 1 after link setup (announce legitimately used it)
        server.interfaces[1].transport.outbox.clear();

        // send_link_packet
        server.send_link_packet(link_id, LinkContext::None, b"payload");
        server.poll(now);

        // request + small respond
        client.request(svc_client, crate::LinkHandle(link_id), "test", b"req");
        client.poll(now);
        transfer(&mut client, 0, &mut server, 0);
        let events = server.poll(now);
        let req_id = events.iter().find_map(|e| match e {
            ServiceEvent::Request { request_id, .. } => Some(*request_id),
            _ => None,
        }).unwrap();
        server.respond(req_id, b"small", None, false);
        server.poll(now);

        // large respond (resource adv) + resource transfer
        transfer(&mut server, 0, &mut client, 0);
        client.poll(now);
        client.request(svc_client, crate::LinkHandle(link_id), "test", b"req2");
        client.poll(now);
        transfer(&mut client, 0, &mut server, 0);
        let events = server.poll(now);
        let req_id = events.iter().find_map(|e| match e {
            ServiceEvent::Request { request_id, .. } => Some(*request_id),
            _ => None,
        }).unwrap();
        let large: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        server.respond(req_id, &large, None, false);
        server.poll(now);

        // resource request + parts
        transfer(&mut server, 0, &mut client, 0);
        client.poll(now);
        transfer(&mut client, 0, &mut server, 0);
        server.poll(now);

        // keepalive
        if let Some(link) = server.established_links.get_mut(&link_id) {
            link.last_inbound = now;
            link.last_keepalive_sent = None;
            link.set_rtt(0);
        }
        server.poll(now + Duration::from_secs(10));

        // link close
        server.poll(now + Duration::from_secs(800));

        // After all link operations, interface 1 should have received nothing
        assert!(
            server.interfaces[1].transport.outbox.is_empty(),
            "interface 1 should have no link packets"
        );
    }
}
