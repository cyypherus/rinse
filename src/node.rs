use std::collections::HashMap;
use std::time::Instant;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::announce::{AnnounceBuilder, AnnounceData};
use crate::aspect::AspectHash;
use crate::crypto::{EphemeralKeyPair, sha256};
use crate::handle::{Destination, NodeHandle, PendingAction, Service};
use crate::stats::{Stats, StatsSnapshot};

const LINK_MDU: usize = 431;

enum ServiceNotification {
    Request {
        service_idx: usize,
        link_id: LinkId,
        request_id: RequestId,
        wire_request_id: WireRequestId,
        from: Address,
        path: String,
        data: Vec<u8>,
    },
    RequestResult {
        service_idx: usize,
        request_id: RequestId,
        result: Result<(Address, Vec<u8>), crate::handle::RequestError>,
    },
    RespondResult {
        service_idx: usize,
        request_id: RequestId,
        result: Result<(), crate::handle::RespondError>,
    },
    Data {
        service_idx: usize,
        from: Address,
        data: Vec<u8>,
    },
    Raw {
        service_idx: usize,
        from: Address,
        data: Vec<u8>,
    },
    DestinationsChanged,
}
use crate::link::{EstablishedLink, LinkId, LinkProof, LinkRequest, LinkState, PendingLink};
use crate::packet::{Address, LinkContext, Packet, SingleDestination};
use crate::packet_hashlist::PacketHashlist;
use crate::request::{PathHash, Request, RequestId, Response, WireRequestId};
use crate::{Interface, Transport};
use ed25519_dalek::Signature;

// "By default, m is set to 128."
const DEFAULT_MAX_HOPS: u8 = 128;
// "By default, r is set to 1."
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;
const LOCAL_REBROADCASTS_MAX: u8 = 2;
const PATHFINDER_RW_MS: u64 = 500;
const ESTABLISHMENT_TIMEOUT_PER_HOP_SECS: u64 = 6;
const ESTABLISHMENT_TIMEOUT_BASE_SECS: u64 = 60;
const PATH_REQUEST_TIMEOUT_SECS: u64 = 60;

pub(crate) struct ServiceEntry<S> {
    service: S,
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
struct PathEntry {
    timestamp: Instant,
    next_hop: Address,
    hops: u8,
    receiving_interface: usize,
    encryption_key: X25519Public,
    signing_key: VerifyingKey,
    #[allow(dead_code)]
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

pub struct Node<T, S, R = ThreadRng> {
    transport: bool,
    max_hops: u8,
    retries: u8,
    retry_delay_ms: u64,
    rng: R,
    transport_id: Address,
    path_table: HashMap<Address, PathEntry>,
    pending_announces: Vec<PendingAnnounce>,
    seen_packets: PacketHashlist,
    reverse_table: HashMap<Address, ReverseTableEntry>,
    receipts: Vec<Receipt>,
    pub(crate) services: Vec<ServiceEntry<S>>,
    pub(crate) interfaces: Vec<Interface<T>>,
    pending_outbound_links: HashMap<LinkId, PendingLink>,
    pub(crate) established_links: HashMap<LinkId, EstablishedLink>,
    link_table: HashMap<LinkId, LinkTableEntry>,
    outbound_resources: HashMap<
        [u8; 32],
        (
            LinkId,
            Address,
            Option<usize>,
            Option<RequestId>,
            crate::resource::OutboundResource,
        ),
    >,
    inbound_resources: HashMap<[u8; 32], (LinkId, crate::resource::InboundResource)>,
    pending_resource_adverts: HashMap<[u8; 32], (LinkId, crate::resource::ResourceAdvertisement)>,
    inbound_request_links: HashMap<RequestId, (WireRequestId, LinkId, usize)>,
    destination_links: HashMap<Address, LinkId>,
    pending_outbound_requests: HashMap<Address, Vec<(Address, RequestId, String, Vec<u8>)>>,
    pending_path_requests: HashMap<Address, Instant>,
    discovery_path_requests: HashMap<Address, usize>,
    stats: Stats,
}

impl<T: Transport, S: Service> Node<T, S, ThreadRng> {
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
            inbound_request_links: HashMap::new(),
            destination_links: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
            pending_path_requests: HashMap::new(),
            discovery_path_requests: HashMap::new(),
            stats: Stats::new(),
        }
    }
}

impl<T: Transport, S: Service, R: RngCore> Node<T, S, R> {
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
            inbound_request_links: HashMap::new(),
            destination_links: HashMap::new(),
            pending_outbound_requests: HashMap::new(),
            pending_path_requests: HashMap::new(),
            discovery_path_requests: HashMap::new(),
            stats: Stats::new(),
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

    fn build_destinations(&self) -> Vec<Destination> {
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

    fn dispatch_to_service<F>(&mut self, service_idx: usize, now: Instant, f: F)
    where
        F: FnOnce(&mut S, &mut NodeHandle),
    {
        let destinations = self.build_destinations();
        let pending = {
            let Node { services, .. } = self;
            let entry = &mut services[service_idx];
            let mut handle = NodeHandle {
                destinations: &destinations,
                pending: Vec::new(),
            };
            f(&mut entry.service, &mut handle);
            handle.pending
        };
        self.process_pending_actions(service_idx, pending, now);
    }

    fn process_pending_actions(
        &mut self,
        service_idx: usize,
        actions: Vec<PendingAction>,
        now: Instant,
    ) {
        let service_addr = self.services[service_idx].address;

        for action in actions {
            match action {
                PendingAction::SendRaw { destination, data } => {
                    self.send_single_data(destination, &data, now);
                }
                PendingAction::Request {
                    destination,
                    path,
                    data,
                } => {
                    self.request(service_addr, destination, &path, &data, now);
                }
                PendingAction::Announce { app_data } => {
                    if let Some(data) = app_data {
                        self.announce_with_app_data(service_addr, Some(data), now);
                    } else {
                        self.announce(service_addr, now);
                    }
                }
                PendingAction::Respond { request_id, data } => {
                    self.send_response(request_id, data, now);
                }
            }
        }
    }

    fn send_single_data(&mut self, destination: Address, data: &[u8], now: Instant) {
        use crate::crypto::SingleDestEncryption;

        if let Some(entry) = self.path_table.get(&destination) {
            let (ephemeral_pub, ciphertext) =
                SingleDestEncryption::encrypt(&mut self.rng, &entry.encryption_key, data);
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
                iface.send(packet, 0, now);
            }
        }
    }

    pub fn request(
        &mut self,
        service_addr: Address,
        destination: Address,
        path: &str,
        data: &[u8],
        now: Instant,
    ) -> RequestId {
        let mut id_bytes = [0u8; 16];
        self.rng.fill_bytes(&mut id_bytes);
        let local_request_id = RequestId(id_bytes);

        self.send_request_inner(
            service_addr,
            destination,
            local_request_id,
            path,
            data.to_vec(),
            now,
        );

        local_request_id
    }

    pub fn respond(&mut self, request_id: RequestId, data: &[u8], now: Instant) {
        self.send_response(request_id, data.to_vec(), now);
    }

    fn send_request_inner(
        &mut self,
        service_addr: Address,
        destination: Address,
        local_request_id: RequestId,
        path: &str,
        data: Vec<u8>,
        now: Instant,
    ) {
        use crate::packet::LinkDataDestination;

        log::info!(
            "Request to <{}> path={} ({} bytes)",
            hex::encode(destination),
            path,
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
                    .insert(wire_request_id, (service_addr, local_request_id));

                log::info!(
                    "Sending request over link {} wire_request_id={} packet_hash={}",
                    hex::encode(link_id),
                    hex::encode(wire_request_id.0),
                    hex::encode(packet.packet_hash())
                );
                for iface in &mut self.interfaces {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += packet.to_bytes().len() as u64;
                    iface.send(packet.clone(), 0, now);
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
                .push((service_addr, local_request_id, path.to_string(), data));

            if self.link(destination, Some(service_addr), now).is_none() {
                log::info!(
                    "No existing link, sending path request for <{}>",
                    hex::encode(destination)
                );
                self.request_path(destination, now);
            }
        }
    }

    fn send_response(&mut self, request_id: RequestId, data: Vec<u8>, now: Instant) {
        use crate::packet::LinkDataDestination;

        if let Some((wire_request_id, link_id, service_idx)) =
            self.inbound_request_links.remove(&request_id)
            && let Some(link) = self.established_links.get(&link_id)
        {
            if data.len() <= LINK_MDU {
                let resp = Response::new(wire_request_id, data);
                let ciphertext = link.encrypt(&mut self.rng, &resp.encode());

                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::Response,
                    data: ciphertext,
                };
                for iface in &mut self.interfaces {
                    iface.send(packet.clone(), 0, now);
                }
                // Small responses are sent directly - notify success immediately
                // (no proof mechanism for direct responses)
                self.dispatch_notifications(
                    vec![ServiceNotification::RespondResult {
                        service_idx,
                        request_id,
                        result: Ok(()),
                    }],
                    now,
                );
            } else {
                let mut resource = crate::resource::OutboundResource::new(
                    &mut self.rng,
                    link,
                    data,
                    None,
                    true,
                    true,
                    Some(wire_request_id.0.to_vec()),
                );
                let adv = resource.advertisement(91);
                let adv_data = adv.encode();
                let hash = resource.hash;

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

                for iface in &mut self.interfaces {
                    iface.send(packet.clone(), 0, now);
                }
            }
        }
    }

    fn dispatch_notifications(&mut self, notifications: Vec<ServiceNotification>, now: Instant) {
        for notification in notifications {
            match notification {
                ServiceNotification::Request {
                    service_idx,
                    link_id,
                    request_id,
                    wire_request_id,
                    from,
                    path,
                    data,
                } => {
                    self.inbound_request_links
                        .insert(request_id, (wire_request_id, link_id, service_idx));
                    self.dispatch_to_service(service_idx, now, |service, handle| {
                        service.on_request(handle, request_id, from, &path, &data);
                    });
                }
                ServiceNotification::RequestResult {
                    service_idx,
                    request_id,
                    result,
                } => {
                    self.dispatch_to_service(service_idx, now, |service, handle| {
                        service.on_request_result(handle, request_id, result);
                    });
                }
                ServiceNotification::RespondResult {
                    service_idx,
                    request_id,
                    result,
                } => {
                    self.dispatch_to_service(service_idx, now, |service, handle| {
                        service.on_respond_result(handle, request_id, result);
                    });
                }
                ServiceNotification::Data {
                    service_idx,
                    from,
                    data,
                } => {
                    self.dispatch_to_service(service_idx, now, |service, handle| {
                        service.on_raw(handle, from, &data);
                    });
                }
                ServiceNotification::Raw {
                    service_idx,
                    from,
                    data,
                } => {
                    self.dispatch_to_service(service_idx, now, |service, handle| {
                        service.on_raw(handle, from, &data);
                    });
                }
                ServiceNotification::DestinationsChanged => {
                    for service_idx in 0..self.services.len() {
                        self.dispatch_to_service(service_idx, now, |service, handle| {
                            service.on_destinations_changed(handle);
                        });
                    }
                }
            }
        }
    }

    pub fn has_destination(&self, dest: &Address) -> bool {
        self.path_table.contains_key(dest)
    }

    pub fn known_destinations(&self) -> Vec<Destination> {
        self.build_destinations()
    }

    pub fn is_link_established(&self, link_id: &LinkId) -> bool {
        self.established_links
            .get(link_id)
            .map(|l| l.state == crate::link::LinkState::Active)
            .unwrap_or(false)
    }

    pub fn close_link(&mut self, link_id: LinkId, now: Instant) {
        if let Some(link) = self.established_links.get(&link_id) {
            if link.state == LinkState::Closed {
                return;
            }
        } else {
            return;
        }

        self.send_link_packet(link_id, LinkContext::LinkClose, &link_id, now);

        let (destination, pending_requests) =
            if let Some(link) = self.established_links.get_mut(&link_id) {
                link.state = LinkState::Closed;
                let pending = std::mem::take(&mut link.pending_requests);
                (Some(link.destination), pending)
            } else {
                (None, std::collections::HashMap::new())
            };

        // Notify services with pending requests on this link
        let mut notifications = Vec::new();
        for (_wire_id, (service_addr, local_request_id)) in pending_requests {
            if let Some(service_idx) = self.services.iter().position(|s| s.address == service_addr)
            {
                notifications.push(ServiceNotification::RequestResult {
                    service_idx,
                    request_id: local_request_id,
                    result: Err(crate::handle::RequestError::LinkClosed),
                });
            }
        }

        // Notify services with pending outbound resources (responses) on this link
        let failed_resources: Vec<_> = self
            .outbound_resources
            .iter()
            .filter(|(_, (lid, _, _, _, _))| *lid == link_id)
            .map(|(hash, (_, _, service_idx, local_request_id, _))| {
                (*hash, *service_idx, *local_request_id)
            })
            .collect();

        for (hash, service_idx, request_id) in failed_resources {
            self.outbound_resources.remove(&hash);
            if let (Some(service_idx), Some(request_id)) = (service_idx, request_id) {
                notifications.push(ServiceNotification::RespondResult {
                    service_idx,
                    request_id,
                    result: Err(crate::handle::RespondError::LinkClosed),
                });
            }
        }

        // Clean up inbound resources on this link
        let failed_inbound: Vec<_> = self
            .inbound_resources
            .iter()
            .filter(|(_, (lid, _))| *lid == link_id)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in failed_inbound {
            self.inbound_resources.remove(&hash);
        }

        if !notifications.is_empty() {
            self.dispatch_notifications(notifications, now);
        }

        if let Some(dest) = destination {
            self.destination_links.remove(&dest);
        }
        self.established_links.remove(&link_id);

        log::debug!("Closed link <{}>", hex::encode(link_id));
    }

    pub fn add_service(&mut self, service: S, identity: &crate::identity::Identity) -> Address {
        let name = service.name();
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
        for path in service.paths() {
            let path_hash = crate::request::path_hash(path);
            registered_paths.insert(path_hash, path.to_string());
        }

        self.services.push(ServiceEntry {
            service,
            address,
            name_hash,
            encryption_secret,
            encryption_public,
            signing_key,
            registered_paths,
        });

        address
    }

    pub fn announce(&mut self, address: Address, now: Instant) {
        self.announce_with_app_data(address, None, now);
    }

    pub fn announce_with_app_data(
        &mut self,
        address: Address,
        app_data: Option<Vec<u8>>,
        now: Instant,
    ) {
        let Some(entry) = self.services.iter().find(|s| s.address == address) else {
            return;
        };

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
            iface.send(packet.clone(), 0, now);
        }
    }

    fn request_path(&mut self, destination: Address, now: Instant) {
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
            iface.send(packet.clone(), 0, now);
        }
    }

    pub fn send_raw(&mut self, destination: Address, data: &[u8], now: Instant) {
        self.send_single_data(destination, data, now);
    }

    // "When a node in the network wants to establish verified connectivity with another node,
    // it will randomly generate a new X25519 private/public key pair. It then creates a
    // link request packet, and broadcast it."
    pub(crate) fn link(
        &mut self,
        destination: Address,
        initiating_service: Option<Address>,
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
                request_time: now,
                initiating_service,
            },
        );

        // Send on the interface that received the announce
        log::debug!(
            "Sending link request to <{}> link_id=<{}>",
            hex::encode(destination),
            hex::encode(link_id)
        );
        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            iface.send(packet, 0, now);
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
                    | LinkContext::ResourcePrf
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
        let mut notifications: Vec<ServiceNotification> = Vec::new();

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
            query_destination, ..
        } = &packet
        {
            let query_dest = *query_destination;

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
                    iface.send(response_packet, 0, now);
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
                    iface.send(response_packet, 0, now);
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

                // Forward path request on all other interfaces
                let packet_len = raw.len();
                for (i, iface) in self.interfaces.iter_mut().enumerate() {
                    if i != interface_index {
                        self.stats.packets_relayed += 1;
                        self.stats.bytes_relayed += packet_len as u64;
                        iface.send(packet.clone(), 0, now);
                    }
                }
            }
        }

        // General transport handling. Takes care of directing packets according
        // to transport tables and recording entries in reverse and link tables.
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
                        iface.send(new_packet, 0, now);
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
                        iface.send(packet.clone(), 0, now);
                        link_entry.timestamp = now;
                    }
                }
            }
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
                        if !is_path_response {
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
                            notifications.push(ServiceNotification::DestinationsChanged);
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
                                iface.send(response_packet, 0, now);
                            }
                        }

                        if self
                            .pending_outbound_requests
                            .contains_key(&destination_hash)
                        {
                            log::info!(
                                "Have pending requests for <{}>, initiating link",
                                hex::encode(destination_hash)
                            );
                            self.link(destination_hash, None, now);
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
                        iface.send(proof_packet, 0, now);
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
                        | LinkContext::ResourcePrf
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
                        if let Some((service_addr, local_request_id)) =
                            link.pending_requests.remove(&resp.request_id)
                            && let Some(service_idx) =
                                self.services.iter().position(|s| s.address == service_addr)
                        {
                            log::info!(
                                "Matched pending request local_id={} - delivering {} bytes",
                                hex::encode(local_request_id.0),
                                resp.data.len()
                            );
                            let from = link.destination;
                            notifications.push(ServiceNotification::RequestResult {
                                service_idx,
                                request_id: local_request_id,
                                result: Ok((from, resp.data)),
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
                } else if let Some(service_idx) = self
                    .services
                    .iter()
                    .position(|s| s.address == link.destination)
                {
                    let from = link.destination;
                    match context {
                        LinkContext::Request => {
                            if let Some(req) = Request::decode(&plaintext) {
                                let wire_request_id =
                                    WireRequestId(packet.packet_hash()[..16].try_into().unwrap());
                                let mut id_bytes = [0u8; 16];
                                self.rng.fill_bytes(&mut id_bytes);
                                let request_id = RequestId(id_bytes);
                                let path = self.services[service_idx]
                                    .registered_paths
                                    .get(&req.path_hash)
                                    .cloned()
                                    .unwrap_or_default();
                                notifications.push(ServiceNotification::Request {
                                    service_idx,
                                    link_id,
                                    request_id,
                                    wire_request_id,
                                    from,
                                    path,
                                    data: req.data.unwrap_or_default(),
                                });
                            } else {
                                notifications.push(ServiceNotification::Data {
                                    service_idx,
                                    from,
                                    data: plaintext,
                                });
                            }
                        }
                        _ => {
                            notifications.push(ServiceNotification::Data {
                                service_idx,
                                from,
                                data: plaintext,
                            });
                        }
                    };
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
                        notifications.push(ServiceNotification::Raw {
                            service_idx,
                            from: [0u8; 16],
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
                            iface.send(packet.clone(), 0, now);
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
                    let link =
                        EstablishedLink::from_initiator(pending, &proof.encryption_public, now);
                    let rtt_secs = link.rtt_seconds();

                    self.established_links.insert(destination_hash, link);
                    self.destination_links.insert(dest, destination_hash);

                    // Send LRRTT packet to inform responder of the measured RTT
                    if let Some(rtt) = rtt_secs {
                        let rtt_data = crate::link::encode_rtt(rtt);
                        self.send_link_packet(
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
            Packet::Proof { data, .. } => {
                // Regular proof - check reverse table for transport
                if let Some(reverse_entry) = self.reverse_table.remove(&destination_hash)
                    && let Some(iface) = self.interfaces.get_mut(reverse_entry.receiving_interface)
                {
                    self.stats.packets_relayed += 1;
                    self.stats.bytes_relayed += raw.len() as u64;
                    self.stats.proofs_relayed += 1;
                    iface.send(packet.clone(), 0, now);
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
                        if crate::crypto::verify(signing_key, &receipt.packet_hash, &signature) {
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

        self.dispatch_notifications(notifications, now);

        Some((packet, for_local_service, for_local_link))
    }

    fn send_link_packet(
        &mut self,
        link_id: LinkId,
        context: LinkContext,
        plaintext: &[u8],
        now: Instant,
    ) {
        use crate::packet::LinkDataDestination;

        let Some(link) = self.established_links.get_mut(&link_id) else {
            return;
        };

        let ciphertext = link.encrypt(&mut self.rng, plaintext);
        link.touch_outbound(now);

        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link_id),
            context,
            data: ciphertext,
        };

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, now);
        }
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
                iface.send(packet, 0, now);
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

                iface.send(packet.clone(), hops, now);
                sent = true;
            }
        }

        sent
    }

    pub fn poll(&mut self, now: Instant) -> Option<std::time::Duration> {
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

        // Process outbound queues
        for iface in &mut self.interfaces {
            if let Some(t) = iface.poll(now) {
                update_wake(t);
            }
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
            if let Some(t) = iface.poll(now) {
                update_wake(t);
            }
        }

        // Remove disconnected interfaces
        let before_count = self.interfaces.len();
        self.interfaces.retain(|iface| iface.is_connected());
        let removed = before_count - self.interfaces.len();
        if removed > 0 {
            log::debug!("Removed {} disconnected interface(s)", removed);
        }

        next_wake.map(|t| t.saturating_duration_since(now))
    }

    fn maintain_links(&mut self, now: Instant) -> Option<Instant> {
        let mut next_wake: Option<Instant> = None;
        let mut update_wake = |t: Instant| {
            next_wake = Some(next_wake.map_or(t, |w| w.min(t)));
        };

        // Check for timed out pending links
        let mut timed_out_pending: Vec<(LinkId, Address, Option<Address>)> = Vec::new();
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
                timed_out_pending.push((*link_id, pending.destination, pending.initiating_service));
            } else {
                let timeout_at =
                    pending.request_time + std::time::Duration::from_secs(timeout_secs);
                update_wake(timeout_at);
            }
        }

        // Handle timed out pending links
        let mut notifications = Vec::new();
        for (link_id, destination, _initiating_service) in timed_out_pending {
            self.pending_outbound_links.remove(&link_id);

            // Fail any queued requests for this destination
            if let Some(queued) = self.pending_outbound_requests.remove(&destination) {
                for (service_addr, local_request_id, _path, _data) in queued {
                    if let Some(service_idx) =
                        self.services.iter().position(|s| s.address == service_addr)
                    {
                        notifications.push(ServiceNotification::RequestResult {
                            service_idx,
                            request_id: local_request_id,
                            result: Err(crate::handle::RequestError::LinkFailed),
                        });
                    }
                }
            }

            log::debug!(
                "Pending link <{}> to <{}> timed out",
                hex::encode(link_id),
                hex::encode(destination)
            );
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

            if let Some(queued) = self.pending_outbound_requests.remove(&destination) {
                for (service_addr, local_request_id, _path, _data) in queued {
                    if let Some(service_idx) =
                        self.services.iter().position(|s| s.address == service_addr)
                    {
                        notifications.push(ServiceNotification::RequestResult {
                            service_idx,
                            request_id: local_request_id,
                            result: Err(crate::handle::RequestError::Timeout),
                        });
                    }
                }
            }

            log::warn!(
                "Path request for <{}> timed out after {} seconds",
                hex::encode(destination),
                PATH_REQUEST_TIMEOUT_SECS
            );
        }

        if !notifications.is_empty() {
            self.dispatch_notifications(notifications, now);
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
            self.send_link_packet(
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
                let close_data = link.encrypt(&mut self.rng, &link_id);
                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::LinkClose,
                    data: close_data,
                };
                for iface in &mut self.interfaces {
                    iface.send(packet.clone(), 0, now);
                }
                self.destination_links.remove(&dest);
            }
            self.established_links.remove(&link_id);
        }

        next_wake
    }

    fn handle_keepalive(&mut self, link_id: LinkId, plaintext: &[u8], now: Instant) {
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
                let packet = Packet::LinkData {
                    hops: 0,
                    destination: LinkDataDestination::Direct(link_id),
                    context: LinkContext::Keepalive,
                    data: response,
                };
                for iface in &mut self.interfaces {
                    iface.send(packet.clone(), 0, now);
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
                        "ResourceAdv: hash={} random_hash={} num_parts={} transfer_size={} compressed={} is_response={} request_id={:?}",
                        hex::encode(adv.hash),
                        hex::encode(adv.random_hash),
                        adv.num_parts,
                        adv.transfer_size,
                        adv.compressed,
                        adv.is_response,
                        adv.request_id.as_ref().map(hex::encode)
                    );

                    // Auto-accept if this is a response to a pending request
                    if !adv.is_response {
                        log::debug!("ResourceAdv not a response, ignoring");
                    } else if adv.request_id.is_none() {
                        log::warn!("ResourceAdv is_response=true but no request_id");
                    } else if let Some(ref req_id_bytes) = adv.request_id
                        && let Some(link) = self.established_links.get(&link_id)
                    {
                        // Check if we have a pending request with this wire ID
                        let wire_req_id: Option<WireRequestId> = req_id_bytes
                            .get(..16)
                            .and_then(|b| <[u8; 16]>::try_from(b).ok())
                            .map(WireRequestId);

                        if let Some(wire_request_id) = wire_req_id {
                            if link.pending_requests.contains_key(&wire_request_id) {
                                log::info!(
                                    "ResourceAdv matched pending request {}",
                                    hex::encode(wire_request_id.0)
                                );
                                // Auto-accept the resource
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
                            for iface in &mut self.interfaces {
                                iface.send(packet.clone(), 0, now);
                            }
                        }
                    }

                    if exhausted
                        && let Some(hmu_data) = resource.hashmap_update(100)
                        && let Some(link) = self.established_links.get(&link_id)
                    {
                        let mut payload = hash.to_vec();
                        payload.extend(&hmu_data);
                        let ciphertext = link.encrypt(&mut self.rng, &payload);
                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::ResourceHmu,
                            data: ciphertext,
                        };
                        for iface in &mut self.interfaces {
                            iface.send(packet.clone(), 0, now);
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
                        if accepted && resource.is_complete() {
                            completed = Some(*hash);
                        } else if accepted {
                            // Pipeline: request more parts as soon as we have room
                            // Don't wait for all outstanding parts to arrive
                            if resource.batch_complete() {
                                resource.complete_batch(now);
                            }
                            need_more = Some(*hash);
                        }
                        break;
                    }
                }
                if let Some(hash) = completed {
                    self.complete_resource(link_id, hash, now);
                } else if let Some(hash) = need_more {
                    self.send_resource_request(link_id, hash, now);
                }
            }
            LinkContext::ResourceHmu => {
                if plaintext.len() < 32 {
                    return;
                }
                let hash: [u8; 32] = plaintext[..32].try_into().unwrap();
                let hmu_data = &plaintext[32..];
                if let Some((_, resource)) = self.inbound_resources.get_mut(&hash) {
                    resource.receive_hashmap_update(hmu_data);
                    self.send_resource_request(link_id, hash, now);
                }
            }
            LinkContext::ResourcePrf => {
                if plaintext.len() < 64 {
                    return;
                }
                let hash: [u8; 32] = plaintext[..32].try_into().unwrap();
                let proof: [u8; 32] = plaintext[32..64].try_into().unwrap();
                if let Some((_, _, service_idx, local_request_id, resource)) =
                    self.outbound_resources.get(&hash)
                    && resource.verify_proof(&proof)
                {
                    let service_idx = *service_idx;
                    let local_request_id = *local_request_id;
                    self.outbound_resources.remove(&hash);

                    // Notify service that response was delivered
                    if let (Some(service_idx), Some(request_id)) = (service_idx, local_request_id) {
                        self.dispatch_notifications(
                            vec![ServiceNotification::RespondResult {
                                service_idx,
                                request_id,
                                result: Ok(()),
                            }],
                            now,
                        );
                    }
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

    fn complete_resource(&mut self, link_id: LinkId, hash: [u8; 32], now: Instant) {
        use crate::packet::LinkDataDestination;

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

        let (data, proof) = match resource.assemble(link) {
            Some(r) => r,
            None => {
                log::warn!(
                    "complete_resource: assemble failed for hash {}",
                    hex::encode(hash)
                );
                return;
            }
        };

        log::info!(
            "Resource completed: hash={} data_len={} is_response={}",
            hex::encode(hash),
            data.len(),
            resource.is_response
        );

        // Send proof
        let mut payload = hash.to_vec();
        payload.extend(&proof);
        let ciphertext = link.encrypt(&mut self.rng, &payload);
        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct(link_id),
            context: LinkContext::ResourcePrf,
            data: ciphertext,
        };
        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, now);
        }

        // If this was a response to a pending request, deliver via on_response
        if !resource.is_response {
            log::debug!(
                "Resource {} is not a response, data ({} bytes) not delivered to any service",
                hex::encode(hash),
                data.len()
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

        log::debug!(
            "Resource is response with request_id={}",
            hex::encode(req_id_bytes)
        );

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

        // Look up the service that made the request
        let request_info = self
            .established_links
            .get_mut(&link_id)
            .and_then(|l| l.pending_requests.remove(&wire_request_id));

        let (service_addr, local_request_id) = match request_info {
            Some(r) => r,
            None => {
                log::warn!(
                    "complete_resource: no pending request for wire_request_id={}",
                    hex::encode(wire_request_id.0)
                );
                return;
            }
        };

        let service_idx = match self.services.iter().position(|s| s.address == service_addr) {
            Some(i) => i,
            None => {
                log::warn!(
                    "complete_resource: service not found for addr {}",
                    hex::encode(service_addr)
                );
                return;
            }
        };

        let from = self
            .established_links
            .get(&link_id)
            .map(|l| l.destination)
            .unwrap_or([0u8; 16]);

        log::info!(
            "Delivering resource response: {} bytes to service {} (request_id={})",
            data.len(),
            service_idx,
            hex::encode(local_request_id.0)
        );

        let notification = ServiceNotification::RequestResult {
            service_idx,
            request_id: local_request_id,
            result: Ok((from, data)),
        };
        self.dispatch_notifications(vec![notification], now);
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
            let packet = Packet::LinkData {
                hops: 0,
                destination: LinkDataDestination::Direct(link_id),
                context: LinkContext::ResourceReq,
                data: ciphertext,
            };
            for iface in &mut self.interfaces {
                iface.send(packet.clone(), 0, now);
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
    use crate::handle::NodeHandle;
    use std::cell::RefCell;
    use std::rc::Rc;

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

    type TestNode = Node<MockTransport, TestService>;

    fn transfer(from: &mut TestNode, from_iface: usize, to: &mut TestNode, to_iface: usize) {
        while let Some(pkt) = from.interfaces[from_iface].transport.outbox.pop_front() {
            to.interfaces[to_iface].transport.inbox.push_back(pkt);
        }
    }

    fn test_interface() -> Interface<MockTransport> {
        Interface::new(MockTransport::new())
    }

    struct TestNetwork {
        nodes: Vec<TestNode>,
        links: Vec<(usize, usize, usize, usize)>,
    }

    impl TestNetwork {
        fn new() -> Self {
            Self {
                nodes: Vec::new(),
                links: Vec::new(),
            }
        }

        fn add_node(&mut self, transport_enabled: bool) -> usize {
            let idx = self.nodes.len();
            self.nodes.push(Node::new(transport_enabled));
            idx
        }

        fn link(&mut self, node_a: usize, node_b: usize) {
            let iface_a = self.nodes[node_a].interfaces.len();
            let iface_b = self.nodes[node_b].interfaces.len();
            self.nodes[node_a].add_interface(test_interface());
            self.nodes[node_b].add_interface(test_interface());
            self.links.push((node_a, iface_a, node_b, iface_b));
        }

        fn node(&mut self, idx: usize) -> &mut TestNode {
            &mut self.nodes[idx]
        }

        fn step(&mut self, now: Instant) {
            for node in &mut self.nodes {
                node.poll(now);
            }
            for &(a, a_iface, b, b_iface) in &self.links {
                let (left, right) = self.nodes.split_at_mut(a.max(b));
                let (node_a, node_b) = if a < b {
                    (&mut left[a], &mut right[0])
                } else {
                    (&mut right[0], &mut left[b])
                };
                while let Some(pkt) = node_a.interfaces[a_iface].transport.outbox.pop_front() {
                    node_b.interfaces[b_iface].transport.inbox.push_back(pkt);
                }
                while let Some(pkt) = node_b.interfaces[b_iface].transport.outbox.pop_front() {
                    node_a.interfaces[a_iface].transport.inbox.push_back(pkt);
                }
            }
        }
    }

    #[derive(Clone)]
    struct ReceivedRequest {
        request_id: RequestId,
        path: String,
        data: Vec<u8>,
    }

    #[derive(Clone)]
    struct ReceivedResponse {
        request_id: RequestId,
        data: Vec<u8>,
    }

    #[derive(Clone)]
    struct ReceivedRaw {
        _from: Address,
        data: Vec<u8>,
    }

    #[derive(Clone)]
    struct RequestFailure {
        request_id: RequestId,
        error: crate::handle::RequestError,
    }

    #[derive(Clone)]
    struct RespondResult {
        _request_id: RequestId,
        success: bool,
    }

    #[derive(Default)]
    struct TestServiceState {
        requests: Vec<ReceivedRequest>,
        responses: Vec<ReceivedResponse>,
        raw_messages: Vec<ReceivedRaw>,
        request_failures: Vec<RequestFailure>,
        respond_results: Vec<RespondResult>,
        destinations_changed_count: usize,
    }

    struct TestService {
        name: String,
        paths: Vec<String>,
        state: Rc<RefCell<TestServiceState>>,
        auto_response: Option<Vec<u8>>,
    }

    impl TestService {
        fn new(name: &str) -> Self {
            Self {
                name: name.into(),
                paths: Vec::new(),
                state: Rc::new(RefCell::new(TestServiceState::default())),
                auto_response: None,
            }
        }

        fn with_paths(mut self, paths: &[&str]) -> Self {
            self.paths = paths.iter().map(|s| s.to_string()).collect();
            self
        }

        fn with_auto_response(mut self, response: Vec<u8>) -> Self {
            self.auto_response = Some(response);
            self
        }

        fn state(&self) -> Rc<RefCell<TestServiceState>> {
            self.state.clone()
        }
    }

    impl Service for TestService {
        fn name(&self) -> &str {
            &self.name
        }

        fn paths(&self) -> Vec<&str> {
            self.paths.iter().map(|s| s.as_str()).collect()
        }

        fn on_raw(&mut self, _handle: &mut NodeHandle, from: Address, data: &[u8]) {
            self.state.borrow_mut().raw_messages.push(ReceivedRaw {
                _from: from,
                data: data.to_vec(),
            });
        }

        fn on_request(
            &mut self,
            handle: &mut NodeHandle,
            request_id: RequestId,
            _from: Address,
            path: &str,
            data: &[u8],
        ) {
            self.state.borrow_mut().requests.push(ReceivedRequest {
                request_id,
                path: path.to_string(),
                data: data.to_vec(),
            });
            if let Some(ref response) = self.auto_response {
                handle.respond(request_id, response);
            }
        }

        fn on_request_result(
            &mut self,
            _handle: &mut NodeHandle,
            request_id: RequestId,
            result: Result<(Address, Vec<u8>), crate::handle::RequestError>,
        ) {
            match result {
                Ok((_from, data)) => {
                    self.state.borrow_mut().responses.push(ReceivedResponse {
                        request_id,
                        data,
                    });
                }
                Err(error) => {
                    self.state
                        .borrow_mut()
                        .request_failures
                        .push(RequestFailure { request_id, error });
                }
            }
        }

        fn on_respond_result(
            &mut self,
            _handle: &mut NodeHandle,
            request_id: RequestId,
            result: Result<(), crate::handle::RespondError>,
        ) {
            self.state.borrow_mut().respond_results.push(RespondResult {
                _request_id: request_id,
                success: result.is_ok(),
            });
        }

        fn on_destinations_changed(&mut self, _handle: &mut NodeHandle) {
            self.state.borrow_mut().destinations_changed_count += 1;
        }
    }

    fn svc(name: &str) -> TestService {
        TestService::new(name)
    }

    fn id(seed: u64) -> crate::identity::Identity {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        crate::identity::Identity::generate(&mut rng)
    }

    #[test]
    fn announce_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr = a.add_service(svc("test"), &id(1));
        let now = Instant::now();

        a.announce(addr, now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert!(b.has_destination(&addr));
    }

    #[test]
    fn announce_three_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        let mut c: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let addr = a.add_service(svc("test"), &id(1));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        a.announce(addr, now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);

        assert!(b.has_destination(&addr));
        assert!(c.has_destination(&addr));
    }

    #[test]
    fn announce_not_echoed_back() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr = a.add_service(svc("test"), &id(1));
        let now = Instant::now();

        a.announce(addr, now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        b.poll(now);

        assert!(b.interfaces[0].transport.outbox.is_empty());
    }

    #[test]
    fn link_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).expect("link should be created");
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
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        let mut c: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let addr_c = c.add_service(svc("server"), &id(1));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(addr_c, None, later).expect("link should be created");
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
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_b = svc("server");
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.send_link_packet(link_id, LinkContext::None, b"payload", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // B receives raw data via on_raw callback
        let state = state_b.borrow();
        assert_eq!(state.raw_messages.len(), 1);
        assert_eq!(state.raw_messages[0].data, b"payload");
    }

    #[test]
    fn link_data_three_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        let mut c: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_c = svc("server");
        let state_c = svc_c.state();
        let addr_c = c.add_service(svc_c, &id(1));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(addr_c, None, later).unwrap();
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        a.send_link_packet(link_id, LinkContext::None, b"payload", later);
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);

        // C receives raw data via on_raw callback
        let state = state_c.borrow();
        assert_eq!(state.raw_messages.len(), 1);
        assert_eq!(state.raw_messages[0].data, b"payload");
    }

    #[test]
    fn request_response_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test.path"])
            .with_auto_response(b"response data".to_vec());
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should know about B's destination
        assert!(a.has_destination(&addr_b));

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Link should be established on both sides
        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.contains_key(&link_id));

        // Send request from A to B
        a.request(addr_a, addr_b, "test.path", b"request data", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // B should have received the request via on_request callback
        {
            let state = state_b.borrow();
            assert_eq!(state.requests.len(), 1);
            assert_eq!(state.requests[0].path, "test.path");
            assert_eq!(state.requests[0].data, b"request data");
            // Note: from field is unreliable - responder doesn't know initiator's service address
        }

        // B's auto_response should have sent a response, transfer it back
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should have received the response via on_response callback
        {
            let state = state_a.borrow();
            assert_eq!(state.responses.len(), 1);
            assert_eq!(state.responses[0].data, b"response data");
        }
    }

    #[test]
    fn request_response_three_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        let mut c: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_c = svc("server")
            .with_paths(&["test.path"])
            .with_auto_response(b"response data".to_vec());
        let state_c = svc_c.state();
        let addr_c = c.add_service(svc_c, &id(1));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // A should know about C's destination (via B as transport)
        assert!(a.has_destination(&addr_c));

        let link_id = a.link(addr_c, None, later).unwrap();
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
        a.request(addr_a, addr_c, "test.path", b"request data", later);
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);

        // C should have received the request via on_request callback
        {
            let state = state_c.borrow();
            assert_eq!(state.requests.len(), 1);
            assert_eq!(state.requests[0].path, "test.path");
            assert_eq!(state.requests[0].data, b"request data");
        }

        // C's auto_response should have sent a response, transfer it back
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // A should have received the response via on_response callback
        {
            let state = state_a.borrow();
            assert_eq!(state.responses.len(), 1);
            assert_eq!(state.responses[0].data, b"response data");
        }
    }

    #[test]
    fn large_response_uses_resource() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Create a large response (> LINK_MDU of 431 bytes) to trigger resource transfer
        let large_response: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server").with_auto_response(large_response.clone());
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Link should be established
        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.contains_key(&link_id));

        // Send request from A to B
        a.request(addr_a, addr_b, "test.path", b"request", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // B should have received the request
        assert_eq!(state_b.borrow().requests.len(), 1);

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
        a.poll(now);

        // Transfer proof
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // A should have received the large response via on_response callback
        {
            let state = state_a.borrow();
            assert_eq!(state.responses.len(), 1);
            assert_eq!(state.responses[0].data, large_response);
        }

        // Resources should be cleaned up
        assert_eq!(a.inbound_resources.len(), 0);
        assert_eq!(b.outbound_resources.len(), 0);
    }

    #[test]
    fn multipart_resource_with_hashmap_updates() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // 10KB response = ~21 parts at 470 bytes/part, needs multiple hashmap updates
        let large_response: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test.path"])
            .with_auto_response(large_response.clone());
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        // Establish link
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Send request
        a.request(addr_a, addr_b, "test.path", b"req", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Transfer until complete (resource adv, requests, parts, hashmap updates, proof)
        for _ in 0..50 {
            transfer(&mut b, 0, &mut a, 0);
            a.poll(now);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(now);
            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

        let state = state_a.borrow();
        assert_eq!(state.responses.len(), 1);
        assert_eq!(state.responses[0].data, large_response);
    }

    #[test]
    fn resource_transfer_three_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        let mut c: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        let large_response: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_c = svc("server")
            .with_paths(&["test.path"])
            .with_auto_response(large_response.clone());
        let addr_c = c.add_service(svc_c, &id(1));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        // Propagate announce: C -> B -> A
        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        // Establish link A -> C (via B)
        a.link(addr_c, None, later).unwrap();
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
        a.request(addr_a, addr_c, "test.path", b"req", later);
        a.poll(later);

        // Transfer until complete
        for _ in 0..30 {
            transfer(&mut a, 0, &mut b, 0);
            b.poll(later);
            transfer(&mut b, 1, &mut c, 0);
            c.poll(later);
            transfer(&mut c, 0, &mut b, 1);
            b.poll(later);
            transfer(&mut b, 0, &mut a, 0);
            a.poll(later);
            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

        let state = state_a.borrow();
        assert_eq!(state.responses.len(), 1);
        assert_eq!(state.responses[0].data, large_response);
    }

    #[test]
    fn rtt_measured_and_propagated() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
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

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
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
    fn pending_link_timeout() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let addr_a = a.add_service(svc_a, &id(1));

        let addr_b = b.add_service(svc("server").with_paths(&["test.path"]), &id(2));
        let now = Instant::now();

        // Announce B so A knows the path
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A initiates link (but we won't complete handshake)
        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);

        // Queue a request while link is pending
        a.request(addr_a, addr_b, "test.path", b"data", now);
        a.poll(now);

        // Verify link is pending
        assert!(a.pending_outbound_links.contains_key(&link_id));
        assert!(a.pending_outbound_requests.contains_key(&addr_b));

        // Time passes beyond establishment timeout (base 60s + 6s per hop, 1 hop = 66s)
        let timeout = now + Duration::from_secs(67);
        a.poll(timeout);

        // Pending link should be removed
        assert!(
            !a.pending_outbound_links.contains_key(&link_id),
            "pending link should be removed after timeout"
        );

        // Pending requests should be removed
        assert!(
            !a.pending_outbound_requests.contains_key(&addr_b),
            "pending requests should be removed after timeout"
        );

        // Service should receive failure notification
        // Note: The notification includes a generated request_id since the original
        // request was never sent, so we just check that we got a failure
        // (The current implementation generates a random request_id for failed queued requests)
    }

    #[test]
    fn stale_link_closed() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
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
    fn link_removed_on_remote_close() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        // Establish link
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.contains_key(&link_id));

        // B closes the link
        b.close_link(link_id, now);
        b.poll(now);

        // B should have removed the link
        assert!(
            !b.established_links.contains_key(&link_id),
            "B should remove link after closing"
        );

        // Transfer close packet to A
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should remove the link immediately upon receiving LinkClose
        assert!(
            !a.established_links.contains_key(&link_id),
            "A should remove link immediately on receiving LinkClose"
        );
    }

    #[test]
    fn link_not_stale_while_request_pending() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        // Server that doesn't auto-respond - we control when response is sent
        let svc_b = svc("server").with_paths(&["test"]);
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(2));

        let now = Instant::now();

        // Establish link
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Send a request
        a.request(addr_a, addr_b, "test", b"request", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Verify request was received
        assert_eq!(
            state_b.borrow().requests.len(),
            1,
            "Server should have received request"
        );

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
        let request_id = state_b.borrow().requests[0].request_id;
        b.respond(request_id, b"late response", after_stale);
        b.poll(after_stale);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(after_stale);

        // Response should be received
        assert_eq!(
            state_a.borrow().responses.len(),
            1,
            "Client should receive late response"
        );
    }

    #[test]
    fn keepalive_request_response() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
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

    fn make_ifac_interface(
        ifac_identity: SigningKey,
        ifac_key: Vec<u8>,
    ) -> Interface<MockTransport> {
        Interface::new(MockTransport::new()).with_ifac(ifac_identity, ifac_key, 8)
    }

    #[test]
    fn ifac_two_nodes_communicate() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        // Both nodes share the SAME IFAC identity and key (derived from network name/key)
        let mut rng = StdRng::seed_from_u64(42);
        let shared_ifac_identity = SigningKey::generate(&mut rng);
        let shared_ifac_key = vec![0xAB; 32];

        let mut a: TestNode = Node::new(false);
        let mut b: TestNode = Node::new(false);
        a.add_interface(make_ifac_interface(
            shared_ifac_identity.clone(),
            shared_ifac_key.clone(),
        ));
        b.add_interface(make_ifac_interface(shared_ifac_identity, shared_ifac_key));

        let _addr_a = a.add_service(svc("client"), &id(1));
        let svc_b = svc("server");
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        // B announces
        b.announce(addr_b, now);
        b.poll(now);

        // Transfer announce (with IFAC) from B to A
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should have learned about B
        assert!(
            a.has_destination(&addr_b),
            "A should know about B after IFAC-protected announce"
        );

        // A establishes link to B
        let link_id = a.link(addr_b, None, now).expect("should create link");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Link should be established on both sides
        assert!(
            a.is_link_established(&link_id),
            "link should be established over IFAC"
        );
        assert!(
            b.established_links.contains_key(&link_id),
            "B should have established link"
        );

        // Send data over the link
        a.send_link_packet(link_id, LinkContext::None, b"hello over ifac", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // B should receive data via on_raw callback
        let state = state_b.borrow();
        assert_eq!(state.raw_messages.len(), 1);
        assert_eq!(state.raw_messages[0].data, b"hello over ifac");
    }

    #[test]
    fn ifac_mismatch_blocks_communication() {
        use ed25519_dalek::SigningKey;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut a: TestNode = Node::new(false);
        let mut b: TestNode = Node::new(false);

        // A uses one IFAC key
        let mut rng_a = StdRng::seed_from_u64(42);
        let ifac_identity_a = SigningKey::generate(&mut rng_a);
        let ifac_key_a = vec![0xAA; 32];
        let iface_a =
            Interface::new(MockTransport::new()).with_ifac(ifac_identity_a, ifac_key_a, 8);
        a.add_interface(iface_a);

        // B uses different IFAC key
        let mut rng_b = StdRng::seed_from_u64(99);
        let ifac_identity_b = SigningKey::generate(&mut rng_b);
        let ifac_key_b = vec![0xBB; 32];
        let iface_b =
            Interface::new(MockTransport::new()).with_ifac(ifac_identity_b, ifac_key_b, 8);
        b.add_interface(iface_b);

        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        // B announces
        b.announce(addr_b, now);
        b.poll(now);

        // Transfer announce from B to A
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should NOT know about B (IFAC mismatch)
        assert!(
            !a.has_destination(&addr_b),
            "A should not learn about B with mismatched IFAC"
        );
    }

    #[test]
    fn on_destinations_changed_called_for_new_destination() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let _addr_a = a.add_service(svc_a, &id(1));
        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        assert_eq!(state_a.borrow().destinations_changed_count, 0);

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().destinations_changed_count,
            1,
            "on_destinations_changed should be called when new destination discovered"
        );

        // Re-announce should not trigger again (not a new destination)
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().destinations_changed_count,
            1,
            "on_destinations_changed should not be called for re-announce"
        );
    }

    #[test]
    fn on_request_called_when_request_received() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_a = a.add_service(svc("client"), &id(1));
        let svc_b = svc("server").with_paths(&["test.path"]);
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.is_link_established(&link_id));
        assert_eq!(state_b.borrow().requests.len(), 0);

        a.request(addr_a, addr_b, "test.path", b"hello", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(
            state_b.borrow().requests.len(),
            1,
            "on_request should be called when request received"
        );
        assert_eq!(state_b.borrow().requests[0].path, "test.path");
        assert_eq!(state_b.borrow().requests[0].data, b"hello");
    }

    #[test]
    fn on_request_result_called_on_response() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));
        let addr_b = b.add_service(
            svc("server")
                .with_paths(&["test.path"])
                .with_auto_response(b"response".to_vec()),
            &id(2),
        );
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.is_link_established(&link_id));

        let request_id = a.request(addr_a, addr_b, "test.path", b"hello", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().responses.len(),
            1,
            "on_request_result should be called with Ok when response received"
        );
        assert_eq!(state_a.borrow().responses[0].request_id, request_id);
        assert_eq!(state_a.borrow().responses[0].data, b"response");
    }

    #[test]
    fn on_request_result_called_on_link_failure() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));
        let addr_b = b.add_service(svc("server"), &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Queue request while link is pending (don't complete handshake)
        let _link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);

        let request_id = a.request(addr_a, addr_b, "test.path", b"hello", now);
        a.poll(now);

        // Time out the link (base 60s + 6s per hop)
        let timeout = now + Duration::from_secs(67);
        a.poll(timeout);

        assert_eq!(
            state_a.borrow().request_failures.len(),
            1,
            "on_request_result should be called with Err when link fails"
        );
        assert_eq!(state_a.borrow().request_failures[0].request_id, request_id);
        assert_eq!(
            state_a.borrow().request_failures[0].error,
            crate::handle::RequestError::LinkFailed
        );
    }

    #[test]
    fn on_respond_result_called_on_small_response() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_a = a.add_service(svc("client"), &id(1));
        let svc_b = svc("server")
            .with_paths(&["test.path"])
            .with_auto_response(b"small".to_vec());
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.is_link_established(&link_id));

        a.request(addr_a, addr_b, "test.path", b"hello", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(
            state_b.borrow().respond_results.len(),
            1,
            "on_respond_result should be called for small response"
        );
        assert!(
            state_b.borrow().respond_results[0].success,
            "on_respond_result should report success"
        );
    }

    #[test]
    fn on_raw_called_when_link_data_received() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let _addr_a = a.add_service(svc("client"), &id(1));
        let svc_b = svc("server");
        let state_b = svc_b.state();
        let addr_b = b.add_service(svc_b, &id(1));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.is_link_established(&link_id));
        assert_eq!(state_b.borrow().raw_messages.len(), 0);

        a.send_link_packet(link_id, LinkContext::None, b"raw data", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(
            state_b.borrow().raw_messages.len(),
            1,
            "on_raw should be called when link data received"
        );
        assert_eq!(state_b.borrow().raw_messages[0].data, b"raw data");
    }

    #[test]
    fn two_sequential_requests_both_get_responses() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));
        let addr_b = b.add_service(
            svc("server")
                .with_paths(&["echo"])
                .with_auto_response(b"response".to_vec()),
            &id(2),
        );
        let now = Instant::now();

        // Setup: announce and establish link
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.is_link_established(&link_id));

        // First request
        let request_id_1 = a.request(addr_a, addr_b, "echo", b"first", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().responses.len(),
            1,
            "first request should get response"
        );
        assert_eq!(state_a.borrow().responses[0].request_id, request_id_1);

        // Second request
        let request_id_2 = a.request(addr_a, addr_b, "echo", b"second", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().responses.len(),
            2,
            "second request should also get response"
        );
        assert_eq!(state_a.borrow().responses[1].request_id, request_id_2);
    }

    #[test]
    fn request_via_callback_then_second_request() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Client that sends request when it discovers server
        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let addr_b = b.add_service(
            svc("server")
                .with_paths(&["echo"])
                .with_auto_response(b"response".to_vec()),
            &id(2),
        );
        let now = Instant::now();

        // B announces
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // A should know about B now
        assert!(a.has_destination(&addr_b));
        assert_eq!(state_a.borrow().destinations_changed_count, 1);

        // Establish link and send first request
        let link_id = a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.is_link_established(&link_id));

        // First request
        a.request(addr_a, addr_b, "echo", b"first", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().responses.len(),
            1,
            "first request should get response"
        );

        // Second request on same link
        a.request(addr_a, addr_b, "echo", b"second", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().responses.len(),
            2,
            "second request should also get response"
        );

        // Third request for good measure
        a.request(addr_a, addr_b, "echo", b"third", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(
            state_a.borrow().responses.len(),
            3,
            "third request should also get response"
        );
    }

    // =============================================================================
    // Path Request/Response Tests
    // =============================================================================
    //
    // These tests verify the path discovery mechanism:
    // 1. Path requests are forwarded through the network
    // 2. Nodes track which interface sent path requests (discovery_path_requests)
    // 3. When an announce arrives for a requested destination, it's forwarded back
    // 4. PATH_RESPONSE announces don't flood the network
    //
    // Topology for chain tests:
    //   A --[0]-- B --[1]-- C --[0]-- D
    //        ^         ^         ^
    //     B.iface0  B.iface1  C.iface0
    //

    #[test]
    fn path_request_reaches_destination_through_chain() {
        // Topology: A -- B -- C -- D
        let mut net = TestNetwork::new();
        let a = net.add_node(true);
        let b = net.add_node(true);
        let c = net.add_node(true);
        let d = net.add_node(true);
        net.link(a, b);
        net.link(b, c);
        net.link(c, d);

        let addr_d = net.node(d).add_service(svc("destination"), &id(4));
        let now = Instant::now();

        net.node(a).request_path(addr_d, now);

        // Step 1: A polls, sends PathRequest to B
        net.step(now);

        // Verify PathRequest arrived at B with correct query_destination
        let b_inbox: Vec<_> = net.nodes[b].interfaces[0]
            .transport
            .inbox
            .iter()
            .cloned()
            .collect();
        assert_eq!(b_inbox.len(), 1, "B should have received 1 packet from A");
        let pkt_at_b = Packet::from_bytes(&b_inbox[0]).unwrap();
        assert!(
            matches!(
                pkt_at_b,
                Packet::PathRequest { query_destination, hops: 0, tag, .. }
                if query_destination == addr_d && tag != [0u8; 16]
            ),
            "Expected PathRequest for addr_d with hops=0, got {:?}",
            pkt_at_b
        );

        // Continue propagation
        net.step(now);
        net.step(now);
        net.step(now);

        // Verify PathRequest reached D (check D's interface inbox before poll clears it)
        // At this point D has already polled, but we can verify A still has pending request
        assert!(
            net.node(a).pending_path_requests.contains_key(&addr_d),
            "A should have pending path request for D"
        );
    }

    #[test]
    fn path_response_returns_to_requester_through_chain() {
        // Topology: A -- B -- C -- D
        // D announces, announce propagates to all nodes
        // A sends path request for D, D responds, A learns path
        let mut net = TestNetwork::new();
        let a = net.add_node(true);
        let b = net.add_node(true);
        let c = net.add_node(true);
        let d = net.add_node(true);
        net.link(a, b);
        net.link(b, c);
        net.link(c, d);

        let addr_d = net.node(d).add_service(svc("destination"), &id(4));
        let now = Instant::now();

        // Capture D's encryption key for later verification
        let d_encryption_key = net.node(d).services[0].encryption_public;

        // D announces, propagates through network
        net.node(d).announce(addr_d, now);
        for i in 0..8 {
            net.step(now + std::time::Duration::from_secs(i));
        }

        // Verify initial path table entries
        assert!(
            net.node(a).has_destination(&addr_d),
            "A should know D after announce"
        );
        assert_eq!(
            net.node(a).path_table.get(&addr_d).unwrap().hops,
            3,
            "A's path to D should be 3 hops (A->B->C->D)"
        );
        assert_eq!(
            net.node(a).path_table.get(&addr_d).unwrap().encryption_key,
            d_encryption_key,
            "A should have D's correct encryption key"
        );

        // Clear A's knowledge and pending request
        net.node(a).path_table.remove(&addr_d);
        net.node(a).pending_path_requests.clear();
        assert!(
            !net.node(a).has_destination(&addr_d),
            "A should not know D after clearing"
        );

        // A sends path request
        let request_time = now + std::time::Duration::from_secs(10);
        net.node(a).request_path(addr_d, request_time);

        // Let path request propagate and response return
        for _ in 0..8 {
            net.step(request_time);
        }

        // Verify A learned path via path response
        let a_path_after = net.node(a).path_table.get(&addr_d).cloned();
        assert!(
            a_path_after.is_some(),
            "A should learn path to D via path request/response"
        );
        let a_path_after = a_path_after.unwrap();
        assert_eq!(a_path_after.hops, 3, "A's path to D should still be 3 hops");
        assert_eq!(
            a_path_after.encryption_key, d_encryption_key,
            "A should have D's correct encryption key from path response"
        );

        // Verify pending path request was cleared
        assert!(
            !net.node(a).pending_path_requests.contains_key(&addr_d),
            "Pending path request should be cleared after receiving response"
        );
    }

    #[test]
    fn path_response_not_rebroadcast_to_all_interfaces() {
        // Topology (diamond):
        //       B
        //      / \
        //     A   D
        //      \ /
        //       C
        let mut net = TestNetwork::new();
        let a = net.add_node(true);
        let b = net.add_node(true);
        let c = net.add_node(true);
        let d = net.add_node(true);
        net.link(a, b); // A iface 0 <-> B iface 0
        net.link(a, c); // A iface 1 <-> C iface 0
        net.link(b, d); // B iface 1 <-> D iface 0
        net.link(c, d); // C iface 1 <-> D iface 1

        let addr_d = net.node(d).add_service(svc("destination"), &id(4));
        let d_encryption_key = net.node(d).services[0].encryption_public;
        let now = Instant::now();

        // D announces, propagates through network
        net.node(d).announce(addr_d, now);
        for i in 0..6 {
            net.step(now + std::time::Duration::from_secs(i));
        }

        // A should know D via 2 hops (either A->B->D or A->C->D)
        let a_initial_path = net.node(a).path_table.get(&addr_d).cloned();
        assert!(a_initial_path.is_some(), "A should know D");
        assert_eq!(
            a_initial_path.unwrap().hops,
            2,
            "A->D should be 2 hops in diamond"
        );

        // Clear A's path table and pending requests
        net.node(a).path_table.remove(&addr_d);
        net.node(a).pending_path_requests.clear();

        // A sends path request
        let request_time = now + std::time::Duration::from_secs(10);
        net.node(a).request_path(addr_d, request_time);

        // Step 1: A sends path request to B and C
        net.step(request_time);

        // Verify both B and C received the path request
        assert_eq!(
            net.nodes[b].interfaces[0].transport.inbox.len(),
            1,
            "B should receive path request from A"
        );
        assert_eq!(
            net.nodes[c].interfaces[0].transport.inbox.len(),
            1,
            "C should receive path request from A"
        );

        // Step 2: B and C process path requests
        // B and C already know D from the earlier announce, so they should
        // immediately respond with PATH_RESPONSE to A
        for node in &mut net.nodes {
            node.poll(request_time);
        }

        // Check what B and C have in their outboxes BEFORE transfer
        // B's interface 0 is to A, interface 1 is to D
        // C's interface 0 is to A, interface 1 is to D
        let b_to_a_count = net.nodes[b].interfaces[0].transport.outbox.len();
        let b_to_d_count = net.nodes[b].interfaces[1].transport.outbox.len();
        let c_to_a_count = net.nodes[c].interfaces[0].transport.outbox.len();
        let c_to_d_count = net.nodes[c].interfaces[1].transport.outbox.len();

        // PATH_RESPONSE should go to A (requester), not back to D
        assert_eq!(
            b_to_d_count, 0,
            "B should NOT rebroadcast PATH_RESPONSE back to D"
        );
        assert_eq!(
            c_to_d_count, 0,
            "C should NOT rebroadcast PATH_RESPONSE back to D"
        );
        assert!(
            b_to_a_count > 0 || c_to_a_count > 0,
            "B or C should forward PATH_RESPONSE to A"
        );

        // Verify the packets going to A are PATH_RESPONSE announces
        for raw in &net.nodes[b].interfaces[0].transport.outbox {
            let pkt = Packet::from_bytes(raw).unwrap();
            assert!(
                matches!(
                    pkt,
                    Packet::Announce {
                        is_path_response: true,
                        ..
                    }
                ),
                "Announce from B to A should be PATH_RESPONSE, got {:?}",
                pkt
            );
        }

        // Finish the network steps to let response reach A
        for _ in 0..4 {
            net.step(request_time);
        }

        // Verify A learned the path
        let a_final_path = net.node(a).path_table.get(&addr_d).cloned();
        assert!(
            a_final_path.is_some(),
            "A should learn path to D via path response"
        );
        let a_final_path = a_final_path.unwrap();
        assert_eq!(a_final_path.hops, 2, "A->D should be 2 hops");
        assert_eq!(
            a_final_path.encryption_key, d_encryption_key,
            "A should have correct encryption key for D"
        );
    }

    #[test]
    fn intermediate_node_tracks_path_request_source() {
        // Topology: A -- B -- C
        // A sends path request for C
        // B should record that the request came from interface 0
        // When C's announce comes, B should forward it to interface 0
        let mut net = TestNetwork::new();
        let a = net.add_node(true);
        let b = net.add_node(true);
        let c = net.add_node(true);
        net.link(a, b);
        net.link(b, c);

        let addr_c = net.node(c).add_service(svc("destination"), &id(3));
        let c_encryption_key = net.node(c).services[0].encryption_public;
        let now = Instant::now();

        // A sends path request for C
        net.node(a).request_path(addr_c, now);

        // Step 1: A sends to B
        net.step(now);

        // Verify B received the path request
        assert_eq!(
            net.nodes[b].interfaces[0].transport.inbox.len(),
            1,
            "B should receive path request from A"
        );

        // Step 2: B forwards to C
        net.step(now);

        // Verify C received the path request
        assert_eq!(
            net.nodes[c].interfaces[0].transport.inbox.len(),
            1,
            "C should receive path request from B"
        );

        assert_eq!(
            net.node(b).discovery_path_requests.get(&addr_c),
            Some(&0),
            "B should record that interface 0 asked about addr_c"
        );

        // C announces (as response to path request)
        net.node(c).announce(addr_c, now);

        // Step 3: C sends announce to B
        net.step(now);

        // Step 4: B processes announce and sends PATH_RESPONSE to A
        net.step(now);

        // Check A's inbox for the PATH_RESPONSE from B
        let a_inbox: Vec<_> = net.nodes[a].interfaces[0]
            .transport
            .inbox
            .iter()
            .cloned()
            .collect();

        assert_eq!(
            a_inbox.len(),
            1,
            "A should receive exactly 1 packet (the PATH_RESPONSE announce) from B"
        );

        // Verify the packet is a PATH_RESPONSE announce
        let pkt = Packet::from_bytes(&a_inbox[0]).unwrap();
        match pkt {
            Packet::Announce {
                is_path_response, ..
            } => {
                assert!(
                    is_path_response,
                    "B should forward announce as PATH_RESPONSE"
                );
                assert_eq!(
                    pkt.destination_hash(),
                    addr_c,
                    "Announce should be for addr_c"
                );
            }
            _ => panic!("Expected Announce packet, got {:?}", pkt),
        }

        // Step 5: A processes the PATH_RESPONSE
        net.step(now);

        // Verify A learned the path
        let a_path = net.node(a).path_table.get(&addr_c).cloned();
        assert!(
            a_path.is_some(),
            "A should learn path to C after path request/response"
        );
        let a_path = a_path.unwrap();
        assert_eq!(a_path.hops, 2, "A->C should be 2 hops (A->B->C)");
        assert_eq!(
            a_path.encryption_key, c_encryption_key,
            "A should have correct encryption key for C"
        );

        // Verify A's pending path request was cleared
        assert!(
            !net.node(a).pending_path_requests.contains_key(&addr_c),
            "A's pending path request should be cleared"
        );
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
        let _ = env_logger::builder().is_test(true).try_init();
        // After 4 consecutive batches with rate > 50 Kbps, window_max should increase to 75
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Large incompressible response for many batches (use hash chain for randomness)
        let mut large_response = vec![0u8; 50_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test"])
            .with_auto_response(large_response.clone());
        let addr_b = b.add_service(svc_b, &id(2));

        // Use short RTT to simulate fast link (high bytes/rtt ratio)
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(addr_a, addr_b, "test", b"", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Simulate fast transfer with small time increments (high rate)
        let mut t = now;
        let mut max_window_seen = 0;
        for _ in 0..500 {
            t += std::time::Duration::from_millis(1); // Fast: ~470KB/s per part
            transfer(&mut b, 0, &mut a, 0);
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                max_window_seen = max_window_seen.max(resource.window);
            }

            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

        // After sustained fast rate, window should be allowed to grow beyond 10
        assert!(
            max_window_seen > 10,
            "window_max should increase to 75 after sustained fast rate, but max was {}",
            max_window_seen
        );
    }

    #[test]
    fn resource_window_max_decreases_on_very_slow_rate() {
        let _ = env_logger::builder().is_test(true).try_init();
        // After 2 consecutive batches with rate < 2 Kbps, window_max should decrease to 4
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data
        let mut large_response = vec![0u8; 50_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test"])
            .with_auto_response(large_response.clone());
        let addr_b = b.add_service(svc_b, &id(2));

        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(addr_a, addr_b, "test", b"", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Simulate very slow transfer with large time increments
        let mut t = now;
        let mut final_window_max = 10; // Default
        for _ in 0..500 {
            t += std::time::Duration::from_secs(10); // Very slow: ~47 bytes/s per part
            transfer(&mut b, 0, &mut a, 0);
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                final_window_max = resource.window_max;
            }

            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

        assert_eq!(
            final_window_max, 4,
            "window_max should decrease to 4 after sustained very slow rate"
        );
    }

    #[test]
    fn resource_window_max_stays_high_if_ever_fast() {
        let _ = env_logger::builder().is_test(true).try_init();
        // Once window_max reaches 75, it should not decrease even if rate becomes slow
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data
        let mut large_response = vec![0u8; 200_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test"])
            .with_auto_response(large_response.clone());
        let addr_b = b.add_service(svc_b, &id(2));

        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(addr_a, addr_b, "test", b"", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        let mut t = now;
        let mut reached_fast = false;
        let mut final_window_max = 10;

        for i in 0..1000 {
            // First half: fast rate
            // Second half: slow rate
            if i < 200 {
                t += std::time::Duration::from_millis(1);
            } else {
                t += std::time::Duration::from_secs(10);
            }

            transfer(&mut b, 0, &mut a, 0);
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                if resource.window_max == 75 {
                    reached_fast = true;
                }
                final_window_max = resource.window_max;
            }

            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

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
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data
        let mut large_response = vec![0u8; 100_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test"])
            .with_auto_response(large_response.clone());
        let addr_b = b.add_service(svc_b, &id(2));

        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.request(addr_a, addr_b, "test", b"", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        let mut t = now;
        let mut max_gap = 0;
        let mut max_window = 0;

        for _ in 0..500 {
            t += std::time::Duration::from_millis(1);
            transfer(&mut b, 0, &mut a, 0);
            a.poll(t);
            transfer(&mut a, 0, &mut b, 0);
            b.poll(t);

            if let Some((_, resource)) = a.inbound_resources.values().next() {
                let gap = resource.window.saturating_sub(resource.window_min);
                max_gap = max_gap.max(gap);
                max_window = max_window.max(resource.window);
            }

            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

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
    fn resource_requests_pipeline_without_waiting_for_full_batch() {
        let _ = env_logger::builder().is_test(true).try_init();
        // After receiving each part, we should request more to keep window full
        // NOT wait for all outstanding parts to arrive
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        // Incompressible data - need many parts
        let mut large_response = vec![0u8; 10_000];
        let mut seed = [0u8; 32];
        for chunk in large_response.chunks_mut(32) {
            seed = crate::crypto::sha256(&seed);
            chunk.copy_from_slice(&seed[..chunk.len()]);
        }

        let svc_a = svc("client");
        let state_a = svc_a.state();
        let addr_a = a.add_service(svc_a, &id(1));

        let svc_b = svc("server")
            .with_paths(&["test"])
            .with_auto_response(large_response);
        let addr_b = b.add_service(svc_b, &id(2));

        let now = Instant::now();

        // Setup link
        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        a.link(addr_b, None, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Send request
        a.request(addr_a, addr_b, "test", b"", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Server sends ResourceAdv, we accept and send first request
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        // Count how many ResourceReq packets are sent
        let initial_reqs = a.interfaces[0].transport.outbox.len();
        assert!(initial_reqs > 0, "Should have sent initial ResourceReq");
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Now transfer ONE part at a time and check if we send a new request
        let mut requests_after_single_part = 0;
        let mut parts_received_before_request = Vec::new();
        let mut parts_in_current_batch = 0;

        for i in 0..50 {
            // Transfer just one packet from server to client
            if let Some(pkt) = b.interfaces[0].transport.outbox.pop_front() {
                a.interfaces[0].transport.inbox.push_back(pkt);
            } else {
                break;
            }

            let t = now + std::time::Duration::from_millis(i as u64 * 100);
            a.poll(t);
            parts_in_current_batch += 1;

            // Check if we sent a request after receiving this part
            if !a.interfaces[0].transport.outbox.is_empty() {
                requests_after_single_part += 1;
                parts_received_before_request.push(parts_in_current_batch);
                parts_in_current_batch = 0;
                // Transfer request to server
                transfer(&mut a, 0, &mut b, 0);
                b.poll(t);
            }

            if state_a.borrow().responses.len() == 1 {
                break;
            }
        }

        eprintln!(
            "Parts received before each request: {:?}",
            parts_received_before_request
        );

        // We should have pipelined - sent additional requests while receiving parts
        assert!(
            requests_after_single_part > 0,
            "Should have sent pipelined requests after receiving parts"
        );

        // We should NOT wait for full window (4 parts) before requesting more
        // Ideally we request more after receiving each part
        let max_parts_before_request = parts_received_before_request
            .iter()
            .max()
            .copied()
            .unwrap_or(0);
        assert!(
            max_parts_before_request < 4,
            "Should pipeline requests - max parts before request was {} (should be < 4)",
            max_parts_before_request
        );
    }
}
