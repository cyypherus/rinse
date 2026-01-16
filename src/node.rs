use std::collections::HashMap;
use std::time::Instant;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::announce::{AnnounceBuilder, AnnounceData};
use crate::crypto::{EphemeralKeyPair, sha256};
use crate::link::{EstablishedLink, LinkId, LinkProof, LinkRequest, LinkState, PendingLink};
use crate::packet::{Address, DataContext, DataDestination, LinkContext, Packet};
use crate::packet_hashlist::PacketHashlist;
use crate::path_request::PathRequest;
use crate::request::{Request, Response};
use crate::{Interface, Transport};
use ed25519_dalek::Signature;

// "By default, m is set to 128."
const DEFAULT_MAX_HOPS: u8 = 128;
// "By default, r is set to 1."
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;
const LOCAL_REBROADCASTS_MAX: u8 = 2;
const PATHFINDER_RW_MS: u64 = 500;

pub enum InboundMessage {
    LinkData {
        link_id: LinkId,
        data: Vec<u8>,
    },
    SingleData {
        data: Vec<u8>,
    },
    Request {
        link_id: LinkId,
        request_id: crate::RequestId,
        path_hash: crate::PathHash,
        data: Vec<u8>,
    },
    Response {
        request_id: crate::RequestId,
        data: Vec<u8>,
    },
    ResourceAdvertised {
        link_id: LinkId,
        hash: [u8; 32],
        size: usize,
        metadata: Option<Vec<u8>>,
    },
    ResourceProgress {
        link_id: LinkId,
        hash: [u8; 32],
        progress: f32,
    },
    ResourceComplete {
        link_id: LinkId,
        hash: [u8; 32],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
    ResourceFailed {
        link_id: LinkId,
        hash: [u8; 32],
    },
}

pub enum OutboundMessage {
    LinkData {
        link_id: LinkId,
        data: Vec<u8>,
    },
    SingleData {
        destination: Address,
        data: Vec<u8>,
    },
    Request {
        link_id: LinkId,
        path: String,
        data: Vec<u8>,
    },
    Response {
        link_id: LinkId,
        request_id: crate::RequestId,
        data: Vec<u8>,
    },
    ResourceSend {
        link_id: LinkId,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    },
    ResourceAccept {
        link_id: LinkId,
        hash: [u8; 32],
    },
    ResourceReject {
        link_id: LinkId,
        hash: [u8; 32],
    },
}

pub trait Service: Send {
    fn name(&self) -> &str;
    fn inbound(&mut self, msg: InboundMessage);
    fn outbound(&mut self) -> Option<OutboundMessage>;
}

struct ServiceEntry<S> {
    service: S,
    address: Address,
    name_hash: [u8; 10],
    encryption_secret: StaticSecret,
    encryption_public: X25519Public,
    signing_key: SigningKey,
}

struct Receipt {
    packet_hash: [u8; 32],
    destination: Address,
}

struct PathEntry {
    timestamp: Instant,
    next_hop: Address,
    hops: u8,
    receiving_interface: usize,
    encryption_key: X25519Public,
    signing_key: VerifyingKey,
    ratchet_key: Option<X25519Public>,
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
    outbound_interface: usize,
}

pub struct Node<T, S, R = ThreadRng> {
    transport: bool,
    max_hops: u8,
    retries: u8,
    pub(crate) retry_delay_ms: u64,
    rng: R,
    transport_id: Address,
    path_table: HashMap<Address, PathEntry>,
    pending_announces: Vec<PendingAnnounce>,
    seen_packets: PacketHashlist,
    reverse_table: HashMap<Address, ReverseTableEntry>,
    control_hashes: std::collections::HashSet<Address>,
    receipts: Vec<Receipt>,
    pub(crate) services: Vec<ServiceEntry<S>>,
    pub(crate) interfaces: Vec<Interface<T>>,
    pending_outbound_links: HashMap<LinkId, PendingLink>,
    pub(crate) established_links: HashMap<LinkId, EstablishedLink>,
    link_table: HashMap<LinkId, LinkTableEntry>,
    outbound_resources: HashMap<[u8; 32], (LinkId, Address, crate::resource::OutboundResource)>,
    inbound_resources: HashMap<[u8; 32], (LinkId, crate::resource::InboundResource)>,
    pending_resource_adverts: HashMap<[u8; 32], (LinkId, crate::resource::ResourceAdvertisement)>,
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
            control_hashes: std::collections::HashSet::new(),
            receipts: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
            outbound_resources: HashMap::new(),
            inbound_resources: HashMap::new(),
            pending_resource_adverts: HashMap::new(),
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
            control_hashes: std::collections::HashSet::new(),
            receipts: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
            outbound_resources: HashMap::new(),
            inbound_resources: HashMap::new(),
            pending_resource_adverts: HashMap::new(),
        }
    }

    pub fn add_interface(&mut self, interface: Interface<T>) -> usize {
        let id = self.interfaces.len();
        self.interfaces.push(interface);
        id
    }

    pub fn has_destination(&self, dest: &Address) -> bool {
        self.path_table.contains_key(dest)
    }

    pub fn known_destinations(&self) -> Vec<Address> {
        self.path_table.keys().copied().collect()
    }

    pub fn is_link_established(&self, link_id: &LinkId) -> bool {
        self.established_links
            .get(link_id)
            .map(|l| l.state == crate::link::LinkState::Active)
            .unwrap_or(false)
    }

    pub fn add_service(&mut self, service: S) -> Address {
        let name = service.name();
        let name_hash: [u8; 10] = sha256(name.as_bytes())[..10].try_into().unwrap();

        let mut enc_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut enc_bytes);
        let encryption_secret = StaticSecret::from(enc_bytes);
        let encryption_public = X25519Public::from(&encryption_secret);

        let mut sig_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut sig_bytes);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        // Compute address: hash(name_hash || identity_hash)
        let mut public_key = [0u8; 64];
        public_key[..32].copy_from_slice(encryption_public.as_bytes());
        public_key[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let identity_hash = &sha256(&public_key)[..16];

        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(&name_hash);
        hash_material.extend_from_slice(identity_hash);
        let address: Address = sha256(&hash_material)[..16].try_into().unwrap();

        log::info!(
            "Added service \"{}\" with address <{}>, identity <{}>",
            name,
            hex::encode(address),
            hex::encode(identity_hash)
        );

        self.services.push(ServiceEntry {
            service,
            address,
            name_hash,
            encryption_secret,
            encryption_public,
            signing_key,
        });

        address
    }

    pub fn announce(&mut self, address: Address, now: Instant) {
        let Some(entry) = self.services.iter().find(|s| s.address == address) else {
            return;
        };

        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash);

        let announce_data = AnnounceBuilder::new(
            *entry.encryption_public.as_bytes(),
            entry.signing_key.clone(),
            entry.name_hash,
            random_hash,
        )
        .build(&address);

        let packet = self.make_announce_packet(address, 0, false, announce_data.to_bytes(), None);

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, now);
        }
    }

    pub fn request_path(&mut self, destination: Address, now: Instant) {
        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);

        let request = PathRequest::new(destination, tag);
        let packet = Packet::Data {
            hops: 0,
            destination: DataDestination::Plain(PathRequest::destination()),
            context: DataContext::None,
            data: request.to_bytes(),
        };

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, now);
        }
    }

    // "When a node in the network wants to establish verified connectivity with another node,
    // it will randomly generate a new X25519 private/public key pair. It then creates a
    // link request packet, and broadcast it."
    pub fn link(&mut self, destination: Address, now: Instant) -> Option<LinkId> {
        // Must have path to this destination
        let path_entry = self.path_table.get(&destination)?;
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
        let packet = self.make_link_request_packet(destination, transport_id, request.to_bytes());
        let link_id = LinkRequest::link_id(&packet.hashable_part());

        // Store pending link
        self.pending_outbound_links.insert(
            link_id,
            PendingLink {
                link_id,
                initiator_encryption_secret: ephemeral.secret,
                initiator_encryption_public: ephemeral.public,
                destination,
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

        if let Packet::LinkData {
            context: LinkContext::Keepalive,
            ..
        } = packet
        {
            return true;
        }

        if let Packet::Data { context, .. } = packet {
            if matches!(context, DataContext::CacheRequest | DataContext::Channel) {
                return true;
            }
        }

        if let Packet::LinkData { context, .. } = packet {
            if matches!(
                context,
                LinkContext::Resource
                    | LinkContext::ResourceReq
                    | LinkContext::ResourcePrf
                    | LinkContext::Channel
            ) {
                return true;
            }
        }

        if let Packet::Data {
            destination: DataDestination::Plain(_) | DataDestination::Group(_),
            hops,
            ..
        } = packet
        {
            if *hops > 1 {
                log::debug!("Dropped PLAIN/GROUP packet with hops {}", hops);
                return false;
            }
        }

        true
    }

    fn inbound(
        &mut self,
        raw: &[u8],
        interface_index: usize,
        now: Instant,
    ) -> Option<(Packet, bool, bool)> {
        let mut packet = match Packet::from_bytes(&raw) {
            Ok(p) => p,
            Err(e) => {
                log::debug!("Failed to parse packet: {:?}", e);
                return None;
            }
        };

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

        // Plain broadcast packets are sent directly on all attached interfaces
        // (no transport routing needed)
        if !self.control_hashes.contains(&destination_hash)
            && matches!(
                packet,
                Packet::Data {
                    destination: DataDestination::Plain(_),
                    ..
                }
            )
        {
            // Send to all interfaces except the originator
            for (i, iface) in self.interfaces.iter_mut().enumerate() {
                if i != interface_index {
                    iface.send(packet.clone(), 0, now);
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
                    if matches!(packet, Packet::LinkRequest { .. }) {
                        let link_id = LinkRequest::link_id(&packet.hashable_part());
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
                                outbound_interface,
                            },
                        );
                    }

                    // Transmit on outbound interface
                    if let Some(iface) = self.interfaces.get_mut(outbound_interface) {
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
                        iface.send(packet.clone(), 0, now);
                        link_entry.timestamp = now;
                    }
                }
            }
        }

        if let Packet::Announce {
            has_ratchet, data, ..
        } = &packet
        {
            let announce = match AnnounceData::parse(data, *has_ratchet) {
                Ok(a) => a,
                Err(_) => return None, // TODO dogshit silent failure
            };

            if announce.verify(&destination_hash).is_err() {
                return None;
            }

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
                if self.transport && packet.transport_id().is_some() {
                    if let Some(pending) = self
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
                }

                let mut should_add = false;
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
                }

                if should_add {
                    let signing_key = match announce.signing_public_key() {
                        Ok(k) => k,
                        Err(_) => return None,
                    };

                    // Update path table
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
                        },
                    );

                    // Schedule for rebroadcast with random delay
                    let delay_ms = self.rng.gen_range(0..=PATHFINDER_RW_MS);
                    let retry_at = now + std::time::Duration::from_millis(delay_ms);
                    self.pending_announces.push(PendingAnnounce {
                        destination: destination_hash,
                        source_interface: interface_index,
                        hops,
                        has_ratchet: *has_ratchet,
                        data: data.clone(),
                        retries_remaining: self.retries,
                        retry_at,
                        local_rebroadcasts: 0,
                    });

                    log::debug!(
                        "Destination <{}> is now {} hops away via <{}>",
                        hex::encode(destination_hash),
                        hops,
                        hex::encode(received_from)
                    );
                }
            }
        }

        if let Packet::LinkRequest { data, .. } = &packet {
            let is_for_us = packet
                .transport_id()
                .map_or(true, |tid| tid == self.transport_id);
            log::debug!(
                "Received LinkRequest for <{}> is_for_us={} for_local_service={}",
                hex::encode(destination_hash),
                is_for_us,
                for_local_service
            );

            if is_for_us && for_local_service {
                let request = LinkRequest::parse(data)?;
                // Find the service
                let service_idx = self
                    .services
                    .iter()
                    .position(|s| s.address == destination_hash)?;
                let service = &self.services[service_idx];

                // Create responder's ephemeral key pair
                let responder_keypair = EphemeralKeyPair::generate(&mut self.rng);

                // Derive link keys

                let new_link_id = LinkRequest::link_id(&packet.hashable_part());
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

                log::debug!("Sending LinkProof for link <{}>", hex::encode(new_link_id));
                if let Some(iface) = self.interfaces.get_mut(interface_index) {
                    iface.send(proof_packet, 0, now);
                }

                log::debug!(
                    "Established link <{}> as responder for service <{}>",
                    hex::encode(new_link_id),
                    hex::encode(destination_hash)
                );
            }
        }

        if let Packet::LinkData { data, context, .. } = &packet {
            if let Some(link) = self.established_links.get_mut(&link_id) {
                if let Some(plaintext) = link.decrypt(data) {
                    link.touch_inbound(now);

                    // Handle keepalive
                    if *context == LinkContext::Keepalive {
                        self.handle_keepalive(link_id, &plaintext, now);
                    } else if *context == LinkContext::LinkRtt {
                        self.handle_link_rtt(link_id, &plaintext);
                    } else if matches!(
                        context,
                        LinkContext::Resource
                            | LinkContext::ResourceAdv
                            | LinkContext::ResourceReq
                            | LinkContext::ResourceHmu
                            | LinkContext::ResourcePrf
                            | LinkContext::ResourceIcl
                            | LinkContext::ResourceRcl
                    ) {
                        self.handle_resource_packet(link_id, *context, &plaintext, now);
                    } else if *context == LinkContext::Response {
                        if let Some(resp) = Response::decode(&plaintext) {
                            if let Some(service_addr) =
                                link.pending_requests.remove(&resp.request_id)
                            {
                                if let Some(service_idx) =
                                    self.services.iter().position(|s| s.address == service_addr)
                                {
                                    let msg = InboundMessage::Response {
                                        request_id: resp.request_id,
                                        data: resp.data,
                                    };
                                    self.services[service_idx].service.inbound(msg);
                                }
                            }
                        }
                    } else if let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.address == link.destination)
                    {
                        let msg = match context {
                            LinkContext::Request => {
                                if let Some(req) = Request::decode(&plaintext) {
                                    let request_id: crate::RequestId =
                                        packet.packet_hash()[..16].try_into().unwrap();
                                    InboundMessage::Request {
                                        link_id,
                                        request_id,
                                        path_hash: req.path_hash,
                                        data: req.data,
                                    }
                                } else {
                                    InboundMessage::LinkData {
                                        link_id,
                                        data: plaintext,
                                    }
                                }
                            }
                            _ => InboundMessage::LinkData {
                                link_id,
                                data: plaintext,
                            },
                        };
                        self.services[service_idx].service.inbound(msg);
                    }
                }
            }
        }

        if let Packet::Data { data, .. } = &packet {
            if for_local_service {
                // Data for a single destination - decrypt with service keys
                // Packet data format: ephemeral_public (32) + ciphertext
                if data.len() >= 32
                    && let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.address == destination_hash)
                {
                    let service = &self.services[service_idx];

                    let ephemeral_public =
                        X25519Public::from(<[u8; 32]>::try_from(&data[..32]).unwrap());
                    let ciphertext = &data[32..];

                    if let Some(plaintext) = crate::crypto::SingleDestEncryption::decrypt(
                        &service.encryption_secret,
                        &ephemeral_public,
                        ciphertext,
                    ) {
                        let msg = InboundMessage::SingleData { data: plaintext };
                        self.services[service_idx].service.inbound(msg);
                    }
                }
            }
        }

        if let Packet::LinkProof { data, .. } = &packet {
            log::debug!(
                "Received LinkProof for link_id=<{}> pending_links={:?}",
                hex::encode(destination_hash),
                self.pending_outbound_links
                    .keys()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
            );
            // Link request proof - check if it needs to be transported
            if let Some(link_entry) = self.link_table.get(&link_id) {
                if interface_index == link_entry.next_hop_interface {
                    // Transport the proof
                    if let Some(iface) = self.interfaces.get_mut(link_entry.receiving_interface) {
                        iface.send(packet.clone(), 0, now);
                    }
                }
            } else if let Some(pending) = self.pending_outbound_links.remove(&destination_hash) {
                // This is a proof for a link we initiated - validate and establish
                let proof = match LinkProof::parse(data) {
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
                let link = EstablishedLink::from_initiator(pending, &proof.encryption_public, now);
                let rtt_secs = link.rtt_seconds();

                self.established_links.insert(destination_hash, link);

                // Send LRRTT packet to inform responder of the measured RTT
                if let Some(rtt) = rtt_secs {
                    let rtt_data = crate::link::encode_rtt(rtt);
                    self.send_link_packet(destination_hash, LinkContext::LinkRtt, &rtt_data, now);
                }

                log::debug!(
                    "Link <{}> established as initiator, RTT: {:?}ms",
                    hex::encode(destination_hash),
                    rtt_secs.map(|r| (r * 1000.0) as u64)
                );
            }
        }

        if let Packet::Proof { data, .. } = &packet {
            // Regular proof - check reverse table for transport
            if let Some(reverse_entry) = self.reverse_table.remove(&destination_hash) {
                if let Some(iface) = self.interfaces.get_mut(reverse_entry.receiving_interface) {
                    iface.send(packet.clone(), 0, now);
                }
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
        // Only for DATA packets to Single/Group destinations (not Plain)
        let generate_receipt = matches!(
            &packet,
            Packet::Data {
                destination: DataDestination::Single(_) | DataDestination::Group(_),
                ..
            }
        );

        // Check if we have a known path for the destination
        // This applies to non-announce packets going to Single destinations
        let use_path = !matches!(packet, Packet::Announce { .. })
            && matches!(
                &packet,
                Packet::Data {
                    destination: DataDestination::Single(_),
                    ..
                } | Packet::LinkRequest { .. }
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
            if let Some(attached) = attached_interface {
                if i == attached {
                    should_transmit = false;
                }
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

    pub fn poll(&mut self, now: Instant) {
        // Receive from all interfaces
        let mut received = Vec::new();
        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            while let Some(raw) = iface.recv() {
                received.push((raw, i));
            }
        }
        for (raw, source) in received {
            self.inbound(&raw, source, now);
        }

        // Process outbound queues
        for iface in &mut self.interfaces {
            iface.poll(now);
        }

        // Handle pending announce rebroadcasts
        let mut to_send = Vec::new();
        for pending in &mut self.pending_announces {
            if pending.retry_at <= now && pending.retries_remaining > 0 {
                pending.retries_remaining -= 1;
                to_send.push((
                    pending.destination,
                    pending.hops,
                    pending.has_ratchet,
                    pending.data.clone(),
                    pending.source_interface,
                ));
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
            let packet =
                self.make_announce_packet(dest, hops, has_ratchet, data, Some(self.transport_id));
            self.outbound(packet, Some(source), now);
        }

        self.drain_service_outbound(now);
        self.maintain_links(now);

        for iface in &mut self.interfaces {
            iface.poll(now);
        }
    }

    fn maintain_links(&mut self, now: Instant) {
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

            if link.state == LinkState::Active && since_inbound >= stale_secs {
                link.state = LinkState::Stale;
            }

            if link.state == LinkState::Stale {
                to_close.push(*link_id);
                continue;
            }

            if link.is_initiator && link.state == LinkState::Active {
                let since_outbound = now.duration_since(link.last_outbound).as_secs();
                if since_outbound >= keepalive_secs {
                    to_keepalive.push(*link_id);
                }
            }
        }

        for link_id in to_keepalive {
            if let Some(link) = self.established_links.get_mut(&link_id) {
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
            }
            self.established_links.remove(&link_id);
        }
    }

    fn handle_keepalive(&mut self, link_id: LinkId, plaintext: &[u8], now: Instant) {
        use crate::link::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE};
        use crate::packet::LinkDataDestination;

        if plaintext.is_empty() {
            return;
        }

        if let Some(link) = self.established_links.get_mut(&link_id) {
            if plaintext[0] == KEEPALIVE_REQUEST && !link.is_initiator {
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
                // Initiator: received keepalive response, update RTT
                if let Some(sent_at) = link.last_keepalive_sent {
                    let rtt_ms = now.duration_since(sent_at).as_millis() as u64;
                    link.set_rtt(rtt_ms);
                    link.last_keepalive_sent = None;
                }
            }
        }
    }

    fn handle_link_rtt(&mut self, link_id: LinkId, plaintext: &[u8]) {
        use crate::link::decode_rtt;

        // LRRTT packet from initiator telling responder the measured RTT
        if let Some(rtt_secs) = decode_rtt(plaintext) {
            if let Some(link) = self.established_links.get_mut(&link_id) {
                if !link.is_initiator {
                    let rtt_ms = (rtt_secs * 1000.0) as u64;
                    link.set_rtt(rtt_ms);
                    link.state = LinkState::Active;
                    link.activated_at = Some(std::time::Instant::now());
                }
            }
        }
    }

    fn handle_resource_packet(
        &mut self,
        link_id: LinkId,
        context: LinkContext,
        plaintext: &[u8],
        now: Instant,
    ) {
        use crate::resource::{MAPHASH_LEN, ResourceAdvertisement};

        match context {
            LinkContext::ResourceAdv => {
                if let Some(adv) = ResourceAdvertisement::decode(plaintext) {
                    let hash = adv.hash;
                    if let Some(service_idx) = self.established_links.get(&link_id).and_then(|l| {
                        self.services
                            .iter()
                            .position(|s| s.address == l.destination)
                    }) {
                        self.pending_resource_adverts
                            .insert(hash, (link_id, adv.clone()));
                        let msg = InboundMessage::ResourceAdvertised {
                            link_id,
                            hash,
                            size: adv.transfer_size,
                            metadata: adv.metadata,
                        };
                        self.services[service_idx].service.inbound(msg);
                    }
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

                if let Some((_, _, resource)) = self.outbound_resources.get_mut(&hash) {
                    resource.mark_transferring();

                    for part_hash in requested_hashes {
                        if let Some(part_data) = resource.get_part(&part_hash) {
                            if let Some(link) = self.established_links.get(&link_id) {
                                let ciphertext = link.encrypt(&mut self.rng, part_data);
                                let packet = Packet::LinkData {
                                    hops: 0,
                                    destination: LinkDataDestination::Direct(link_id),
                                    context: LinkContext::Resource,
                                    data: ciphertext,
                                };
                                for iface in &mut self.interfaces {
                                    iface.send(packet.clone(), 0, now);
                                }
                            }
                        }
                    }

                    if exhausted {
                        if let Some(hmu_data) = resource.hashmap_update(100) {
                            if let Some(link) = self.established_links.get(&link_id) {
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
                }
            }
            LinkContext::Resource => {
                let mut completed = None;
                for (hash, (res_link_id, resource)) in &mut self.inbound_resources {
                    if *res_link_id == link_id {
                        let old_progress = resource.progress();
                        if resource.receive_part(plaintext.to_vec()) {
                            let new_progress = resource.progress();
                            if (new_progress - old_progress) >= 0.05 || new_progress >= 1.0 {
                                if let Some(service_idx) =
                                    self.established_links.get(&link_id).and_then(|l| {
                                        self.services
                                            .iter()
                                            .position(|s| s.address == l.destination)
                                    })
                                {
                                    let msg = InboundMessage::ResourceProgress {
                                        link_id,
                                        hash: *hash,
                                        progress: new_progress,
                                    };
                                    self.services[service_idx].service.inbound(msg);
                                }
                            }
                            if resource.is_complete() {
                                completed = Some(*hash);
                            }
                        }
                        break;
                    }
                }
                if let Some(hash) = completed {
                    self.complete_resource(link_id, hash, now);
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
                if let Some((res_link_id, service_addr, resource)) =
                    self.outbound_resources.get_mut(&hash)
                {
                    if resource.verify_proof(&proof) {
                        resource.mark_complete();
                        if let Some(service_idx) = self
                            .services
                            .iter()
                            .position(|s| s.address == *service_addr)
                        {
                            let msg = InboundMessage::ResourceComplete {
                                link_id: *res_link_id,
                                hash,
                                data: Vec::new(),
                                metadata: resource.metadata.clone(),
                            };
                            self.services[service_idx].service.inbound(msg);
                        }
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

                if let Some(service_idx) = self.established_links.get(&link_id).and_then(|l| {
                    self.services
                        .iter()
                        .position(|s| s.address == l.destination)
                }) {
                    let msg = InboundMessage::ResourceFailed { link_id, hash };
                    self.services[service_idx].service.inbound(msg);
                }
            }
            _ => {}
        }
    }

    fn complete_resource(&mut self, link_id: LinkId, hash: [u8; 32], now: Instant) {
        use crate::packet::LinkDataDestination;

        if let Some((_, resource)) = self.inbound_resources.remove(&hash) {
            if let Some(link) = self.established_links.get(&link_id) {
                if let Some(data) = resource.assemble(link) {
                    let proof = resource.generate_proof();
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

                    if let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.address == link.destination)
                    {
                        let msg = InboundMessage::ResourceComplete {
                            link_id,
                            hash,
                            data,
                            metadata: resource.metadata.clone(),
                        };
                        self.services[service_idx].service.inbound(msg);
                    }
                } else if let Some(service_idx) = self
                    .services
                    .iter()
                    .position(|s| s.address == link.destination)
                {
                    let msg = InboundMessage::ResourceFailed { link_id, hash };
                    self.services[service_idx].service.inbound(msg);
                }
            }
        }
    }

    fn send_resource_request(&mut self, link_id: LinkId, hash: [u8; 32], now: Instant) {
        use crate::packet::LinkDataDestination;

        if let Some((_, resource)) = self.inbound_resources.get_mut(&hash) {
            let needed = resource.needed_hashes();
            if needed.is_empty() && resource.is_complete() {
                return;
            }

            let exhausted = resource.is_hashmap_exhausted();
            let mut payload = Vec::new();
            payload.push(if exhausted { 1u8 } else { 0u8 });
            if exhausted {
                if let Some(last_hash) = resource.last_hashmap_hash() {
                    payload.extend(&last_hash);
                }
            }
            payload.extend(&hash);
            for h in needed {
                payload.extend(&h);
            }

            if let Some(link) = self.established_links.get(&link_id) {
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
            }
        }
    }

    fn drain_service_outbound(&mut self, now: Instant) {
        use crate::crypto::SingleDestEncryption;
        use crate::packet::LinkDataDestination;

        let mut messages = Vec::new();
        for entry in &mut self.services {
            while let Some(msg) = entry.service.outbound() {
                messages.push((entry.address, msg));
            }
        }

        for (service_addr, msg) in messages {
            match msg {
                OutboundMessage::LinkData { link_id, data } => {
                    if let Some(link) = self.established_links.get(&link_id) {
                        let ciphertext = link.encrypt(&mut self.rng, &data);
                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::None,
                            data: ciphertext,
                        };
                        for iface in &mut self.interfaces {
                            iface.send(packet.clone(), 0, now);
                        }
                    }
                }
                OutboundMessage::SingleData { destination, data } => {
                    if let Some(entry) = self.path_table.get(&destination) {
                        let (ephemeral_pub, ciphertext) = SingleDestEncryption::encrypt(
                            &mut self.rng,
                            &entry.encryption_key,
                            &data,
                        );
                        let mut payload = ephemeral_pub.as_bytes().to_vec();
                        payload.extend(ciphertext);

                        let dest = if entry.hops > 1 {
                            DataDestination::Transport {
                                transport_id: entry.next_hop,
                                destination,
                            }
                        } else {
                            DataDestination::Single(destination)
                        };
                        let packet = Packet::Data {
                            hops: 0,
                            destination: dest,
                            context: DataContext::None,
                            data: payload,
                        };
                        let target = entry.receiving_interface;
                        if let Some(iface) = self.interfaces.get_mut(target) {
                            iface.send(packet, 0, now);
                        }
                    }
                }
                OutboundMessage::Request {
                    link_id,
                    path,
                    data,
                } => {
                    if let Some(link) = self.established_links.get_mut(&link_id) {
                        let req = Request::new(&path, data);
                        let encoded = req.encode();
                        let ciphertext = link.encrypt(&mut self.rng, &encoded);

                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::Request,
                            data: ciphertext,
                        };
                        let request_id: crate::RequestId =
                            packet.packet_hash()[..16].try_into().unwrap();
                        link.pending_requests.insert(request_id, service_addr);

                        for iface in &mut self.interfaces {
                            iface.send(packet.clone(), 0, now);
                        }
                    }
                }
                OutboundMessage::Response {
                    link_id,
                    request_id,
                    data,
                } => {
                    if let Some(link) = self.established_links.get(&link_id) {
                        let resp = Response::new(request_id, data);
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
                    }
                }
                OutboundMessage::ResourceSend {
                    link_id,
                    data,
                    metadata,
                    compress,
                } => {
                    if let Some(link) = self.established_links.get(&link_id) {
                        let mut resource = crate::resource::OutboundResource::new(
                            &mut self.rng,
                            link,
                            data,
                            metadata,
                            compress,
                        );
                        let adv = resource.advertisement(100);
                        let adv_data = adv.encode();
                        let hash = resource.hash;

                        let ciphertext = link.encrypt(&mut self.rng, &adv_data);
                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::ResourceAdv,
                            data: ciphertext,
                        };

                        self.outbound_resources
                            .insert(hash, (link_id, service_addr, resource));

                        for iface in &mut self.interfaces {
                            iface.send(packet.clone(), 0, now);
                        }
                    }
                }
                OutboundMessage::ResourceAccept { link_id, hash } => {
                    if let Some((_, adv)) = self.pending_resource_adverts.remove(&hash) {
                        let mut resource =
                            crate::resource::InboundResource::from_advertisement(&adv);
                        resource.mark_transferring();
                        self.inbound_resources.insert(hash, (link_id, resource));
                        self.send_resource_request(link_id, hash, now);
                    }
                }
                OutboundMessage::ResourceReject { link_id, hash } => {
                    self.pending_resource_adverts.remove(&hash);
                    if let Some(link) = self.established_links.get(&link_id) {
                        let mut payload = vec![0u8]; // flags
                        payload.extend(&hash);
                        let ciphertext = link.encrypt(&mut self.rng, &payload);
                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::ResourceRcl,
                            data: ciphertext,
                        };
                        for iface in &mut self.interfaces {
                            iface.send(packet.clone(), 0, now);
                        }
                    }
                }
            }
        }
    }

    fn make_announce_packet(
        &self,
        dest: Address,
        hops: u8,
        has_ratchet: bool,
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
    use std::collections::VecDeque;

    struct MockTransport {
        outbox: VecDeque<Vec<u8>>,
        inbox: VecDeque<Vec<u8>>,
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                outbox: VecDeque::new(),
                inbox: VecDeque::new(),
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

    #[derive(Default)]
    struct TestService {
        name: String,
        inbox: Vec<InboundMessage>,
        outbox: VecDeque<OutboundMessage>,
    }

    impl Service for TestService {
        fn name(&self) -> &str {
            &self.name
        }
        fn inbound(&mut self, msg: InboundMessage) {
            self.inbox.push(msg);
        }
        fn outbound(&mut self) -> Option<OutboundMessage> {
            self.outbox.pop_front()
        }
    }

    fn svc(name: &str) -> TestService {
        TestService {
            name: name.into(),
            inbox: Vec::new(),
            outbox: VecDeque::new(),
        }
    }

    #[test]
    fn announce_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr = a.add_service(svc("test"));
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

        let addr = a.add_service(svc("test"));
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

        let addr = a.add_service(svc("test"));
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

        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).expect("link should be created");
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert!(a.established_links.contains_key(&link_id));
        assert!(b.established_links.values().any(|l| l.link_id == link_id));
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

        let addr_c = c.add_service(svc("server"));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(addr_c, later).expect("link should be created");
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
        assert!(c.established_links.values().any(|l| l.link_id == link_id));
    }

    #[test]
    fn link_data_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.send_link_packet(link_id, LinkContext::None, b"payload", now);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(b.services[0].service.inbox.len(), 1);
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

        let addr_c = c.add_service(svc("server"));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(addr_c, later).unwrap();
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

        assert_eq!(c.services[0].service.inbox.len(), 1);
    }

    #[test]
    fn single_data_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_a = a.add_service(svc("sender"));
        let addr_b = b.add_service(svc("receiver"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::SingleData {
                destination: addr_b,
                data: b"hello".to_vec(),
            });
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(b.services[0].service.inbox.len(), 1);
        assert!(matches!(
            &b.services[0].service.inbox[0],
            InboundMessage::SingleData { data } if data == b"hello"
        ));
    }

    #[test]
    fn single_data_three_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        let mut c: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());
        b.add_interface(test_interface());
        c.add_interface(test_interface());

        a.add_service(svc("sender"));
        let addr_c = c.add_service(svc("receiver"));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        a.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::SingleData {
                destination: addr_c,
                data: b"hello".to_vec(),
            });
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);

        assert_eq!(c.services[0].service.inbox.len(), 1);
        assert!(matches!(
            &c.services[0].service.inbox[0],
            InboundMessage::SingleData { data } if data == b"hello"
        ));
    }

    #[test]
    fn request_response_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        a.add_service(svc("client"));
        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        a.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::Request {
                link_id,
                path: "test.path".into(),
                data: b"request data".to_vec(),
            });
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        assert_eq!(b.services[0].service.inbox.len(), 1);
        let (req_link_id, req_id) = match &b.services[0].service.inbox[0] {
            InboundMessage::Request {
                link_id,
                request_id,
                data,
                ..
            } => {
                assert_eq!(data, b"request data");
                (*link_id, *request_id)
            }
            _ => panic!("expected Request"),
        };

        b.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::Response {
                link_id: req_link_id,
                request_id: req_id,
                data: b"response data".to_vec(),
            });
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        assert_eq!(a.services[0].service.inbox.len(), 1);
        assert!(matches!(
            &a.services[0].service.inbox[0],
            InboundMessage::Response { data, .. } if data == b"response data"
        ));
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

        a.add_service(svc("client"));
        let addr_c = c.add_service(svc("server"));
        let now = Instant::now();
        let later = now + std::time::Duration::from_secs(1);

        c.announce(addr_c, now);
        c.poll(now);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(now);
        b.poll(later); // rebroadcast after delay
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        let link_id = a.link(addr_c, later).unwrap();
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        a.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::Request {
                link_id,
                path: "test.path".into(),
                data: b"request data".to_vec(),
            });
        a.poll(later);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(later);
        transfer(&mut b, 1, &mut c, 0);
        c.poll(later);

        assert_eq!(c.services[0].service.inbox.len(), 1);
        let (req_link_id, req_id) = match &c.services[0].service.inbox[0] {
            InboundMessage::Request {
                link_id,
                request_id,
                data,
                ..
            } => {
                assert_eq!(data, b"request data");
                (*link_id, *request_id)
            }
            _ => panic!("expected Request"),
        };

        c.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::Response {
                link_id: req_link_id,
                request_id: req_id,
                data: b"response data".to_vec(),
            });
        c.poll(later);
        transfer(&mut c, 0, &mut b, 1);
        b.poll(later);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(later);

        assert_eq!(a.services[0].service.inbox.len(), 1);
        assert!(matches!(
            &a.services[0].service.inbox[0],
            InboundMessage::Response { data, .. } if data == b"response data"
        ));
    }

    #[test]
    fn resource_two_nodes() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        a.add_service(svc("sender"));
        let addr_b = b.add_service(svc("receiver"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let test_data = b"Hello, this is a resource transfer test with some data!".to_vec();
        a.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::ResourceSend {
                link_id,
                data: test_data.clone(),
                metadata: Some(b"test-meta".to_vec()),
                compress: false,
            });
        a.poll(now);
        println!("a.outbound_resources: {}", a.outbound_resources.len());
        println!(
            "a.interfaces[0].transport.outbox: {}",
            a.interfaces[0].transport.outbox.len()
        );
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        println!("b.inbox.len: {}", b.services[0].service.inbox.len());
        println!(
            "b.pending_resource_adverts: {}",
            b.pending_resource_adverts.len()
        );

        assert!(b.services[0].service.inbox.iter().any(|m| matches!(
            m,
            InboundMessage::ResourceAdvertised { size, .. } if *size > 0
        )));

        let hash = match &b.services[0].service.inbox[0] {
            InboundMessage::ResourceAdvertised { hash, .. } => *hash,
            _ => panic!("expected ResourceAdvertised"),
        };

        b.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::ResourceAccept { link_id, hash });
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let b_complete = b.services[0].service.inbox.iter().any(|m| {
            matches!(
                m,
                InboundMessage::ResourceComplete { data, .. } if data == &test_data
            )
        });
        assert!(b_complete, "receiver should have complete resource");

        let a_complete = a.services[0]
            .service
            .inbox
            .iter()
            .any(|m| matches!(m, InboundMessage::ResourceComplete { .. }));
        assert!(a_complete, "sender should get completion notification");
    }

    #[test]
    fn rtt_measured_and_propagated() {
        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
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
        let b_link = b
            .established_links
            .values()
            .find(|l| l.link_id == link_id)
            .unwrap();
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

        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        // Helper to count keepalives sent over a time period
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
                // Keep inbound fresh to avoid stale
                if let Some(l) = node.established_links.get_mut(&link) {
                    l.last_inbound = t;
                }
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
                    // Simulate response to clear last_keepalive_sent
                    if let Some(l) = node.established_links.get_mut(&link) {
                        l.last_keepalive_sent = None;
                        l.last_outbound = t;
                    }
                }
                t += Duration::from_secs(step_secs);
            }
            count
        };

        // Test with low RTT (0ms -> 5s interval)
        // Over 60 seconds, expect ~12 keepalives (60/5)
        if let Some(link) = a.established_links.get_mut(&link_id) {
            link.set_rtt(0);
            link.last_outbound = now;
            link.last_inbound = now;
            link.last_keepalive_sent = None;
        }
        let low_rtt_count = count_keepalives(&mut a, link_id, now, 60, 1);
        assert!(
            low_rtt_count >= 10 && low_rtt_count <= 14,
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
    fn stale_link_closed() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
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
    fn keepalive_request_response() {
        use std::time::Duration;

        let mut a: TestNode = Node::new(true);
        let mut b: TestNode = Node::new(true);
        a.add_interface(test_interface());
        b.add_interface(test_interface());

        let addr_b = b.add_service(svc("server"));
        let now = Instant::now();

        b.announce(addr_b, now);
        b.poll(now);
        transfer(&mut b, 0, &mut a, 0);
        a.poll(now);

        let link_id = a.link(addr_b, now).unwrap();
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

        // Set up to trigger keepalive: outbound old enough, but inbound recent enough to not be stale
        // With RTT 9999ms, keepalive_interval = 360s (clamped to max), stale_time = 720s
        let future = now + Duration::from_secs(400);

        if let Some(link) = a.established_links.get_mut(&link_id) {
            link.last_outbound = now;
            link.last_inbound = future - Duration::from_secs(100);
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

        // RTT should be updated from keepalive measurement
        let a_link = a.established_links.get(&link_id).unwrap();
        assert!(
            a_link.last_keepalive_sent.is_none(),
            "keepalive should be acknowledged"
        );
        let rtt_after = a_link.rtt_ms.unwrap();
        assert_eq!(
            rtt_after, 50,
            "RTT should be exactly 50ms from keepalive roundtrip"
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

        let _addr_a = a.add_service(svc("client"));
        let addr_b = b.add_service(svc("server"));
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
        let link_id = a.link(addr_b, now).expect("should create link");
        a.poll(now);
        println!(
            "A outbox after link request: {}",
            a.interfaces[0].transport.outbox.len()
        );
        transfer(&mut a, 0, &mut b, 0);
        println!(
            "B inbox after transfer: {}",
            b.interfaces[0].transport.inbox.len()
        );
        b.poll(now);
        println!(
            "B outbox after poll: {}",
            b.interfaces[0].transport.outbox.len()
        );
        println!("B established_links: {}", b.established_links.len());
        println!("B ifac_size: {}", b.interfaces[0].ifac_size);
        println!(
            "B ifac_identity: {}",
            b.interfaces[0].ifac_identity.is_some()
        );
        println!("B ifac_key: {}", b.interfaces[0].ifac_key.is_some());
        if let Some(raw) = b.interfaces[0].transport.outbox.front() {
            println!(
                "B outbox packet len: {}, first byte: 0x{:02x}",
                raw.len(),
                raw[0]
            );
        }
        transfer(&mut b, 0, &mut a, 0);
        println!(
            "A inbox after transfer: {}",
            a.interfaces[0].transport.inbox.len()
        );
        if let Some(raw) = a.interfaces[0].transport.inbox.front() {
            println!(
                "Raw packet len: {}, first byte: 0x{:02x}",
                raw.len(),
                raw[0]
            );
        }
        a.poll(now);
        println!("A established_links: {}", a.established_links.len());
        println!(
            "A pending_outbound_links: {}",
            a.pending_outbound_links.len()
        );

        assert!(
            a.is_link_established(&link_id),
            "link should be established over IFAC"
        );

        // Send data over the link
        a.services[0]
            .service
            .outbox
            .push_back(OutboundMessage::LinkData {
                link_id,
                data: b"hello over ifac".to_vec(),
            });
        a.poll(now);
        transfer(&mut a, 0, &mut b, 0);
        b.poll(now);

        let received = b.services[0].service.inbox.iter().any(
            |m| matches!(m, InboundMessage::LinkData { data, .. } if data == b"hello over ifac"),
        );
        assert!(received, "B should receive data over IFAC-protected link");
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

        let addr_b = b.add_service(svc("server"));
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
}
