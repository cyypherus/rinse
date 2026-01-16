use std::collections::HashMap;
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rand::rngs::ThreadRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::announce::{AnnounceBuilder, AnnounceData};
use crate::crypto::{EphemeralKeyPair, sha256};
pub use crate::link::LinkId;
use crate::link::{EstablishedLink, LinkProof, LinkRequest, LinkState, PendingLink};
use crate::packet::{Address, DataContext, DataDestination, LinkContext, Packet};
use crate::packet_hashlist::PacketHashlist;
use crate::path_request::PathRequest;
use crate::{Interface, Transport};
use ed25519_dalek::Signature;

// "By default, m is set to 128."
const DEFAULT_MAX_HOPS: u8 = 128;
// "By default, r is set to 1."
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;
const LOCAL_REBROADCASTS_MAX: u8 = 2;

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
}

pub trait Service: Send {
    fn name(&self) -> &str;
    fn inbound(&mut self, msg: InboundMessage);
    fn outbound(&mut self) -> Option<OutboundMessage>;
}

struct ServiceEntry {
    service: Box<dyn Service>,
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

pub struct Node<T, R = ThreadRng> {
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
    services: Vec<ServiceEntry>,
    interfaces: Vec<Interface<T>>,
    pending_outbound_links: HashMap<LinkId, PendingLink>,
    established_links: HashMap<LinkId, EstablishedLink>,
    link_table: HashMap<LinkId, LinkTableEntry>,
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
            control_hashes: std::collections::HashSet::new(),
            receipts: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
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
            control_hashes: std::collections::HashSet::new(),
            receipts: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
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

    pub fn add_service(&mut self, service: impl Service + 'static) -> Address {
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
            service: Box::new(service),
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

        let packet = self.make_announce_packet(address, 0, false, announce_data.to_bytes());

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, &mut self.rng, now);
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
            iface.send(packet.clone(), 0, &mut self.rng, now);
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
            iface.send(packet, 0, &mut self.rng, now);
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
            if matches!(
                context,
                DataContext::Resource
                    | DataContext::ResourceReq
                    | DataContext::ResourcePrf
                    | DataContext::CacheRequest
                    | DataContext::Channel
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

    fn validate_ifac(
        raw: &[u8],
        ifac_identity: Option<&SigningKey>,
        ifac_size: usize,
        ifac_key: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        if raw.len() <= 2 {
            return None;
        }

        if let Some(ifac_id) = ifac_identity {
            // Interface has IFAC enabled
            if raw[0] & 0x80 == 0x80 {
                // IFAC flag is set - good
                if raw.len() > 2 + ifac_size {
                    // Extract IFAC
                    let ifac = &raw[2..2 + ifac_size];

                    // Generate mask
                    let mask = crate::crypto::hkdf_expand(ifac, ifac_key?, raw.len());

                    // Unmask payload
                    let mut unmasked_raw = Vec::with_capacity(raw.len());
                    for (i, &byte) in raw.iter().enumerate() {
                        if i <= 1 || i > ifac_size + 1 {
                            // Unmask header bytes and payload
                            unmasked_raw.push(byte ^ mask[i]);
                        } else {
                            // Don't unmask IFAC itself
                            unmasked_raw.push(byte);
                        }
                    }

                    // Unset IFAC flag
                    let new_header = [unmasked_raw[0] & 0x7f, unmasked_raw[1]];

                    // Re-assemble packet
                    let mut new_raw = Vec::with_capacity(raw.len() - ifac_size);
                    new_raw.extend_from_slice(&new_header);
                    new_raw.extend_from_slice(&unmasked_raw[2 + ifac_size..]);

                    // Calculate expected IFAC
                    let signature = crate::crypto::sign(ifac_id, &new_raw);
                    let expected_ifac = &signature.to_bytes()[64 - ifac_size..];

                    // Check it
                    if ifac == expected_ifac {
                        Some(new_raw)
                    } else {
                        None
                    }
                } else {
                    // Too short
                    None
                }
            } else {
                // IFAC flag not set but should be
                None
            }
        } else {
            // Interface does NOT have IFAC enabled
            if raw[0] & 0x80 == 0x80 {
                // Flag set but shouldn't be
                None
            } else {
                Some(raw.to_vec())
            }
        }
    }

    fn inbound(
        &mut self,
        raw: &[u8],
        interface_index: usize,
        now: Instant,
    ) -> Option<(Packet, bool, bool)> {
        let interface = self.interfaces.get(interface_index)?;
        let raw = Self::validate_ifac(
            raw,
            interface.ifac_identity.as_ref(),
            interface.ifac_size,
            interface.ifac_key.as_deref(),
        )?;

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
            let raw = packet.to_bytes();
            // Send to all interfaces except the originator
            for (i, iface) in self.interfaces.iter_mut().enumerate() {
                if i != interface_index {
                    iface.transport.send(&raw);
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
                    let new_raw = new_packet.to_bytes();

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
                        iface.transport.send(&new_raw);
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

                    let raw = packet.to_bytes();
                    if let Some(iface) = self.interfaces.get_mut(out_iface) {
                        iface.transport.send(&raw);
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

                if hops >= self.max_hops + 1 {
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

                    // Schedule for rebroadcast
                    self.pending_announces.push(PendingAnnounce {
                        destination: destination_hash,
                        source_interface: interface_index,
                        hops,
                        has_ratchet: *has_ratchet,
                        data: data.clone(),
                        retries_remaining: self.retries,
                        retry_at: now, // Rebroadcast immediately on first receive
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
                    iface.transport.send(&proof_packet.to_bytes());
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

                    if let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.address == link.destination)
                    {
                        let msg = match context {
                            LinkContext::Request => {
                                if let Some(req) = crate::Request::decode(&plaintext) {
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
                            LinkContext::Response => {
                                if let Some(resp) = crate::Response::decode(&plaintext) {
                                    InboundMessage::Response {
                                        request_id: resp.request_id,
                                        data: resp.data,
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
                    let raw = packet.to_bytes();
                    if let Some(iface) = self.interfaces.get_mut(link_entry.receiving_interface) {
                        iface.transport.send(&raw);
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

                self.established_links.insert(destination_hash, link);

                log::debug!(
                    "Link <{}> established as initiator",
                    hex::encode(destination_hash)
                );
            }
        }

        if let Packet::Proof { data, .. } = &packet {
            // Regular proof - check reverse table for transport
            if let Some(reverse_entry) = self.reverse_table.remove(&destination_hash) {
                let raw = packet.to_bytes();
                if let Some(iface) = self.interfaces.get_mut(reverse_entry.receiving_interface) {
                    iface.transport.send(&raw);
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
            iface.send(packet.clone(), 0, &mut self.rng, now);
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
        // and not for resource-related contexts
        let generate_receipt = matches!(
            &packet,
            Packet::Data {
                destination: DataDestination::Single(_) | DataDestination::Group(_),
                context,
                ..
            } if !matches!(context,
                DataContext::Resource |
                DataContext::ResourceAdv |
                DataContext::ResourceReq |
                DataContext::ResourceHmu |
                DataContext::ResourcePrf |
                DataContext::ResourceIcl |
                DataContext::ResourceRcl
            )
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
            let raw = packet.to_bytes();
            if let Some(iface) = self.interfaces.get_mut(outbound_interface) {
                iface.transport.send(&raw);
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

                iface.send(packet.clone(), hops, &mut self.rng, now);
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
            let packet = self.make_announce_packet(dest, hops, has_ratchet, data);
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
                    iface.send(packet.clone(), 0, &mut self.rng, now);
                }
            }
            self.established_links.remove(&link_id);
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
                            iface.send(packet.clone(), 0, &mut self.rng, now);
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

                        let packet = Packet::Data {
                            hops: 0,
                            destination: DataDestination::Single(destination),
                            context: DataContext::None,
                            data: payload,
                        };
                        let target = entry.receiving_interface;
                        if let Some(iface) = self.interfaces.get_mut(target) {
                            iface.send(packet, 0, &mut self.rng, now);
                        }
                    }
                }
                OutboundMessage::Request {
                    link_id,
                    path,
                    data,
                } => {
                    if let Some(link) = self.established_links.get_mut(&link_id) {
                        let req = crate::Request::new(&path, data);
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
                            iface.send(packet.clone(), 0, &mut self.rng, now);
                        }
                    }
                }
                OutboundMessage::Response {
                    link_id,
                    request_id,
                    data,
                } => {
                    if let Some(link) = self.established_links.get(&link_id) {
                        let resp = crate::Response::new(request_id, data);
                        let ciphertext = link.encrypt(&mut self.rng, &resp.encode());

                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: LinkDataDestination::Direct(link_id),
                            context: LinkContext::Response,
                            data: ciphertext,
                        };
                        for iface in &mut self.interfaces {
                            iface.send(packet.clone(), 0, &mut self.rng, now);
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
    ) -> Packet {
        use crate::packet::AnnounceDestination;
        Packet::Announce {
            hops,
            destination: AnnounceDestination::Single(dest),
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
