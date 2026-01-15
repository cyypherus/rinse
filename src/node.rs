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
use crate::path_request::PathRequest;
use crate::{
    Address, Addresses, Context, DestinationType, Interface, Packet, PacketType, PropagationType,
    Transport,
};
use ed25519_dalek::Signature;

// "By default, m is set to 128."
const DEFAULT_MAX_HOPS: u8 = 128;
// "By default, r is set to 1."
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;

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

struct AnnounceEntry {
    // "record into a table which Transport Node the announce was received from"
    source_interface: usize,
    // "how many times in total it has been retransmitted to get here"
    hops: u8,
    app_data: Vec<u8>,
    retries_remaining: u8,
    retry_at: Option<Instant>,
    // "The sender already knows the public key of the destination from an earlier
    // received announce"
    encryption_key: X25519Public,
    // "where the signature can be verified against the destination's known public signing key"
    signing_key: VerifyingKey,
    // "(or ratchet key, if available)"
    ratchet_key: Option<X25519Public>,
    // Transport node that forwarded the announce (for Type2 packets)
    next_hop: Option<Address>,
}

struct LinkTableEntry {
    toward_initiator: usize,
    toward_destination: usize,
    receiving_interface: usize,
    next_hop_interface: usize,
}

struct PathTableEntry {
    next_hop: Address,
    hops: u8,
    receiving_interface: usize,
}

struct ReverseTableEntry {
    receiving_interface: usize,
    outbound_interface: usize,
}

pub struct Node<T, R = ThreadRng> {
    max_hops: u8,
    retries: u8,
    pub(crate) retry_delay_ms: u64,
    rng: R,
    transport_id: Address,
    seen_announces: HashMap<Address, AnnounceEntry>,
    seen_packet_hashes: std::collections::HashSet<[u8; 32]>,
    path_table: HashMap<Address, PathTableEntry>,
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
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut transport_id = [0u8; 16];
        rng.fill_bytes(&mut transport_id);
        log::info!(
            "Node started with transport_id <{}>",
            hex::encode(transport_id)
        );
        Self {
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            rng,
            transport_id,
            seen_announces: HashMap::new(),
            seen_packet_hashes: std::collections::HashSet::new(),
            path_table: HashMap::new(),
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
    pub fn with_rng(mut rng: R) -> Self {
        let mut transport_id = [0u8; 16];
        rng.fill_bytes(&mut transport_id);
        log::info!(
            "Node started with transport_id <{}>",
            hex::encode(transport_id)
        );
        Self {
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            rng,
            transport_id,
            seen_announces: HashMap::new(),
            seen_packet_hashes: std::collections::HashSet::new(),
            path_table: HashMap::new(),
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
        self.seen_announces.contains_key(dest)
    }

    pub fn known_destinations(&self) -> Vec<Address> {
        self.seen_announces.keys().copied().collect()
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

        let packet = self.make_announce_packet(address, 0, announce_data.to_bytes());

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, &mut self.rng, now);
        }
    }

    // "Requests a path to the destination from the network. If another reachable peer
    // on the network knows a path, it will announce it."
    pub fn request_path(&mut self, destination: Address, now: Instant) {
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };

        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);

        let request = PathRequest::new(destination, tag);
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single(PathRequest::destination()),
            Context::None,
            request.to_bytes(),
        )
        .unwrap();

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, &mut self.rng, now);
        }
    }

    // "When a node in the network wants to establish verified connectivity with another node,
    // it will randomly generate a new X25519 private/public key pair. It then creates a
    // link request packet, and broadcast it."
    pub fn link(&mut self, destination: Address, now: Instant) -> Option<LinkId> {
        // Must have seen an announce for this destination
        let announce_entry = self.seen_announces.get(&destination)?;
        let target_interface = announce_entry.source_interface;
        let hops = announce_entry.hops;
        let next_hop = announce_entry.next_hop;

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
        if let Some(iface) = self.interfaces.get_mut(target_interface) {
            iface.send(packet, 0, &mut self.rng, now);
        }

        Some(link_id)
    }

    fn inbound(
        &mut self,
        raw: &[u8],
        interface_index: usize,
        _now: Instant,
    ) -> Option<(Packet, bool, bool)> {
        // If interface access codes are enabled,
        // we must authenticate each packet.
        if raw.len() <= 2 {
            return None;
        }

        let interface = self.interfaces.get(interface_index)?;
        let ifac_identity = interface.ifac_identity.as_ref();
        let raw = if let Some(ifac_id) = ifac_identity {
            // Check that IFAC flag is set
            if raw[0] & 0x80 != 0x80 {
                // If the IFAC flag is not set, but should be,
                // drop the packet.
                return None;
            }

            let ifac_size = interface.ifac_size;
            if raw.len() <= 2 + ifac_size {
                return None;
            }

            // Extract IFAC
            let ifac = &raw[2..2 + ifac_size];

            // Generate mask
            let mask = crate::crypto::hkdf_expand(ifac, interface.ifac_key.as_ref()?, raw.len());

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
            if ifac != expected_ifac {
                return None;
            }

            new_raw
        } else {
            // If the interface does not have IFAC enabled,
            // check the received packet IFAC flag.
            if raw[0] & 0x80 == 0x80 {
                // If the flag is set, drop the packet
                return None;
            }
            raw.to_vec()
        };

        // Parse packet
        let ifac_len = if ifac_identity.is_some() {
            0 // IFAC already stripped
        } else {
            interface.ifac_len
        };
        let mut packet = match Packet::from_bytes(&raw, ifac_len) {
            Ok(p) => p,
            Err(_) => return None,
        };

        // Increment hop count
        packet.header.hops = packet.header.hops.saturating_add(1);

        let packet_hash = sha256(&packet.hashable_part());

        // Packet filter: check if we've already seen this packet
        if self.seen_packet_hashes.contains(&packet_hash) {
            return None;
        }

        // By default, remember packet hashes to avoid routing
        // loops in the network, using the packet filter.
        let mut remember_packet_hash = true;

        // Get destination hash for lookups
        let destination_hash = match packet.addresses {
            Addresses::Single(addr) => addr,
            Addresses::Double(_, addr) => addr,
        };

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
        if packet.header.packet_type == PacketType::Proof
            && packet.context == Context::LinkRequestProof
        {
            remember_packet_hash = false;
        }

        if remember_packet_hash {
            self.seen_packet_hashes.insert(packet_hash);
        }

        let for_local_service = packet.header.packet_type != PacketType::Announce
            && self.services.iter().any(|s| s.address == destination_hash);

        let for_local_link = packet.header.packet_type != PacketType::Announce
            && self.established_links.contains_key(&link_id);

        // Plain broadcast packets are sent directly on all attached interfaces
        // (no transport routing needed)
        if !self.control_hashes.contains(&destination_hash)
            && packet.header.destination_type == DestinationType::Plain
            && packet.header.propagation_type == PropagationType::Broadcast
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
        if for_local_service || for_local_link {
            // If the packet is in transport (has transport_id), check whether we
            // are the designated next hop, and process it accordingly if we are.
            if let Addresses::Double(transport_id, dest) = packet.addresses {
                if transport_id == self.transport_id
                    && packet.header.packet_type != PacketType::Announce
                {
                    if let Some(path_entry) = self.path_table.get(&dest) {
                        let next_hop = path_entry.next_hop;
                        let remaining_hops = path_entry.hops;
                        let outbound_interface = path_entry.receiving_interface;

                        // Build forwarded packet
                        let new_raw = if remaining_hops > 1 {
                            // Replace transport_id with next_hop, keep rest
                            let mut raw = packet.to_bytes();
                            raw[2..18].copy_from_slice(&next_hop);
                            raw
                        } else if remaining_hops == 1 {
                            // Strip transport headers - convert Type2 to Type1
                            let mut new_packet = packet.clone();
                            new_packet.header.header_type = crate::HeaderType::Type1;
                            new_packet.header.propagation_type = PropagationType::Broadcast;
                            new_packet.addresses = Addresses::Single(dest);
                            new_packet.to_bytes()
                        } else {
                            // remaining_hops == 0, local delivery
                            packet.to_bytes()
                        };

                        // Record in link_table for link requests, reverse_table for others
                        if packet.header.packet_type == PacketType::LinkRequest {
                            let link_id = LinkRequest::link_id(&packet.hashable_part());
                            self.link_table.insert(
                                link_id,
                                LinkTableEntry {
                                    toward_initiator: interface_index,
                                    toward_destination: outbound_interface,
                                    receiving_interface: interface_index,
                                    next_hop_interface: outbound_interface,
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
                        }
                    } else {
                        log::debug!(
                            "Got packet in transport, but no known path to destination <{}>",
                            hex::encode(dest)
                        );
                    }
                }
            }

            // Link transport handling. Directs packets according to entries in the link tables
            if packet.header.packet_type != PacketType::Announce
                && packet.header.packet_type != PacketType::LinkRequest
                && packet.context != Context::LinkRequestProof
            {
                if let Some(link_entry) = self.link_table.get(&link_id) {
                    let outbound_interface =
                        if link_entry.next_hop_interface == link_entry.receiving_interface {
                            // Same interface both directions - just repeat
                            Some(link_entry.next_hop_interface)
                        } else if interface_index == link_entry.next_hop_interface {
                            // Received from next_hop side, send to receiving side
                            Some(link_entry.receiving_interface)
                        } else if interface_index == link_entry.receiving_interface {
                            // Received from receiving side, send to next_hop side
                            Some(link_entry.next_hop_interface)
                        } else {
                            None
                        };

                    if let Some(out_iface) = outbound_interface {
                        // Add to packet hash filter now that we know it's our turn
                        self.seen_packet_hashes.insert(packet_hash);

                        let raw = packet.to_bytes();
                        if let Some(iface) = self.interfaces.get_mut(out_iface) {
                            iface.transport.send(&raw);
                        }
                    }
                }
            }
        }

        if packet.header.packet_type == PacketType::Announce {
            let has_ratchet = packet.header.context_flag == crate::ContextFlag::Set;
            let announce = match AnnounceData::parse(&packet.data, has_ratchet) {
                Ok(a) => a,
                Err(_) => return None,
            };

            // Validate announce signature
            if announce.verify(&destination_hash).is_err() {
                return None;
            }
            if announce.verify_destination(&destination_hash).is_err() {
                return None;
            }

            // Check if this is a local destination (one of our services)
            let is_local = self.services.iter().any(|s| s.address == destination_hash);

            if !is_local {
                // Get received_from (transport_id if present, else destination_hash)
                let received_from = match packet.addresses {
                    Addresses::Double(transport_id, _) => transport_id,
                    Addresses::Single(_) => destination_hash,
                };

                // Check if this is a rebroadcast we were waiting for
                if let Some(entry) = self.seen_announces.get_mut(&destination_hash) {
                    if packet.header.hops == entry.hops.saturating_add(1) {
                        // Another node rebroadcasted our announce, stop retrying
                        log::trace!(
                            "Announce for <{}> passed on by another node",
                            hex::encode(destination_hash)
                        );
                        entry.retries_remaining = 0;
                        entry.retry_at = None;
                    }
                }

                // Determine if we should add/update path table
                let mut should_add = false;
                let hops = packet.header.hops;

                // First, check hops are less than max
                if hops < self.max_hops + 1 {
                    if let Some(existing) = self.path_table.get(&destination_hash) {
                        // Update if new path is shorter or equal
                        if hops <= existing.hops {
                            should_add = true;
                        }
                    } else {
                        // Unknown destination, add it
                        should_add = true;
                    }
                }

                if should_add {
                    let signing_key = match announce.signing_public_key() {
                        Ok(k) => k,
                        Err(_) => return None,
                    };

                    // Update path table
                    self.path_table.insert(
                        destination_hash,
                        PathTableEntry {
                            next_hop: received_from,
                            hops,
                            receiving_interface: interface_index,
                        },
                    );

                    // Update seen_announces for rebroadcast scheduling
                    self.seen_announces.insert(
                        destination_hash,
                        AnnounceEntry {
                            source_interface: interface_index,
                            hops,
                            app_data: announce.app_data.clone(),
                            retries_remaining: self.retries,
                            retry_at: None, // Will be set by poll()
                            encryption_key: announce.encryption_public_key(),
                            signing_key,
                            ratchet_key: announce.ratchet.map(X25519Public::from),
                            next_hop: match packet.addresses {
                                Addresses::Double(t, _) => Some(t),
                                Addresses::Single(_) => None,
                            },
                        },
                    );

                    log::debug!(
                        "Destination <{}> is now {} hops away via <{}>",
                        hex::encode(destination_hash),
                        hops,
                        hex::encode(received_from)
                    );
                }
            }
        }

        if packet.header.packet_type == PacketType::LinkRequest {
            let is_for_us = match packet.addresses {
                Addresses::Single(_) => true,
                Addresses::Double(transport_id, _) => transport_id == self.transport_id,
            };

            if is_for_us && for_local_service {
                let request = match LinkRequest::parse(&packet.data) {
                    Some(r) => r,
                    None => return None,
                };

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
                    _now,
                );

                // Create and send proof
                let proof = LinkProof::create(
                    &new_link_id,
                    &responder_keypair.public,
                    &service.signing_key,
                );
                let proof_packet = self.make_link_proof_packet(new_link_id, proof.to_bytes());

                self.established_links.insert(new_link_id, link);

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

        if packet.header.packet_type == PacketType::Data {
            if packet.header.destination_type == DestinationType::Link {
                // Data for a link - decrypt with link keys
                if let Some(link) = self.established_links.get_mut(&link_id) {
                    if let Some(plaintext) = link.decrypt(&packet.data) {
                        link.touch_inbound(_now);

                        // Find the service this link belongs to
                        if let Some(service_idx) = self
                            .services
                            .iter()
                            .position(|s| s.address == link.destination)
                        {
                            let msg = InboundMessage::LinkData {
                                link_id,
                                data: plaintext,
                            };
                            self.services[service_idx].service.inbound(msg);
                        }
                    }
                }
            } else if for_local_service {
                // Data for a single destination - decrypt with service keys
                // Packet data format: ephemeral_public (32) + ciphertext
                if packet.data.len() >= 32 {
                    if let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.address == destination_hash)
                    {
                        let service = &self.services[service_idx];

                        let ephemeral_public =
                            X25519Public::from(<[u8; 32]>::try_from(&packet.data[..32]).unwrap());
                        let ciphertext = &packet.data[32..];

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
        }

        if packet.header.packet_type == PacketType::Proof {
            if packet.context == Context::LinkRequestProof {
                // Link request proof - check if it needs to be transported
                if let Some(link_entry) = self.link_table.get(&link_id) {
                    if interface_index == link_entry.next_hop_interface {
                        // Transport the proof
                        let raw = packet.to_bytes();
                        if let Some(iface) = self.interfaces.get_mut(link_entry.receiving_interface)
                        {
                            iface.transport.send(&raw);
                        }
                    }
                } else if let Some(pending) = self.pending_outbound_links.remove(&destination_hash)
                {
                    // This is a proof for a link we initiated - validate and establish
                    let proof = match LinkProof::parse(&packet.data) {
                        Some(p) => p,
                        None => {
                            self.pending_outbound_links
                                .insert(destination_hash, pending);
                            return None;
                        }
                    };

                    // Get the destination's signing key from the announce we received
                    let signing_key = match self.seen_announces.get(&pending.destination) {
                        Some(entry) => entry.signing_key,
                        None => {
                            log::debug!(
                                "No announce found for destination <{}>",
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
                    let link =
                        EstablishedLink::from_initiator(pending, &proof.encryption_public, _now);

                    self.established_links.insert(destination_hash, link);

                    log::debug!(
                        "Link <{}> established as initiator",
                        hex::encode(destination_hash)
                    );
                }
            } else {
                // Regular proof - check reverse table for transport
                if let Some(reverse_entry) = self.reverse_table.remove(&destination_hash) {
                    let raw = packet.to_bytes();
                    if let Some(iface) = self.interfaces.get_mut(reverse_entry.receiving_interface)
                    {
                        iface.transport.send(&raw);
                    }
                }

                // Check local receipts - validate proof against outstanding receipts
                // Proof format: explicit = hash (32) + signature (64), implicit = signature (64)
                let proof_data = &packet.data;
                let (proof_hash, signature_bytes) = if proof_data.len() == 96 {
                    // Explicit proof
                    (
                        Some(<[u8; 32]>::try_from(&proof_data[..32]).ok()),
                        &proof_data[32..96],
                    )
                } else if proof_data.len() == 64 {
                    // Implicit proof
                    (None, &proof_data[..64])
                } else {
                    (None, &[] as &[u8])
                };

                if !signature_bytes.is_empty() {
                    if let Ok(signature) = Signature::from_slice(signature_bytes) {
                        self.receipts.retain(|receipt| {
                            // For explicit proofs, check hash matches
                            if let Some(Some(ph)) = proof_hash {
                                if ph != receipt.packet_hash {
                                    return true; // Keep - not for this receipt
                                }
                            }

                            // Get destination's signing key to verify
                            let signing_key = match self.seen_announces.get(&receipt.destination) {
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

        Some((packet, for_local_service, for_local_link))
    }

    fn send_link_packet(
        &mut self,
        link_id: LinkId,
        context: Context,
        plaintext: &[u8],
        now: Instant,
    ) {
        use crate::{ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType};

        let Some(link) = self.established_links.get_mut(&link_id) else {
            return;
        };

        let ciphertext = link.encrypt(&mut self.rng, plaintext);
        link.touch_outbound(now);

        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single(link_id),
            context,
            ciphertext,
        )
        .unwrap();

        for iface in &mut self.interfaces {
            iface.send(packet.clone(), 0, &mut self.rng, now);
        }
    }

    // "If another reachable peer on the network knows a path, it will announce it."
    fn handle_path_request(&mut self, packet: &Packet, now: Instant) {
        let Some(request) = PathRequest::parse(&packet.data) else {
            return;
        };

        // Check if we have a local service for this destination
        if let Some(entry) = self
            .services
            .iter()
            .find(|s| s.address == request.destination_hash)
        {
            // Re-announce our local service
            let mut random_hash = [0u8; 10];
            self.rng.fill_bytes(&mut random_hash);

            let announce_data = AnnounceBuilder::new(
                *entry.encryption_public.as_bytes(),
                entry.signing_key.clone(),
                entry.name_hash,
                random_hash,
            )
            .build(&entry.address);

            let announce_packet =
                self.make_announce_packet(entry.address, 0, announce_data.to_bytes());

            for iface in &mut self.interfaces {
                iface.send(announce_packet.clone(), 0, &mut self.rng, now);
            }
        }
        // TODO: If we're a transport node and have seen an announce for this destination,
        // we could re-broadcast the cached announce
    }

    // "After a randomised delay, the announce will be retransmitted on all interfaces
    // that have bandwidth available for processing announces."
    //
    // "If any given interface does not have enough bandwidth available for retransmitting
    // the announce, the announce will be assigned a priority inversely proportional to its
    // hop count, and be inserted into a queue managed by the interface."
    //
    // "When the interface has bandwidth available for processing an announce, it will
    // prioritise announces for destinations that are closest in terms of hops, thus
    // prioritising reachability and connectivity of local nodes, even on slow networks
    // that connect to wider and faster networks."
    fn outbound(&mut self, packet: Packet, exclude: Option<usize>, now: Instant) {
        let dest = match packet.addresses {
            Addresses::Single(a) => a,
            Addresses::Double(_, dest) => dest,
        };
        let hops = packet.header.hops;

        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            if Some(i) != exclude {
                iface.send(packet.clone(), hops, &mut self.rng, now);
            }
        }

        // "After the announce has been re-transmitted, and if no other nodes are heard
        // retransmitting the announce with a greater hop count than when it left this
        // node, transmitting it will be retried r times. By default, r is set to 1."
        if let Some(entry) = self.seen_announces.get_mut(&dest)
            && entry.retries_remaining > 0
        {
            entry.retry_at = Some(now + Duration::from_millis(self.retry_delay_ms));
        }
    }

    pub fn poll(&mut self, now: Instant) {
        // Receive from all interfaces
        let mut received = Vec::new();
        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            while let Some(packet) = iface.recv() {
                received.push((packet, i));
            }
        }
        for (packet, source) in received {
            self.inbound(&packet, source, now);
        }

        // Process outbound queues
        for iface in &mut self.interfaces {
            iface.poll(now);
        }

        // Handle retries
        let mut to_retry = Vec::new();
        for (dest, entry) in &mut self.seen_announces {
            if let Some(retry_at) = entry.retry_at
                && retry_at <= now
                && entry.retries_remaining > 0
            {
                entry.retries_remaining -= 1;
                entry.retry_at = None;
                to_retry.push((
                    *dest,
                    entry.hops,
                    entry.app_data.clone(),
                    entry.source_interface,
                ));
            }
        }

        for (dest, hops, data, source) in to_retry {
            let packet = self.make_announce_packet(dest, hops, data);
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
                Context::Keepalive,
                &[crate::link::KEEPALIVE_REQUEST],
                now,
            );
        }

        for link_id in to_close {
            if let Some(link) = self.established_links.get(&link_id)
                && link.state != LinkState::Closed
            {
                let close_data = link.encrypt(&mut self.rng, &link_id);
                let header = crate::Header {
                    ifac_flag: crate::IfacFlag::Open,
                    header_type: crate::HeaderType::Type1,
                    context_flag: crate::ContextFlag::Unset,
                    propagation_type: crate::PropagationType::Broadcast,
                    destination_type: crate::DestinationType::Link,
                    packet_type: PacketType::Data,
                    hops: 0,
                };
                let packet = Packet::new(
                    header,
                    None,
                    Addresses::Single(link_id),
                    Context::LinkClose,
                    close_data,
                )
                .unwrap();
                for iface in &mut self.interfaces {
                    iface.send(packet.clone(), 0, &mut self.rng, now);
                }
            }
            self.established_links.remove(&link_id);
        }
    }

    fn drain_service_outbound(&mut self, now: Instant) {
        use crate::crypto::SingleDestEncryption;
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };

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
                        let header = Header {
                            ifac_flag: IfacFlag::Open,
                            header_type: HeaderType::Type1,
                            context_flag: ContextFlag::Unset,
                            propagation_type: PropagationType::Broadcast,
                            destination_type: DestinationType::Link,
                            packet_type: PacketType::Data,
                            hops: 0,
                        };
                        if let Ok(packet) = Packet::new(
                            header,
                            None,
                            Addresses::Single(link_id),
                            Context::None,
                            ciphertext,
                        ) {
                            for iface in &mut self.interfaces {
                                iface.send(packet.clone(), 0, &mut self.rng, now);
                            }
                        }
                    }
                }
                OutboundMessage::SingleData { destination, data } => {
                    if let Some(entry) = self.seen_announces.get(&destination) {
                        let (ephemeral_pub, ciphertext) = SingleDestEncryption::encrypt(
                            &mut self.rng,
                            &entry.encryption_key,
                            &data,
                        );
                        let mut payload = ephemeral_pub.as_bytes().to_vec();
                        payload.extend(ciphertext);

                        let header = Header {
                            ifac_flag: IfacFlag::Open,
                            header_type: HeaderType::Type1,
                            context_flag: ContextFlag::Unset,
                            propagation_type: PropagationType::Broadcast,
                            destination_type: DestinationType::Single,
                            packet_type: PacketType::Data,
                            hops: 0,
                        };
                        if let Ok(packet) = Packet::new(
                            header,
                            None,
                            Addresses::Single(destination),
                            Context::None,
                            payload,
                        ) {
                            let target = entry.source_interface;
                            if let Some(iface) = self.interfaces.get_mut(target) {
                                iface.send(packet, 0, &mut self.rng, now);
                            }
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

                        let request_id: crate::RequestId =
                            crate::crypto::sha256(&ciphertext)[..16].try_into().unwrap();
                        link.pending_requests.insert(request_id, service_addr);

                        let header = Header {
                            ifac_flag: IfacFlag::Open,
                            header_type: HeaderType::Type1,
                            context_flag: ContextFlag::Unset,
                            propagation_type: PropagationType::Broadcast,
                            destination_type: DestinationType::Link,
                            packet_type: PacketType::Data,
                            hops: 0,
                        };
                        if let Ok(packet) = Packet::new(
                            header,
                            None,
                            Addresses::Single(link_id),
                            Context::Request,
                            ciphertext,
                        ) {
                            for iface in &mut self.interfaces {
                                iface.send(packet.clone(), 0, &mut self.rng, now);
                            }
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

                        let header = Header {
                            ifac_flag: IfacFlag::Open,
                            header_type: HeaderType::Type1,
                            context_flag: ContextFlag::Unset,
                            propagation_type: PropagationType::Broadcast,
                            destination_type: DestinationType::Link,
                            packet_type: PacketType::Data,
                            hops: 0,
                        };
                        if let Ok(packet) = Packet::new(
                            header,
                            None,
                            Addresses::Single(link_id),
                            Context::Response,
                            ciphertext,
                        ) {
                            for iface in &mut self.interfaces {
                                iface.send(packet.clone(), 0, &mut self.rng, now);
                            }
                        }
                    }
                }
            }
        }
    }

    fn make_announce_packet(&self, dest: Address, hops: u8, data: Vec<u8>) -> Packet {
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        };
        Packet::new(header, None, Addresses::Single(dest), Context::None, data).unwrap()
    }

    // "The link request is addressed to the destination hash of the desired destination"
    fn make_link_request_packet(
        &self,
        dest: Address,
        transport_id: Option<Address>,
        data: Vec<u8>,
    ) -> Packet {
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let (header_type, propagation_type, addresses) = match transport_id {
            Some(tid) => (
                HeaderType::Type2,
                PropagationType::Transport,
                Addresses::Double(tid, dest),
            ),
            None => (
                HeaderType::Type1,
                PropagationType::Broadcast,
                Addresses::Single(dest),
            ),
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type,
            context_flag: ContextFlag::Unset,
            propagation_type,
            destination_type: DestinationType::Link,
            packet_type: PacketType::LinkRequest,
            hops: 0,
        };
        Packet::new(header, None, addresses, Context::None, data).unwrap()
    }

    // "This packet is addressed to the link id of the link."
    fn make_link_proof_packet(&self, link_id: LinkId, data: Vec<u8>) -> Packet {
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
            hops: 0,
        };
        Packet::new(
            header,
            None,
            Addresses::Single(link_id),
            Context::None,
            data,
        )
        .unwrap()
    }

    fn process_announce_inner(
        &mut self,
        destination: Address,
        hops: u8,
        app_data: Vec<u8>,
        source: usize,
        encryption_key: X25519Public,
        signing_key: VerifyingKey,
        ratchet_key: Option<X25519Public>,
        next_hop: Option<Address>,
    ) -> bool {
        let dest_hex = hex::encode(destination);

        if let Some(entry) = self.seen_announces.get_mut(&destination) {
            // "If a newer announce from the same destination arrives, while an identical one
            // is already waiting to be transmitted, the newest announce is discarded. If the
            // newest announce contains different application specific data, it will replace
            // the old announce."
            if entry.retry_at.is_some() && entry.app_data == app_data {
                log::debug!(
                    "Ignored announce for <{}>, already queued for rebroadcast",
                    dest_hex
                );
                return false;
            }
            if entry.app_data != app_data {
                log::debug!(
                    "Updating announce for <{}> with new app_data ({} -> {} bytes), hop count {}",
                    dest_hex,
                    entry.app_data.len(),
                    app_data.len(),
                    hops
                );
                entry.app_data = app_data;
                entry.hops = hops;
                entry.source_interface = source;
                entry.retries_remaining = self.retries;
                entry.retry_at = None;
                entry.encryption_key = encryption_key;
                entry.signing_key = signing_key;
                entry.ratchet_key = ratchet_key;
                entry.next_hop = next_hop;
                return hops < self.max_hops;
            }
            // "If this exact announce has already been received before, ignore it."
            log::debug!("Ignored duplicate announce for <{}>", dest_hex);
            return false;
        }

        // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
        // By default, m is set to 128."
        if hops > self.max_hops {
            log::debug!(
                "Ignored announce for <{}>, hop count {} exceeds max {}",
                dest_hex,
                hops,
                self.max_hops
            );
            return false;
        }

        log::debug!(
            "Recording announce for <{}> with hop count {}",
            dest_hex,
            hops
        );

        // "If not, record into a table which Transport Node the announce was received from,
        // and how many times in total it has been retransmitted to get here."
        self.seen_announces.insert(
            destination,
            AnnounceEntry {
                source_interface: source,
                hops,
                app_data,
                retries_remaining: self.retries,
                retry_at: None,
                encryption_key,
                signing_key,
                ratchet_key,
                next_hop,
            },
        );

        hops < self.max_hops
    }
}

impl<T: Transport> Default for Node<T, ThreadRng> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::sync::{Arc, Mutex};

    struct MockTransport {
        bandwidth: bool,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        inbox: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockTransport {
        fn new(bandwidth: bool) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let inbox = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    bandwidth,
                    sent: sent.clone(),
                    inbox: inbox.clone(),
                },
                sent,
                inbox,
            )
        }
    }

    impl Transport for MockTransport {
        fn send(&mut self, data: &[u8]) {
            self.sent.lock().unwrap().push(data.to_vec());
        }

        fn recv(&mut self) -> Option<Vec<u8>> {
            let mut inbox = self.inbox.lock().unwrap();
            if inbox.is_empty() {
                None
            } else {
                Some(inbox.remove(0))
            }
        }

        fn bandwidth_available(&self) -> bool {
            self.bandwidth
        }
    }

    struct MockWire {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        inbox: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockWire {
        fn inject(&self, packet: &Packet) {
            self.inbox.lock().unwrap().push(packet.to_bytes());
        }

        fn take_sent(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut self.sent.lock().unwrap())
        }
    }

    fn make_interface(bandwidth: bool) -> (Interface<MockTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (transport, sent, _inbox) = MockTransport::new(bandwidth);
        let mut iface = Interface::new(transport, 0);
        iface.min_delay_ms = 0;
        iface.max_delay_ms = 0;
        (iface, sent)
    }

    fn make_mock_interface(bandwidth: bool) -> (Interface<MockTransport>, MockWire) {
        let (transport, sent, inbox) = MockTransport::new(bandwidth);
        let mut iface = Interface::new(transport, 0);
        iface.min_delay_ms = 0;
        iface.max_delay_ms = 0;
        (iface, MockWire { sent, inbox })
    }

    fn make_announce_packet(seed: Address, hops: u8, app_data: Vec<u8>) -> (Packet, Address) {
        use crate::announce::AnnounceBuilder;
        use crate::crypto::sha256;
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

        let key_seed = sha256(&seed);
        let enc_secret = StaticSecret::from(key_seed);
        let enc_public = X25519Public::from(&enc_secret);
        let signing_key = SigningKey::from_bytes(&sha256(&key_seed));

        let name_hash: [u8; 10] = sha256(&seed)[..10].try_into().unwrap();
        let random_hash: [u8; 10] = [0; 10];

        let mut public_keys = [0u8; 64];
        public_keys[..32].copy_from_slice(enc_public.as_bytes());
        public_keys[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let identity_hash: [u8; 16] = sha256(&public_keys)[..16].try_into().unwrap();

        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(&name_hash);
        hash_material.extend_from_slice(&identity_hash);
        let dest: Address = sha256(&hash_material)[..16].try_into().unwrap();

        let announce =
            AnnounceBuilder::new(*enc_public.as_bytes(), signing_key, name_hash, random_hash)
                .with_app_data(app_data)
                .build(&dest);

        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single(dest),
            Context::None,
            announce.to_bytes(),
        )
        .unwrap();
        (packet, dest)
    }

    // "If this exact announce has already been received before, ignore it."
    #[test]
    fn if_this_exact_announce_has_already_been_received_before_ignore_it() {
        let mut node: Node<MockTransport> = Node::new();
        let (iface, tx) = make_interface(true);
        let src = node.add_interface(iface);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([1u8; 16], 1, vec![0xAB]);
        node.inbound(&packet, src, now);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx.lock().unwrap().len(), 0);
    }

    // "If not, record into a table which Transport Node the announce was received from,
    // and how many times in total it has been retransmitted to get here."
    #[test]
    fn record_into_a_table_which_transport_node_the_announce_was_received_from() {
        let mut node: Node<MockTransport> = Node::new();
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([2u8; 16], 5, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
    // By default, m is set to 128."
    #[test]
    fn if_the_announce_has_been_retransmitted_m_plus_1_times_it_will_not_be_forwarded() {
        let mut node: Node<MockTransport> = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([3u8; 16], 129, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 0);
    }

    // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
    // By default, m is set to 128."
    #[test]
    fn announce_at_exactly_m_hops_is_accepted_but_not_forwarded() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([4u8; 16], 128, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 0);
    }

    // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
    // By default, m is set to 128."
    #[test]
    fn announce_below_m_hops_is_forwarded() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([6u8; 16], 126, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "If a newer announce from the same destination arrives, while an identical one is
    // already waiting to be transmitted, the newest announce is discarded."
    #[test]
    fn if_a_newer_announce_from_the_same_destination_arrives_while_an_identical_one_is_already_waiting_the_newest_is_discarded()
     {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        let src1 = node.add_interface(iface1);

        let now = Instant::now();
        let seed = [11u8; 16];
        let (packet1, _) = make_announce_packet(seed, 1, vec![0x01]);
        let (packet2, _) = make_announce_packet(seed, 2, vec![0x01]);
        node.inbound(&packet1, src0, now);
        node.inbound(&packet2, src1, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "If the newest announce contains different application specific data, it will
    // replace the old announce."
    #[test]
    fn if_the_newest_announce_contains_different_application_specific_data_it_will_replace_the_old_announce()
     {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        let src1 = node.add_interface(iface1);

        let now = Instant::now();
        let seed = [7u8; 16];
        let (packet1, _) = make_announce_packet(seed, 1, vec![0x01]);
        let (packet2, _) = make_announce_packet(seed, 2, vec![0x02]);
        node.inbound(&packet1, src0, now);
        node.inbound(&packet2, src1, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 1);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "After a randomised delay, the announce will be retransmitted on all interfaces
    // that have bandwidth available for processing announces."
    #[test]
    fn the_announce_will_be_retransmitted_on_all_interfaces_that_have_bandwidth_available() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let (iface2, tx2) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);
        node.add_interface(iface2);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([8u8; 16], 1, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 1);
        assert_eq!(tx2.lock().unwrap().len(), 1);
    }

    // "If any given interface does not have enough bandwidth available for retransmitting
    // the announce, the announce will be assigned a priority inversely proportional to its
    // hop count, and be inserted into a queue managed by the interface."
    #[test]
    fn if_any_given_interface_does_not_have_enough_bandwidth_the_announce_will_be_inserted_into_a_queue()
     {
        let mut node = Node::new();
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(false);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([9u8; 16], 1, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 0);
    }

    // "After the announce has been re-transmitted, and if no other nodes are heard
    // retransmitting the announce with a greater hop count than when it left this node,
    // transmitting it will be retried r times. By default, r is set to 1."
    #[test]
    fn if_no_other_nodes_are_heard_retransmitting_with_greater_hop_count_it_will_be_retried() {
        let mut node = Node::new();
        node.retry_delay_ms = 10;
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let (packet, _) = make_announce_packet([13u8; 16], 1, vec![]);
        node.inbound(&packet, src0, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 1);

        node.poll(now + Duration::from_millis(50));
        assert_eq!(tx1.lock().unwrap().len(), 2);

        node.poll(now + Duration::from_millis(100));
        assert_eq!(tx1.lock().unwrap().len(), 2);
    }

    // "After the announce has been re-transmitted, and if no other nodes are heard
    // retransmitting the announce with a greater hop count than when it left this node,
    // transmitting it will be retried r times. By default, r is set to 1."
    #[test]
    fn retry_cancelled_when_higher_hop_announce_heard() {
        let mut node = Node::new();
        node.retry_delay_ms = 10;
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        let src1 = node.add_interface(iface1);

        let now = Instant::now();
        let seed = [14u8; 16];
        let (packet1, _) = make_announce_packet(seed, 1, vec![]);
        let (packet2, _) = make_announce_packet(seed, 2, vec![]);
        node.inbound(&packet1, src0, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 1);

        node.inbound(&packet2, src1, now);

        node.poll(now + Duration::from_millis(50));
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // --- routing.md tests ---
    // Two nodes connected via mock transports, announcing services to each other

    struct TestService {
        name: String,
        received: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl TestService {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                received: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn received(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
            Arc::clone(&self.received)
        }
    }

    impl Service for TestService {
        fn name(&self) -> &str {
            &self.name
        }
        fn inbound(&mut self, msg: InboundMessage) {
            match msg {
                InboundMessage::LinkData { data, .. } | InboundMessage::SingleData { data, .. } => {
                    self.received.lock().unwrap().push(data);
                }
                _ => {}
            }
        }
        fn outbound(&mut self) -> Option<OutboundMessage> {
            None
        }
    }

    // "When the packet is sent to a single destination type, Reticulum will automatically
    // create an ephemeral encryption key, perform an ECDH key exchange with the destination's
    // public key (or ratchet key, if available), and encrypt the information."
    //
    // "The sender already knows the public key of the destination from an earlier received
    // announce, and can thus perform the ECDH key exchange locally, before sending the packet."
    #[test]
    fn node_announces_service_and_other_node_receives_keys() {
        let mut receiver: Node<MockTransport> = Node::new();
        let (recv_iface, recv_wire) = make_mock_interface(true);
        receiver.add_interface(recv_iface);

        let chat_addr = receiver.add_service(TestService::new("myapp.chat"));

        let now = Instant::now();
        receiver.announce(chat_addr, now);
        receiver.poll(now);

        // Announce was sent on wire
        let sent = recv_wire.take_sent();
        assert_eq!(sent.len(), 1);

        // Other node receives the announce via poll (injected into its interface)
        let mut sender: Node<MockTransport> = Node::new();
        let (sender_iface, sender_wire) = make_mock_interface(true);
        let announce_packet = Packet::from_bytes(&sent[0], 0).unwrap();
        sender_wire.inject(&announce_packet);
        sender.add_interface(sender_iface);

        sender.poll(now);

        // Sender now has keys for the announced service
        let entry = sender.seen_announces.get(&chat_addr).unwrap();
        assert_eq!(entry.encryption_key.as_bytes().len(), 32);
    }

    // "Once the packet has been received and decrypted by the addressed destination, that
    // destination can opt to prove its receipt of the packet. It does this by calculating
    // the SHA-256 hash of the received packet, and signing this hash with its Ed25519
    // signing key."
    //
    // "Transport nodes in the network can then direct this proof back to the packets origin,
    // where the signature can be verified against the destination's known public signing key."
    #[test]
    fn proof_of_receipt_flow() {
        use crate::crypto::{create_proof, verify_proof};
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let rng = StdRng::seed_from_u64(99);
        let mut receiver: Node<MockTransport, StdRng> = Node::with_rng(rng);
        let (recv_iface, recv_tx) = make_interface(true);
        receiver.add_interface(recv_iface);

        let service_addr = receiver.add_service(TestService::new("proof.test"));
        let receiver_signing_key = receiver
            .services
            .iter()
            .find(|s| s.address == service_addr)
            .unwrap()
            .signing_key
            .clone();

        let now = Instant::now();
        receiver.announce(service_addr, now);
        receiver.poll(now);

        // Sender receives announce
        let mut sender: Node<MockTransport> = Node::new();
        let (sender_iface, _) = make_interface(true);
        let src = sender.add_interface(sender_iface);

        let announce_packet = Packet::from_bytes(&recv_tx.lock().unwrap()[0], 0).unwrap();
        sender.inbound(&announce_packet, src, now);

        // Receiver creates proof for some packet data
        let packet_data = b"packet payload";
        let proof = create_proof(&receiver_signing_key, packet_data);

        // Sender verifies using stored signing key
        let entry = sender.seen_announces.get(&service_addr).unwrap();
        assert!(verify_proof(&entry.signing_key, packet_data, &proof));
        assert!(!verify_proof(&entry.signing_key, b"tampered", &proof));
    }

    // "In case the packet is addressed to a group destination type, the packet will be
    // encrypted with the pre-shared AES-256 key associated with the destination."
    #[test]
    fn group_destination_encrypt_decrypt_flow() {
        use crate::crypto::{GroupDestEncryption, sha256};
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(99);

        // Pre-shared key known by group members
        let psk: [u8; 32] = std::array::from_fn(|i| (i * 13) as u8);
        let wrong_psk: [u8; 32] = std::array::from_fn(|i| (i * 17) as u8);

        // Create two group member nodes and one non-member
        let mut _member1: Node<MockTransport> = Node::new();
        let mut _member2: Node<MockTransport> = Node::new();
        let mut _non_member: Node<MockTransport> = Node::new();

        let (iface1, _tx1) = make_interface(true);
        let (iface2, _tx2) = make_interface(true);
        let (iface3, _tx3) = make_interface(true);
        _member1.add_interface(iface1);
        _member2.add_interface(iface2);
        _non_member.add_interface(iface3);

        // Group destination address (derived from PSK in real impl)
        let group_dest: Address = sha256(&psk)[..16].try_into().unwrap();

        // Sender encrypts message with PSK
        let plaintext = b"message for the group";
        let ciphertext = GroupDestEncryption::encrypt(&mut rng, &psk, plaintext);

        // Create group packet
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Group,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single(group_dest),
            Context::None,
            ciphertext,
        )
        .unwrap();

        // Members can decrypt with PSK
        let decrypted1 = GroupDestEncryption::decrypt(&psk, &packet.data).unwrap();
        assert_eq!(decrypted1, plaintext);

        let decrypted2 = GroupDestEncryption::decrypt(&psk, &packet.data).unwrap();
        assert_eq!(decrypted2, plaintext);

        // Non-member cannot decrypt
        let bad_decrypt = GroupDestEncryption::decrypt(&wrong_psk, &packet.data);
        assert!(
            bad_decrypt.is_none() || bad_decrypt.as_ref().unwrap() != plaintext,
            "Non-member should not be able to decrypt"
        );
    }

    // "In case the packet is addressed to a plain destination type, the payload data will
    // not be encrypted."
    #[test]
    fn plain_destination_no_encryption_flow() {
        // Setup two nodes connected via mock transport
        let mut sender: Node<MockTransport> = Node::new();
        let mut receiver: Node<MockTransport> = Node::new();

        let (sender_iface, _sender_tx) = make_interface(true);
        let (receiver_iface, _) = make_interface(true);
        sender.add_interface(sender_iface);
        let recv_src = receiver.add_interface(receiver_iface);

        // Create plain destination packet
        let dest: Address = [0xAB; 16];
        let plaintext = b"unencrypted payload";
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Plain,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single(dest),
            Context::None,
            plaintext.to_vec(),
        )
        .unwrap();

        // Verify plaintext appears directly in wire data (no encryption)
        let wire_data = packet.to_bytes();
        let plaintext_in_wire = wire_data.windows(plaintext.len()).any(|w| w == plaintext);
        assert!(
            plaintext_in_wire,
            "Plain destination packet should contain unencrypted payload on wire"
        );

        // Receiver gets packet, payload is plaintext
        let now = Instant::now();
        receiver.inbound(&packet, recv_src, now);

        // The packet data is the plaintext directly
        assert_eq!(
            packet.data, plaintext,
            "Plain destination packet data should be plaintext"
        );
    }

    // "When the packet is sent to a single destination type, Reticulum will automatically
    // create an ephemeral encryption key, perform an ECDH key exchange with the destination's
    // public key, and encrypt the information."
    //
    // "When the destination receives the packet, it can itself perform an ECDH key exchange
    // and decrypt the packet."
    #[test]
    fn single_destination_data_delivered_to_service() {
        use crate::crypto::SingleDestEncryption;

        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);

        let test_service = TestService::new("delivery.test");
        let received = test_service.received();
        let service_addr = server.add_service(test_service);

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Server announces service
        server.announce(service_addr, now);
        server.poll(now);

        // Client receives announce
        let announce_bytes = server_wire.take_sent().remove(0);
        let announce = Packet::from_bytes(&announce_bytes, 0).unwrap();
        client_wire.inject(&announce);
        client.poll(now);

        // Client gets the encryption key from announce
        let announce_entry = client.seen_announces.get(&service_addr).unwrap();
        let dest_public = announce_entry.encryption_key;

        // Client encrypts and sends data
        let plaintext = b"hello service!";
        let (ephemeral_public, ciphertext) =
            SingleDestEncryption::encrypt(&mut rand::thread_rng(), &dest_public, plaintext);

        // Build the data packet with ephemeral key prepended
        let mut data = Vec::new();
        data.extend_from_slice(ephemeral_public.as_bytes());
        data.extend_from_slice(&ciphertext);

        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single(service_addr),
            Context::None,
            data,
        )
        .unwrap();

        // Server receives packet
        server_wire.inject(&packet);
        server.poll(now);

        // Service should have received the decrypted plaintext
        let received_data = received.lock().unwrap();
        assert_eq!(received_data.len(), 1, "Service should receive one message");
        assert_eq!(
            received_data[0], plaintext,
            "Service should receive decrypted plaintext"
        );
    }

    // --- Link Establishment Tests ---
    // Two nodes establish a link after announce exchange

    // "When a node in the network wants to establish verified connectivity with another node,
    // it will randomly generate a new X25519 private/public key pair. It then creates a
    // link request packet, and broadcast it."
    #[test]
    fn link_request_requires_prior_announce() {
        let mut initiator: Node<MockTransport> = Node::new();
        let (iface, _wire) = make_mock_interface(true);
        initiator.add_interface(iface);

        let now = Instant::now();
        // Try to link to unknown destination
        let unknown_dest: Address = [0xDE; 16];
        let result = initiator.link(unknown_dest, now);

        assert!(result.is_none(), "Link to unknown destination should fail");
    }

    // "First, the node that wishes to establish a link will send out a link request packet"
    #[test]
    fn link_sends_link_request_packet() {
        let mut responder: Node<MockTransport> = Node::new();
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);

        let service_addr = responder.add_service(TestService::new("link.test"));
        let now = Instant::now();
        responder.announce(service_addr, now);
        responder.poll(now);

        // Initiator receives the announce
        let mut initiator: Node<MockTransport> = Node::new();
        let (init_iface, init_wire) = make_mock_interface(true);
        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();
        init_wire.inject(&announce_packet);
        initiator.add_interface(init_iface);
        initiator.poll(now);

        // Initiator sends link request
        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        // Verify link request was sent
        let sent = init_wire.take_sent();
        assert_eq!(sent.len(), 1);

        let link_request = Packet::from_bytes(&sent[0], 0).unwrap();
        assert_eq!(link_request.header.packet_type, PacketType::LinkRequest);
        assert_eq!(link_request.header.destination_type, DestinationType::Link);

        // Verify pending link was stored
        assert!(initiator.pending_outbound_links.contains_key(&link_id));
    }

    // When an announce arrives via a transport node (Type2 packet), the client must send
    // link requests as Type2 packets addressed to that transport node. Otherwise, the
    // transport node won't know how to forward the packet.
    #[test]
    fn link_request_uses_type2_when_announce_came_via_transport() {
        // Server behind a transport node
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("remote.service"));

        // Transport node in the middle
        let mut transport: Node<MockTransport> = Node::new();
        let (transport_server_iface, transport_server_wire) = make_mock_interface(true);
        let (transport_client_iface, transport_client_wire) = make_mock_interface(true);
        transport.add_interface(transport_server_iface);
        transport.add_interface(transport_client_iface);

        // Client
        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Server announces (Type1 broadcast)
        server.announce(service_addr, now);
        server.poll(now);
        let announce_bytes = server_wire.take_sent().remove(0);
        let announce = Packet::from_bytes(&announce_bytes, 0).unwrap();
        assert_eq!(announce.header.header_type, HeaderType::Type1);

        // Transport receives and forwards (becomes Type2 with transport_id)
        transport_server_wire.inject(&announce);
        transport.poll(now);
        let forwarded = transport_client_wire.take_sent();
        assert_eq!(forwarded.len(), 1);
        let forwarded_announce = Packet::from_bytes(&forwarded[0], 0).unwrap();
        assert_eq!(forwarded_announce.header.header_type, HeaderType::Type2);

        // Extract transport_id from forwarded announce
        let transport_id = match forwarded_announce.addresses {
            Addresses::Double(tid, _) => tid,
            _ => panic!("Expected Type2 addresses"),
        };

        // Client receives announce via transport
        client_wire.inject(&forwarded_announce);
        client.poll(now);

        // Client should have stored the next_hop
        let entry = client.seen_announces.get(&service_addr).unwrap();
        assert_eq!(entry.next_hop, Some(transport_id));

        // Client sends link request - should be Type2 with transport_id
        let _link_id = client.link(service_addr, now).unwrap();
        client.poll(now);

        let sent = client_wire.take_sent();
        assert_eq!(sent.len(), 1);
        let link_request = Packet::from_bytes(&sent[0], 0).unwrap();

        assert_eq!(
            link_request.header.header_type,
            HeaderType::Type2,
            "Link request should be Type2 when destination is behind transport"
        );
        assert_eq!(
            link_request.header.propagation_type,
            PropagationType::Transport,
            "Link request should use transport propagation"
        );

        // Verify addresses: transport_id first, destination second
        match link_request.addresses {
            Addresses::Double(tid, dest) => {
                assert_eq!(tid, transport_id, "First address should be transport_id");
                assert_eq!(dest, service_addr, "Second address should be destination");
            }
            _ => panic!("Expected Type2 addresses in link request"),
        }
    }

    // Direct link requests (no transport node) should remain Type1 broadcast
    #[test]
    fn link_request_uses_type1_for_direct_connection() {
        let mut responder: Node<MockTransport> = Node::new();
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);

        let service_addr = responder.add_service(TestService::new("direct.service"));
        let now = Instant::now();
        responder.announce(service_addr, now);
        responder.poll(now);

        let mut initiator: Node<MockTransport> = Node::new();
        let (init_iface, init_wire) = make_mock_interface(true);
        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();

        // Direct announce is Type1 (no transport_id)
        assert_eq!(announce_packet.header.header_type, HeaderType::Type1);

        init_wire.inject(&announce_packet);
        initiator.add_interface(init_iface);
        initiator.poll(now);

        // Verify no next_hop stored
        let entry = initiator.seen_announces.get(&service_addr).unwrap();
        assert_eq!(entry.next_hop, None);

        // Send link request
        let _link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        let sent = init_wire.take_sent();
        assert_eq!(sent.len(), 1);
        let link_request = Packet::from_bytes(&sent[0], 0).unwrap();

        assert_eq!(
            link_request.header.header_type,
            HeaderType::Type1,
            "Direct link request should be Type1"
        );
        assert_eq!(
            link_request.header.propagation_type,
            PropagationType::Broadcast,
            "Direct link request should use broadcast propagation"
        );
        assert!(
            matches!(link_request.addresses, Addresses::Single(_)),
            "Direct link request should have single address"
        );
    }

    // Topology: Client -> Transport -> Server
    // When client is 1 hop away from transport (stored hops=2), client sends Type2 to transport.
    // Transport then strips headers when forwarding to directly-connected server.
    #[test]
    fn link_request_through_single_transport() {
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("nearby.service"));

        let mut transport: Node<MockTransport> = Node::new();
        let (transport_server_iface, transport_server_wire) = make_mock_interface(true);
        let (transport_client_iface, transport_client_wire) = make_mock_interface(true);
        transport.add_interface(transport_server_iface);
        transport.add_interface(transport_client_iface);

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        server.announce(service_addr, now);
        server.poll(now);
        let server_announce = Packet::from_bytes(&server_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(server_announce.header.hops, 0);

        transport_server_wire.inject(&server_announce);
        transport.poll(now);
        let transport_announce =
            Packet::from_bytes(&transport_client_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(transport_announce.header.hops, 1);
        assert_eq!(transport_announce.header.header_type, HeaderType::Type2);
        let transport_id = match transport_announce.addresses {
            Addresses::Double(tid, _) => tid,
            _ => panic!("Expected Type2"),
        };

        client_wire.inject(&transport_announce);
        client.poll(now);

        let entry = client.seen_announces.get(&service_addr).unwrap();
        assert_eq!(entry.hops, 2);

        let _link_id = client.link(service_addr, now).unwrap();
        client.poll(now);

        let link_request = Packet::from_bytes(&client_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(link_request.header.header_type, HeaderType::Type2);
        match link_request.addresses {
            Addresses::Double(tid, dest) => {
                assert_eq!(tid, transport_id);
                assert_eq!(dest, service_addr);
            }
            _ => panic!("Expected Type2"),
        }

        transport_client_wire.inject(&link_request);
        transport.poll(now);

        let forwarded = transport_server_wire.take_sent();
        assert_eq!(forwarded.len(), 1);
        let forwarded_request = Packet::from_bytes(&forwarded[0], 0).unwrap();
        assert_eq!(forwarded_request.header.header_type, HeaderType::Type1);
        assert!(
            matches!(forwarded_request.addresses, Addresses::Single(addr) if addr == service_addr)
        );
    }

    // Behavior 2 (hops > 1): When destination is more than 1 hop away, client sends Type2
    // with the next transport's ID so intermediate nodes know how to route.
    //
    // Topology: Client -> Transport1 -> Transport2 -> Server
    // Server announces (hops=0) -> T2 re-announces (hops=1) -> T1 re-announces (hops=2) -> Client
    // Client should send Type2 with T1's transport_id
    #[test]
    fn link_request_uses_type2_when_destination_is_multiple_hops_away() {
        // Server
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("far.service"));

        // Transport2 (closer to server)
        let mut transport2: Node<MockTransport> = Node::new();
        let (t2_server_iface, t2_server_wire) = make_mock_interface(true);
        let (t2_t1_iface, t2_t1_wire) = make_mock_interface(true);
        transport2.add_interface(t2_server_iface);
        transport2.add_interface(t2_t1_iface);

        // Transport1 (closer to client)
        let mut transport1: Node<MockTransport> = Node::new();
        let (t1_t2_iface, t1_t2_wire) = make_mock_interface(true);
        let (t1_client_iface, t1_client_wire) = make_mock_interface(true);
        transport1.add_interface(t1_t2_iface);
        transport1.add_interface(t1_client_iface);

        // Client
        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Server announces (Type1, hops=0)
        server.announce(service_addr, now);
        server.poll(now);
        let announce = Packet::from_bytes(&server_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(announce.header.hops, 0);

        // Transport2 receives and forwards (Type2, hops=1)
        t2_server_wire.inject(&announce);
        transport2.poll(now);
        let announce = Packet::from_bytes(&t2_t1_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(announce.header.hops, 1);
        assert_eq!(announce.header.header_type, HeaderType::Type2);

        // Transport1 receives and forwards (Type2, hops=2)
        t1_t2_wire.inject(&announce);
        transport1.poll(now);
        let announce = Packet::from_bytes(&t1_client_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(announce.header.hops, 2);
        assert_eq!(announce.header.header_type, HeaderType::Type2);
        let transport1_id = match announce.addresses {
            Addresses::Double(tid, _) => tid,
            _ => panic!("Expected Type2 addresses"),
        };

        // Client receives announce with hops=2
        client_wire.inject(&announce);
        client.poll(now);

        let entry = client.seen_announces.get(&service_addr).unwrap();
        assert_eq!(entry.hops, 3);

        // Client sends link request - should be Type2 with transport1's ID
        let _link_id = client.link(service_addr, now).unwrap();
        client.poll(now);

        let link_request = Packet::from_bytes(&client_wire.take_sent().remove(0), 0).unwrap();
        assert_eq!(
            link_request.header.header_type,
            HeaderType::Type2,
            "Link request should be Type2 when destination is >1 hop away"
        );
        match link_request.addresses {
            Addresses::Double(tid, dest) => {
                assert_eq!(tid, transport1_id, "Transport ID should be transport1's ID");
                assert_eq!(dest, service_addr, "Destination should be service address");
            }
            _ => panic!("Expected Type2 addresses"),
        }
    }

    // Behavior 3: When a transport node forwards a Type2 packet and the destination
    // is only 1 hop away (remaining_hops == 1), it strips the transport headers
    // and converts to Type1 before sending to the final destination.
    #[test]
    fn transport_strips_type2_headers_when_one_hop_remaining() {
        // Server
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("strip.test"));

        // Transport (in the middle)
        let mut transport: Node<MockTransport> = Node::new();
        let (t_server_iface, t_server_wire) = make_mock_interface(true);
        let (t_client_iface, t_client_wire) = make_mock_interface(true);
        transport.add_interface(t_server_iface); // interface 0 -> server
        transport.add_interface(t_client_iface); // interface 1 -> client

        // Client
        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Set up path: Server announces through transport to client
        server.announce(service_addr, now);
        server.poll(now);
        let announce = Packet::from_bytes(&server_wire.take_sent().remove(0), 0).unwrap();

        t_server_wire.inject(&announce);
        transport.poll(now);
        let forwarded_announce =
            Packet::from_bytes(&t_client_wire.take_sent().remove(0), 0).unwrap();

        client_wire.inject(&forwarded_announce);
        client.poll(now);

        // Client creates a Type2 link request (simulating >1 hop scenario)
        // We manually craft this to test transport's stripping behavior
        let transport_id = transport.transport_id;
        let link_request_data = vec![0u8; 64]; // dummy link request data

        let type2_link_request = Packet::new(
            Header {
                ifac_flag: crate::IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: crate::ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::LinkRequest,
                hops: 0,
            },
            None,
            Addresses::Double(transport_id, service_addr),
            crate::Context::None,
            link_request_data,
        )
        .unwrap();

        // Transport receives Type2 link request addressed to it
        t_client_wire.inject(&type2_link_request);
        transport.poll(now);

        // Transport should forward to server, stripped to Type1
        let forwarded = t_server_wire.take_sent();
        assert_eq!(
            forwarded.len(),
            1,
            "Transport should forward the link request"
        );

        let forwarded_packet = Packet::from_bytes(&forwarded[0], 0).unwrap();
        assert_eq!(
            forwarded_packet.header.header_type,
            HeaderType::Type1,
            "Transport should strip Type2 headers when forwarding to final destination"
        );
        assert_eq!(
            forwarded_packet.header.propagation_type,
            PropagationType::Broadcast,
            "Should be broadcast propagation after stripping"
        );
        assert!(
            matches!(forwarded_packet.addresses, Addresses::Single(addr) if addr == service_addr),
            "Should have single address after stripping"
        );
    }

    // Behavior 4: When a transport node forwards a Type2 packet and remaining_hops > 1,
    // it keeps Type2 but replaces the transport_id with the next hop's transport_id.
    #[test]
    fn transport_replaces_transport_id_when_multiple_hops_remaining() {
        // Server
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("multihop.test"));

        // Transport2 (closer to server)
        let mut transport2: Node<MockTransport> = Node::new();
        let (t2_server_iface, t2_server_wire) = make_mock_interface(true);
        let (t2_t1_iface, t2_t1_wire) = make_mock_interface(true);
        transport2.add_interface(t2_server_iface); // interface 0 -> server
        transport2.add_interface(t2_t1_iface); // interface 1 -> transport1

        // Transport1 (closer to client)
        let mut transport1: Node<MockTransport> = Node::new();
        let (t1_t2_iface, t1_t2_wire) = make_mock_interface(true);
        let (t1_client_iface, t1_client_wire) = make_mock_interface(true);
        transport1.add_interface(t1_t2_iface); // interface 0 -> transport2
        transport1.add_interface(t1_client_iface); // interface 1 -> client

        let now = Instant::now();

        // Set up path through announces
        server.announce(service_addr, now);
        server.poll(now);
        let announce = Packet::from_bytes(&server_wire.take_sent().remove(0), 0).unwrap();

        t2_server_wire.inject(&announce);
        transport2.poll(now);
        let announce = Packet::from_bytes(&t2_t1_wire.take_sent().remove(0), 0).unwrap();

        t1_t2_wire.inject(&announce);
        transport1.poll(now);
        let _ = t1_client_wire.take_sent(); // clear

        // Now send a Type2 link request from client side, addressed to transport1
        let link_request_data = vec![0u8; 64];
        let type2_request = Packet::new(
            Header {
                ifac_flag: crate::IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: crate::ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::LinkRequest,
                hops: 0,
            },
            None,
            Addresses::Double(transport1.transport_id, service_addr),
            crate::Context::None,
            link_request_data,
        )
        .unwrap();

        // Transport1 receives it
        t1_client_wire.inject(&type2_request);
        transport1.poll(now);

        // Transport1 should forward to transport2, with transport2's ID
        let forwarded = t1_t2_wire.take_sent();
        assert_eq!(forwarded.len(), 1, "Transport1 should forward the request");

        let forwarded_packet = Packet::from_bytes(&forwarded[0], 0).unwrap();
        assert_eq!(
            forwarded_packet.header.header_type,
            HeaderType::Type2,
            "Should remain Type2 when >1 hops remaining"
        );
        match forwarded_packet.addresses {
            Addresses::Double(tid, dest) => {
                assert_eq!(
                    tid, transport2.transport_id,
                    "Transport ID should be updated to transport2's ID"
                );
                assert_eq!(dest, service_addr, "Destination should remain the same");
            }
            _ => panic!("Expected Type2 addresses"),
        }
    }

    // Behavior 5: Transport nodes ignore Type2 packets (non-announce) where
    // the transport_id doesn't match their own identity.
    #[test]
    fn transport_ignores_type2_packets_for_other_transport() {
        let mut transport: Node<MockTransport> = Node::new();
        let (iface, wire) = make_mock_interface(true);
        transport.add_interface(iface);
        let service_addr = transport.add_service(TestService::new("filter.test"));

        let now = Instant::now();

        // Create a Type2 packet with a different transport_id
        let other_transport_id: Address = [0xAB; 16];
        assert_ne!(other_transport_id, transport.transport_id);

        let packet = Packet::new(
            Header {
                ifac_flag: crate::IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: crate::ContextFlag::Unset,
                propagation_type: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::LinkRequest,
                hops: 0,
            },
            None,
            Addresses::Double(other_transport_id, service_addr),
            crate::Context::None,
            vec![0u8; 64],
        )
        .unwrap();

        // Inject the packet
        wire.inject(&packet);
        transport.poll(now);

        // Transport should NOT forward or process this packet
        let sent = wire.take_sent();
        assert!(
            sent.is_empty(),
            "Transport should ignore Type2 packets for other transport instances"
        );

        // Link table should be empty (packet wasn't processed)
        assert!(
            transport.link_table.is_empty(),
            "No link table entry should be created"
        );
    }

    // "When the destination receives the link request packet, it will decide whether to
    // accept the request. If it is accepted, the destination will also generate a new
    // X25519 private/public key pair"
    //
    // "A link proof packet is now constructed and transmitted over the network."
    #[test]
    fn responder_sends_link_proof() {
        let mut responder: Node<MockTransport> = Node::new();
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);

        let service_addr = responder.add_service(TestService::new("link.test"));
        let now = Instant::now();
        responder.announce(service_addr, now);
        responder.poll(now);

        // Initiator receives announce
        let mut initiator: Node<MockTransport> = Node::new();
        let (init_iface, init_wire) = make_mock_interface(true);
        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();
        init_wire.inject(&announce_packet);
        initiator.add_interface(init_iface);
        initiator.poll(now);

        // Initiator sends link request
        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        // Responder receives link request
        let link_request_bytes = init_wire.take_sent().remove(0);
        let link_request = Packet::from_bytes(&link_request_bytes, 0).unwrap();
        resp_wire.inject(&link_request);
        responder.poll(now);

        // Verify responder established the link
        assert!(responder.established_links.contains_key(&link_id));

        // Verify link proof was sent
        let sent = resp_wire.take_sent();
        assert_eq!(sent.len(), 1);

        let proof_packet = Packet::from_bytes(&sent[0], 0).unwrap();
        assert_eq!(proof_packet.header.packet_type, PacketType::Proof);
        assert_eq!(proof_packet.header.destination_type, DestinationType::Link);
    }

    // "When the source receives the proof, it will know unequivocally that a verified path
    // has been established to the destination. It can now also use the X25519 public key
    // contained in the link proof to perform it's own Diffie Hellman Key Exchange and
    // derive the symmetric key that is used to encrypt the channel."
    #[test]
    fn full_link_establishment_between_two_nodes() {
        let mut responder: Node<MockTransport> = Node::new();
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);

        let service_addr = responder.add_service(TestService::new("link.test"));
        let now = Instant::now();
        responder.announce(service_addr, now);
        responder.poll(now);

        // Initiator receives announce
        let mut initiator: Node<MockTransport> = Node::new();
        let (init_iface, init_wire) = make_mock_interface(true);
        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();
        init_wire.inject(&announce_packet);
        initiator.add_interface(init_iface);
        initiator.poll(now);

        // Initiator sends link request
        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        // Responder receives link request and sends proof
        let link_request_bytes = init_wire.take_sent().remove(0);
        let link_request = Packet::from_bytes(&link_request_bytes, 0).unwrap();
        resp_wire.inject(&link_request);
        responder.poll(now);

        // Initiator receives proof
        let proof_bytes = resp_wire.take_sent().remove(0);
        let proof_packet = Packet::from_bytes(&proof_bytes, 0).unwrap();
        init_wire.inject(&proof_packet);
        initiator.poll(now);

        // Both nodes should have established links
        assert!(initiator.established_links.contains_key(&link_id));
        assert!(responder.established_links.contains_key(&link_id));

        // Both sides can encrypt/decrypt to each other
        let initiator_link = initiator.established_links.get(&link_id).unwrap();
        let responder_link = responder.established_links.get(&link_id).unwrap();
        let mut rng = StdRng::seed_from_u64(999);
        let plaintext = b"test message";
        let ciphertext = initiator_link.encrypt(&mut rng, plaintext);
        let decrypted = responder_link.decrypt(&ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);

        // Pending link should be removed from initiator
        assert!(!initiator.pending_outbound_links.contains_key(&link_id));
    }

    // "By verifying this link proof packet, all nodes that originally transported the
    // link request packet to the destination from the originator can now verify that
    // the intended destination received the request and accepted it"
    #[test]
    fn link_proof_verification_rejects_invalid_signature() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(42));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);

        let service_addr = responder.add_service(TestService::new("link.test"));
        let now = Instant::now();
        responder.announce(service_addr, now);
        responder.poll(now);

        // Initiator receives announce
        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(99));
        let (init_iface, init_wire) = make_mock_interface(true);
        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();
        init_wire.inject(&announce_packet);
        initiator.add_interface(init_iface);
        initiator.poll(now);

        // Initiator sends link request
        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        // Responder receives link request
        let link_request_bytes = init_wire.take_sent().remove(0);
        let link_request = Packet::from_bytes(&link_request_bytes, 0).unwrap();
        resp_wire.inject(&link_request);
        responder.poll(now);

        // Get the proof but tamper with it
        let proof_bytes = resp_wire.take_sent().remove(0);
        let mut tampered = proof_bytes.clone();
        // Flip a byte in the signature area
        if let Some(b) = tampered.get_mut(50) {
            *b ^= 0xFF;
        }

        let tampered_packet = Packet::from_bytes(&tampered, 0).unwrap();
        init_wire.inject(&tampered_packet);
        initiator.poll(now);

        // Initiator should NOT have established link (bad signature)
        assert!(!initiator.established_links.contains_key(&link_id));
        // Pending link should still be there
        assert!(initiator.pending_outbound_links.contains_key(&link_id));
    }

    // "The link initiator remains completely anonymous."
    #[test]
    fn link_request_does_not_reveal_initiator_identity() {
        let mut responder: Node<MockTransport> = Node::new();
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);

        let service_addr = responder.add_service(TestService::new("link.test"));
        let now = Instant::now();
        responder.announce(service_addr, now);
        responder.poll(now);

        // Initiator has a service too (but shouldn't reveal it)
        let mut initiator: Node<MockTransport> = Node::new();
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);
        let initiator_service = initiator.add_service(TestService::new("initiator.service"));

        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();
        init_wire.inject(&announce_packet);
        initiator.poll(now);

        // Initiator sends link request
        initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        // Check the link request doesn't contain initiator's service address
        let link_request_bytes = init_wire.take_sent().remove(0);
        let contains_initiator_addr = link_request_bytes
            .windows(16)
            .any(|w| w == initiator_service);
        assert!(
            !contains_initiator_addr,
            "Link request should not contain initiator's service address"
        );
    }

    // --- Path Request Tests ---

    // "Requests a path to the destination from the network. If another reachable peer
    // on the network knows a path, it will announce it."
    #[test]
    fn path_request_triggers_announce_from_service_owner() {
        // Server has a service
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("path.test"));

        // Client doesn't know about the service yet
        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Client sends path request for the service address
        client.request_path(service_addr, now);
        client.poll(now);

        // Path request was sent
        let sent = client_wire.take_sent();
        assert_eq!(sent.len(), 1);
        let path_request_packet = Packet::from_bytes(&sent[0], 0).unwrap();
        assert_eq!(path_request_packet.header.packet_type, PacketType::Data);

        // Server receives the path request
        server_wire.inject(&path_request_packet);
        server.poll(now);

        // Server should have sent an announce in response
        let server_sent = server_wire.take_sent();
        assert_eq!(server_sent.len(), 1);
        let announce_packet = Packet::from_bytes(&server_sent[0], 0).unwrap();
        assert_eq!(announce_packet.header.packet_type, PacketType::Announce);

        // The announce is for our service
        let announce_dest = match announce_packet.addresses {
            Addresses::Single(a) => a,
            Addresses::Double(_, dest) => dest,
        };
        assert_eq!(announce_dest, service_addr);
    }

    #[test]
    fn path_request_for_unknown_destination_is_ignored() {
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        // Server has no services

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Client requests path for unknown destination
        let unknown_dest: Address = [0xAB; 16];
        client.request_path(unknown_dest, now);
        client.poll(now);

        let sent = client_wire.take_sent();
        assert_eq!(sent.len(), 1);
        let path_request_packet = Packet::from_bytes(&sent[0], 0).unwrap();

        // Server receives but doesn't know the destination
        server_wire.inject(&path_request_packet);
        server.poll(now);

        // Server should not have sent anything
        let server_sent = server_wire.take_sent();
        assert!(server_sent.is_empty());
    }

    #[test]
    fn full_discovery_flow_request_path_then_link() {
        // Server has a service
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("discovery.test"));

        // Client knows the service address (out of band) but hasn't seen an announce
        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Client can't link yet (no announce seen)
        assert!(client.link(service_addr, now).is_none());

        // Client requests path
        client.request_path(service_addr, now);
        client.poll(now);

        // Server receives path request and announces
        let path_request = Packet::from_bytes(&client_wire.take_sent()[0], 0).unwrap();
        server_wire.inject(&path_request);
        server.poll(now);

        // Client receives announce
        let announce = Packet::from_bytes(&server_wire.take_sent()[0], 0).unwrap();
        client_wire.inject(&announce);
        client.poll(now);

        // Now client can link
        let link_id = client.link(service_addr, now);
        assert!(link_id.is_some());
    }

    // --- Transport Node Tests ---
    // Transport nodes forward packets between endpoints

    // "Any node that forwards the link request will store a link id in it's link table,
    // along with the amount of hops the packet had taken when received."
    #[test]
    fn transport_forwards_link_request_to_destination() {
        // Topology: Client <-> Transport <-> Server
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("transport.test"));

        let mut transport: Node<MockTransport> = Node::new();
        let (transport_server_iface, transport_server_wire) = make_mock_interface(true);
        let (transport_client_iface, transport_client_wire) = make_mock_interface(true);
        transport.add_interface(transport_server_iface); // index 0 - toward server
        transport.add_interface(transport_client_iface); // index 1 - toward client

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Server announces
        server.announce(service_addr, now);
        server.poll(now);

        // Transport receives announce from server side, should forward to client side
        let announce_bytes = server_wire.take_sent().remove(0);
        let announce = Packet::from_bytes(&announce_bytes, 0).unwrap();
        transport_server_wire.inject(&announce);
        transport.poll(now);

        // Transport should have forwarded the announce
        let forwarded = transport_client_wire.take_sent();
        assert_eq!(forwarded.len(), 1);

        // Client receives the announce
        let forwarded_announce = Packet::from_bytes(&forwarded[0], 0).unwrap();
        client_wire.inject(&forwarded_announce);
        client.poll(now);

        // Client sends link request
        let link_id = client.link(service_addr, now).unwrap();
        client.poll(now);

        // Transport receives link request from client side
        let link_request_bytes = client_wire.take_sent().remove(0);
        let link_request = Packet::from_bytes(&link_request_bytes, 0).unwrap();
        transport_client_wire.inject(&link_request);
        transport.poll(now);

        // Transport should forward link request toward server
        let forwarded_request = transport_server_wire.take_sent();
        assert_eq!(
            forwarded_request.len(),
            1,
            "Transport should forward link request"
        );

        // Transport should have stored link_id in link table
        assert!(
            transport.link_table.contains_key(&link_id),
            "Transport should store link_id in link table"
        );
    }

    // "By verifying this link proof packet, all nodes that originally transported the link
    // request packet to the destination from the originator can now verify that the intended
    // destination received the request and accepted it"
    #[test]
    fn transport_routes_link_proof_back_to_originator() {
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("transport.test"));

        let mut transport: Node<MockTransport> = Node::new();
        let (transport_server_iface, transport_server_wire) = make_mock_interface(true);
        let (transport_client_iface, transport_client_wire) = make_mock_interface(true);
        transport.add_interface(transport_server_iface);
        transport.add_interface(transport_client_iface);

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Server announces -> Transport -> Client
        server.announce(service_addr, now);
        server.poll(now);
        let announce = Packet::from_bytes(&server_wire.take_sent()[0], 0).unwrap();
        transport_server_wire.inject(&announce);
        transport.poll(now);
        let forwarded_announce =
            Packet::from_bytes(&transport_client_wire.take_sent()[0], 0).unwrap();
        client_wire.inject(&forwarded_announce);
        client.poll(now);

        // Client sends link request -> Transport -> Server
        let link_id = client.link(service_addr, now).unwrap();
        client.poll(now);
        let link_request = Packet::from_bytes(&client_wire.take_sent()[0], 0).unwrap();
        transport_client_wire.inject(&link_request);
        transport.poll(now);
        let forwarded_request =
            Packet::from_bytes(&transport_server_wire.take_sent()[0], 0).unwrap();
        server_wire.inject(&forwarded_request);
        server.poll(now);

        // Server sends proof -> Transport
        let proof = Packet::from_bytes(&server_wire.take_sent()[0], 0).unwrap();
        transport_server_wire.inject(&proof);
        transport.poll(now);

        // Transport should route proof back toward client
        let routed_proof = transport_client_wire.take_sent();
        assert_eq!(routed_proof.len(), 1, "Transport should route proof back");

        // Client receives proof and establishes link
        let proof_packet = Packet::from_bytes(&routed_proof[0], 0).unwrap();
        client_wire.inject(&proof_packet);
        client.poll(now);

        assert!(
            client.established_links.contains_key(&link_id),
            "Client should have established link"
        );
    }

    // "Any transport node with knowledge of the announce will be able to direct the packet
    // towards the destination by looking up the most efficient next node to the destination."
    #[test]
    fn transport_forwards_data_packet_to_destination() {
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("transport.test"));

        let mut transport: Node<MockTransport> = Node::new();
        let (transport_server_iface, transport_server_wire) = make_mock_interface(true);
        let (transport_client_iface, transport_client_wire) = make_mock_interface(true);
        transport.add_interface(transport_server_iface);
        transport.add_interface(transport_client_iface);

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Server announces -> Transport -> Client
        server.announce(service_addr, now);
        server.poll(now);
        let announce = Packet::from_bytes(&server_wire.take_sent()[0], 0).unwrap();
        transport_server_wire.inject(&announce);
        transport.poll(now);
        let forwarded_announce =
            Packet::from_bytes(&transport_client_wire.take_sent()[0], 0).unwrap();
        client_wire.inject(&forwarded_announce);
        client.poll(now);

        // Client sends data packet to service -> Transport should forward to Server
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let data_packet = Packet::new(
            header,
            None,
            Addresses::Single(service_addr),
            Context::None,
            b"hello".to_vec(),
        )
        .unwrap();

        client_wire.inject(&data_packet);
        client.poll(now);
        // Client doesn't know the route, so it should just drop or we need to send it
        // Actually client needs to send it out - let's manually send

        // Send from client to transport
        transport_client_wire.inject(&data_packet);
        transport.poll(now);

        // Transport should forward to server
        let forwarded = transport_server_wire.take_sent();
        assert_eq!(forwarded.len(), 1, "Transport should forward data packet");

        let forwarded_packet = Packet::from_bytes(&forwarded[0], 0).unwrap();
        assert_eq!(forwarded_packet.data, b"hello");
    }

    // "Packets can now be exchanged bi-directionally from either end of the link simply by
    // adressing the packets to the link id of the link."
    #[test]
    fn transport_forwards_link_addressed_packet() {
        let mut server: Node<MockTransport> = Node::new();
        let (server_iface, server_wire) = make_mock_interface(true);
        server.add_interface(server_iface);
        let service_addr = server.add_service(TestService::new("transport.test"));

        let mut transport: Node<MockTransport> = Node::new();
        let (transport_server_iface, transport_server_wire) = make_mock_interface(true);
        let (transport_client_iface, transport_client_wire) = make_mock_interface(true);
        transport.add_interface(transport_server_iface);
        transport.add_interface(transport_client_iface);

        let mut client: Node<MockTransport> = Node::new();
        let (client_iface, client_wire) = make_mock_interface(true);
        client.add_interface(client_iface);

        let now = Instant::now();

        // Full link establishment through transport
        server.announce(service_addr, now);
        server.poll(now);
        let announce = Packet::from_bytes(&server_wire.take_sent()[0], 0).unwrap();
        transport_server_wire.inject(&announce);
        transport.poll(now);
        let forwarded_announce =
            Packet::from_bytes(&transport_client_wire.take_sent()[0], 0).unwrap();
        client_wire.inject(&forwarded_announce);
        client.poll(now);

        let link_id = client.link(service_addr, now).unwrap();
        client.poll(now);
        let link_request = Packet::from_bytes(&client_wire.take_sent()[0], 0).unwrap();
        transport_client_wire.inject(&link_request);
        transport.poll(now);
        let forwarded_request =
            Packet::from_bytes(&transport_server_wire.take_sent()[0], 0).unwrap();
        server_wire.inject(&forwarded_request);
        server.poll(now);

        let proof = Packet::from_bytes(&server_wire.take_sent()[0], 0).unwrap();
        transport_server_wire.inject(&proof);
        transport.poll(now);
        let routed_proof = Packet::from_bytes(&transport_client_wire.take_sent()[0], 0).unwrap();
        client_wire.inject(&routed_proof);
        client.poll(now);

        // Link is now established. Send packet addressed to link_id from server -> client
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Transport,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let link_packet = Packet::new(
            header,
            None,
            Addresses::Single(link_id),
            Context::None,
            b"link data".to_vec(),
        )
        .unwrap();

        // Server sends to transport
        transport_server_wire.inject(&link_packet);
        transport.poll(now);

        // Transport should forward toward client (reverse direction from link request)
        let forwarded = transport_client_wire.take_sent();
        assert_eq!(
            forwarded.len(),
            1,
            "Transport should forward link-addressed packet"
        );
    }

    // --- Link Lifecycle Tests ---

    #[test]
    fn initiator_sends_rtt_packet_after_receiving_proof() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(TestService::new("rtt.test"));

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        let announce_bytes = resp_wire.take_sent().remove(0);
        let announce_packet = Packet::from_bytes(&announce_bytes, 0).unwrap();
        init_wire.inject(&announce_packet);
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        let request_bytes = init_wire.take_sent().remove(0);
        let request_packet = Packet::from_bytes(&request_bytes, 0).unwrap();
        resp_wire.inject(&request_packet);
        responder.poll(now);

        let proof_bytes = resp_wire.take_sent().remove(0);
        let proof_packet = Packet::from_bytes(&proof_bytes, 0).unwrap();

        let later = now + Duration::from_millis(50);
        init_wire.inject(&proof_packet);
        initiator.poll(later);

        let sent = init_wire.take_sent();
        assert_eq!(sent.len(), 1, "Initiator should send RTT packet");

        let rtt_packet = Packet::from_bytes(&sent[0], 0).unwrap();
        assert_eq!(rtt_packet.context, Context::LinkRtt);
        assert_eq!(rtt_packet.header.destination_type, DestinationType::Link);

        let initiator_link = initiator.established_links.get(&link_id).unwrap();
        assert!(initiator_link.rtt_ms.is_some());
    }

    #[test]
    fn responder_becomes_active_after_receiving_rtt() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(TestService::new("rtt.test"));

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        let announce_bytes = resp_wire.take_sent().remove(0);
        init_wire.inject(&Packet::from_bytes(&announce_bytes, 0).unwrap());
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        let request_bytes = init_wire.take_sent().remove(0);
        resp_wire.inject(&Packet::from_bytes(&request_bytes, 0).unwrap());
        responder.poll(now);

        assert_eq!(
            responder.established_links.get(&link_id).unwrap().state,
            crate::link::LinkState::Handshake
        );

        let proof_bytes = resp_wire.take_sent().remove(0);
        init_wire.inject(&Packet::from_bytes(&proof_bytes, 0).unwrap());
        initiator.poll(now);

        let rtt_bytes = init_wire.take_sent().remove(0);
        resp_wire.inject(&Packet::from_bytes(&rtt_bytes, 0).unwrap());
        responder.poll(now);

        assert_eq!(
            responder.established_links.get(&link_id).unwrap().state,
            crate::link::LinkState::Active
        );
    }

    #[test]
    fn initiator_sends_keepalive_after_interval() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(TestService::new("keepalive.test"));

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);

        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);

        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);

        init_wire.take_sent();

        // RTT is ~0ms, so keepalive_interval = 5 seconds (minimum), stale_time = 10 seconds
        // Poll at 6 seconds should trigger keepalive but not stale
        let later = now + Duration::from_secs(6);
        initiator.poll(later);

        let sent = init_wire.take_sent();
        assert_eq!(sent.len(), 1, "Initiator should send keepalive");

        let keepalive_packet = Packet::from_bytes(&sent[0], 0).unwrap();
        assert_eq!(keepalive_packet.context, Context::Keepalive);

        let link = initiator.established_links.get(&link_id).unwrap();
        let decrypted = link.decrypt(&keepalive_packet.data).unwrap();
        assert_eq!(decrypted, [0xFF]);
    }

    #[test]
    fn responder_replies_to_keepalive() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(TestService::new("keepalive.test"));

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);
        resp_wire.take_sent();

        // RTT is ~0ms, so keepalive_interval = 5 seconds (minimum), stale_time = 10 seconds
        let later = now + Duration::from_secs(6);
        initiator.poll(later);
        let keepalive_bytes = init_wire.take_sent().remove(0);
        resp_wire.inject(&Packet::from_bytes(&keepalive_bytes, 0).unwrap());
        responder.poll(later);

        let sent = resp_wire.take_sent();
        assert_eq!(sent.len(), 1, "Responder should reply to keepalive");

        let reply_packet = Packet::from_bytes(&sent[0], 0).unwrap();
        assert_eq!(reply_packet.context, Context::Keepalive);

        let link = responder.established_links.get(&link_id).unwrap();
        let decrypted = link.decrypt(&reply_packet.data).unwrap();
        assert_eq!(decrypted, [0xFE]);
    }

    #[test]
    fn link_becomes_stale_and_closes_after_timeout() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(TestService::new("timeout.test"));

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);

        assert!(responder.established_links.contains_key(&link_id));

        // stale_time = 10 seconds (KEEPALIVE_MIN * STALE_FACTOR = 5 * 2)
        let much_later = now + Duration::from_secs(15);
        responder.poll(much_later);

        assert!(
            !responder.established_links.contains_key(&link_id),
            "Link should be removed after timeout"
        );
    }

    #[test]
    fn link_closes_on_linkclose_packet() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(TestService::new("close.test"));

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);

        assert!(
            responder.established_links.contains_key(&link_id),
            "Responder should have link before close"
        );
        let resp_state_before = responder.established_links.get(&link_id).unwrap().state;
        assert_eq!(
            resp_state_before,
            crate::link::LinkState::Active,
            "Responder should be Active after RTT"
        );

        let init_link = initiator.established_links.get(&link_id).unwrap();
        let close_data = init_link.encrypt(&mut StdRng::seed_from_u64(99), &link_id);
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let close_packet = Packet::new(
            header,
            None,
            Addresses::Single(link_id),
            Context::LinkClose,
            close_data,
        )
        .unwrap();

        resp_wire.inject(&close_packet);
        responder.poll(now);

        // After receiving LinkClose and polling, link should be removed
        assert!(
            !responder.established_links.contains_key(&link_id),
            "Link should be removed after receiving LinkClose"
        );
    }

    #[test]
    fn data_received_over_link_resets_inbound_timer() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_clone = received.clone();

        struct RecordingService {
            name: String,
            received: Arc<Mutex<Vec<Vec<u8>>>>,
        }
        impl Service for RecordingService {
            fn name(&self) -> &str {
                &self.name
            }
            fn inbound(&mut self, msg: InboundMessage) {
                match msg {
                    InboundMessage::LinkData { data, .. }
                    | InboundMessage::SingleData { data, .. } => {
                        self.received.lock().unwrap().push(data);
                    }
                    _ => {}
                }
            }
            fn outbound(&mut self) -> Option<OutboundMessage> {
                None
            }
        }

        let mut responder: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(1));
        let (resp_iface, resp_wire) = make_mock_interface(true);
        responder.add_interface(resp_iface);
        let service_addr = responder.add_service(RecordingService {
            name: "timer.test".to_string(),
            received: received_clone,
        });

        let mut initiator: Node<MockTransport, StdRng> = Node::with_rng(StdRng::seed_from_u64(2));
        let (init_iface, init_wire) = make_mock_interface(true);
        initiator.add_interface(init_iface);

        let now = Instant::now();

        responder.announce(service_addr, now);
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);

        let link_id = initiator.link(service_addr, now).unwrap();
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);
        init_wire.inject(&Packet::from_bytes(&resp_wire.take_sent().remove(0), 0).unwrap());
        initiator.poll(now);
        resp_wire.inject(&Packet::from_bytes(&init_wire.take_sent().remove(0), 0).unwrap());
        responder.poll(now);

        let last_inbound_before = responder
            .established_links
            .get(&link_id)
            .unwrap()
            .last_inbound;

        let later = now + Duration::from_secs(100);
        let init_link = initiator.established_links.get(&link_id).unwrap();
        let encrypted = init_link.encrypt(&mut StdRng::seed_from_u64(99), b"hello");
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let data_packet = Packet::new(
            header,
            None,
            Addresses::Single(link_id),
            Context::None,
            encrypted,
        )
        .unwrap();

        resp_wire.inject(&data_packet);
        responder.poll(later);

        let last_inbound_after = responder
            .established_links
            .get(&link_id)
            .unwrap()
            .last_inbound;

        assert!(last_inbound_after > last_inbound_before);
        assert_eq!(received.lock().unwrap().len(), 1);
        assert_eq!(received.lock().unwrap()[0], b"hello");
    }
}
