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

struct PathEntry {
    next_hop: Address,
    hops: u8,
    receiving_interface: usize,
    encryption_key: X25519Public,
    signing_key: VerifyingKey,
    ratchet_key: Option<X25519Public>,
}

struct PendingAnnounce {
    destination: Address,
    source_interface: usize,
    hops: u8,
    app_data: Vec<u8>,
    retries_remaining: u8,
    retry_at: Instant,
}

struct LinkTableEntry {
    toward_initiator: usize,
    toward_destination: usize,
    receiving_interface: usize,
    next_hop_interface: usize,
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
    seen_packet_hashes: std::collections::HashSet<[u8; 32]>,
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
            seen_packet_hashes: std::collections::HashSet::new(),
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
            seen_packet_hashes: std::collections::HashSet::new(),
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

        // Packet filter if !filtered
        unimplemented!("Packet filter");

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

        // TODO review
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
        if self.transport || for_local_service || for_local_link {
            // TODO missing cache request handling

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
                            // TODO missing insert IDXPTTIMESTAMP tracking time entry in path table
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
                    // TODO this logic does not match
                    // # If receiving and outbound interface is
                    // # the same for this link, direction doesn't
                    // # matter, and we simply repeat the packet.
                    // outbound_interface = None
                    // if link_entry[IDX_LT_NH_IF] == link_entry[IDX_LT_RCVD_IF]:
                    //     # But check that taken hops matches one
                    //     # of the expectede values.
                    //     if packet.hops == link_entry[IDX_LT_REM_HOPS] or packet.hops == link_entry[IDX_LT_HOPS]:
                    //         outbound_interface = link_entry[IDX_LT_NH_IF]
                    // else:
                    //     # If interfaces differ, we transmit on
                    //     # the opposite interface of what the
                    //     # packet was received on.
                    //     if packet.receiving_interface == link_entry[IDX_LT_NH_IF]:
                    //         # Also check that expected hop count matches
                    //         if packet.hops == link_entry[IDX_LT_REM_HOPS]:
                    //             outbound_interface = link_entry[IDX_LT_RCVD_IF]
                    //     elif packet.receiving_interface == link_entry[IDX_LT_RCVD_IF]:
                    //         # Also check that expected hop count matches
                    //         if packet.hops == link_entry[IDX_LT_HOPS]:
                    //             outbound_interface = link_entry[IDX_LT_NH_IF]

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
                            // TODO missing insert IDXLTTIMESTAMP tracking time entry in path table
                            // Transport.link_table[packet.destination_hash][IDX_LT_TIMESTAMP] = time.time()
                        }
                    }
                }
            }
        }

        if packet.header.packet_type == PacketType::Announce {
            let has_ratchet = packet.header.context_flag == crate::ContextFlag::Set;
            let announce = match AnnounceData::parse(&packet.data, has_ratchet) {
                Ok(a) => a,
                Err(_) => return None, // TODO dogshit silent failure
            };

            // TODO should only validate signature here
            // Validate announce signature
            if announce.verify(&destination_hash).is_err() {
                return None;
            }
            if announce.verify_destination(&destination_hash).is_err() {
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

            // TODO full validate announce here
            if !is_local {
                // Get received_from (transport_id if present, else destination_hash)
                let received_from = match packet.addresses {
                    Addresses::Double(transport_id, _) => transport_id,
                    Addresses::Single(_) => destination_hash,
                };

                // TODO This shit doesn't look right
                // # Check if this is a next retransmission from
                //  # another node. If it is, we're removing the
                //  # announce in question from our pending table
                //  if RNS.Reticulum.transport_enabled() and packet.destination_hash in Transport.announce_table:
                //      announce_entry = Transport.announce_table[packet.destination_hash]

                //      if packet.hops-1 == announce_entry[IDX_AT_HOPS]:
                //          RNS.log(f"Heard a rebroadcast of announce for {RNS.prettyhexrep(packet.destination_hash)} on {packet.receiving_interface}", RNS.LOG_EXTREME)
                //          announce_entry[IDX_AT_LCL_RBRD] += 1
                //          if announce_entry[IDX_AT_RETRIES] > 0:
                //              if announce_entry[IDX_AT_LCL_RBRD] >= Transport.LOCAL_REBROADCASTS_MAX:
                //                  RNS.log("Completed announce processing for "+RNS.prettyhexrep(packet.destination_hash)+", local rebroadcast limit reached", RNS.LOG_EXTREME)
                //                  if packet.destination_hash in Transport.announce_table: Transport.announce_table.pop(packet.destination_hash)

                //      if packet.hops-1 == announce_entry[IDX_AT_HOPS]+1 and announce_entry[IDX_AT_RETRIES] > 0:
                //          now = time.time()
                //          if now < announce_entry[IDX_AT_RTRNS_TMO]:
                //              RNS.log("Rebroadcasted announce for "+RNS.prettyhexrep(packet.destination_hash)+" has been passed on to another node, no further tries needed", RNS.LOG_EXTREME)
                //              if packet.destination_hash in Transport.announce_table:
                //                  Transport.announce_table.pop(packet.destination_hash)

                // Check if this is a rebroadcast we were waiting for
                // If we see an announce with hop count one higher than what we sent,
                // another node picked it up - cancel our retry
                let our_hops = self.path_table.get(&destination_hash).map(|e| e.hops);
                if let Some(h) = our_hops {
                    if packet.header.hops == h.saturating_add(1) {
                        log::trace!(
                            "Announce for <{}> passed on by another node",
                            hex::encode(destination_hash)
                        );
                        self.pending_announces
                            .retain(|a| a.destination != destination_hash);
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
                        PathEntry {
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
                        app_data: announce.app_data.clone(),
                        retries_remaining: self.retries,
                        retry_at: _now, // Rebroadcast immediately on first receive
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
        if let Some(pending) = self
            .pending_announces
            .iter_mut()
            .find(|a| a.destination == dest)
        {
            if pending.retries_remaining > 0 {
                pending.retry_at = now + Duration::from_millis(self.retry_delay_ms);
            }
        }
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
                    pending.app_data.clone(),
                    pending.source_interface,
                ));
            }
        }
        // Remove announces with no retries left
        self.pending_announces.retain(|a| a.retries_remaining > 0);

        for (dest, hops, data, source) in to_send {
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
                    if let Some(entry) = self.path_table.get(&destination) {
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
                            let target = entry.receiving_interface;
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
}
