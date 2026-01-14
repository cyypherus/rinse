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
use crate::{Address, Addresses, Context, Interface, Packet, PacketType, Transport};

// "By default, m is set to 128."
const DEFAULT_MAX_HOPS: u8 = 128;
// "By default, r is set to 1."
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;

pub enum MessageContext {
    Link(LinkId),
    Single(Address),
}

pub struct OutboundMessage {
    pub context: MessageContext,
    pub data: Vec<u8>,
}

pub trait Service: Send {
    fn name(&self) -> &str;
    fn receive(&mut self, data: &[u8], ctx: MessageContext);
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
}

struct LinkTableEntry {
    toward_initiator: usize,
    toward_destination: usize,
}

pub struct Node<T, R = ThreadRng> {
    max_hops: u8,
    retries: u8,
    pub(crate) retry_delay_ms: u64,
    rng: R,
    seen_announces: HashMap<Address, AnnounceEntry>,
    services: Vec<ServiceEntry>,
    interfaces: Vec<Interface<T>>,
    pending_outbound_links: HashMap<LinkId, PendingLink>,
    established_links: HashMap<LinkId, EstablishedLink>,
    link_table: HashMap<LinkId, LinkTableEntry>,
}

impl<T: Transport> Node<T, ThreadRng> {
    pub fn new() -> Self {
        Self {
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            rng: rand::thread_rng(),
            seen_announces: HashMap::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            pending_outbound_links: HashMap::new(),
            established_links: HashMap::new(),
            link_table: HashMap::new(),
        }
    }
}

impl<T: Transport, R: RngCore> Node<T, R> {
    pub fn with_rng(rng: R) -> Self {
        Self {
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            rng,
            seen_announces: HashMap::new(),
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

        // "randomly generate a new X25519 private/public key pair"
        let ephemeral = EphemeralKeyPair::generate(&mut self.rng);

        // Generate signing keypair for this link
        let mut sig_bytes = [0u8; 32];
        self.rng.fill_bytes(&mut sig_bytes);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        let request = LinkRequest::new(ephemeral.public, signing_key.verifying_key().to_bytes());

        // Build link request packet
        let packet = self.make_link_request_packet(destination, request.to_bytes());
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

    pub(crate) fn inbound(&mut self, packet: &Packet, source: usize, now: Instant) {
        match packet.header.packet_type {
            PacketType::Announce => self.handle_announce(packet, source, now),
            PacketType::LinkRequest => self.handle_link_request(packet, source, now),
            PacketType::Proof => self.handle_link_proof(packet, now),
            PacketType::Data => self.handle_data_packet(packet, source, now),
        }
    }

    fn handle_announce(&mut self, packet: &Packet, source: usize, now: Instant) {
        let dest = match packet.addresses {
            Addresses::Single(a) | Addresses::Double(a, _) => a,
        };
        let hops = packet.header.hops;

        // "After the announce has been re-transmitted, and if no other nodes are heard
        // retransmitting the announce with a greater hop count than when it left this
        // node, transmitting it will be retried r times."
        if let Some(entry) = self.seen_announces.get_mut(&dest)
            && hops > entry.hops
        {
            entry.retries_remaining = 0;
            entry.retry_at = None;
        }

        let has_ratchet = packet.header.context_flag == crate::ContextFlag::Set;
        let Ok(announce) = AnnounceData::parse(&packet.data, has_ratchet) else {
            return;
        };
        if announce.verify(&dest).is_err() {
            return;
        }
        if announce.verify_destination(&dest).is_err() {
            return;
        }
        let Ok(signing_key) = announce.signing_public_key() else {
            return;
        };

        let should_forward = self.process_announce_inner(
            dest,
            hops,
            announce.app_data.clone(),
            source,
            announce.encryption_public_key(),
            signing_key,
            announce.ratchet.map(X25519Public::from),
        );

        if should_forward {
            self.outbound(packet.clone(), Some(source), now);
        }
    }

    // "When the destination receives the link request packet, it will decide whether to
    // accept the request."
    fn handle_link_request(&mut self, packet: &Packet, source: usize, now: Instant) {
        let dest = match packet.addresses {
            Addresses::Single(a) | Addresses::Double(a, _) => a,
        };
        let hops = packet.header.hops;

        let Some(request) = LinkRequest::parse(&packet.data) else {
            return;
        };

        let link_id = LinkRequest::link_id(&packet.hashable_part());

        // Check if this is for a local service
        if let Some(service_index) = self.services.iter().position(|s| s.address == dest) {
            // "If it is accepted, the destination will also generate a new X25519 private/public
            // key pair, and perform a Diffie Hellman Key Exchange"
            let responder_ephemeral = EphemeralKeyPair::generate(&mut self.rng);

            let established = EstablishedLink::from_responder(
                link_id,
                &responder_ephemeral.secret,
                &request.encryption_public,
                dest,
                now,
            );
            self.established_links.insert(link_id, established);

            // "A link proof packet is now constructed and transmitted over the network."
            let service = &self.services[service_index];
            let proof =
                LinkProof::create(&link_id, &responder_ephemeral.public, &service.signing_key);

            let proof_packet = self.make_link_proof_packet(link_id, proof.to_bytes());

            if let Some(iface) = self.interfaces.get_mut(source) {
                iface.send(proof_packet, 0, &mut self.rng, now);
            }
            return;
        }

        // "Any node that forwards the link request will store a link id in it's link table,
        // along with the amount of hops the packet had taken when received."
        if let Some(announce_entry) = self.seen_announces.get(&dest) {
            let toward_destination = announce_entry.source_interface;

            self.link_table.insert(
                link_id,
                LinkTableEntry {
                    toward_initiator: source,
                    toward_destination,
                },
            );

            let mut forwarded = packet.clone();
            forwarded.header.hops = hops.saturating_add(1);

            if let Some(iface) = self.interfaces.get_mut(toward_destination) {
                iface.send(forwarded, 0, &mut self.rng, now);
            }
        }
    }

    // "When the source receives the proof, it will know unequivocally that a verified path
    // has been established to the destination."
    fn handle_link_proof(&mut self, packet: &Packet, now: Instant) {
        let link_id: LinkId = match packet.addresses {
            Addresses::Single(a) => a,
            Addresses::Double(a, _) => a,
        };

        // Check if this is for a link we initiated
        if let Some(pending) = self.pending_outbound_links.remove(&link_id) {
            let Some(proof) = LinkProof::parse(&packet.data) else {
                self.pending_outbound_links.insert(link_id, pending);
                return;
            };

            let Some(announce_entry) = self.seen_announces.get(&pending.destination) else {
                self.pending_outbound_links.insert(link_id, pending);
                return;
            };

            if !proof.verify(&link_id, &announce_entry.signing_key) {
                self.pending_outbound_links.insert(link_id, pending);
                return;
            }

            // "It can now also use the X25519 public key contained in the link proof to perform
            // it's own Diffie Hellman Key Exchange and derive the symmetric key"
            let rtt_ms = now.duration_since(pending.request_time).as_millis() as u32;
            let mut established =
                EstablishedLink::from_initiator(pending, &proof.encryption_public, now);
            established.rtt_ms = Some(rtt_ms as u64);
            self.established_links.insert(link_id, established);

            self.send_link_packet(link_id, Context::LinkRtt, &rtt_ms.to_be_bytes(), now);
            return;
        }

        // "By verifying this link proof packet, all nodes that originally transported the link
        // request packet to the destination from the originator can now verify that the intended
        // destination received the request and accepted it"
        if let Some(entry) = self.link_table.get(&link_id)
            && let Some(iface) = self.interfaces.get_mut(entry.toward_initiator)
        {
            iface.send(packet.clone(), 0, &mut self.rng, now);
        }
    }

    fn handle_data_packet(&mut self, packet: &Packet, source: usize, now: Instant) {
        use crate::crypto::SingleDestEncryption;

        let dest = match packet.addresses {
            Addresses::Single(a) | Addresses::Double(a, _) => a,
        };

        if dest == PathRequest::destination() {
            self.handle_path_request(packet, now);
            return;
        }

        // "Packets can now be exchanged bi-directionally from either end of the link simply by
        // adressing the packets to the link id of the link."
        if packet.header.destination_type == crate::DestinationType::Link {
            let link_id = dest;

            if self.established_links.contains_key(&link_id) {
                self.handle_link_data(link_id, packet, now);
                return;
            }

            if let Some(entry) = self.link_table.get(&link_id) {
                let target = if source == entry.toward_initiator {
                    entry.toward_destination
                } else {
                    entry.toward_initiator
                };
                if let Some(iface) = self.interfaces.get_mut(target) {
                    iface.send(packet.clone(), 0, &mut self.rng, now);
                }
            }
            return;
        }

        // "When the destination receives the packet, it can itself perform an ECDH key exchange
        // and decrypt the packet."
        if packet.header.destination_type == crate::DestinationType::Single
            && let Some(service) = self.services.iter_mut().find(|s| s.address == dest)
        {
            if packet.data.len() < 32 {
                return;
            }
            let ephemeral_public =
                X25519Public::from(<[u8; 32]>::try_from(&packet.data[..32]).unwrap());
            let ciphertext = &packet.data[32..];

            if let Some(plaintext) = SingleDestEncryption::decrypt(
                &service.encryption_secret,
                &ephemeral_public,
                ciphertext,
            ) {
                service
                    .service
                    .receive(&plaintext, MessageContext::Single(dest));
            }
            return;
        }

        // "Any transport node with knowledge of the announce will be able to direct the packet
        // towards the destination by looking up the most efficient next node to the destination."
        if let Some(announce_entry) = self.seen_announces.get(&dest) {
            let target_interface = announce_entry.source_interface;
            if let Some(iface) = self.interfaces.get_mut(target_interface) {
                iface.send(packet.clone(), 0, &mut self.rng, now);
            }
        }
    }

    fn handle_link_data(&mut self, link_id: LinkId, packet: &Packet, now: Instant) {
        let Some(link) = self.established_links.get_mut(&link_id) else {
            return;
        };

        link.touch_inbound(now);

        match packet.context {
            Context::None => {
                if let Some(plaintext) = link.decrypt(&packet.data) {
                    let service_addr = link.destination;
                    if let Some(service) =
                        self.services.iter_mut().find(|s| s.address == service_addr)
                    {
                        service
                            .service
                            .receive(&plaintext, MessageContext::Link(link_id));
                    }
                }
            }

            Context::LinkRtt => {
                if !link.is_initiator
                    && link.state == LinkState::Handshake
                    && let Some(plaintext) = link.decrypt(&packet.data)
                    && plaintext.len() >= 4
                {
                    let rtt_bytes: [u8; 4] = plaintext[..4].try_into().unwrap_or([0; 4]);
                    let rtt_ms = u32::from_be_bytes(rtt_bytes) as u64;
                    link.rtt_ms = Some(rtt_ms);
                    link.state = LinkState::Active;
                    link.activated_at = Some(now);
                }
            }

            Context::Keepalive => {
                if let Some(plaintext) = link.decrypt(&packet.data)
                    && !link.is_initiator
                    && plaintext == [0xFF]
                {
                    self.send_link_packet(link_id, Context::Keepalive, &[0xFE], now);
                }
            }

            Context::LinkClose => {
                if let Some(plaintext) = link.decrypt(&packet.data)
                    && plaintext == link_id
                {
                    link.state = LinkState::Closed;
                }
            }

            _ => {}
        }
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
            Addresses::Single(a) | Addresses::Double(a, _) => a,
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
            self.send_link_packet(link_id, Context::Keepalive, &[0xFF], now);
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
                messages.push(msg);
            }
        }

        for msg in messages {
            match msg.context {
                MessageContext::Link(link_id) => {
                    if let Some(link) = self.established_links.get(&link_id) {
                        let ciphertext = link.encrypt(&mut self.rng, &msg.data);
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
                MessageContext::Single(destination) => {
                    if let Some(entry) = self.seen_announces.get(&destination) {
                        let (ephemeral_pub, ciphertext) = SingleDestEncryption::encrypt(
                            &mut self.rng,
                            &entry.encryption_key,
                            &msg.data,
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
    fn make_link_request_packet(&self, dest: Address, data: Vec<u8>) -> Packet {
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::LinkRequest,
            hops: 0,
        };
        Packet::new(header, None, Addresses::Single(dest), Context::None, data).unwrap()
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
    ) -> bool {
        if let Some(entry) = self.seen_announces.get_mut(&destination) {
            // "If a newer announce from the same destination arrives, while an identical one
            // is already waiting to be transmitted, the newest announce is discarded. If the
            // newest announce contains different application specific data, it will replace
            // the old announce."
            if entry.retry_at.is_some() && entry.app_data == app_data {
                return false;
            }
            if entry.app_data != app_data {
                entry.app_data = app_data;
                entry.hops = hops;
                entry.source_interface = source;
                entry.retries_remaining = self.retries;
                entry.retry_at = None;
                entry.encryption_key = encryption_key;
                entry.signing_key = signing_key;
                entry.ratchet_key = ratchet_key;
                return hops < self.max_hops;
            }
            // "If this exact announce has already been received before, ignore it."
            return false;
        }

        // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
        // By default, m is set to 128."
        if hops > self.max_hops {
            return false;
        }

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
        let (packet, _) = make_announce_packet([6u8; 16], 127, vec![]);
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
        fn receive(&mut self, data: &[u8], _ctx: MessageContext) {
            self.received.lock().unwrap().push(data.to_vec());
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
            Addresses::Double(a, _) => a,
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
            fn receive(&mut self, data: &[u8], _ctx: MessageContext) {
                self.received.lock().unwrap().push(data.to_vec());
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
