use std::collections::HashMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::announce::{AnnounceBuilder, AnnounceData};
use crate::api::ServiceId;
use crate::channel::{ChannelMessage, QueueChannelError};
use crate::crypto::{EphemeralKeyPair, sha256};
use crate::runtime::{NodeOwner, ReceiveQueue};
use crate::{LinkError, MonoTime, SendError, TimeSpan};
use crate::{ServiceEvent, ServiceReceiveError};

pub(crate) const LINK_MDU: usize = 431;
use crate::link::{EstablishedLink, LinkId, LinkProof, LinkRequest, LinkResponder, PendingLink};
use crate::packet::{DestinationAddress, LinkContext, Packet, RoutedDestination};
use crate::request::{PathHash, Request, RequestId, Response, WireRequestId};
use ed25519_dalek::Signature;

const DEFAULT_MAX_HOPS: u8 = 128;
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;
const LOCAL_REBROADCASTS_MAX: u8 = 2;
const PATHFINDER_RW_MS: u64 = 500;
const PATH_REQUEST_TIMEOUT_SECS: u64 = 60;
const PATH_TIMEOUT: TimeSpan = TimeSpan::from_secs(7 * 24 * 60 * 60);
const REVERSE_TIMEOUT: TimeSpan = TimeSpan::from_secs(8 * 60);
const RETAINED_RATCHETS: usize = 512;

fn split_metadata(mut data: Vec<u8>, has_metadata: bool) -> (Vec<u8>, Option<Vec<u8>>) {
    if !has_metadata || data.len() < 3 {
        return (data, None);
    }
    let metadata_size = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
    if data.len() < metadata_size + 3 {
        log::warn!("Metadata size exceeds data length");
        return (data, None);
    }
    log::debug!(
        "Extracting {} byte metadata, {} byte data",
        metadata_size,
        data.len() - metadata_size - 3
    );
    let content = data.split_off(metadata_size + 3);
    let metadata = data.split_off(3);
    (content, Some(metadata))
}

pub(crate) struct ServiceState {
    address: DestinationAddress,
    name_hash: [u8; 10],
    encryption_secret: StaticSecret,
    signing_key: SigningKey,
    registered_paths: HashMap<PathHash, String>,
    pub(crate) ratchets: Vec<StaticSecret>,
    pub(crate) events: ReceiveQueue<ServiceEvent, ServiceReceiveError>,
}

impl ServiceState {
    fn decrypt(&self, ephemeral: &X25519Public, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.ratchets
            .iter()
            .find_map(|ratchet| {
                crate::crypto::SingleDestEncryption::decrypt(ratchet, ephemeral, ciphertext)
            })
            .or_else(|| {
                crate::crypto::SingleDestEncryption::decrypt(
                    &self.encryption_secret,
                    ephemeral,
                    ciphertext,
                )
            })
    }
}

pub(crate) struct Receipt {
    packet_hash: [u8; 32],
    destination: DestinationAddress,
}

#[derive(Clone)]
pub(crate) struct PathEntry {
    timestamp: MonoTime,
    next_hop: DestinationAddress,
    hops: u8,
    receiving_interface: usize,
    announce: AnnounceData,
}

impl PathEntry {
    fn encryption_key(&self) -> X25519Public {
        self.announce
            .ratchet
            .map(X25519Public::from)
            .unwrap_or(self.announce.encryption_key)
    }
}

#[derive(Debug)]
pub(crate) struct PendingAnnounce {
    destination: DestinationAddress,
    source_interface: usize,
    hops: u8,
    has_ratchet: bool,
    data: Vec<u8>,
    retries_remaining: u8,
    retry_at: MonoTime,
    local_rebroadcasts: u8,
}

pub(crate) struct LinkTableEntry {
    timestamp: MonoTime,
    receiving_interface: usize,
    next_hop_interface: usize,
    remaining_hops: u8,
    hops: u8,
}

pub(crate) struct ReverseTableEntry {
    timestamp: MonoTime,
    receiving_interface: usize,
}

pub(crate) struct MultiSegmentTransfer {
    local_request_id: RequestId,
    total_segments: usize,
    segments_received: usize,
    accumulated_data: Vec<u8>,
    has_metadata: bool,
}

pub(crate) struct OutboundMultiSegment {
    full_data: Vec<u8>,
    compress: bool,
    request_id: Option<Vec<u8>>,
    current_segment: usize,
}

pub(crate) struct PendingInboundLink {
    destination: DestinationAddress,
    service: ServiceId,
    request: LinkRequest,
    interface: usize,
}

pub(crate) struct PreparedInbound {
    packet: Packet,
    packet_hash: [u8; 32],
    source: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScheduledTimer {
    pub(crate) at: MonoTime,
    pub(crate) event: ProtocolTimer,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) enum ProtocolTimer {
    AnnounceRetry(DestinationAddress),
    PathExpiry(DestinationAddress),
    ReversePathExpiry(DestinationAddress),
    ChannelRetry(LinkId),
    PendingLinkTimeout(LinkId),
    PathRequestTimeout(DestinationAddress),
    RequestTimeout(RequestId),
    LinkMaintenance(LinkId),
}

impl PreparedInbound {
    pub(crate) fn parse(raw: Vec<u8>, source: usize) -> Option<Self> {
        let wire_len = raw.len();
        let mut hasher = Sha256::new();
        hasher.update([raw.first().copied().unwrap_or(0) & 0b0000_1111]);
        let skip = if raw.first().copied().unwrap_or(0) & 0b0100_0000 != 0 {
            2 + std::mem::size_of::<DestinationAddress>()
        } else {
            2
        };
        if raw.len() >= skip {
            hasher.update(&raw[skip..]);
        }
        let packet_hash = hasher.finalize().into();
        match Packet::from_vec(raw) {
            Ok(packet) => Some(Self {
                packet,
                packet_hash,
                source,
            }),
            Err(error) => {
                log::debug!("Failed to parse packet: {:?} (len={})", error, wire_len);
                None
            }
        }
    }
}

pub(crate) struct ProtocolOutbound {
    pub(crate) interface: usize,
    pub(crate) packet: Packet,
    pub(crate) priority: u8,
}

pub(crate) struct PreparedIdentify {
    pub(crate) outbound: ProtocolOutbound,
    identity: [u8; 16],
}

pub(crate) struct PreparedRequest {
    pub(crate) outbound: ProtocolOutbound,
    link: LinkId,
    wire: WireRequestId,
    local: RequestId,
    deadline: MonoTime,
}

pub(crate) struct PreparedResponse {
    pub(crate) outbound: ProtocolOutbound,
    resource: Option<PreparedResponseResource>,
}

struct PreparedResponseResource {
    hash: [u8; 32],
    resource: crate::resource::OutboundResource,
    segmented: Option<([u8; 32], OutboundMultiSegment)>,
}

pub(crate) struct PreparedAnnouncement {
    pub(crate) outbounds: Vec<ProtocolOutbound>,
    service: ServiceId,
    ratchets: Option<Vec<StaticSecret>>,
    restart_ratchet: Option<crate::RatchetSecret>,
}

impl NodeOwner {
    fn schedule_timer(&mut self, at: MonoTime, event: ProtocolTimer) {
        self.timers.schedule(ScheduledTimer { at, event });
    }

    fn schedule_path_expiry(&mut self, destination: DestinationAddress) {
        if let Some(entry) = self.path_table.get(&destination) {
            self.schedule_timer(
                entry
                    .timestamp
                    .checked_add(PATH_TIMEOUT)
                    .and_then(|at| at.checked_add(TimeSpan::from_micros(1)))
                    .expect("path expiry overflow"),
                ProtocolTimer::PathExpiry(destination),
            );
        }
    }

    fn schedule_channel_retry(&mut self, link: LinkId) {
        let rtt = self
            .established_links
            .get(&link)
            .and_then(EstablishedLink::rtt)
            .unwrap_or(TimeSpan::from_millis(25));
        if let Some(retry_at) = self
            .established_links
            .get(&link)
            .and_then(|link| link.channel.as_ref())
            .and_then(|channel| channel.protocol_state.next_retry(rtt))
        {
            self.schedule_timer(retry_at, ProtocolTimer::ChannelRetry(link));
        }
    }

    fn schedule_link_maintenance(&mut self, link_id: LinkId) {
        if let Some(link) = self.established_links.get(&link_id)
            && let Some(at) = Self::link_maintenance_at(link)
        {
            self.schedule_timer(at, ProtocolTimer::LinkMaintenance(link_id));
        }
    }

    fn link_maintenance_at(link: &EstablishedLink) -> Option<MonoTime> {
        let stale_at = link.pending_requests.is_empty().then(|| {
            link.last_inbound
                .checked_add(TimeSpan::from_secs(link.stale_time_secs()))
                .expect("link stale deadline overflow")
        });
        let keepalive_at = (link.is_initiator() && link.is_active()).then(|| {
            let keepalive = TimeSpan::from_secs(link.keepalive_interval_secs());
            link.last_inbound
                .checked_add(keepalive)
                .expect("link keepalive deadline overflow")
                .max(
                    link.last_keepalive_sent
                        .map(|sent| {
                            sent.checked_add(keepalive)
                                .expect("link keepalive deadline overflow")
                        })
                        .unwrap_or(link.last_inbound),
                )
        });
        match (stale_at, keepalive_at) {
            (Some(stale), Some(keepalive)) => Some(stale.min(keepalive)),
            (Some(at), None) | (None, Some(at)) => Some(at),
            (None, None) => None,
        }
    }

    fn queue_packet(&mut self, interface: usize, packet: Packet, priority: u8) -> bool {
        log::trace!("[SEND] interface={interface} {}", packet.log_format());
        self.interfaces
            .get_mut(interface)
            .is_some_and(|slot| slot.enqueue_protocol_packet(priority, &packet))
    }

    pub(crate) fn remove_service(&mut self, service: ServiceId) -> Vec<LinkId> {
        let Some(entry) = self.services.get_mut(service.0) else {
            return Vec::new();
        };
        let Some(mut removed) = entry.take() else {
            return Vec::new();
        };
        removed.events.close(ServiceReceiveError::ServiceClosed);
        self.pending_inbound_links
            .retain(|_, pending| pending.service != service);
        self.established_links
            .iter()
            .filter_map(|(link, state)| (state.local_service() == Some(service)).then_some(*link))
            .collect()
    }

    pub(crate) fn prepare_request(
        &mut self,
        link_id: LinkId,
        path: &str,
        data: &[u8],
        now: MonoTime,
        timeout: TimeSpan,
    ) -> Result<PreparedRequest, LinkError> {
        let Some(established) = self.established_links.get(&link_id) else {
            log::warn!("Request on non-existent link {}", hex::encode(link_id));
            return Err(LinkError::LinkClosed);
        };
        if !established.is_active() {
            return Err(LinkError::LinkClosed);
        }

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
        let link = self
            .established_links
            .get(&link_id)
            .ok_or(LinkError::LinkClosed)?;
        let req = Request::new(path, data.to_vec());
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
            destination: RoutedDestination::direct(link_id),
            context: LinkContext::Request,
            data: ciphertext,
        };
        let wire_request_id = WireRequestId(packet.packet_hash()[..16].try_into().unwrap());
        log::info!(
            "Sending request over link {} wire_request_id={} packet_hash={}",
            hex::encode(link_id),
            hex::encode(wire_request_id.0),
            hex::encode(packet.packet_hash())
        );
        Ok(PreparedRequest {
            outbound: ProtocolOutbound {
                interface: target_interface,
                packet,
                priority: 0,
            },
            link: link_id,
            wire: wire_request_id,
            local: local_request_id,
            deadline: now.checked_add(timeout).expect("request deadline overflow"),
        })
    }

    pub(crate) fn commit_request(&mut self, request: PreparedRequest) -> RequestId {
        self.established_links
            .get_mut(&request.link)
            .expect("admitted request link disappeared")
            .pending_requests
            .insert(request.wire, request.local);
        self.schedule_timer(
            request.deadline,
            ProtocolTimer::RequestTimeout(request.local),
        );
        request.local
    }

    pub(crate) fn prepare_response(
        &mut self,
        link_id: LinkId,
        wire_request_id: WireRequestId,
        data: &[u8],
    ) -> Result<PreparedResponse, LinkError> {
        use crate::packet::RoutedDestination;

        let link = self
            .established_links
            .get(&link_id)
            .ok_or(LinkError::LinkClosed)?;
        let target_interface = link.receiving_interface;
        if data.len() <= LINK_MDU {
            let resp = Response::new(wire_request_id, data.to_vec());
            let ciphertext = link.encrypt(&mut self.rng, &resp.encode());

            let packet = Packet::LinkData {
                hops: 0,
                destination: RoutedDestination::direct(link_id),
                context: LinkContext::Response,
                data: ciphertext,
            };
            Ok(PreparedResponse {
                outbound: ProtocolOutbound {
                    interface: target_interface,
                    packet,
                    priority: 0,
                },
                resource: None,
            })
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
                None,
                true,
                Some(wire_request_id.0.to_vec()),
                crate::resource::ResourceSegment::First {
                    total_data_size: needs_segmentation.then_some(total_size),
                },
            );

            let adv = resource.advertisement(91);
            let adv_data = adv.encode();
            let hash = resource.hash;
            let original_hash = resource.original_hash;

            let segmented = needs_segmentation.then(|| {
                (
                    original_hash,
                    OutboundMultiSegment {
                        full_data: packed_response,
                        compress: true,
                        request_id: Some(wire_request_id.0.to_vec()),
                        current_segment: 1,
                    },
                )
            });
            if needs_segmentation {
                log::info!(
                    "Created multi-segment outbound resource: {} segments, {} bytes total",
                    resource.total_segments,
                    total_size
                );
            }

            let ciphertext = link.encrypt(&mut self.rng, &adv_data);
            let packet = Packet::LinkData {
                hops: 0,
                destination: RoutedDestination::direct(link_id),
                context: LinkContext::ResourceAdv,
                data: ciphertext,
            };

            Ok(PreparedResponse {
                outbound: ProtocolOutbound {
                    interface: target_interface,
                    packet,
                    priority: 0,
                },
                resource: Some(PreparedResponseResource {
                    hash,
                    resource,
                    segmented,
                }),
            })
        }
    }

    pub(crate) fn commit_response(&mut self, response: PreparedResponse) {
        if let Some(resource) = response.resource {
            self.outbound_resources.insert(
                resource.hash,
                (
                    response.outbound.packet.destination_hash(),
                    resource.resource,
                ),
            );
            if let Some((hash, transfer)) = resource.segmented {
                self.outbound_multi_segments.insert(hash, transfer);
            }
        }
    }

    pub fn add_service(
        &mut self,
        name: &str,
        paths: &[&str],
        identity: &crate::identity::PrivateIdentity,
        restart_ratchet: Option<crate::RatchetSecret>,
        events: ReceiveQueue<ServiceEvent, ServiceReceiveError>,
    ) -> ServiceId {
        let name_hash: [u8; 10] = sha256(name.as_bytes())[..10].try_into().unwrap();

        let encryption_secret = StaticSecret::from(*identity.encryption_secret.as_bytes());
        let signing_key = SigningKey::from_bytes(identity.signing_key.as_bytes());

        let identity_hash = identity.hash();

        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(&name_hash);
        hash_material.extend_from_slice(&identity_hash);
        let address: DestinationAddress = sha256(&hash_material)[..16].try_into().unwrap();

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

        let service_id = ServiceId(
            self.services
                .iter()
                .position(Option::is_none)
                .unwrap_or(self.services.len()),
        );
        let service = ServiceState {
            address,
            name_hash,
            encryption_secret,
            signing_key,
            registered_paths,
            ratchets: restart_ratchet
                .map(|secret| StaticSecret::from(secret.to_bytes()))
                .into_iter()
                .collect(),
            events,
        };
        if service_id.0 == self.services.len() {
            self.services.push(Some(service));
        } else {
            self.services[service_id.0] = Some(service);
        }

        service_id
    }

    pub(crate) fn prepare_announcement(
        &mut self,
        service: ServiceId,
        app_data: Vec<u8>,
        ratchet: crate::RatchetAction,
    ) -> Option<PreparedAnnouncement> {
        let entry = self.services.get(service.0)?.as_ref()?;

        let (ratchet_public, ratchets, restart_ratchet) = match ratchet {
            crate::RatchetAction::Keep => (
                entry
                    .ratchets
                    .first()
                    .map(|secret| *X25519Public::from(secret).as_bytes()),
                None,
                None,
            ),
            crate::RatchetAction::Rotate => {
                let mut bytes = [0; 32];
                loop {
                    self.rng.fill_bytes(&mut bytes);
                    if bytes != [0; 32] {
                        break;
                    }
                }
                let next = StaticSecret::from(bytes);
                let restart_ratchet = crate::RatchetSecret::from_bytes(bytes).ok()?;
                let ratchet_public = *X25519Public::from(&next).as_bytes();
                let mut prospective =
                    Vec::with_capacity(RETAINED_RATCHETS.min(entry.ratchets.len() + 1));
                for secret in core::iter::once(next).chain(
                    entry
                        .ratchets
                        .iter()
                        .map(|secret| StaticSecret::from(secret.to_bytes())),
                ) {
                    let public = *X25519Public::from(&secret).as_bytes();
                    if prospective
                        .iter()
                        .all(|stored| *X25519Public::from(stored).as_bytes() != public)
                    {
                        prospective.push(secret);
                        if prospective.len() == RETAINED_RATCHETS {
                            break;
                        }
                    }
                }
                (
                    Some(ratchet_public),
                    Some(prospective),
                    Some(restart_ratchet),
                )
            }
        };

        let address = entry.address;

        let mut random_hash = [0u8; 10];
        self.rng.fill_bytes(&mut random_hash);

        let mut builder = AnnounceBuilder::new(
            *X25519Public::from(&entry.encryption_secret).as_bytes(),
            entry.signing_key.clone(),
            entry.name_hash,
            random_hash,
        );
        if let Some(ratchet) = ratchet_public {
            builder = builder.with_ratchet(ratchet);
        }
        builder = builder.with_app_data(app_data);
        let announce_data = builder.build(&address);

        let packet = self.make_announce_packet(
            address,
            0,
            ratchet_public.is_some(),
            false,
            announce_data.to_bytes(),
            None,
        );
        Some(PreparedAnnouncement {
            outbounds: Self::outbound_interfaces(&self.interfaces)
                .map(|interface| ProtocolOutbound {
                    interface,
                    packet: packet.clone(),
                    priority: 0,
                })
                .collect(),
            service,
            ratchets,
            restart_ratchet,
        })
    }

    pub(crate) fn commit_announcement(
        &mut self,
        announcement: PreparedAnnouncement,
    ) -> Option<crate::RatchetSecret> {
        if let Some(ratchets) = announcement.ratchets {
            self.services[announcement.service.0]
                .as_mut()
                .expect("announced service disappeared")
                .ratchets = ratchets;
        }
        announcement.restart_ratchet
    }

    pub fn has_path(&self, destination: DestinationAddress) -> bool {
        self.path_table.contains_key(&destination)
    }

    pub fn request_path(&mut self, destination: DestinationAddress, now: MonoTime) {
        log::info!(
            "Sending path request for <{}> on {} interface(s)",
            hex::encode(destination),
            Self::outbound_interfaces(&self.interfaces).count()
        );
        self.pending_path_requests.insert(destination, now);
        self.schedule_timer(
            now.checked_add(TimeSpan::from_secs(PATH_REQUEST_TIMEOUT_SECS))
                .expect("path request deadline overflow"),
            ProtocolTimer::PathRequestTimeout(destination),
        );

        let mut tag = [0u8; 16];
        self.rng.fill_bytes(&mut tag);

        let packet = Packet::PathRequest {
            hops: 0,
            query_destination: destination,
            requesting_transport: None,
            tag,
        };

        for interface in 0..self.interfaces.len() {
            if !self.interfaces[interface].accepts_outbound() {
                continue;
            }
            log::info!("Sending path request on interface {}", interface);
            self.queue_packet(interface, packet.clone(), 0);
        }
    }

    pub(crate) fn prepare_destination_datagram(
        &mut self,
        destination: DestinationAddress,
        data: &[u8],
    ) -> Result<ProtocolOutbound, SendError> {
        if !self.path_table.contains_key(&destination) {
            return Err(SendError::NoRoute);
        }
        use crate::crypto::SingleDestEncryption;
        let entry = &self.path_table[&destination];
        let target_key = entry.encryption_key();
        let (ephemeral_pub, ciphertext) =
            SingleDestEncryption::encrypt(&mut self.rng, &target_key, data);
        let mut payload = ephemeral_pub.as_bytes().to_vec();
        payload.extend(ciphertext);
        let packet = Packet::SingleData {
            hops: 0,
            destination: if entry.hops > 1 {
                RoutedDestination::via(entry.next_hop, destination)
            } else {
                RoutedDestination::direct(destination)
            },
            ciphertext: payload,
        };
        Ok(ProtocolOutbound {
            interface: entry.receiving_interface,
            packet,
            priority: 0,
        })
    }

    pub(crate) fn prepare_link_datagram(
        &mut self,
        link: LinkId,
        data: &[u8],
    ) -> Result<ProtocolOutbound, LinkError> {
        let established = self
            .established_links
            .get(&link)
            .ok_or(LinkError::LinkClosed)?;
        if !established.is_active() {
            return Err(LinkError::LinkClosed);
        }
        let receiving_interface = established.receiving_interface;
        let packet = self
            .make_encrypted_link_packet(link, LinkContext::None, data)
            .map_err(|_| LinkError::LinkClosed)?;
        Ok(ProtocolOutbound {
            interface: receiving_interface,
            packet,
            priority: 0,
        })
    }

    pub fn try_queue_channel_message(
        &mut self,
        link: LinkId,
        message: &ChannelMessage,
        now: MonoTime,
    ) -> Result<[u8; 32], QueueChannelError> {
        self.send_channel_data(link, message.message_type().get(), message.body(), now)
    }

    pub(crate) fn send_buffer_data(
        &mut self,
        link: LinkId,
        raw: &[u8],
        now: MonoTime,
    ) -> Result<[u8; 32], QueueChannelError> {
        self.send_channel_data(link, crate::buffer::STREAM_MESSAGE_TYPE, raw, now)
    }

    fn send_channel_data(
        &mut self,
        link_id: LinkId,
        message_type: u16,
        data: &[u8],
        now: MonoTime,
    ) -> Result<[u8; 32], QueueChannelError> {
        let link = self
            .established_links
            .get_mut(&link_id)
            .ok_or(QueueChannelError::LinkNotFound)?;
        if !link.is_active() {
            return Err(QueueChannelError::LinkNotActive);
        }
        let raw = link
            .channel
            .as_mut()
            .ok_or(QueueChannelError::LinkNotActive)?
            .protocol_state
            .prepare(message_type, data)?;
        let packet = self.make_encrypted_link_packet(link_id, LinkContext::Channel, &raw)?;
        let target_interface = self.established_links[&link_id].receiving_interface;
        self.queue_packet(target_interface, packet.clone(), 0);
        let hash = packet.packet_hash();
        self.established_links
            .get_mut(&link_id)
            .expect("link disappeared")
            .channel
            .as_mut()
            .expect("channel disappeared")
            .protocol_state
            .track(packet, now);
        self.schedule_channel_retry(link_id);
        Ok(hash)
    }

    pub(crate) fn open_channel(&mut self, link_id: LinkId) -> Result<(), QueueChannelError> {
        let link = self
            .established_links
            .get_mut(&link_id)
            .ok_or(QueueChannelError::LinkNotFound)?;
        if !link.is_active() {
            return Err(QueueChannelError::LinkNotActive);
        }
        if link.channel.is_some() {
            return Err(QueueChannelError::AlreadyOpen);
        }
        Ok(())
    }

    pub fn remove_link_state(&mut self, link: LinkId) -> Option<Vec<RequestId>> {
        let existed = self.established_links.contains_key(&link)
            || self.pending_outbound_links.contains_key(&link);
        if let Some(established) = self.established_links.get(&link) {
            let interface = established.receiving_interface;
            let data = established.encrypt(&mut self.rng, &link);
            self.queue_packet(
                interface,
                Packet::LinkData {
                    hops: 0,
                    destination: RoutedDestination::direct(link),
                    context: LinkContext::LinkClose,
                    data,
                },
                0,
            );
        }
        if let Some(l) = self.established_links.get(&link) {
            let dest = l.destination;
            self.destination_links.remove(&dest);
        }
        let requests = self
            .established_links
            .remove(&link)
            .map(|link| link.pending_requests.into_values().collect())
            .unwrap_or_default();
        self.pending_outbound_links.remove(&link);
        existed.then_some(requests)
    }

    pub(crate) fn prepare_identify(
        &mut self,
        link_id: LinkId,
        service: ServiceId,
    ) -> Result<PreparedIdentify, crate::IdentifyError> {
        let link = self
            .established_links
            .get(&link_id)
            .ok_or(crate::IdentifyError::LinkClosed)?;
        if !link.is_active() || !link.is_initiator() {
            return Err(crate::IdentifyError::LinkClosed);
        }
        let interface = link.receiving_interface;
        let local_identity = link.local_identity;
        let service = &self
            .services
            .get(service.0)
            .and_then(Option::as_ref)
            .ok_or(crate::IdentifyError::ServiceClosed)?;
        let encryption_public = *X25519Public::from(&service.encryption_secret).as_bytes();
        let mut public_keys = [0; 64];
        public_keys[..32].copy_from_slice(&encryption_public);
        public_keys[32..].copy_from_slice(service.signing_key.verifying_key().as_bytes());
        let identity = sha256(&public_keys)[..16]
            .try_into()
            .expect("identity hash");
        if let crate::link::LocalIdentityState::Bound(bound) = local_identity
            && bound != identity
        {
            return Err(crate::IdentifyError::BoundToDifferentIdentity);
        }
        let identify =
            crate::link::LinkIdentify::create(&link_id, encryption_public, &service.signing_key);
        let packet = self
            .make_encrypted_link_packet(link_id, LinkContext::LinkIdentify, &identify.to_bytes())
            .map_err(|_| crate::IdentifyError::LinkClosed)?;
        Ok(PreparedIdentify {
            outbound: ProtocolOutbound {
                interface,
                packet,
                priority: 0,
            },
            identity,
        })
    }

    pub(crate) fn commit_identify(&mut self, link: LinkId, identify: &PreparedIdentify) {
        let link = self
            .established_links
            .get_mut(&link)
            .expect("identified link disappeared");
        if matches!(
            link.local_identity,
            crate::link::LocalIdentityState::Anonymous
        ) {
            link.local_identity = crate::link::LocalIdentityState::Bound(identify.identity);
        }
    }

    pub(crate) fn begin_outbound_link(
        &mut self,
        destination: DestinationAddress,
        now: MonoTime,
        handshake_timeout: TimeSpan,
        open: crate::runtime::PendingOpenLink,
    ) -> LinkId {
        let path_entry = self
            .path_table
            .get(&destination)
            .expect("link route disappeared");
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
        let packet = Packet::LinkRequest {
            hops: 0,
            destination: transport_id.map_or_else(
                || RoutedDestination::direct(destination),
                |transport| RoutedDestination::via(transport, destination),
            ),
            data: request_data.clone(),
        };
        let link_id = LinkRequest::link_id_from_packet(&packet.hashable_part(), request_data.len());

        // Store pending link
        self.pending_outbound_links.insert(
            link_id,
            PendingLink {
                link_id,
                initiator_encryption_secret: ephemeral.secret,
                initiator_signing_key: signing_key,
                responder_signing_key: path_entry.announce.signing_key,
                destination,
                local_service: None,
                request_time: now,
                open: Some(open),
            },
        );
        self.schedule_timer(
            now.checked_add(handshake_timeout)
                .expect("link establishment deadline overflow"),
            ProtocolTimer::PendingLinkTimeout(link_id),
        );

        // Send on the interface that received the announce
        log::debug!(
            "Sending link request to <{}> link_id=<{}>",
            hex::encode(destination),
            hex::encode(link_id)
        );
        self.queue_packet(target_interface, packet, 0);
        link_id
    }

    pub(crate) fn accept_incoming_link(&mut self, link_id: LinkId, now: MonoTime) -> bool {
        let Some(pending) = self.pending_inbound_links.remove(&link_id) else {
            return false;
        };
        let responder = EphemeralKeyPair::generate(&mut self.rng);
        let Some(signing_key) = self.services[pending.service.0]
            .as_ref()
            .map(|service| service.signing_key.clone())
        else {
            return false;
        };
        let Some(peer_signing_key) = VerifyingKey::from_bytes(&pending.request.signing_public).ok()
        else {
            return false;
        };
        let link = EstablishedLink::from_responder(
            link_id,
            LinkResponder {
                destination: pending.destination,
                service: pending.service,
                encryption_secret: &responder.secret,
                signing_key: signing_key.clone(),
            },
            &pending.request.encryption_public,
            peer_signing_key,
            pending.interface,
            now,
        );
        let proof = LinkProof::create(&link_id, &responder.public, &signing_key);
        let packet = Packet::LinkProof {
            hops: 0,
            destination: RoutedDestination::direct(link_id),
            data: proof.to_bytes(),
        };
        self.established_links.insert(link_id, link);
        self.destination_links.insert(pending.destination, link_id);
        self.schedule_link_maintenance(link_id);
        self.queue_packet(pending.interface, packet, 0)
    }

    pub(crate) fn reject_incoming_link(&mut self, link_id: LinkId) -> bool {
        self.pending_inbound_links.remove(&link_id).is_some()
    }

    fn accept_packet(&self, packet: &Packet, packet_hash: &[u8; 32]) -> bool {
        use crate::packet::LinkContext;

        if !matches!(packet, Packet::Announce { .. })
            && packet
                .transport_id()
                .is_some_and(|tid| tid != self.relay_address)
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
        if self.seen_packets.contains(packet_hash) {
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
        mut packet: Packet,
        packet_hash: [u8; 32],
        interface_index: usize,
        now: MonoTime,
    ) {
        let mut link_datagrams = Vec::new();
        let mut channel_deliveries = Vec::new();
        let mut delivered_packets = Vec::new();
        let mut request_results = Vec::new();
        let mut inbound_requests = Vec::new();
        let mut pending_next_segments: Vec<(LinkId, [u8; 32])> = Vec::new();

        if !self.accept_packet(&packet, &packet_hash) {
            return;
        }

        packet.increment_hops();

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
            && self
                .services
                .iter()
                .flatten()
                .any(|s| s.address == destination_hash);

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
            let local_service = self
                .services
                .iter()
                .flatten()
                .find(|s| s.address == query_dest);
            if let Some(entry) = local_service {
                log::debug!(
                    "Answering path request for <{}>, destination is local",
                    hex::encode(query_dest)
                );

                // Create PATH_RESPONSE announce for the local service
                let mut random_hash = [0u8; 10];
                self.rng.fill_bytes(&mut random_hash);

                let builder = AnnounceBuilder::new(
                    *X25519Public::from(&entry.encryption_secret).as_bytes(),
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
                    Some(self.relay_address),
                );

                // Send only to the requesting interface
                self.queue_packet(interface_index, response_packet, 0);
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
                    path_entry.announce.ratchet.is_some(),
                    true, // is_path_response
                    path_entry.announce.to_bytes(),
                    Some(self.relay_address),
                );

                // Send only to the requesting interface
                self.queue_packet(interface_index, response_packet, 0);
            } else if self.relays_packets {
                // Unknown path, but we're a transport node - record and forward
                let other_interfaces = Self::outbound_interfaces(&self.interfaces)
                    .count()
                    .saturating_sub(1);
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
                    requesting_transport: Some(self.relay_address),
                    tag: request_tag,
                };

                // Forward path request on all other interfaces
                for interface in 0..self.interfaces.len() {
                    if interface != interface_index && self.interfaces[interface].accepts_outbound()
                    {
                        self.queue_packet(interface, new_packet.clone(), 0);
                    }
                }
            }
        }

        // General transport handling. Takes care of directing packets according
        // to transport tables and recording entries in reverse and link tables.
        let mut relayed_via_link_table = false;
        if self.relays_packets || for_local_service || for_local_link {
            // TODO missing cache request handling

            // If the packet is in transport (has transport_id), check whether we
            // are the designated next hop, and process it accordingly if we are.
            if let Some(transport_id) = packet.transport_id()
                && transport_id == self.relay_address
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
                                timestamp: now,
                                receiving_interface: interface_index,
                            },
                        );
                        self.timers.schedule(ScheduledTimer {
                            at: now
                                .checked_add(REVERSE_TIMEOUT)
                                .and_then(|at| at.checked_add(TimeSpan::from_micros(1)))
                                .expect("reverse path expiry overflow"),
                            event: ProtocolTimer::ReversePathExpiry(destination_hash),
                        });
                    }

                    // Transmit on outbound interface
                    if self
                        .interfaces
                        .get_mut(outbound_interface)
                        .is_some_and(|slot| slot.enqueue_protocol_packet(0, &new_packet))
                    {
                        path_entry.timestamp = now;
                        self.timers.schedule(ScheduledTimer {
                            at: now
                                .checked_add(PATH_TIMEOUT)
                                .and_then(|at| at.checked_add(TimeSpan::from_micros(1)))
                                .expect("path expiry overflow"),
                            event: ProtocolTimer::PathExpiry(dest),
                        });
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

                    if self
                        .interfaces
                        .get_mut(out_iface)
                        .is_some_and(|slot| slot.enqueue_protocol_packet(0, &packet))
                    {
                        link_entry.timestamp = now;
                        relayed_via_link_table = true;
                    }
                }
            }
        }

        // Skip local processing for packets that were relayed via link_table
        if relayed_via_link_table && !for_local_link {
            return;
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
                    Err(_) => return,
                };

                if announce.verify(&destination_hash).is_err() {
                    return;
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
                let is_local = self
                    .services
                    .iter()
                    .flatten()
                    .any(|s| s.address == destination_hash);

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
                    if self.relays_packets
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
                    let hops = packet.hops();

                    if hops > DEFAULT_MAX_HOPS {
                        log::debug!(
                            "Announce for <{}> exceeded max hops ({} >= {})",
                            hex::encode(destination_hash),
                            hops,
                            DEFAULT_MAX_HOPS + 1
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
                        let service_hash = announce.name_hash;
                        let application_data = announce.app_data.clone();
                        // Update path table
                        self.path_table.insert(
                            destination_hash,
                            PathEntry {
                                timestamp: now,
                                next_hop: received_from,
                                hops,
                                receiving_interface: interface_index,
                                announce,
                            },
                        );
                        self.schedule_path_expiry(destination_hash);
                        let application_data = bytes::Bytes::from(application_data);
                        for service in self.services.iter_mut().flatten() {
                            let _ = service.events.push(
                                ServiceEvent::Announce(crate::DiscoveredService {
                                    destination: crate::Destination::from_bytes(destination_hash),
                                    service_hash: crate::ServiceHash::from_bytes(service_hash),
                                    application_data: application_data.clone(),
                                }),
                                0,
                            );
                        }

                        // Schedule for rebroadcast with random delay
                        // PATH_RESPONSE announces are not rebroadcast (they're one-shot responses)
                        // Only schedule if we are a transport node (relay enabled)
                        if !is_path_response && self.relays_packets {
                            let delay_ms = self.rng.gen_range(0..=PATHFINDER_RW_MS);
                            let retry_at = now
                                .checked_add(TimeSpan::from_millis(delay_ms))
                                .expect("announce retry deadline overflow");
                            self.pending_announces
                                .retain(|pending| pending.destination != destination_hash);
                            self.pending_announces.push(PendingAnnounce {
                                destination: destination_hash,
                                source_interface: interface_index,
                                hops,
                                has_ratchet,
                                data: data.clone(),
                                retries_remaining: DEFAULT_RETRIES,
                                retry_at,
                                local_rebroadcasts: 0,
                            });
                            self.schedule_timer(
                                retry_at,
                                ProtocolTimer::AnnounceRetry(destination_hash),
                            );
                        }

                        log::debug!(
                            "Destination <{}> is now {} hops away via <{}>",
                            hex::encode(destination_hash),
                            hops,
                            hex::encode(received_from)
                        );

                        if self
                            .pending_path_requests
                            .remove(&destination_hash)
                            .is_some()
                        {
                            log::info!(
                                "Received announce for <{}> which we had a pending path request for",
                                hex::encode(destination_hash)
                            );
                            self.resolve_route(destination_hash, true, now);
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
                                Some(self.relay_address),
                            );

                            self.queue_packet(requesting_interface, response_packet, 0);
                        }
                    }
                }
            }
            Packet::LinkRequest { data, .. } => {
                let is_for_us = packet
                    .transport_id()
                    .is_none_or(|tid| tid == self.relay_address);
                log::debug!(
                    "Received LinkRequest for <{}> is_for_us={} for_local_service={}",
                    hex::encode(destination_hash),
                    is_for_us,
                    for_local_service
                );

                if is_for_us && for_local_service {
                    if self.at_link_capacity() {
                        return;
                    }
                    let Some(request) = LinkRequest::parse(&data) else {
                        return;
                    };
                    let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.as_ref().is_some_and(|s| s.address == destination_hash))
                    else {
                        return;
                    };
                    let new_link_id =
                        LinkRequest::link_id_from_packet(&packet.hashable_part(), data.len());
                    if self.established_links.contains_key(&new_link_id)
                        || self.pending_inbound_links.contains_key(&new_link_id)
                    {
                        return;
                    }
                    let service = ServiceId(service_idx);
                    self.pending_inbound_links.insert(
                        new_link_id,
                        PendingInboundLink {
                            destination: destination_hash,
                            service,
                            request,
                            interface: interface_index,
                        },
                    );
                    self.enqueue_incoming_link(service, new_link_id);
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
                        return;
                    }
                };
                link.touch_inbound(now);

                let decrypt = |link: &EstablishedLink, data: &[u8]| -> Option<Vec<u8>> {
                    match link.decrypt(data) {
                        Some(p) => Some(p),
                        None => {
                            log::warn!(
                                "Failed to decrypt LinkData on link {} (ctx={:?}, data_len={}, is_initiator={}, dest={})",
                                hex::encode(link_id),
                                context,
                                data.len(),
                                link.is_initiator(),
                                hex::encode(link.destination)
                            );
                            None
                        }
                    }
                };

                match context {
                    // === NOT ENCRYPTED ===
                    LinkContext::Resource => {
                        self.handle_resource_packet(link_id, context, &data, now);
                    }

                    LinkContext::CacheRequest => {
                        log::debug!(
                            "Received CacheRequest on link {} ({} bytes)",
                            hex::encode(link_id),
                            data.len()
                        );
                    }

                    LinkContext::Keepalive => {
                        self.handle_keepalive(link_id, &data);
                    }

                    // === ENCRYPTED ===
                    LinkContext::LinkRtt => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            self.handle_link_rtt(link_id, &plaintext);
                        }
                    }

                    LinkContext::LinkIdentify => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            self.handle_link_identify(link_id, &plaintext);
                        }
                    }

                    LinkContext::LinkClose => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            if plaintext.as_slice() == link_id {
                                let dest = link.destination;
                                log::info!(
                                    "Link <{}> closed by remote (dest=<{}>)",
                                    hex::encode(link_id),
                                    hex::encode(dest)
                                );
                                let requests =
                                    link.pending_requests.values().copied().collect::<Vec<_>>();
                                self.terminate_link_handles(
                                    link_id,
                                    crate::LinkCloseReason::RemoteClosed,
                                );
                                self.destination_links.remove(&dest);
                                self.established_links.remove(&link_id);
                                for request_id in requests {
                                    request_results.push((request_id, Err(LinkError::LinkClosed)));
                                }
                            } else {
                                log::warn!(
                                    "Received LinkClose with mismatched link_id: expected {}, got {}",
                                    hex::encode(link_id),
                                    hex::encode(&plaintext)
                                );
                            }
                        }
                    }

                    LinkContext::ResourceAdv
                    | LinkContext::ResourceReq
                    | LinkContext::ResourceHmu
                    | LinkContext::ResourceIcl
                    | LinkContext::ResourceRcl => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            self.handle_resource_packet(link_id, context, &plaintext, now);
                        }
                    }

                    LinkContext::Response => {
                        if let Some(plaintext) = decrypt(link, &data) {
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
                                if let Some(local_request_id) =
                                    link.pending_requests.remove(&resp.request_id)
                                {
                                    log::info!(
                                        "Matched pending request local_id={} - delivering {} bytes",
                                        hex::encode(local_request_id.0),
                                        resp.data.len()
                                    );
                                    request_results.push((local_request_id, Ok(resp.data)));
                                } else {
                                    log::warn!(
                                        "Response wire_request_id={} did not match any pending request",
                                        hex::encode(resp.request_id.0)
                                    );
                                }
                            } else {
                                log::warn!("Failed to decode Response from plaintext");
                            }
                        }
                    }

                    LinkContext::Request => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            if let Some(service) = link.local_service() {
                                if let Some(req) = Request::decode(&plaintext) {
                                    let wire_request_id = WireRequestId(
                                        packet.packet_hash()[..16].try_into().unwrap(),
                                    );
                                    let request_id = RequestId(wire_request_id.0);
                                    let service_entry = &self.services[service.0]
                                        .as_ref()
                                        .expect("link references removed service");
                                    let path =
                                        service_entry.registered_paths.get(&req.path_hash).cloned();
                                    log::info!(
                                        "Request path_hash={} matched={:?} registered_count={}",
                                        hex::encode(req.path_hash),
                                        path,
                                        service_entry.registered_paths.len()
                                    );
                                    inbound_requests.push((
                                        link_id,
                                        request_id,
                                        path.unwrap_or_default(),
                                        req.data.unwrap_or_default(),
                                    ));
                                } else {
                                    log::warn!(
                                        "Failed to decode Request from plaintext {} bytes",
                                        plaintext.len()
                                    );
                                }
                            } else {
                                log::warn!(
                                    "No local_service for Request: link_id={} context={:?}",
                                    hex::encode(link_id),
                                    context
                                );
                            }
                        }
                    }

                    LinkContext::Channel => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            let packet_hash = packet.packet_hash();
                            let signature = crate::crypto::sign(&link.signing_key, &packet_hash);
                            let mut proof_data = packet_hash.to_vec();
                            proof_data.extend_from_slice(&signature.to_bytes());
                            let proof = Packet::Proof {
                                hops: 0,
                                destination: crate::packet::ProofDestination::Link(link_id),
                                context: crate::packet::ProofContext::None,
                                data: proof_data,
                            };
                            let target_interface = link.receiving_interface;
                            let _ = self
                                .interfaces
                                .get_mut(target_interface)
                                .map(|slot| slot.enqueue_protocol_packet(0, &proof));
                            let Some(channel) = link.channel.as_mut() else {
                                self.close_link(link_id, crate::LinkCloseReason::ProtocolViolation);
                                return;
                            };
                            let messages = channel.protocol_state.receive(&plaintext);
                            for (message_type, data) in messages {
                                if message_type == crate::buffer::STREAM_MESSAGE_TYPE {
                                    if let Some((stream, chunk)) = crate::buffer::decode(&data) {
                                        channel_deliveries.push((
                                            link_id,
                                            crate::ChannelReceive::Buffer { stream, chunk },
                                        ));
                                    }
                                } else if let Ok(message_type) =
                                    crate::MessageType::new(message_type)
                                    && let Ok(message) =
                                        crate::ChannelMessage::new(message_type, data.into())
                                {
                                    channel_deliveries
                                        .push((link_id, crate::ChannelReceive::Message(message)));
                                }
                            }
                        }
                    }

                    LinkContext::None | LinkContext::Command | LinkContext::CommandStatus => {
                        if let Some(plaintext) = decrypt(link, &data) {
                            if link.local_service().is_some() {
                                link_datagrams.push((link_id, plaintext));
                            } else {
                                log::warn!(
                                    "No local_service for link data: link_id={} context={:?}",
                                    hex::encode(link_id),
                                    context
                                );
                            }
                        }
                    }
                }
            }
            Packet::SingleData { ciphertext, .. } => {
                // Data for a single destination - decrypt with service keys
                // Packet data format: ephemeral_public (32) + ciphertext
                if ciphertext.len() >= 32
                    && let Some(service_idx) = self
                        .services
                        .iter()
                        .position(|s| s.as_ref().is_some_and(|s| s.address == destination_hash))
                {
                    let service = &self.services[service_idx]
                        .as_ref()
                        .expect("located service");

                    let ephemeral_public =
                        X25519Public::from(<[u8; 32]>::try_from(&ciphertext[..32]).unwrap());
                    if let Some(data) = service.decrypt(&ephemeral_public, &ciphertext[32..]) {
                        let _ = self.services[service_idx]
                            .as_mut()
                            .expect("located service")
                            .events
                            .push(ServiceEvent::Datagram(data.into()), 0);
                    }
                }
            }
            Packet::GroupData { .. } | Packet::PathRequest { .. } => {
                // GroupData: would need group decryption (not implemented)
                // PathRequest: handled by transport layer, not delivered to services
            }
            Packet::LinkProof { data, .. } => {
                log::info!(
                    "Received LinkProof: dest_from_packet=<{}> pending_links={:?}",
                    hex::encode(destination_hash),
                    self.pending_outbound_links
                        .keys()
                        .map(hex::encode)
                        .collect::<Vec<_>>()
                );
                // Link request proof - check if it needs to be transported
                if let Some(receiving_interface) = self.link_table.get(&link_id).and_then(|entry| {
                    (interface_index == entry.next_hop_interface)
                        .then_some(entry.receiving_interface)
                }) {
                    // Transport the proof
                    let _ = self.queue_packet(receiving_interface, packet.clone(), 0);
                } else if let Some(mut pending) =
                    self.pending_outbound_links.remove(&destination_hash)
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
                            return;
                        }
                    };

                    // Get the destination's signing key from path_table
                    let signing_key = match self.path_table.get(&pending.destination) {
                        Some(entry) => entry.announce.signing_key,
                        None => {
                            log::debug!(
                                "No path found for destination <{}>",
                                hex::encode(pending.destination)
                            );
                            self.pending_outbound_links
                                .insert(destination_hash, pending);
                            return;
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
                        return;
                    }

                    // Establish the link using the responder's public key from the proof
                    let dest = pending.destination;
                    let open = pending
                        .open
                        .take()
                        .expect("pending link open state disappeared");
                    let link = EstablishedLink::from_initiator(
                        pending,
                        &proof.encryption_public,
                        interface_index,
                        now,
                    );
                    let rtt_secs = link.rtt().map(|rtt| rtt.as_secs_f64());

                    self.established_links.insert(destination_hash, link);
                    self.destination_links.insert(dest, destination_hash);
                    self.schedule_link_maintenance(destination_hash);
                    self.complete_link_open(destination_hash, open, Ok(()));

                    // Send LRRTT packet to inform responder of the measured RTT
                    if let Some(rtt) = rtt_secs {
                        let rtt_data = crate::link::encode_rtt(rtt);
                        if let Some(link) = self.established_links.get_mut(&destination_hash) {
                            link.touch_outbound(now);
                        }
                        self.send_link_packet(destination_hash, LinkContext::LinkRtt, &rtt_data);
                    }

                    let link = self.established_links.get(&destination_hash).unwrap();
                    log::debug!(
                        "Link <{}> established as initiator, RTT: {:?}ms, keepalive_interval: {}s",
                        hex::encode(destination_hash),
                        link.rtt().map(|rtt| rtt.as_millis()),
                        link.keepalive_interval_secs()
                    );
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
                        if let Some((link_id, outbound)) =
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
                                self.outbound_resources.remove(&resource_hash);

                                if is_last_segment {
                                    // Last segment - clean up and notify
                                    self.outbound_multi_segments.remove(&original_hash);
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
                    if let Some(reverse_entry) = self.reverse_table.remove(&destination_hash) {
                        let _ =
                            self.queue_packet(reverse_entry.receiving_interface, packet.clone(), 0);
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
                        if let Some(Some(proof_hash)) = proof_hash {
                            let valid =
                                self.established_links
                                    .get(&destination_hash)
                                    .is_some_and(|link| {
                                        crate::crypto::verify(
                                            &link.peer_signing_key,
                                            &proof_hash,
                                            &signature,
                                        )
                                    });
                            let tracked = self
                                .established_links
                                .get(&destination_hash)
                                .and_then(|link| link.channel.as_ref())
                                .is_some_and(|channel| {
                                    channel
                                        .protocol_state
                                        .pending_hashes()
                                        .any(|hash| hash == proof_hash)
                                });
                            log::trace!(
                                "Link proof link={} packet={} valid={} tracked={}",
                                hex::encode(destination_hash),
                                hex::encode(proof_hash),
                                valid,
                                tracked
                            );
                            if valid
                                && let Some(channel) = self
                                    .established_links
                                    .get_mut(&destination_hash)
                                    .and_then(|link| link.channel.as_mut())
                                && channel.protocol_state.delivered(&proof_hash)
                            {
                                delivered_packets.push(proof_hash);
                            }
                        }
                        self.receipts.retain(|receipt| {
                            // For explicit proofs, check hash matches
                            if let Some(Some(ph)) = proof_hash
                                && ph != receipt.packet_hash
                            {
                                return true; // Keep - not for this receipt
                            }

                            // Get destination's signing key to verify
                            let signing_key = match self.path_table.get(&receipt.destination) {
                                Some(entry) => &entry.announce.signing_key,
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

        for (link, data) in link_datagrams {
            self.enqueue_link_datagram(link, data);
        }
        for (link, delivery) in channel_deliveries {
            self.enqueue_channel_event(link, delivery);
        }
        for packet in delivered_packets {
            self.handle_channel_delivery(destination_hash, packet, true, now);
        }
        for (request, result) in request_results {
            self.complete_request(request, result);
        }
        for (link, request, path, data) in inbound_requests {
            self.handle_incoming_request(link, request, path, data, now);
        }

        self.schedule_channel_retry(destination_hash);
        self.schedule_link_maintenance(link_id);

        for (link_id, original_hash) in pending_next_segments {
            self.send_next_segment(link_id, original_hash);
        }
    }

    fn send_next_segment(&mut self, link_id: LinkId, original_hash: [u8; 32]) {
        use crate::packet::RoutedDestination;
        use crate::resource::MAX_EFFICIENT_SIZE;

        let Some(multi) = self.outbound_multi_segments.get_mut(&original_hash) else {
            log::warn!(
                "send_next_segment: no multi-segment transfer for {}",
                hex::encode(original_hash)
            );
            return;
        };

        let total_segments = multi.full_data.len().div_ceil(MAX_EFFICIENT_SIZE);
        let next_segment = multi.current_segment + 1;
        if next_segment > total_segments {
            log::warn!(
                "send_next_segment: already sent all {} segments for {}",
                total_segments,
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
            multi.request_id.clone(),
            crate::resource::ResourceSegment::Continuation {
                previous_segments: std::num::NonZeroUsize::new(multi.current_segment).unwrap(),
                original_hash,
                total_data_size: multi.full_data.len(),
            },
        );

        let adv = resource.advertisement(91);
        let adv_data = adv.encode();
        let hash = resource.hash;

        log::debug!(
            "Sending segment {}/{} for multi-segment transfer {}",
            next_segment,
            total_segments,
            hex::encode(original_hash)
        );

        let ciphertext = link.encrypt(&mut self.rng, &adv_data);
        let packet = Packet::LinkData {
            hops: 0,
            destination: RoutedDestination::direct(link_id),
            context: LinkContext::ResourceAdv,
            data: ciphertext,
        };

        multi.current_segment = next_segment;

        self.outbound_resources.insert(hash, (link_id, resource));

        self.queue_packet(target_interface, packet, 0);
    }

    fn send_link_packet(&mut self, link_id: LinkId, context: LinkContext, plaintext: &[u8]) {
        let Ok(packet) = self.make_encrypted_link_packet(link_id, context, plaintext) else {
            return;
        };
        let target_interface = self.established_links[&link_id].receiving_interface;

        self.queue_packet(target_interface, packet, 0);
    }

    fn make_encrypted_link_packet(
        &mut self,
        link_id: LinkId,
        context: LinkContext,
        plaintext: &[u8],
    ) -> Result<Packet, QueueChannelError> {
        use crate::packet::RoutedDestination;

        let link = self
            .established_links
            .get(&link_id)
            .ok_or(QueueChannelError::LinkNotFound)?;
        let data = link.encrypt(&mut self.rng, plaintext);
        Ok(Packet::LinkData {
            hops: 0,
            destination: RoutedDestination::direct(link_id),
            context,
            data,
        })
    }

    fn outbound(&mut self, mut packet: Packet, attached_interface: Option<usize>, now: MonoTime) {
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
            self.queue_packet(outbound_interface, packet, 0);

            // Update path timestamp
            if let Some(entry) = self.path_table.get_mut(&destination_hash) {
                entry.timestamp = now;
            }
            self.schedule_path_expiry(destination_hash);

            return;
        }

        // No known path - broadcast on all interfaces (with filtering)
        let mut first = true;

        for interface in 0..self.interfaces.len() {
            if !self.interfaces[interface].accepts_outbound() {
                continue;
            }
            // If packet has an attached interface, skip that one (don't echo back)
            if attached_interface == Some(interface) {
                continue;
            }

            // Announce rate limiting is handled by interface.send()
            // which queues announces based on hop count priority

            if first {
                self.seen_packets.insert(packet.packet_hash());
                if generate_receipt {
                    self.receipts.push(Receipt {
                        destination: destination_hash,
                        packet_hash: packet.packet_hash(),
                    });
                }
                first = false;
            }

            self.queue_packet(interface, packet.clone(), hops);
        }
    }

    pub(crate) fn handle_packets(&mut self, now: MonoTime, received: Vec<PreparedInbound>) {
        for received in received {
            let PreparedInbound {
                packet,
                packet_hash,
                source,
            } = received;
            log::trace!("[RECV] interface={source} {}", packet.log_format());
            self.inbound(packet, packet_hash, source, now);
        }

        // Process batched resource requests (deduplicated)
        for (link_id, hash) in std::mem::take(&mut self.pending_resource_requests) {
            self.send_resource_request(link_id, hash, now);
        }
    }

    pub(crate) fn handle_timer(&mut self, now: MonoTime, scheduled: ScheduledTimer) {
        let ScheduledTimer { at, event } = scheduled;
        if now < at {
            return;
        }
        match event {
            ProtocolTimer::AnnounceRetry(destination) => {
                let Some(index) = self.pending_announces.iter().position(|pending| {
                    pending.destination == destination
                        && pending.retry_at == at
                        && pending.retries_remaining > 0
                }) else {
                    return;
                };
                let (hops, has_ratchet, data, source, next_retry) = {
                    let pending = &mut self.pending_announces[index];
                    pending.retries_remaining -= 1;
                    let next_retry = if pending.retries_remaining > 0 {
                        pending.retry_at = now
                            .checked_add(TimeSpan::from_millis(DEFAULT_RETRY_DELAY_MS))
                            .expect("announce retry deadline overflow");
                        Some(pending.retry_at)
                    } else {
                        None
                    };
                    (
                        pending.hops,
                        pending.has_ratchet,
                        pending.data.clone(),
                        pending.source_interface,
                        next_retry,
                    )
                };
                let packet = self.make_announce_packet(
                    destination,
                    hops,
                    has_ratchet,
                    false,
                    data,
                    Some(self.relay_address),
                );
                if let Some(retry_at) = next_retry {
                    self.schedule_timer(retry_at, ProtocolTimer::AnnounceRetry(destination));
                } else {
                    self.pending_announces.swap_remove(index);
                }
                self.outbound(packet, Some(source), now);
            }
            ProtocolTimer::PathExpiry(destination) => {
                if self.path_table.get(&destination).is_some_and(|entry| {
                    entry
                        .timestamp
                        .checked_add(PATH_TIMEOUT)
                        .and_then(|at| at.checked_add(TimeSpan::from_micros(1)))
                        == Some(at)
                }) {
                    self.path_table.remove(&destination);
                }
            }
            ProtocolTimer::ReversePathExpiry(destination) => {
                if self.reverse_table.get(&destination).is_some_and(|entry| {
                    entry
                        .timestamp
                        .checked_add(REVERSE_TIMEOUT)
                        .and_then(|at| at.checked_add(TimeSpan::from_micros(1)))
                        == Some(at)
                }) {
                    self.reverse_table.remove(&destination);
                }
            }
            ProtocolTimer::ChannelRetry(link) => {
                let rtt = self
                    .established_links
                    .get(&link)
                    .and_then(EstablishedLink::rtt)
                    .unwrap_or(TimeSpan::from_millis(25));
                let Some(channel) = self
                    .established_links
                    .get_mut(&link)
                    .and_then(|link| link.channel.as_mut())
                else {
                    return;
                };
                if channel.protocol_state.next_retry(rtt) != Some(at) {
                    return;
                }
                let (packets, failed) = channel.protocol_state.retries(now, rtt);
                if failed {
                    let failed_packets: Vec<_> = channel.protocol_state.pending_hashes().collect();
                    for packet in failed_packets {
                        self.handle_channel_delivery(link, packet, false, now);
                    }
                    self.close_link_channel(link, crate::ChannelReceiveError::ChannelClosed);
                } else {
                    if let Some(interface) = self
                        .established_links
                        .get(&link)
                        .map(|link| link.receiving_interface)
                    {
                        for packet in packets {
                            self.queue_packet(interface, packet, 0);
                        }
                    }
                    self.schedule_channel_retry(link);
                }
            }
            ProtocolTimer::PendingLinkTimeout(link) => {
                let mut pending = self
                    .pending_outbound_links
                    .remove(&link)
                    .expect("timed out pending link disappeared");
                let open = pending
                    .open
                    .take()
                    .expect("pending link open state disappeared");
                self.complete_link_open(link, open, Err(crate::LinkError::TimedOut));
            }
            ProtocolTimer::PathRequestTimeout(destination) => {
                if self
                    .pending_path_requests
                    .get(&destination)
                    .is_none_or(|requested| {
                        requested.checked_add(TimeSpan::from_secs(PATH_REQUEST_TIMEOUT_SECS))
                            != Some(at)
                    })
                {
                    return;
                }
                self.pending_path_requests.remove(&destination);
                self.resolve_route(destination, false, now);
            }
            ProtocolTimer::RequestTimeout(request) => {
                let mut removed = false;
                for link in self.established_links.values_mut() {
                    let before = link.pending_requests.len();
                    link.pending_requests
                        .retain(|_, pending| *pending != request);
                    removed |= link.pending_requests.len() != before;
                }
                if removed {
                    self.complete_request(request, Err(LinkError::TimedOut));
                }
            }
            ProtocolTimer::LinkMaintenance(link_id) => {
                let Some(link) = self.established_links.get(&link_id) else {
                    return;
                };
                if Self::link_maintenance_at(link) != Some(at) {
                    return;
                }
                let stale = now.duration_since(link.last_inbound)
                    >= TimeSpan::from_secs(link.stale_time_secs())
                    && link.pending_requests.is_empty();
                let keepalive = link.is_initiator()
                    && link.is_active()
                    && now.duration_since(link.last_inbound)
                        >= TimeSpan::from_secs(link.keepalive_interval_secs())
                    && link.last_keepalive_sent.is_none_or(|sent| {
                        now.duration_since(sent)
                            >= TimeSpan::from_secs(link.keepalive_interval_secs())
                    });
                if stale {
                    let destination = link.destination;
                    let interface = link.receiving_interface;
                    let data = link.encrypt(&mut self.rng, &link_id);
                    let packet = Packet::LinkData {
                        hops: 0,
                        destination: crate::packet::RoutedDestination::direct(link_id),
                        context: LinkContext::LinkClose,
                        data,
                    };
                    self.queue_packet(interface, packet, 0);
                    self.destination_links.remove(&destination);
                    self.terminate_link_handles(link_id, crate::LinkCloseReason::IdleTimeout);
                    let requests = self
                        .established_links
                        .remove(&link_id)
                        .into_iter()
                        .flat_map(|link| link.pending_requests.into_values())
                        .collect::<Vec<_>>();
                    for request_id in requests {
                        self.complete_request(request_id, Err(LinkError::LinkClosed));
                    }
                } else {
                    if keepalive {
                        let interface = link.receiving_interface;
                        let packet = Packet::LinkData {
                            hops: 0,
                            destination: crate::packet::RoutedDestination::direct(link_id),
                            context: LinkContext::Keepalive,
                            data: vec![crate::link::KEEPALIVE_REQUEST],
                        };
                        if let Some(link) = self.established_links.get_mut(&link_id) {
                            link.last_keepalive_sent = Some(now);
                            link.touch_outbound(now);
                        }
                        self.queue_packet(interface, packet, 0);
                    }
                    self.schedule_link_maintenance(link_id);
                }
            }
        }
    }

    fn handle_keepalive(&mut self, link_id: LinkId, data: &[u8]) {
        use crate::link::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE};
        use crate::packet::RoutedDestination;

        if data.is_empty() {
            return;
        }

        let Some(link) = self.established_links.get(&link_id) else {
            return;
        };

        let is_initiator = link.is_initiator();
        let target_interface = link.receiving_interface;

        if data[0] == KEEPALIVE_REQUEST && !is_initiator {
            log::debug!(
                "Received keepalive request on link {}, sending response",
                hex::encode(link_id)
            );
            let packet = Packet::LinkData {
                hops: 0,
                destination: RoutedDestination::direct(link_id),
                context: LinkContext::Keepalive,
                data: vec![KEEPALIVE_RESPONSE],
            };
            self.queue_packet(target_interface, packet, 0);
        } else if data[0] == KEEPALIVE_RESPONSE && is_initiator {
            log::debug!(
                "Received keepalive response on link {}",
                hex::encode(link_id)
            );
        } else {
            log::warn!(
                "Unexpected keepalive byte 0x{:02x} on link {} (is_initiator={})",
                data[0],
                hex::encode(link_id),
                is_initiator
            );
        }
    }

    fn handle_link_rtt(&mut self, link_id: LinkId, plaintext: &[u8]) {
        use crate::link::decode_rtt;

        // LRRTT packet from initiator telling responder the measured RTT
        if let Some(rtt_secs) = decode_rtt(plaintext)
            && let Some(link) = self.established_links.get_mut(&link_id)
            && !link.is_initiator()
        {
            let rtt_ms = (rtt_secs * 1000.0) as u64;
            link.activate(rtt_ms);
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
            self.complete_identification(
                link_id,
                Err(crate::LinkCloseReason::AuthenticationFailed),
            );
            return;
        };

        if !identify.verify(&link_id) {
            log::warn!(
                "LinkIdentify verification failed on link {}",
                hex::encode(link_id)
            );
            self.complete_identification(
                link_id,
                Err(crate::LinkCloseReason::AuthenticationFailed),
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
            match link.remote_identity {
                Some(current) if current == identity_hash => return,
                Some(_) => {
                    self.complete_identification(
                        link_id,
                        Err(crate::LinkCloseReason::AuthenticationFailed),
                    );
                    return;
                }
                None => {}
            }
        }
        self.complete_identification(link_id, Ok(identity_hash));
    }

    pub(crate) fn commit_remote_identity(&mut self, link: LinkId, identity: [u8; 16]) {
        if let Some(link) = self.established_links.get_mut(&link) {
            link.remote_identity = Some(identity);
        }
    }

    fn handle_resource_packet(
        &mut self,
        link_id: LinkId,
        context: LinkContext,
        plaintext: &[u8],
        now: MonoTime,
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
                        adv.request_id.is_some(),
                        adv.request_id.as_ref().map(hex::encode),
                        adv.segment_index,
                        adv.total_segments,
                        adv.total_segments > 1
                    );

                    // Auto-accept if this is a response to a pending request or a continuation
                    if adv.request_id.is_none() {
                        log::debug!("ResourceAdv not a response, ignoring");
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
                            let resource =
                                crate::resource::InboundResource::from_advertisement(&adv);
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
                                    let resource =
                                        crate::resource::InboundResource::from_advertisement(&adv);
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
                use crate::packet::RoutedDestination;

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
                let mut packets = Vec::new();
                if let Some((_, resource)) = self.outbound_resources.get_mut(&hash) {
                    for part_hash in requested_hashes {
                        if let Some(part_data) = resource.get_part(&part_hash) {
                            // Resource parts are already encrypted at the stream level,
                            // so we send them as raw data (no Token encryption)
                            let packet = Packet::LinkData {
                                hops: 0,
                                destination: RoutedDestination::direct(link_id),
                                context: LinkContext::Resource,
                                data: part_data.to_vec(),
                            };
                            packets.push(packet);
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
                            destination: RoutedDestination::direct(link_id),
                            context: LinkContext::ResourceHmu,
                            data: ciphertext,
                        };
                        packets.push(packet);
                    }
                }
                if let Some(interface) = target_interface {
                    for packet in packets {
                        self.queue_packet(interface, packet, 0);
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
                        if accepted {
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

                if let Some(hash) = completed {
                    self.complete_resource(link_id, hash, now);
                } else if let Some(hash) = need_more {
                    self.pending_resource_requests.insert((link_id, hash));
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
            }
            _ => {}
        }
    }

    fn complete_resource(&mut self, link_id: LinkId, hash: [u8; 32], _now: MonoTime) {
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
            resource.request_id.is_some()
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
        self.queue_packet(target_interface, packet, 0);

        let Some(req_id_bytes) = resource.request_id.as_ref() else {
            log::debug!(
                "Dropping unsolicited resource {} with {} bytes",
                hex::encode(hash),
                segment_data.len()
            );
            return;
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
                    let local_request_id = self
                        .established_links
                        .get_mut(&link_id)
                        .and_then(|l| l.pending_requests.remove(&wire_request_id))
                        .unwrap_or(RequestId([0; 16]));

                    MultiSegmentTransfer {
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
        let (final_data, _metadata, local_request_id) = if is_multi_segment {
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
            let (data, metadata) = split_metadata(transfer.accumulated_data, transfer.has_metadata);

            (data, metadata, transfer.local_request_id)
        } else {
            // Single-segment - extract metadata and get request info
            let (data, metadata) = split_metadata(segment_data, resource.has_metadata);

            let local_request_id = match self
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

            (data, metadata, local_request_id)
        };

        log::info!(
            "Delivering resource response: {} bytes (request_id={})",
            final_data.len(),
            hex::encode(local_request_id.0)
        );

        // Resource responses are msgpack [request_id, response_data] - extract response_data
        use serde_bytes::ByteBuf;
        let data = rmp_serde::from_slice::<(ByteBuf, ByteBuf)>(&final_data)
            .map(|(_, response_data)| response_data.into_vec())
            .unwrap_or(final_data);

        self.complete_request(local_request_id, Ok(data));
    }

    fn send_resource_request(&mut self, link_id: LinkId, hash: [u8; 32], now: MonoTime) {
        use crate::packet::RoutedDestination;
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
                destination: RoutedDestination::direct(link_id),
                context: LinkContext::ResourceReq,
                data: ciphertext,
            };
            self.queue_packet(target_interface, packet, 0);

            // Mark request sent for rate tracking
            if let Some((_, resource)) = self.inbound_resources.get_mut(&hash) {
                resource.mark_req_sent(now);
            }
        }
    }

    fn make_announce_packet(
        &self,
        dest: DestinationAddress,
        hops: u8,
        has_ratchet: bool,
        is_path_response: bool,
        data: Vec<u8>,
        transport_id: Option<DestinationAddress>,
    ) -> Packet {
        let destination = transport_id.map_or_else(
            || RoutedDestination::direct(dest),
            |transport| RoutedDestination::via(transport, dest),
        );
        Packet::Announce {
            hops,
            destination,
            has_ratchet,
            is_path_response,
            data,
        }
    }
}
