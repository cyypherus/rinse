use bytes::Bytes;

pub const ADDR_LEN: usize = 16;
pub type DestinationAddress = [u8; ADDR_LEN];

const DEST_SINGLE: u8 = 0b00;
const DEST_GROUP: u8 = 0b01;
const DEST_PLAIN: u8 = 0b10;
const DEST_LINK: u8 = 0b11;

const PKT_DATA: u8 = 0b00;
const PKT_ANNOUNCE: u8 = 0b01;
const PKT_LINKREQUEST: u8 = 0b10;
const PKT_PROOF: u8 = 0b11;

const CTX_LRPROOF: u8 = 0xFF;
const CTX_PATH_RESPONSE: u8 = 0x0B;

pub(crate) const PATH_REQUEST_DEST: DestinationAddress = [
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkContext {
    None = 0x00,
    Resource = 0x01,
    ResourceAdv = 0x02,
    ResourceReq = 0x03,
    ResourceHmu = 0x04,
    ResourceIcl = 0x06,
    ResourceRcl = 0x07,
    CacheRequest = 0x08,
    Request = 0x09,
    Response = 0x0A,
    Command = 0x0C,
    CommandStatus = 0x0D,
    Channel = 0x0E,
    Keepalive = 0xFA,
    LinkIdentify = 0xFB,
    LinkClose = 0xFC,
    LinkRtt = 0xFE,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofContext {
    None = 0x00,
    Resource = 0x01,
    ResourcePrf = 0x05,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Announce {
        hops: u8,
        destination: RoutedDestination,
        has_ratchet: bool,
        is_path_response: bool,
        data: Bytes,
    },
    Proof {
        hops: u8,
        destination: ProofDestination,
        context: ProofContext,
        data: Bytes,
    },
    LinkData {
        hops: u8,
        destination: RoutedDestination,
        context: LinkContext,
        data: Bytes,
    },
    LinkRequest {
        hops: u8,
        destination: RoutedDestination,
        data: Bytes,
    },
    LinkProof {
        hops: u8,
        destination: RoutedDestination,
        data: Bytes,
    },
    PathRequest {
        hops: u8,
        query_destination: DestinationAddress,
        requesting_transport: Option<DestinationAddress>,
        tag: DestinationAddress,
    },
    SingleData {
        hops: u8,
        destination: RoutedDestination,
        ciphertext: Bytes,
    },
    GroupData {
        hops: u8,
        destination: DestinationAddress,
        ciphertext: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofDestination {
    Single(DestinationAddress),
    Link(DestinationAddress),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoutedDestination {
    address: DestinationAddress,
    transport: Option<DestinationAddress>,
}

impl RoutedDestination {
    pub(crate) fn direct(address: DestinationAddress) -> Self {
        Self {
            address,
            transport: None,
        }
    }

    pub(crate) fn via(transport: DestinationAddress, address: DestinationAddress) -> Self {
        Self {
            address,
            transport: Some(transport),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidContext,
    InvalidDestinationType,
    InvalidPacketType,
}

impl LinkContext {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Resource),
            0x02 => Some(Self::ResourceAdv),
            0x03 => Some(Self::ResourceReq),
            0x04 => Some(Self::ResourceHmu),
            0x06 => Some(Self::ResourceIcl),
            0x07 => Some(Self::ResourceRcl),
            0x08 => Some(Self::CacheRequest),
            0x09 => Some(Self::Request),
            0x0A => Some(Self::Response),
            0x0C => Some(Self::Command),
            0x0D => Some(Self::CommandStatus),
            0x0E => Some(Self::Channel),
            0xFA => Some(Self::Keepalive),
            0xFB => Some(Self::LinkIdentify),
            0xFC => Some(Self::LinkClose),
            0xFE => Some(Self::LinkRtt),
            _ => None,
        }
    }
}

impl ProofContext {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Resource),
            0x05 => Some(Self::ResourcePrf),
            _ => None,
        }
    }
}

impl Packet {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.header_byte());
        out.push(self.hops());

        if let Some(transport_id) = self.transport_id() {
            out.extend_from_slice(&transport_id);
        }
        out.extend_from_slice(&self.destination_hash());
        out.push(self.context_byte());

        match self {
            Packet::Announce { data, .. }
            | Packet::Proof { data, .. }
            | Packet::LinkData { data, .. }
            | Packet::LinkRequest { data, .. }
            | Packet::LinkProof { data, .. } => out.extend_from_slice(data),
            Packet::PathRequest {
                query_destination,
                requesting_transport,
                tag,
                ..
            } => {
                out.extend_from_slice(query_destination);
                if let Some(transport) = requesting_transport {
                    out.extend_from_slice(transport);
                }
                out.extend_from_slice(tag);
            }
            Packet::SingleData { ciphertext, .. } | Packet::GroupData { ciphertext, .. } => {
                out.extend_from_slice(ciphertext)
            }
        }

        out
    }

    #[cfg(test)]
    pub fn from_bytes(raw: &[u8]) -> Result<Self, ParseError> {
        Self::from_vec(raw.to_vec())
    }

    pub(crate) fn from_vec(raw: Vec<u8>) -> Result<Self, ParseError> {
        let raw = Bytes::from(raw);
        if raw.len() < 4 {
            return Err(ParseError::TooShort);
        }

        let flags = raw[0];
        let hops = raw[1];

        let context_flag = (flags & 0b0010_0000) >> 5;
        let destination_type = (flags & 0b0000_1100) >> 2;
        let packet_type = flags & 0b0000_0011;

        let is_type2 = flags & 0b0100_0000 != 0;
        let is_transport = flags & 0b0001_0000 != 0;

        let (transport_id, destination_hash, context_byte, data_offset) = if is_type2 {
            if raw.len() < 2 + 2 * ADDR_LEN + 1 {
                return Err(ParseError::TooShort);
            }
            (
                Some(raw[2..2 + ADDR_LEN].try_into().unwrap()),
                raw[2 + ADDR_LEN..2 + 2 * ADDR_LEN].try_into().unwrap(),
                raw[2 + 2 * ADDR_LEN],
                2 + 2 * ADDR_LEN + 1,
            )
        } else {
            if raw.len() < 2 + ADDR_LEN + 1 {
                return Err(ParseError::TooShort);
            }
            (
                None,
                raw[2..2 + ADDR_LEN].try_into().unwrap(),
                raw[2 + ADDR_LEN],
                2 + ADDR_LEN + 1,
            )
        };
        let data = raw.slice(data_offset..);

        match packet_type {
            PKT_DATA => {
                if destination_type == DEST_LINK {
                    let context =
                        LinkContext::from_byte(context_byte).ok_or(ParseError::InvalidContext)?;
                    Ok(Packet::LinkData {
                        hops,
                        destination: RoutedDestination {
                            address: destination_hash,
                            transport: transport_id,
                        },
                        context,
                        data,
                    })
                } else if destination_type == DEST_PLAIN {
                    if destination_hash == PATH_REQUEST_DEST {
                        if data.len() < 32 {
                            return Err(ParseError::TooShort);
                        }
                        let query_destination: DestinationAddress = data[..16].try_into().unwrap();
                        let (requesting_transport, tag) = if data.len() >= 48 {
                            let transport: DestinationAddress = data[16..32].try_into().unwrap();
                            let tag: DestinationAddress = data[32..48].try_into().unwrap();
                            (Some(transport), tag)
                        } else {
                            let tag: DestinationAddress = data[16..32].try_into().unwrap();
                            (None, tag)
                        };
                        Ok(Packet::PathRequest {
                            hops,
                            query_destination,
                            requesting_transport,
                            tag,
                        })
                    } else {
                        Err(ParseError::InvalidDestinationType)
                    }
                } else if destination_type == DEST_SINGLE {
                    let destination = match (transport_id, is_transport) {
                        (None, false) => RoutedDestination::direct(destination_hash),
                        (Some(tid), true) => RoutedDestination::via(tid, destination_hash),
                        _ => return Err(ParseError::InvalidDestinationType),
                    };
                    Ok(Packet::SingleData {
                        hops,
                        destination,
                        ciphertext: data,
                    })
                } else if destination_type == DEST_GROUP {
                    if transport_id.is_some() {
                        return Err(ParseError::InvalidDestinationType);
                    }
                    Ok(Packet::GroupData {
                        hops,
                        destination: destination_hash,
                        ciphertext: data,
                    })
                } else {
                    Err(ParseError::InvalidDestinationType)
                }
            }
            PKT_ANNOUNCE => {
                if destination_type != DEST_SINGLE {
                    return Err(ParseError::InvalidDestinationType);
                }
                let has_ratchet = context_flag == 1;
                let is_path_response = context_byte == CTX_PATH_RESPONSE;
                Ok(Packet::Announce {
                    hops,
                    destination: RoutedDestination {
                        address: destination_hash,
                        transport: transport_id,
                    },
                    has_ratchet,
                    is_path_response,
                    data,
                })
            }
            PKT_LINKREQUEST => {
                if destination_type != DEST_SINGLE {
                    return Err(ParseError::InvalidDestinationType);
                }
                Ok(Packet::LinkRequest {
                    hops,
                    destination: RoutedDestination {
                        address: destination_hash,
                        transport: transport_id,
                    },
                    data,
                })
            }
            PKT_PROOF => {
                if context_byte == CTX_LRPROOF {
                    Ok(Packet::LinkProof {
                        hops,
                        destination: RoutedDestination {
                            address: destination_hash,
                            transport: transport_id,
                        },
                        data,
                    })
                } else {
                    if transport_id.is_some() {
                        return Err(ParseError::InvalidDestinationType);
                    }
                    let context =
                        ProofContext::from_byte(context_byte).ok_or(ParseError::InvalidContext)?;
                    let destination = match destination_type {
                        DEST_SINGLE => ProofDestination::Single(destination_hash),
                        DEST_LINK => ProofDestination::Link(destination_hash),
                        _ => return Err(ParseError::InvalidDestinationType),
                    };
                    Ok(Packet::Proof {
                        hops,
                        destination,
                        context,
                        data,
                    })
                }
            }
            _ => Err(ParseError::InvalidPacketType),
        }
    }

    pub fn hops(&self) -> u8 {
        match self {
            Packet::Announce { hops, .. }
            | Packet::Proof { hops, .. }
            | Packet::LinkData { hops, .. }
            | Packet::LinkRequest { hops, .. }
            | Packet::LinkProof { hops, .. }
            | Packet::PathRequest { hops, .. }
            | Packet::SingleData { hops, .. }
            | Packet::GroupData { hops, .. } => *hops,
        }
    }

    pub fn increment_hops(&mut self) {
        let hops = match self {
            Packet::Announce { hops, .. }
            | Packet::Proof { hops, .. }
            | Packet::LinkData { hops, .. }
            | Packet::LinkRequest { hops, .. }
            | Packet::LinkProof { hops, .. }
            | Packet::PathRequest { hops, .. }
            | Packet::SingleData { hops, .. }
            | Packet::GroupData { hops, .. } => hops,
        };
        *hops = hops.saturating_add(1);
    }

    pub fn destination_hash(&self) -> DestinationAddress {
        match self {
            Packet::Announce { destination, .. }
            | Packet::LinkData { destination, .. }
            | Packet::LinkRequest { destination, .. }
            | Packet::LinkProof { destination, .. }
            | Packet::SingleData { destination, .. } => destination.address,
            Packet::Proof { destination, .. } => match destination {
                ProofDestination::Single(a) | ProofDestination::Link(a) => *a,
            },
            Packet::PathRequest { .. } => PATH_REQUEST_DEST,
            Packet::GroupData { destination, .. } => *destination,
        }
    }

    pub fn transport_id(&self) -> Option<DestinationAddress> {
        match self {
            Packet::Announce { destination, .. }
            | Packet::LinkData { destination, .. }
            | Packet::LinkRequest { destination, .. }
            | Packet::LinkProof { destination, .. }
            | Packet::SingleData { destination, .. } => destination.transport,
            Packet::Proof { .. } | Packet::PathRequest { .. } | Packet::GroupData { .. } => None,
        }
    }

    pub fn received_from(&self) -> DestinationAddress {
        self.transport_id()
            .unwrap_or_else(|| self.destination_hash())
    }

    fn header_byte(&self) -> u8 {
        let routed = u8::from(self.transport_id().is_some());

        let context_flag: u8 = match self {
            Packet::Announce {
                has_ratchet: true, ..
            } => 1,
            _ => 0,
        };

        let destination_type: u8 = match self {
            Packet::Announce { .. } => DEST_SINGLE,
            Packet::Proof { destination, .. } => match destination {
                ProofDestination::Single(_) => DEST_SINGLE,
                ProofDestination::Link(_) => DEST_LINK,
            },
            Packet::LinkData { .. } => DEST_LINK,
            Packet::LinkRequest { .. } => DEST_SINGLE,
            Packet::LinkProof { .. } => DEST_LINK,
            Packet::PathRequest { .. } => DEST_PLAIN,
            Packet::SingleData { .. } => DEST_SINGLE,
            Packet::GroupData { .. } => DEST_GROUP,
        };

        let packet_type: u8 = match self {
            Packet::LinkData { .. }
            | Packet::PathRequest { .. }
            | Packet::SingleData { .. }
            | Packet::GroupData { .. } => PKT_DATA,
            Packet::Announce { .. } => PKT_ANNOUNCE,
            Packet::LinkRequest { .. } => PKT_LINKREQUEST,
            Packet::Proof { .. } | Packet::LinkProof { .. } => PKT_PROOF,
        };

        (routed << 6) | (context_flag << 5) | (routed << 4) | (destination_type << 2) | packet_type
    }

    fn context_byte(&self) -> u8 {
        match self {
            Packet::Announce {
                is_path_response: true,
                ..
            } => CTX_PATH_RESPONSE,
            Packet::Announce { .. } => 0x00,
            Packet::Proof { context, .. } => *context as u8,
            Packet::LinkData { context, .. } => *context as u8,
            Packet::LinkRequest { .. }
            | Packet::PathRequest { .. }
            | Packet::SingleData { .. }
            | Packet::GroupData { .. } => 0x00,
            Packet::LinkProof { .. } => CTX_LRPROOF,
        }
    }

    pub(crate) fn link_id(&self) -> Option<[u8; 16]> {
        let Self::LinkRequest { data, .. } = self else {
            return None;
        };
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([self.header_byte() & 0b0000_1111]);
        hasher.update(self.destination_hash());
        hasher.update([self.context_byte()]);
        hasher.update(&data[..data.len().min(64)]);
        Some(hasher.finalize()[..16].try_into().unwrap())
    }

    pub fn packet_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([self.header_byte() & 0b0000_1111]);
        hasher.update(self.destination_hash());
        hasher.update([self.context_byte()]);
        match self {
            Packet::Announce { data, .. }
            | Packet::Proof { data, .. }
            | Packet::LinkData { data, .. }
            | Packet::LinkRequest { data, .. }
            | Packet::LinkProof { data, .. } => hasher.update(data),
            Packet::PathRequest {
                query_destination,
                requesting_transport,
                tag,
                ..
            } => {
                hasher.update(query_destination);
                if let Some(transport) = requesting_transport {
                    hasher.update(transport);
                }
                hasher.update(tag);
            }
            Packet::SingleData { ciphertext, .. } | Packet::GroupData { ciphertext, .. } => {
                hasher.update(ciphertext)
            }
        }
        hasher.finalize().into()
    }

    pub fn set_transport_id(&mut self, new_id: DestinationAddress) {
        if let Some(transport) = self
            .routed_destination_mut()
            .and_then(|destination| destination.transport.as_mut())
        {
            *transport = new_id;
        }
    }

    pub fn strip_transport(&mut self) {
        if let Some(destination) = self.routed_destination_mut() {
            destination.transport = None;
        }
    }

    pub fn insert_transport(&mut self, next_hop: DestinationAddress) {
        if let Some(destination) = self.routed_destination_mut() {
            destination.transport = Some(next_hop);
        }
    }

    fn routed_destination_mut(&mut self) -> Option<&mut RoutedDestination> {
        match self {
            Packet::Announce { destination, .. }
            | Packet::LinkData { destination, .. }
            | Packet::LinkRequest { destination, .. }
            | Packet::LinkProof { destination, .. }
            | Packet::SingleData { destination, .. } => Some(destination),
            Packet::Proof { .. } | Packet::PathRequest { .. } | Packet::GroupData { .. } => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_vec_keeps_payload_in_input_allocation() {
        let packet = Packet::LinkData {
            hops: 0,
            destination: RoutedDestination::direct([1; 16]),
            context: LinkContext::Resource,
            data: vec![2; 1024].into(),
        };
        let raw = packet.to_bytes();
        let allocation = raw.as_ptr();
        let parsed = Packet::from_vec(raw).unwrap();
        let Packet::LinkData { data, .. } = parsed else {
            panic!("expected link data");
        };
        assert_eq!(data.as_ptr(), allocation.wrapping_add(19));
    }

    #[test]
    fn spec_example1_type2_transport_single_data_hops4() {
        let hash1 = [1u8; 16];
        let hash2 = [2u8; 16];
        let ciphertext = vec![0xAB, 0xCD];
        let packet = Packet::SingleData {
            hops: 4,
            destination: RoutedDestination::via(hash1, hash2),
            ciphertext: ciphertext.clone().into(),
        };

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b0101_0000);
        assert_eq!(bytes[1], 4);
        assert_eq!(&bytes[2..18], &hash1);
        assert_eq!(&bytes[18..34], &hash2);
        assert_eq!(bytes[34], 0x00);
        assert_eq!(&bytes[35..], &ciphertext);

        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_example2_type1_broadcast_single_data_hops7() {
        let hash1 = [3u8; 16];
        let ciphertext = vec![0xEF];
        let packet = Packet::SingleData {
            hops: 7,
            destination: RoutedDestination::direct(hash1),
            ciphertext: ciphertext.clone().into(),
        };

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b0000_0000);
        assert_eq!(bytes[1], 7);
        assert_eq!(&bytes[2..18], &hash1);
        assert_eq!(bytes[18], 0x00);
        assert_eq!(&bytes[19..], &ciphertext);

        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_keepalive_20_bytes() {
        let packet = Packet::LinkData {
            hops: 0,
            destination: RoutedDestination::direct([0u8; 16]),
            context: LinkContext::Keepalive,
            data: vec![0u8; 1].into(),
        };
        assert_eq!(packet.to_bytes().len(), 20);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_path_request_51_bytes() {
        let packet = Packet::PathRequest {
            hops: 0,
            query_destination: [0u8; 16],
            requesting_transport: None,
            tag: [0u8; 16],
        };

        assert_eq!(packet.to_bytes().len(), 51);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_request_83_bytes() {
        let packet = Packet::LinkRequest {
            hops: 0,
            destination: RoutedDestination::via([0u8; 16], [0u8; 16]),
            data: vec![0u8; 48].into(),
        };
        assert_eq!(packet.to_bytes().len(), 83);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_rtt_99_bytes() {
        let packet = Packet::LinkData {
            hops: 0,
            destination: RoutedDestination::via([0u8; 16], [0u8; 16]),
            context: LinkContext::LinkRtt,
            data: vec![0u8; 64].into(),
        };
        assert_eq!(packet.to_bytes().len(), 99);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_proof_115_bytes() {
        let packet = Packet::LinkProof {
            hops: 0,
            destination: RoutedDestination::via([0u8; 16], [0u8; 16]),
            data: vec![0u8; 80].into(),
        };
        assert_eq!(packet.to_bytes().len(), 115);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_announce_167_bytes() {
        let packet = Packet::Announce {
            hops: 0,
            destination: RoutedDestination::direct([0u8; 16]),
            has_ratchet: false,
            is_path_response: false,
            data: vec![0u8; 148].into(),
        };
        assert_eq!(packet.to_bytes().len(), 167);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn announce_packet_format_matches_python() {
        use crate::announce::{AnnounceBuilder, AnnounceData, SIGNATURE_LEN};
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

        let enc_prv_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let sig_prv_bytes: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);
        let enc_secret = StaticSecret::from(enc_prv_bytes);
        let enc_public = X25519Public::from(&enc_secret);
        let signing_key = SigningKey::from_bytes(&sig_prv_bytes);
        let expected_signing_pub = signing_key.verifying_key().to_bytes();

        let name_hash: [u8; 10] = [198, 102, 83, 152, 248, 48, 103, 107, 210, 131];
        let random_hash: [u8; 10] = [1, 2, 3, 4, 5, 0, 0, 0, 0, 0];
        let dest_hash: [u8; 16] = [
            85, 145, 28, 204, 77, 65, 140, 130, 169, 25, 222, 45, 116, 198, 106, 149,
        ];

        let announce =
            AnnounceBuilder::new(*enc_public.as_bytes(), signing_key, name_hash, random_hash)
                .build(&dest_hash);

        let packet = Packet::Announce {
            hops: 0,
            destination: RoutedDestination::direct(dest_hash),
            has_ratchet: false,
            is_path_response: false,
            data: announce.to_bytes().into(),
        };

        let bytes = packet.to_bytes();

        assert_eq!(
            bytes[0], 0b0000_0001,
            "header byte should be 0x01 for announce"
        );

        assert_eq!(bytes[1], 0, "hops should be 0");

        assert_eq!(&bytes[2..18], &dest_hash, "destination hash mismatch");

        assert_eq!(bytes[18], 0x00, "context byte should be 0x00");

        let announce_data = &bytes[19..];

        assert_eq!(
            &announce_data[..32],
            enc_public.as_bytes(),
            "encryption key mismatch"
        );

        assert_eq!(
            &announce_data[32..64],
            &expected_signing_pub,
            "signing key mismatch"
        );

        assert_eq!(&announce_data[64..74], &name_hash, "name_hash mismatch");

        assert_eq!(&announce_data[74..84], &random_hash, "random_hash mismatch");

        assert_eq!(
            announce_data.len(),
            64 + 10 + 10 + SIGNATURE_LEN,
            "total announce data length mismatch"
        );

        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);

        let parsed_announce = AnnounceData::parse(&announce.to_bytes(), false).unwrap();
        assert_eq!(parsed_announce.encryption_key, enc_public);
        parsed_announce.verify(&dest_hash).unwrap();

        let packet_data_start = 19;
        assert_eq!(
            &bytes[packet_data_start..],
            &announce.to_bytes()[..],
            "packet data should match announce bytes"
        );

        assert_eq!(bytes.len(), 167, "total packet size");

        assert_eq!(
            bytes.len() - packet_data_start,
            148,
            "announce data should be 148 bytes"
        );

        eprintln!("=== ANNOUNCE PACKET DEBUG ===");
        eprintln!("Total length: {} bytes", bytes.len());
        eprintln!("Header byte: 0x{:02x} (expect 0x01)", bytes[0]);
        eprintln!("Hops: {}", bytes[1]);
        eprintln!("Dest hash: {:02x?}", &bytes[2..18]);
        eprintln!("Context byte: 0x{:02x}", bytes[18]);
        eprintln!("Data length: {} bytes", bytes.len() - 19);
        eprintln!("Public key (first 64 bytes of data):");
        eprintln!("  Encryption key: {:02x?}", &bytes[19..51]);
        eprintln!("  Signing key: {:02x?}", &bytes[51..83]);
    }
}
