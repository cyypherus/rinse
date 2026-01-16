pub const ADDR_LEN: usize = 16;
pub type Address = [u8; ADDR_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataContext {
    None = 0x00,
    Resource = 0x01,
    ResourceAdv = 0x02,
    ResourceReq = 0x03,
    ResourceHmu = 0x04,
    ResourcePrf = 0x05,
    ResourceIcl = 0x06,
    ResourceRcl = 0x07,
    CacheRequest = 0x08,
    Request = 0x09,
    Response = 0x0A,
    PathResponse = 0x0B,
    Command = 0x0C,
    CommandStatus = 0x0D,
    Channel = 0x0E,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkContext {
    None = 0x00,
    Keepalive = 0xFA,
    LinkIdentify = 0xFB,
    LinkClose = 0xFC,
    LinkProof = 0xFD,
    LinkRtt = 0xFE,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofContext {
    None = 0x00,
    Resource = 0x01,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Data {
        hops: u8,
        destination: DataDestination,
        context: DataContext,
        data: Vec<u8>,
    },
    Announce {
        hops: u8,
        destination: AnnounceDestination,
        has_ratchet: bool,
        data: Vec<u8>,
    },
    Proof {
        hops: u8,
        destination: ProofDestination,
        context: ProofContext,
        data: Vec<u8>,
    },
    LinkData {
        hops: u8,
        destination: LinkDataDestination,
        context: LinkContext,
        data: Vec<u8>,
    },
    LinkRequest {
        hops: u8,
        destination: LinkRequestDestination,
        data: Vec<u8>,
    },
    LinkProof {
        hops: u8,
        destination: LinkProofDestination,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofDestination {
    Single(Address),
    Link(Address),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRequestDestination {
    Direct(Address),
    Transport {
        transport_id: Address,
        destination: Address,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkProofDestination {
    Direct(Address),
    Transport {
        transport_id: Address,
        link_id: Address,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDataDestination {
    Direct(Address),
    Transport {
        transport_id: Address,
        link_id: Address,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDestination {
    Single(Address),
    Group(Address),
    Plain(Address),
    Transport {
        transport_id: Address,
        destination: Address,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnounceDestination {
    Single(Address),
    Transport {
        transport_id: Address,
        destination: Address,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidContext,
    InvalidDestinationType,
    InvalidPacketType,
}

impl DataContext {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Resource),
            0x02 => Some(Self::ResourceAdv),
            0x03 => Some(Self::ResourceReq),
            0x04 => Some(Self::ResourceHmu),
            0x05 => Some(Self::ResourcePrf),
            0x06 => Some(Self::ResourceIcl),
            0x07 => Some(Self::ResourceRcl),
            0x08 => Some(Self::CacheRequest),
            0x09 => Some(Self::Request),
            0x0A => Some(Self::Response),
            0x0B => Some(Self::PathResponse),
            0x0C => Some(Self::Command),
            0x0D => Some(Self::CommandStatus),
            0x0E => Some(Self::Channel),
            _ => None,
        }
    }
}

impl LinkContext {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::None),
            0xFA => Some(Self::Keepalive),
            0xFB => Some(Self::LinkIdentify),
            0xFC => Some(Self::LinkClose),
            0xFD => Some(Self::LinkProof),
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
        out.extend_from_slice(self.data());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, ParseError> {
        if raw.len() < 4 {
            return Err(ParseError::TooShort);
        }

        let flags = raw[0];
        let hops = raw[1];

        let header_type = (flags & 0b0100_0000) >> 6;
        let context_flag = (flags & 0b0010_0000) >> 5;
        let propagation_type = (flags & 0b0001_0000) >> 4;
        let destination_type = (flags & 0b0000_1100) >> 2;
        let packet_type = flags & 0b0000_0011;

        let is_type2 = header_type == 1;
        let is_transport = propagation_type == 1;

        let (transport_id, destination_hash, context_byte, data) = if is_type2 {
            if raw.len() < 2 + ADDR_LEN + ADDR_LEN + 1 {
                return Err(ParseError::TooShort);
            }
            let mut tid = [0u8; ADDR_LEN];
            let mut dest = [0u8; ADDR_LEN];
            tid.copy_from_slice(&raw[2..2 + ADDR_LEN]);
            dest.copy_from_slice(&raw[2 + ADDR_LEN..2 + 2 * ADDR_LEN]);
            let ctx = raw[2 + 2 * ADDR_LEN];
            let data = raw[2 + 2 * ADDR_LEN + 1..].to_vec();
            (Some(tid), dest, ctx, data)
        } else {
            if raw.len() < 2 + ADDR_LEN + 1 {
                return Err(ParseError::TooShort);
            }
            let mut dest = [0u8; ADDR_LEN];
            dest.copy_from_slice(&raw[2..2 + ADDR_LEN]);
            let ctx = raw[2 + ADDR_LEN];
            let data = raw[2 + ADDR_LEN + 1..].to_vec();
            (None, dest, ctx, data)
        };

        match packet_type {
            0b00 => {
                if destination_type == 0b11 {
                    let context =
                        LinkContext::from_byte(context_byte).ok_or(ParseError::InvalidContext)?;
                    let destination = match transport_id {
                        None => LinkDataDestination::Direct(destination_hash),
                        Some(tid) => LinkDataDestination::Transport {
                            transport_id: tid,
                            link_id: destination_hash,
                        },
                    };
                    Ok(Packet::LinkData {
                        hops,
                        destination,
                        context,
                        data,
                    })
                } else {
                    let context =
                        DataContext::from_byte(context_byte).ok_or(ParseError::InvalidContext)?;
                    let destination = match (destination_type, transport_id, is_transport) {
                        (0b00, None, false) => DataDestination::Single(destination_hash),
                        (0b01, None, false) => DataDestination::Group(destination_hash),
                        (0b10, None, false) => DataDestination::Plain(destination_hash),
                        (0b00, Some(tid), true) => DataDestination::Transport {
                            transport_id: tid,
                            destination: destination_hash,
                        },
                        _ => return Err(ParseError::InvalidDestinationType),
                    };
                    Ok(Packet::Data {
                        hops,
                        destination,
                        context,
                        data,
                    })
                }
            }
            0b01 => {
                if destination_type != 0b00 {
                    return Err(ParseError::InvalidDestinationType);
                }
                let has_ratchet = context_flag == 1;
                let destination = match transport_id {
                    None => AnnounceDestination::Single(destination_hash),
                    Some(tid) => AnnounceDestination::Transport {
                        transport_id: tid,
                        destination: destination_hash,
                    },
                };
                Ok(Packet::Announce {
                    hops,
                    destination,
                    has_ratchet,
                    data,
                })
            }
            0b10 => {
                if destination_type != 0b11 {
                    return Err(ParseError::InvalidDestinationType);
                }
                let destination = match transport_id {
                    None => LinkRequestDestination::Direct(destination_hash),
                    Some(tid) => LinkRequestDestination::Transport {
                        transport_id: tid,
                        destination: destination_hash,
                    },
                };
                Ok(Packet::LinkRequest {
                    hops,
                    destination,
                    data,
                })
            }
            0b11 => {
                if context_byte == 0xFF {
                    let destination = match transport_id {
                        None => LinkProofDestination::Direct(destination_hash),
                        Some(tid) => LinkProofDestination::Transport {
                            transport_id: tid,
                            link_id: destination_hash,
                        },
                    };
                    Ok(Packet::LinkProof {
                        hops,
                        destination,
                        data,
                    })
                } else {
                    if transport_id.is_some() {
                        return Err(ParseError::InvalidDestinationType);
                    }
                    let context =
                        ProofContext::from_byte(context_byte).ok_or(ParseError::InvalidContext)?;
                    let destination = match destination_type {
                        0b00 => ProofDestination::Single(destination_hash),
                        0b11 => ProofDestination::Link(destination_hash),
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
            Packet::Data { hops, .. } => *hops,
            Packet::Announce { hops, .. } => *hops,
            Packet::Proof { hops, .. } => *hops,
            Packet::LinkData { hops, .. } => *hops,
            Packet::LinkRequest { hops, .. } => *hops,
            Packet::LinkProof { hops, .. } => *hops,
        }
    }

    pub fn data(&self) -> &[u8] {
        match self {
            Packet::Data { data, .. } => data,
            Packet::Announce { data, .. } => data,
            Packet::Proof { data, .. } => data,
            Packet::LinkData { data, .. } => data,
            Packet::LinkRequest { data, .. } => data,
            Packet::LinkProof { data, .. } => data,
        }
    }

    pub fn destination_hash(&self) -> Address {
        match self {
            Packet::Data { destination, .. } => match destination {
                DataDestination::Single(a) => *a,
                DataDestination::Group(a) => *a,
                DataDestination::Plain(a) => *a,
                DataDestination::Transport { destination, .. } => *destination,
            },
            Packet::Announce { destination, .. } => match destination {
                AnnounceDestination::Single(a) => *a,
                AnnounceDestination::Transport { destination, .. } => *destination,
            },
            Packet::Proof { destination, .. } => match destination {
                ProofDestination::Single(a) => *a,
                ProofDestination::Link(a) => *a,
            },
            Packet::LinkData { destination, .. } => match destination {
                LinkDataDestination::Direct(a) => *a,
                LinkDataDestination::Transport { link_id, .. } => *link_id,
            },
            Packet::LinkRequest { destination, .. } => match destination {
                LinkRequestDestination::Direct(a) => *a,
                LinkRequestDestination::Transport { destination, .. } => *destination,
            },
            Packet::LinkProof { destination, .. } => match destination {
                LinkProofDestination::Direct(a) => *a,
                LinkProofDestination::Transport { link_id, .. } => *link_id,
            },
        }
    }

    pub fn transport_id(&self) -> Option<Address> {
        match self {
            Packet::Data { destination, .. } => match destination {
                DataDestination::Transport { transport_id, .. } => Some(*transport_id),
                _ => None,
            },
            Packet::Announce { destination, .. } => match destination {
                AnnounceDestination::Transport { transport_id, .. } => Some(*transport_id),
                _ => None,
            },
            Packet::Proof { .. } => None,
            Packet::LinkData { destination, .. } => match destination {
                LinkDataDestination::Transport { transport_id, .. } => Some(*transport_id),
                _ => None,
            },
            Packet::LinkRequest { destination, .. } => match destination {
                LinkRequestDestination::Transport { transport_id, .. } => Some(*transport_id),
                _ => None,
            },
            Packet::LinkProof { destination, .. } => match destination {
                LinkProofDestination::Transport { transport_id, .. } => Some(*transport_id),
                _ => None,
            },
        }
    }

    fn header_byte(&self) -> u8 {
        let header_type: u8 = if self.transport_id().is_some() { 1 } else { 0 };

        let context_flag: u8 = match self {
            Packet::Announce {
                has_ratchet: true, ..
            } => 1,
            _ => 0,
        };

        let propagation_type: u8 = match self {
            Packet::Data {
                destination: DataDestination::Transport { .. },
                ..
            } => 1,
            Packet::Announce {
                destination: AnnounceDestination::Transport { .. },
                ..
            } => 1,
            Packet::LinkData {
                destination: LinkDataDestination::Transport { .. },
                ..
            } => 1,
            Packet::LinkRequest {
                destination: LinkRequestDestination::Transport { .. },
                ..
            } => 1,
            Packet::LinkProof {
                destination: LinkProofDestination::Transport { .. },
                ..
            } => 1,
            _ => 0,
        };

        let destination_type: u8 = match self {
            Packet::Data { destination, .. } => match destination {
                DataDestination::Single(_) | DataDestination::Transport { .. } => 0b00,
                DataDestination::Group(_) => 0b01,
                DataDestination::Plain(_) => 0b10,
            },
            Packet::Announce { .. } => 0b00,
            Packet::Proof { destination, .. } => match destination {
                ProofDestination::Single(_) => 0b00,
                ProofDestination::Link(_) => 0b11,
            },
            Packet::LinkData { .. } => 0b11,
            Packet::LinkRequest { .. } => 0b11,
            Packet::LinkProof { .. } => 0b11,
        };

        let packet_type: u8 = match self {
            Packet::Data { .. } | Packet::LinkData { .. } => 0b00,
            Packet::Announce { .. } => 0b01,
            Packet::LinkRequest { .. } => 0b10,
            Packet::Proof { .. } | Packet::LinkProof { .. } => 0b11,
        };

        (header_type << 6)
            | (context_flag << 5)
            | (propagation_type << 4)
            | (destination_type << 2)
            | packet_type
    }

    fn context_byte(&self) -> u8 {
        match self {
            Packet::Data { context, .. } => *context as u8,
            Packet::Announce { .. } => 0x00,
            Packet::Proof { context, .. } => *context as u8,
            Packet::LinkData { context, .. } => *context as u8,
            Packet::LinkRequest { .. } => 0x00,
            Packet::LinkProof { .. } => 0xFF,
        }
    }

    pub fn packet_hash(&self) -> [u8; 32] {
        use crate::crypto::sha256;
        let bytes = self.to_bytes();
        let mut hashable = Vec::new();
        hashable.push(bytes[0] & 0b0000_1111);
        let skip = if self.transport_id().is_some() {
            2 + ADDR_LEN
        } else {
            2
        };
        hashable.extend_from_slice(&bytes[skip..]);
        sha256(&hashable)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example1_type2_transport_single_data_hops4() {
        // 01010000 00000100 [HASH1, 16 bytes] [HASH2, 16 bytes] [CONTEXT, 1 byte] [DATA]
        // IFAC=0, HeaderType=1, ContextFlag=0, Propagation=1, Destination=00, PacketType=00
        // Hops=4
        let hash1 = [1u8; 16];
        let hash2 = [2u8; 16];
        let data = vec![0xAB, 0xCD];
        let packet = Packet::Data {
            hops: 4,
            destination: DataDestination::Transport {
                transport_id: hash1,
                destination: hash2,
            },
            context: DataContext::None,
            data: data.clone(),
        };

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b0101_0000);
        assert_eq!(bytes[1], 4);
        assert_eq!(&bytes[2..18], &hash1);
        assert_eq!(&bytes[18..34], &hash2);
        assert_eq!(bytes[34], 0x00);
        assert_eq!(&bytes[35..], &data);

        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_example2_type1_broadcast_single_data_hops7() {
        // 00000000 00000111 [HASH1, 16 bytes] [CONTEXT, 1 byte] [DATA]
        // IFAC=0, HeaderType=0, ContextFlag=0, Propagation=0, Destination=00, PacketType=00
        // Hops=7
        let hash1 = [3u8; 16];
        let data = vec![0xEF];
        let packet = Packet::Data {
            hops: 7,
            destination: DataDestination::Single(hash1),
            context: DataContext::None,
            data: data.clone(),
        };

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b0000_0000);
        assert_eq!(bytes[1], 7);
        assert_eq!(&bytes[2..18], &hash1);
        assert_eq!(bytes[18], 0x00);
        assert_eq!(&bytes[19..], &data);

        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_keepalive_20_bytes() {
        let packet = Packet::LinkData {
            hops: 0,
            destination: LinkDataDestination::Direct([0u8; 16]),
            context: LinkContext::Keepalive,
            data: vec![0u8; 1],
        };
        assert_eq!(packet.to_bytes().len(), 20);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_path_request_51_bytes() {
        let packet = Packet::Data {
            hops: 0,
            destination: DataDestination::Single([0u8; 16]),
            context: DataContext::PathResponse,
            data: vec![0u8; 32],
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
            destination: LinkRequestDestination::Transport {
                transport_id: [0u8; 16],
                destination: [0u8; 16],
            },
            data: vec![0u8; 48],
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
            destination: LinkDataDestination::Transport {
                transport_id: [0u8; 16],
                link_id: [0u8; 16],
            },
            context: LinkContext::LinkRtt,
            data: vec![0u8; 64],
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
            destination: LinkProofDestination::Transport {
                transport_id: [0u8; 16],
                link_id: [0u8; 16],
            },
            data: vec![0u8; 80],
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
            destination: AnnounceDestination::Single([0u8; 16]),
            has_ratchet: false,
            data: vec![0u8; 148],
        };
        assert_eq!(packet.to_bytes().len(), 167);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);
    }
}
