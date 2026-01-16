pub const ADDR_LEN: usize = 16;
pub type Address = [u8; ADDR_LEN];

const DEST_SINGLE: u8 = 0b00;
const DEST_GROUP: u8 = 0b01;
const DEST_PLAIN: u8 = 0b10;
const DEST_LINK: u8 = 0b11;

const PKT_DATA: u8 = 0b00;
const PKT_ANNOUNCE: u8 = 0b01;
const PKT_LINKREQUEST: u8 = 0b10;
const PKT_PROOF: u8 = 0b11;

const CTX_LRPROOF: u8 = 0xFF;

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
    PathResponse = 0x0B,
    Command = 0x0C,
    CommandStatus = 0x0D,
    Channel = 0x0E,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkContext {
    None = 0x00,
    Request = 0x09,
    Response = 0x0A,
    Channel = 0x0E,
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
            0x09 => Some(Self::Request),
            0x0A => Some(Self::Response),
            0x0E => Some(Self::Channel),
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

    pub fn log_format(&self) -> String {
        let dest = hex::encode(self.destination_hash());
        let transport = self
            .transport_id()
            .map(|t| format!(" via <{}>", hex::encode(t)))
            .unwrap_or_default();
        let data_len = self.data().len();
        match self {
            Packet::Data { hops, context, .. } => {
                format!("Data to <{dest}>{transport} hops={hops} ctx={context:?} len={data_len}")
            }
            Packet::Announce {
                hops, has_ratchet, ..
            } => {
                format!(
                    "Announce <{dest}>{transport} hops={hops} ratchet={has_ratchet} len={data_len}"
                )
            }
            Packet::Proof { hops, context, .. } => {
                format!("Proof to <{dest}> hops={hops} ctx={context:?} len={data_len}")
            }
            Packet::LinkData { hops, context, .. } => {
                format!(
                    "LinkData to <{dest}>{transport} hops={hops} ctx={context:?} len={data_len}"
                )
            }
            Packet::LinkRequest { hops, .. } => {
                format!("LinkRequest to <{dest}>{transport} hops={hops} len={data_len}")
            }
            Packet::LinkProof { hops, .. } => {
                format!("LinkProof for <{dest}>{transport} hops={hops} len={data_len}")
            }
        }
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
            PKT_DATA => {
                if destination_type == DEST_LINK {
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
                        (DEST_SINGLE, None, false) => DataDestination::Single(destination_hash),
                        (DEST_GROUP, None, false) => DataDestination::Group(destination_hash),
                        (DEST_PLAIN, None, false) => DataDestination::Plain(destination_hash),
                        (DEST_SINGLE, Some(tid), true) => DataDestination::Transport {
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
            PKT_ANNOUNCE => {
                if destination_type != DEST_SINGLE {
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
            PKT_LINKREQUEST => {
                if destination_type != DEST_SINGLE {
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
            PKT_PROOF => {
                if context_byte == CTX_LRPROOF {
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
            Packet::Data { hops, .. } => *hops,
            Packet::Announce { hops, .. } => *hops,
            Packet::Proof { hops, .. } => *hops,
            Packet::LinkData { hops, .. } => *hops,
            Packet::LinkRequest { hops, .. } => *hops,
            Packet::LinkProof { hops, .. } => *hops,
        }
    }

    pub fn increment_hops(&mut self) {
        let hops = match self {
            Packet::Data { hops, .. } => hops,
            Packet::Announce { hops, .. } => hops,
            Packet::Proof { hops, .. } => hops,
            Packet::LinkData { hops, .. } => hops,
            Packet::LinkRequest { hops, .. } => hops,
            Packet::LinkProof { hops, .. } => hops,
        };
        *hops = hops.saturating_add(1);
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

    pub fn received_from(&self) -> Address {
        self.transport_id()
            .unwrap_or_else(|| self.destination_hash())
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
                DataDestination::Single(_) | DataDestination::Transport { .. } => DEST_SINGLE,
                DataDestination::Group(_) => DEST_GROUP,
                DataDestination::Plain(_) => DEST_PLAIN,
            },
            Packet::Announce { .. } => DEST_SINGLE,
            Packet::Proof { destination, .. } => match destination {
                ProofDestination::Single(_) => DEST_SINGLE,
                ProofDestination::Link(_) => DEST_LINK,
            },
            Packet::LinkData { .. } => DEST_LINK,
            Packet::LinkRequest { .. } => DEST_SINGLE,
            Packet::LinkProof { .. } => DEST_LINK,
        };

        let packet_type: u8 = match self {
            Packet::Data { .. } | Packet::LinkData { .. } => PKT_DATA,
            Packet::Announce { .. } => PKT_ANNOUNCE,
            Packet::LinkRequest { .. } => PKT_LINKREQUEST,
            Packet::Proof { .. } | Packet::LinkProof { .. } => PKT_PROOF,
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
            Packet::LinkProof { .. } => CTX_LRPROOF,
        }
    }

    pub fn hashable_part(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        let mut hashable = Vec::new();
        hashable.push(bytes[0] & 0b0000_1111);
        let skip = if self.transport_id().is_some() {
            2 + ADDR_LEN
        } else {
            2
        };
        hashable.extend_from_slice(&bytes[skip..]);
        hashable
    }

    pub fn packet_hash(&self) -> [u8; 32] {
        use crate::crypto::sha256;
        sha256(&self.hashable_part())
    }

    pub fn set_transport_id(&mut self, new_id: Address) {
        match self {
            Packet::Data { destination, .. } => {
                if let DataDestination::Transport { transport_id, .. } = destination {
                    *transport_id = new_id;
                }
            }
            Packet::Announce { destination, .. } => {
                if let AnnounceDestination::Transport { transport_id, .. } = destination {
                    *transport_id = new_id;
                }
            }
            Packet::Proof { .. } => {}
            Packet::LinkData { destination, .. } => {
                if let LinkDataDestination::Transport { transport_id, .. } = destination {
                    *transport_id = new_id;
                }
            }
            Packet::LinkRequest { destination, .. } => {
                if let LinkRequestDestination::Transport { transport_id, .. } = destination {
                    *transport_id = new_id;
                }
            }
            Packet::LinkProof { destination, .. } => {
                if let LinkProofDestination::Transport { transport_id, .. } = destination {
                    *transport_id = new_id;
                }
            }
        }
    }

    pub fn strip_transport(&mut self) {
        match self {
            Packet::Data { destination, .. } => {
                if let DataDestination::Transport {
                    destination: dest, ..
                } = *destination
                {
                    *destination = DataDestination::Single(dest);
                }
            }
            Packet::Announce { destination, .. } => {
                if let AnnounceDestination::Transport {
                    destination: dest, ..
                } = *destination
                {
                    *destination = AnnounceDestination::Single(dest);
                }
            }
            Packet::Proof { .. } => {}
            Packet::LinkData { destination, .. } => {
                if let LinkDataDestination::Transport { link_id, .. } = *destination {
                    *destination = LinkDataDestination::Direct(link_id);
                }
            }
            Packet::LinkRequest { destination, .. } => {
                if let LinkRequestDestination::Transport {
                    destination: dest, ..
                } = *destination
                {
                    *destination = LinkRequestDestination::Direct(dest);
                }
            }
            Packet::LinkProof { destination, .. } => {
                if let LinkProofDestination::Transport { link_id, .. } = *destination {
                    *destination = LinkProofDestination::Direct(link_id);
                }
            }
        }
    }

    pub fn insert_transport(&mut self, next_hop: Address) {
        match self {
            Packet::Data { destination, .. } => {
                if let DataDestination::Single(dest) = *destination {
                    *destination = DataDestination::Transport {
                        transport_id: next_hop,
                        destination: dest,
                    };
                }
            }
            Packet::Announce { destination, .. } => {
                if let AnnounceDestination::Single(dest) = *destination {
                    *destination = AnnounceDestination::Transport {
                        transport_id: next_hop,
                        destination: dest,
                    };
                }
            }
            Packet::Proof { .. } => {}
            Packet::LinkData { destination, .. } => {
                if let LinkDataDestination::Direct(link_id) = *destination {
                    *destination = LinkDataDestination::Transport {
                        transport_id: next_hop,
                        link_id,
                    };
                }
            }
            Packet::LinkRequest { destination, .. } => {
                if let LinkRequestDestination::Direct(dest) = *destination {
                    *destination = LinkRequestDestination::Transport {
                        transport_id: next_hop,
                        destination: dest,
                    };
                }
            }
            Packet::LinkProof { destination, .. } => {
                if let LinkProofDestination::Direct(link_id) = *destination {
                    *destination = LinkProofDestination::Transport {
                        transport_id: next_hop,
                        link_id,
                    };
                }
            }
        }
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

    #[test]
    fn announce_packet_format_matches_python() {
        use crate::announce::{AnnounceBuilder, AnnounceData, SIGNATURE_LEN};
        use ed25519_dalek::SigningKey;
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

        // Create keys
        let enc_prv_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let sig_prv_bytes: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);
        let enc_secret = StaticSecret::from(enc_prv_bytes);
        let enc_public = X25519Public::from(&enc_secret);
        let signing_key = SigningKey::from_bytes(&sig_prv_bytes);
        let expected_signing_pub = signing_key.verifying_key().to_bytes();

        // Create destination hash (name_hash + identity_hash truncated)
        let name_hash: [u8; 10] = [198, 102, 83, 152, 248, 48, 103, 107, 210, 131];
        let random_hash: [u8; 10] = [1, 2, 3, 4, 5, 0, 0, 0, 0, 0];
        let dest_hash: [u8; 16] = [
            85, 145, 28, 204, 77, 65, 140, 130, 169, 25, 222, 45, 116, 198, 106, 149,
        ];

        // Build announce data
        let announce =
            AnnounceBuilder::new(*enc_public.as_bytes(), signing_key, name_hash, random_hash)
                .build(&dest_hash);

        // Create packet
        let packet = Packet::Announce {
            hops: 0,
            destination: AnnounceDestination::Single(dest_hash),
            has_ratchet: false,
            data: announce.to_bytes(),
        };

        let bytes = packet.to_bytes();

        // Verify header byte format:
        // bit 7: IFAC flag (0)
        // bit 6: header_type (0 = Type1)
        // bit 5: context_flag (0 = no ratchet)
        // bit 4: propagation_type (0 = broadcast)
        // bits 3-2: destination_type (00 = single)
        // bits 1-0: packet_type (01 = announce)
        assert_eq!(
            bytes[0], 0b0000_0001,
            "header byte should be 0x01 for announce"
        );

        // Verify hops
        assert_eq!(bytes[1], 0, "hops should be 0");

        // Verify destination hash
        assert_eq!(&bytes[2..18], &dest_hash, "destination hash mismatch");

        // Verify context byte (should be 0x00 for announce)
        assert_eq!(bytes[18], 0x00, "context byte should be 0x00");

        // Verify announce data starts at byte 19
        let announce_data = &bytes[19..];

        // First 32 bytes should be encryption public key
        assert_eq!(
            &announce_data[..32],
            enc_public.as_bytes(),
            "encryption key mismatch"
        );

        // Next 32 bytes should be signing public key
        assert_eq!(
            &announce_data[32..64],
            &expected_signing_pub,
            "signing key mismatch"
        );

        // Next 10 bytes should be name_hash
        assert_eq!(&announce_data[64..74], &name_hash, "name_hash mismatch");

        // Next 10 bytes should be random_hash
        assert_eq!(&announce_data[74..84], &random_hash, "random_hash mismatch");

        // Next 64 bytes should be signature
        assert_eq!(
            announce_data.len(),
            64 + 10 + 10 + SIGNATURE_LEN,
            "total announce data length mismatch"
        );

        // Verify the packet can be parsed back
        let parsed = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, packet);

        // Verify announce data can be parsed
        let parsed_announce = AnnounceData::parse(&announce.to_bytes(), false).unwrap();
        assert_eq!(parsed_announce.encryption_key, *enc_public.as_bytes());
        parsed_announce.verify(&dest_hash).unwrap();

        // Verify packet.data (bytes[19:]) matches announce_data.to_bytes()
        // This is exactly what Python's unpack() does: self.data = self.raw[DST_LEN+3:]
        // where DST_LEN = 16, so data starts at byte 19
        let packet_data_start = 19; // 2 (header) + 16 (dest) + 1 (context)
        assert_eq!(
            &bytes[packet_data_start..],
            &announce.to_bytes()[..],
            "packet data should match announce bytes"
        );

        // Verify total packet size matches Python expectations
        // Header (2) + dest_hash (16) + context (1) + announce_data (148) = 167
        assert_eq!(bytes.len(), 167, "total packet size");

        // Verify that data portion is exactly 148 bytes (the announce data)
        assert_eq!(
            bytes.len() - packet_data_start,
            148,
            "announce data should be 148 bytes"
        );

        // Print debug info for manual verification
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
