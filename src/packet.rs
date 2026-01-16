use sha2::Sha256;

use crate::crypto::sha256;

pub const ADDR_LEN: usize = 16;
pub const MAX_DATA_LEN: usize = 465;
pub const MAX_IFAC_LEN: usize = 64;

/// open             0  Packet for publically accessible interface
/// authenticated    1  Interface authentication is included in packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfacFlag {
    Open = 0,
    Authenticated = 1,
}

/// type 1           0  Two byte header, one 16 byte address field
/// type 2           1  Two byte header, two 16 byte address fields
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderType {
    Type1 = 0,
    Type2 = 1,
}

/// unset            0  The context flag is used for various types
/// set              1  of signallingpending on packet context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextFlag {
    Unset = 0,
    Set = 1,
}

/// broadcast        0
/// transport        1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationType {
    Broadcast = 0,
    Transport = 1,
}

/// single          00
/// group           01
/// plain           10
/// link            11
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationType {
    Single = 0b00,
    Group = 0b01,
    Plain = 0b10,
    Link = 0b11,
}

/// data            00
/// announce        01
/// link request    10
/// proof           11
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0b00,
    Announce = 0b01,
    LinkRequest = 0b10,
    Proof = 0b11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Context {
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
    Keepalive = 0xFA,
    LinkIdentify = 0xFB,
    LinkClose = 0xFC,
    LinkProof = 0xFD,
    LinkRtt = 0xFE,
    LinkRequestProof = 0xFF,
}

impl Context {
    pub fn from_byte(b: u8) -> Option<Self> {
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
            0xFA => Some(Self::Keepalive),
            0xFB => Some(Self::LinkIdentify),
            0xFC => Some(Self::LinkClose),
            0xFD => Some(Self::LinkProof),
            0xFE => Some(Self::LinkRtt),
            0xFF => Some(Self::LinkRequestProof),
            _ => Option::None,
        }
    }
}

/// The HEADER field is 2 bytes long.
///   Byte 1: [IFAC Flag], [Header Type], [Context Flag], [Propagation Type],
///           [Destination Type] and [Packet Type]
///   Byte 2: Number of hops
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub ifac_flag: IfacFlag,
    pub header_type: HeaderType,
    pub context_flag: ContextFlag,
    pub propagation_type: PropagationType,
    pub destination_type: DestinationType,
    pub packet_type: PacketType,
    pub hops: u8,
}

impl Header {
    pub fn to_bytes(self) -> [u8; 2] {
        let byte0 = ((self.ifac_flag as u8) << 7)
            | ((self.header_type as u8) << 6)
            | ((self.context_flag as u8) << 5)
            | ((self.propagation_type as u8) << 4)
            | ((self.destination_type as u8) << 2)
            | (self.packet_type as u8);
        [byte0, self.hops]
    }

    pub fn from_bytes(bytes: [u8; 2]) -> Self {
        let byte0 = bytes[0];
        Self {
            ifac_flag: if byte0 & 0b1000_0000 != 0 {
                IfacFlag::Authenticated
            } else {
                IfacFlag::Open
            },
            header_type: if byte0 & 0b0100_0000 != 0 {
                HeaderType::Type2
            } else {
                HeaderType::Type1
            },
            context_flag: if byte0 & 0b0010_0000 != 0 {
                ContextFlag::Set
            } else {
                ContextFlag::Unset
            },
            propagation_type: if byte0 & 0b0001_0000 != 0 {
                PropagationType::Transport
            } else {
                PropagationType::Broadcast
            },
            destination_type: match (byte0 >> 2) & 0b11 {
                0b00 => DestinationType::Single,
                0b01 => DestinationType::Group,
                0b10 => DestinationType::Plain,
                _ => DestinationType::Link,
            },
            packet_type: match byte0 & 0b11 {
                0b00 => PacketType::Data,
                0b01 => PacketType::Announce,
                0b10 => PacketType::LinkRequest,
                _ => PacketType::Proof,
            },
            hops: bytes[1],
        }
    }
}

/// Addresses are SHA-256 hashes truncated to 16 bytes.
pub type Address = [u8; ADDR_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addresses {
    Single {
        transport_id: Address,
    },
    Double {
        transport_id: Address,
        final_destination: Address,
    },
}

impl Addresses {
    pub(crate) fn transport_id(&self) -> Address {
        match self {
            Addresses::Single { transport_id } => *transport_id,
            Addresses::Double { transport_id, .. } => *transport_id,
        }
    }
}

/// [HEADER 2 bytes] [ADDRESSES 16/32 bytes] [CONTEXT 1 byte] [DATA 0-465 bytes]
///
/// Interface Access Code field if the IFAC flag was set.
/// The length of the Interface Access Code can vary from
/// 1 to 64 bytes according to physical interface
/// capabilities and configuration.
///
/// The IFAC can be the full 512-bit Ed25519 signature, or a truncated version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub ifac: Option<Vec<u8>>,
    pub addresses: Addresses,
    /// The CONTEXT field is 1 byte. It is used by Reticulum to determine packet context.
    pub context: Context,
    /// The DATA field is between 0 and 465 bytes. It contains the packets data payload.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    DataTooLong,
    IfacTooLong,
    HeaderAddressMismatch,
    InvalidContext,
}

impl Packet {
    pub fn new(
        header: Header,
        ifac: Option<Vec<u8>>,
        addresses: Addresses,
        context: Context,
        data: Vec<u8>,
    ) -> Result<Self, ParseError> {
        if data.len() > MAX_DATA_LEN {
            return Err(ParseError::DataTooLong);
        }
        if let Some(ref ifac) = ifac
            && (ifac.len() > MAX_IFAC_LEN || ifac.is_empty())
        {
            return Err(ParseError::IfacTooLong);
        }
        let expected_type = match addresses {
            Addresses::Single { .. } => HeaderType::Type1,
            Addresses::Double { .. } => HeaderType::Type2,
        };
        if header.header_type != expected_type {
            return Err(ParseError::HeaderAddressMismatch);
        }
        if ifac.is_some() && header.ifac_flag != IfacFlag::Authenticated {
            return Err(ParseError::HeaderAddressMismatch);
        }
        if ifac.is_none() && header.ifac_flag == IfacFlag::Authenticated {
            return Err(ParseError::HeaderAddressMismatch);
        }
        Ok(Self {
            header,
            ifac,
            addresses,
            context,
            data,
        })
    }

    pub(crate) fn packet_hash(&self) -> [u8; 32] {
        sha256(&self.hashable_part())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.header.to_bytes());
        if let Some(ref ifac) = self.ifac {
            out.extend_from_slice(ifac);
        }
        match self.addresses {
            Addresses::Single { transport_id: a } => out.extend_from_slice(&a),
            Addresses::Double {
                transport_id: a,
                final_destination: b,
            } => {
                out.extend_from_slice(&a);
                out.extend_from_slice(&b);
            }
        }
        out.push(self.context as u8);
        out.extend_from_slice(&self.data);
        out
    }

    /// `ifac_len`: The length of the Interface Access Code can vary from
    /// 1 to 64 bytes according to physical interface capabilities and configuration.
    pub fn from_bytes(bytes: &[u8], ifac_len: usize) -> Result<Self, ParseError> {
        if bytes.len() < 2 {
            return Err(ParseError::TooShort);
        }
        let header = Header::from_bytes([bytes[0], bytes[1]]);
        let mut pos = 2;

        let ifac = if header.ifac_flag == IfacFlag::Authenticated {
            if ifac_len == 0 || ifac_len > MAX_IFAC_LEN {
                return Err(ParseError::IfacTooLong);
            }
            if bytes.len() < pos + ifac_len {
                return Err(ParseError::TooShort);
            }
            let ifac_data = bytes[pos..pos + ifac_len].to_vec();
            pos += ifac_len;
            Some(ifac_data)
        } else {
            None
        };

        let addresses = match header.header_type {
            HeaderType::Type1 => {
                let mut addr = [0u8; ADDR_LEN];
                addr.copy_from_slice(&bytes[pos..pos + ADDR_LEN]);
                Addresses::Single { transport_id: addr }
            }
            HeaderType::Type2 => {
                let mut transport = [0u8; ADDR_LEN];
                let mut destination = [0u8; ADDR_LEN];
                transport.copy_from_slice(&bytes[pos..pos + ADDR_LEN]);
                destination.copy_from_slice(&bytes[pos + ADDR_LEN..pos + 2 * ADDR_LEN]);
                Addresses::Double {
                    transport_id: transport,
                    final_destination: destination,
                }
            }
        };

        pos += match header.header_type {
            HeaderType::Type1 => 1 * ADDR_LEN,
            HeaderType::Type2 => 2 * ADDR_LEN,
        } + 1;

        if bytes.len() < pos {
            return Err(ParseError::TooShort);
        }

        let context = Context::from_byte(bytes[pos]).ok_or(ParseError::InvalidContext)?;
        pos += 1;

        let data = bytes[pos..].to_vec();
        if data.len() > MAX_DATA_LEN {
            return Err(ParseError::DataTooLong);
        }

        Ok(Self {
            header,
            ifac,
            addresses,
            context,
            data,
        })
    }

    pub fn wire_len(&self) -> usize {
        let ifac_len = self.ifac.as_ref().map_or(0, |v| v.len());
        let addr_len = match self.addresses {
            Addresses::Single { .. } => ADDR_LEN,
            Addresses::Double { .. } => 2 * ADDR_LEN,
        };
        2 + ifac_len + addr_len + 1 + self.data.len()
    }

    pub fn hashable_part(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        let mut out = Vec::new();
        out.push(bytes[0] & 0b0000_1111);
        let skip = if self.header.header_type == HeaderType::Type2 {
            2 + ADDR_LEN
        } else {
            2
        };
        out.extend_from_slice(&bytes[skip..]);
        out
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
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 4,
        };
        assert_eq!(header.to_bytes(), [0b0101_0000, 4]);

        let hash1 = [1u8; 16];
        let hash2 = [2u8; 16];
        let data = vec![0xAB, 0xCD];
        let packet = Packet::new(
            header,
            None,
            Addresses::Double {
                transport_id: hash1,
                final_destination: hash2,
            },
            Context::None,
            data.clone(),
        )
        .unwrap();

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b0101_0000);
        assert_eq!(bytes[1], 4);
        assert_eq!(&bytes[2..18], &hash1);
        assert_eq!(&bytes[18..34], &hash2);
        assert_eq!(bytes[34], 0x00);
        assert_eq!(&bytes[35..], &data);

        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_example2_type1_broadcast_single_data_hops7() {
        // 00000000 00000111 [HASH1, 16 bytes] [CONTEXT, 1 byte] [DATA]
        // IFAC=0, HeaderType=0, ContextFlag=0, Propagation=0, Destination=00, PacketType=00
        // Hops=7
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 7,
        };
        assert_eq!(header.to_bytes(), [0b0000_0000, 7]);

        let hash1 = [3u8; 16];
        let data = vec![0xEF];
        let packet = Packet::new(
            header,
            None,
            Addresses::Single {
                transport_id: hash1,
            },
            Context::None,
            data.clone(),
        )
        .unwrap();

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b0000_0000);
        assert_eq!(bytes[1], 7);
        assert_eq!(&bytes[2..18], &hash1);
        assert_eq!(bytes[18], 0x00);
        assert_eq!(&bytes[19..], &data);

        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_example3_type1_broadcast_single_data_hops7_with_ifac() {
        // 10000000 00000111 [IFAC, N bytes] [HASH1, 16 bytes] [CONTEXT, 1 byte] [DATA]
        // IFAC=1, HeaderType=0, ContextFlag=0, Propagation=0, Destination=00, PacketType=00
        // Hops=7
        let header = Header {
            ifac_flag: IfacFlag::Authenticated,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 7,
        };
        assert_eq!(header.to_bytes(), [0b1000_0000, 7]);

        let ifac = vec![0x11, 0x22, 0x33, 0x44];
        let hash1 = [4u8; 16];
        let data = vec![0x99];
        let packet = Packet::new(
            header,
            Some(ifac.clone()),
            Addresses::Single {
                transport_id: hash1,
            },
            Context::None,
            data.clone(),
        )
        .unwrap();

        let bytes = packet.to_bytes();
        assert_eq!(bytes[0], 0b1000_0000);
        assert_eq!(bytes[1], 7);
        assert_eq!(&bytes[2..6], &ifac);
        assert_eq!(&bytes[6..22], &hash1);
        assert_eq!(bytes[22], 0x00);
        assert_eq!(&bytes[23..], &data);

        let parsed = Packet::from_bytes(&bytes, ifac.len()).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_keepalive_20_bytes() {
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
            Addresses::Single {
                transport_id: [0u8; 16],
            },
            Context::Keepalive,
            vec![0u8; 1],
        )
        .unwrap();
        assert_eq!(packet.wire_len(), 20);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_path_request_51_bytes() {
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
            Addresses::Single {
                transport_id: [0u8; 16],
            },
            Context::PathResponse,
            vec![0u8; 32],
        )
        .unwrap();
        assert_eq!(packet.wire_len(), 51);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_request_83_bytes() {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::LinkRequest,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Double {
                transport_id: [0u8; 16],
                final_destination: [0u8; 16],
            },
            Context::None,
            vec![0u8; 48],
        )
        .unwrap();
        assert_eq!(packet.wire_len(), 83);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_rtt_99_bytes() {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Data,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Double {
                transport_id: [0u8; 16],
                final_destination: [0u8; 16],
            },
            Context::LinkRtt,
            vec![0u8; 64],
        )
        .unwrap();
        assert_eq!(packet.wire_len(), 99);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_link_proof_115_bytes() {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Link,
            packet_type: PacketType::Proof,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Double {
                transport_id: [0u8; 16],
                final_destination: [0u8; 16],
            },
            Context::LinkProof,
            vec![0u8; 80],
        )
        .unwrap();
        assert_eq!(packet.wire_len(), 115);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn spec_size_announce_167_bytes() {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops: 0,
        };
        let packet = Packet::new(
            header,
            None,
            Addresses::Single {
                transport_id: [0u8; 16],
            },
            Context::None,
            vec![0u8; 148],
        )
        .unwrap();
        assert_eq!(packet.wire_len(), 167);

        let bytes = packet.to_bytes();
        let parsed = Packet::from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed, packet);
    }
}
