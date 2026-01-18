use crate::packet::Address;

// Path request destination for PLAIN destination "rnstransport.path.request"
// Computed as: sha256(sha256("rnstransport.path.request")[:10])[:16]
const PATH_REQUEST_DEST: Address = [
    0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27, 0x61,
];

// Path Request: 51 bytes on wire
// Addressed to well-known "reticulum.path.request" destination
// Data: destination_hash (16) + tag (16) = 32 bytes
pub(crate) struct PathRequest {
    pub destination_hash: Address,
    pub tag: Address,
}

impl PathRequest {
    pub fn new(destination_hash: Address, tag: Address) -> Self {
        Self {
            destination_hash,
            tag,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&self.destination_hash);
        out.extend_from_slice(&self.tag);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }
        let destination_hash: Address = data[..16].try_into().ok()?;
        let tag: Address = data[16..32].try_into().ok()?;
        Some(Self {
            destination_hash,
            tag,
        })
    }

    pub fn destination() -> Address {
        PATH_REQUEST_DEST
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_request_destination_hash() {
        // PLAIN destination hash algorithm:
        // 1. name_hash = sha256("rnstransport.path.request")[:10]
        // 2. address = sha256(name_hash)[:16]
        let name_hash = crate::crypto::sha256(b"rnstransport.path.request");
        let addr = crate::crypto::sha256(&name_hash[..10]);
        println!("Correct address: {}", hex::encode(&addr[..16]));
        assert_eq!(&PATH_REQUEST_DEST, &addr[..16]);
    }
}
