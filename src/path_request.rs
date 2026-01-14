use crate::Address;

// "reticulum.path.request" hashed to 16 bytes
const PATH_REQUEST_DEST: Address = compute_path_request_dest();

const fn compute_path_request_dest() -> Address {
    let hash = sha256_const(b"reticulum.path.request");
    [
        hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9],
        hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
    ]
}

const fn sha256_const(_input: &[u8]) -> [u8; 32] {
    // Precomputed: sha256("reticulum.path.request")
    [
        0xa5, 0x7e, 0x16, 0xc3, 0xea, 0xbc, 0x17, 0xb9, 0xe7, 0xa9, 0x70, 0x33, 0x68, 0x9f, 0x0f,
        0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]
}

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

    pub fn parse(data: &[u8]) -> Option<Self> {
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
        let expected = crate::crypto::sha256(b"reticulum.path.request");
        assert_eq!(&PATH_REQUEST_DEST, &expected[..16]);
    }

    #[test]
    fn path_request_roundtrip() {
        let dest: Address = [0xAB; 16];
        let tag: Address = [0xCD; 16];
        let request = PathRequest::new(dest, tag);
        let bytes = request.to_bytes();
        let parsed = PathRequest::parse(&bytes).unwrap();
        assert_eq!(parsed.destination_hash, dest);
        assert_eq!(parsed.tag, tag);
    }

    #[test]
    fn path_request_too_short() {
        let short = [0u8; 31];
        assert!(PathRequest::parse(&short).is_none());
    }
}
