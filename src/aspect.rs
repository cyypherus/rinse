use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceHash([u8; 10]);

impl ServiceHash {
    pub fn from_service_name(name: &crate::ServiceName) -> Self {
        let hash = Sha256::digest(name.as_str().as_bytes());
        let mut bytes = [0u8; 10];
        bytes.copy_from_slice(&hash[..10]);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 10]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 10] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 10] {
        self.0
    }
}

impl std::fmt::Debug for ServiceHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceHash({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for ServiceHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
