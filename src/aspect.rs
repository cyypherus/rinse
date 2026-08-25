use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceNameHash([u8; 10]);

impl ServiceNameHash {
    pub fn from_service_name(name: &str) -> Self {
        let hash = Sha256::digest(name.as_bytes());
        let mut bytes = [0u8; 10];
        bytes.copy_from_slice(&hash[..10]);
        Self(bytes)
    }

    pub(crate) fn from_bytes(bytes: [u8; 10]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for ServiceNameHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServiceNameHash({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for ServiceNameHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
