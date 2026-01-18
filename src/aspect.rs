use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AspectHash([u8; 10]);

impl AspectHash {
    pub fn from_name(name: &str) -> Self {
        let hash = Sha256::digest(name.as_bytes());
        let mut bytes = [0u8; 10];
        bytes.copy_from_slice(&hash[..10]);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 10]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 10] {
        &self.0
    }
}

impl std::fmt::Debug for AspectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AspectHash({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for AspectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
