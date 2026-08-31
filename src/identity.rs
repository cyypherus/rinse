use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::sha256;
use crate::model::{Destination, ServiceName};

pub struct PrivateIdentity {
    pub(crate) encryption_secret: StaticSecret,
    pub(crate) signing_key: SigningKey,
}

impl PrivateIdentity {
    pub(crate) fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut enc_bytes = [0u8; 32];
        rng.fill_bytes(&mut enc_bytes);
        let encryption_secret = StaticSecret::from(enc_bytes);

        let mut sig_bytes = [0u8; 32];
        rng.fill_bytes(&mut sig_bytes);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        Self {
            encryption_secret,
            signing_key,
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 64]) -> Option<Self> {
        let enc_bytes: [u8; 32] = bytes[..32].try_into().unwrap();
        let sig_bytes: [u8; 32] = bytes[32..].try_into().unwrap();
        if enc_bytes == [0; 32] {
            return None;
        }
        if sig_bytes == [0; 32] {
            return None;
        }

        let encryption_secret = StaticSecret::from(enc_bytes);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        Some(Self {
            encryption_secret,
            signing_key,
        })
    }

    pub fn to_secret_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.encryption_secret.as_bytes());
        out[32..].copy_from_slice(self.signing_key.as_bytes());
        out
    }

    pub fn destination(&self, name: &ServiceName) -> Destination {
        let name_hash = sha256(name.as_str().as_bytes());
        let identity_hash = self.hash();
        let mut material = [0; 26];
        material[..10].copy_from_slice(&name_hash[..10]);
        material[10..].copy_from_slice(&identity_hash);
        Destination::from_bytes(sha256(&material)[..16].try_into().unwrap())
    }

    pub(crate) fn public_key(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(X25519Public::from(&self.encryption_secret).as_bytes());
        out[32..].copy_from_slice(self.signing_key.verifying_key().as_bytes());
        out
    }

    pub(crate) fn hash(&self) -> [u8; 16] {
        sha256(&self.public_key())[..16].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn roundtrip_bytes() {
        let mut rng = StdRng::seed_from_u64(42);
        let id = PrivateIdentity::generate(&mut rng);
        let bytes = id.to_secret_bytes();
        let id2 = PrivateIdentity::from_secret_bytes(bytes).unwrap();

        assert_eq!(id.public_key(), id2.public_key());
        assert_eq!(id.signing_key.as_bytes(), id2.signing_key.as_bytes());
    }

    #[test]
    fn public_key_matches() {
        let mut rng = StdRng::seed_from_u64(42);
        let id = PrivateIdentity::generate(&mut rng);
        let pub_key = id.public_key();

        assert_eq!(
            &pub_key[..32],
            X25519Public::from(&id.encryption_secret).as_bytes()
        );
        assert_eq!(&pub_key[32..], id.signing_key.verifying_key().as_bytes());
    }
}
