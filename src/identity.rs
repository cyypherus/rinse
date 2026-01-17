use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::sha256;

pub struct Identity {
    pub(crate) encryption_secret: StaticSecret,
    pub(crate) encryption_public: X25519Public,
    pub(crate) signing_key: SigningKey,
}

impl Identity {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut enc_bytes = [0u8; 32];
        rng.fill_bytes(&mut enc_bytes);
        let encryption_secret = StaticSecret::from(enc_bytes);
        let encryption_public = X25519Public::from(&encryption_secret);

        let mut sig_bytes = [0u8; 32];
        rng.fill_bytes(&mut sig_bytes);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        Self {
            encryption_secret,
            encryption_public,
            signing_key,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let enc_bytes: [u8; 32] = bytes[..32].try_into().ok()?;
        let sig_bytes: [u8; 32] = bytes[32..64].try_into().ok()?;

        let encryption_secret = StaticSecret::from(enc_bytes);
        let encryption_public = X25519Public::from(&encryption_secret);
        let signing_key = SigningKey::from_bytes(&sig_bytes);

        Some(Self {
            encryption_secret,
            encryption_public,
            signing_key,
        })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.encryption_secret.as_bytes());
        out[32..].copy_from_slice(self.signing_key.as_bytes());
        out
    }

    pub fn public_key(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.encryption_public.as_bytes());
        out[32..].copy_from_slice(self.signing_key.verifying_key().as_bytes());
        out
    }

    pub(crate) fn hash(&self) -> [u8; 16] {
        sha256(&self.public_key())[..16].try_into().unwrap()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self::from_bytes(&self.to_bytes()).unwrap()
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
        let id = Identity::generate(&mut rng);
        let bytes = id.to_bytes();
        let id2 = Identity::from_bytes(&bytes).unwrap();

        assert_eq!(
            id.encryption_public.as_bytes(),
            id2.encryption_public.as_bytes()
        );
        assert_eq!(id.signing_key.as_bytes(), id2.signing_key.as_bytes());
    }

    #[test]
    fn public_key_matches() {
        let mut rng = StdRng::seed_from_u64(42);
        let id = Identity::generate(&mut rng);
        let pub_key = id.public_key();

        assert_eq!(&pub_key[..32], id.encryption_public.as_bytes());
        assert_eq!(&pub_key[32..], id.signing_key.verifying_key().as_bytes());
    }
}
