use aes::cipher::KeyIvInit;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use curve25519_dalek::{
    edwards::EdwardsBasepointTable, montgomery::MontgomeryPoint, traits::BasepointTable,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const AES_KEY_LEN: usize = 32;
const AES_IV_LEN: usize = 16;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sign(signing_key: &SigningKey, data: &[u8]) -> Signature {
    signing_key.sign(data)
}

pub fn verify(verifying_key: &VerifyingKey, data: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(data, signature).is_ok()
}

fn derive_key(shared_secret: &[u8], salt: &[u8]) -> [u8; AES_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut key = [0u8; AES_KEY_LEN];
    hk.expand(b"reticulum", &mut key).expect("valid length");
    key
}

pub fn hkdf_expand(ikm: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];
    hk.expand(&[], &mut output).expect("valid length");
    output
}

fn encrypt_aes256_token(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8], prefix: &[u8]) -> Vec<u8> {
    let cipher = cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into());
    let header_len = prefix.len() + AES_IV_LEN;
    let mut token = vec![0; header_len + (plaintext.len() / 16 + 1) * 16];
    token[..prefix.len()].copy_from_slice(prefix);
    token[prefix.len()..header_len].copy_from_slice(iv);
    let encrypted_len = cipher
        .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(
            plaintext,
            &mut token[header_len..],
        )
        .expect("allocated space for PKCS7 padding")
        .len();
    token.truncate(header_len + encrypted_len);
    token
}

fn decrypt_aes256(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        log::warn!(
            "decrypt_aes256: ciphertext length {} not multiple of 16",
            ciphertext.len()
        );
        return None;
    }
    let cipher = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
    match cipher.decrypt_padded_vec_mut::<aes::cipher::block_padding::Pkcs7>(ciphertext) {
        Ok(plaintext) => Some(plaintext),
        Err(error) => {
            log::warn!(
                "decrypt_aes256: invalid ciphertext or PKCS7 padding: {:?}",
                error
            );
            None
        }
    }
}

pub struct EphemeralKeyPair {
    pub secret: StaticSecret,
    pub public: X25519Public,
}

impl EphemeralKeyPair {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = X25519Key::from_bytes(bytes).public_key();
        Self { secret, public }
    }

    pub fn ecdh(&self, their_public: &X25519Public) -> [u8; 32] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }
}

#[derive(Clone, Default)]
enum DestinationMultiplication {
    #[default]
    Unseen,
    Observed(X25519Public),
    Prepared(X25519Public, Option<std::sync::Arc<EdwardsBasepointTable>>),
}

#[derive(Clone, Default)]
pub struct SingleDestEncryption {
    destination: DestinationMultiplication,
}

impl SingleDestEncryption {
    pub(crate) fn prepare(&mut self, dest_public: &X25519Public) {
        match &self.destination {
            DestinationMultiplication::Prepared(key, _) if key == dest_public => {}
            DestinationMultiplication::Observed(key) if key == dest_public => {
                let table = MontgomeryPoint(*dest_public.as_bytes())
                    .to_edwards(0)
                    .map(|point| std::sync::Arc::new(EdwardsBasepointTable::create(&point)));
                self.destination = DestinationMultiplication::Prepared(*dest_public, table);
            }
            _ => self.destination = DestinationMultiplication::Observed(*dest_public),
        }
    }

    pub fn encrypt<R: RngCore>(
        &mut self,
        rng: &mut R,
        dest_public: &X25519Public,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let ephemeral = EphemeralKeyPair::generate(rng);
        self.prepare(dest_public);
        let shared = match &self.destination {
            DestinationMultiplication::Prepared(_, Some(table)) => table
                .mul_base_clamped(ephemeral.secret.to_bytes())
                .to_montgomery()
                .to_bytes(),
            _ => ephemeral.ecdh(dest_public),
        };

        let mut iv = [0u8; AES_IV_LEN];
        rng.fill_bytes(&mut iv);

        let key = derive_key(&shared, &iv);
        encrypt_aes256_token(&key, &iv, plaintext, ephemeral.public.as_bytes())
    }
}

pub(crate) struct X25519Key(aws_lc_rs::agreement::PrivateKey);

impl Clone for X25519Key {
    fn clone(&self) -> Self {
        Self::from_bytes(self.seed())
    }
}

impl X25519Key {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(
            aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::X25519,
                &bytes,
            )
            .expect("32-byte X25519 private key"),
        )
    }

    fn seed(&self) -> [u8; 32] {
        use aws_lc_rs::encoding::{AsBigEndian, Curve25519SeedBin};
        let seed: Curve25519SeedBin = self.0.as_be_bytes().expect("X25519 seed export");
        seed.as_ref().try_into().expect("32-byte X25519 seed")
    }

    pub(crate) fn public_key(&self) -> X25519Public {
        let public = self.0.compute_public_key().expect("X25519 public key");
        X25519Public::from(
            <[u8; 32]>::try_from(public.as_ref()).expect("32-byte X25519 public key"),
        )
    }

    pub fn decrypt(
        &self,
        sender_ephemeral_public: &X25519Public,
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext.len() < AES_IV_LEN {
            log::warn!(
                "single dest decrypt: ciphertext too short ({} bytes)",
                ciphertext.len()
            );
            return None;
        }
        let iv: [u8; AES_IV_LEN] = ciphertext[..AES_IV_LEN].try_into().ok()?;
        let encrypted = &ciphertext[AES_IV_LEN..];

        use aws_lc_rs::agreement::{UnparsedPublicKey, X25519, agree};
        let shared = agree(
            &self.0,
            UnparsedPublicKey::new(&X25519, sender_ephemeral_public.as_bytes()),
            (),
            |shared| shared.try_into().map_err(|_| ()),
        )
        .unwrap_or_else(|()| {
            StaticSecret::from(self.seed())
                .diffie_hellman(sender_ephemeral_public)
                .to_bytes()
        });
        let key = derive_key(&shared, &iv);

        decrypt_aes256(&key, &iv, encrypted)
    }
}

pub(crate) struct LinkEncryption;

impl LinkEncryption {
    pub fn derive_keys(shared_secret: &[u8; 32], link_id: &[u8; 16]) -> LinkKeys {
        let hk = Hkdf::<Sha256>::new(Some(link_id), shared_secret);
        let mut derived = [0u8; 64];
        hk.expand(b"", &mut derived).expect("valid length");
        let mut signing_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        signing_key.copy_from_slice(&derived[..32]);
        encryption_key.copy_from_slice(&derived[32..]);
        LinkKeys {
            signing_key,
            encryption_key,
        }
    }

    pub fn encrypt<R: RngCore>(rng: &mut R, keys: &LinkKeys, plaintext: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; AES_IV_LEN];
        rng.fill_bytes(&mut iv);

        let signed_parts = encrypt_aes256_token(&keys.encryption_key, &iv, plaintext, &[]);

        let hmac = hmac_sha256(&keys.signing_key, &signed_parts);

        let mut result = signed_parts;
        result.extend_from_slice(&hmac);
        result
    }

    pub fn decrypt(keys: &LinkKeys, token: &[u8]) -> Option<Vec<u8>> {
        if token.len() < AES_IV_LEN + 32 {
            log::warn!(
                "link decrypt: token too short ({} bytes, need at least {})",
                token.len(),
                AES_IV_LEN + 32
            );
            return None;
        }

        let signed_parts = &token[..token.len() - 32];
        let received_hmac = &token[token.len() - 32..];

        let expected_hmac = hmac_sha256(&keys.signing_key, signed_parts);
        if received_hmac != expected_hmac {
            log::warn!("link decrypt: HMAC verification failed");
            return None;
        }

        let iv: [u8; AES_IV_LEN] = signed_parts[..AES_IV_LEN].try_into().ok()?;
        let ciphertext = &signed_parts[AES_IV_LEN..];

        decrypt_aes256(&keys.encryption_key, &iv, ciphertext)
    }
}

pub(crate) struct LinkKeys {
    signing_key: [u8; 32],
    encryption_key: [u8; 32],
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("valid key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
pub(crate) fn create_proof(signing_key: &SigningKey, packet_data: &[u8]) -> Signature {
    let hash = sha256(packet_data);
    sign(signing_key, &hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(12345)
    }

    #[test]
    fn prepared_receiver_matches_dalek() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let secret = StaticSecret::from(bytes);
            let receiver = X25519Key::from_bytes(bytes);
            assert_eq!(receiver.public_key(), X25519Public::from(&secret));
            assert_eq!(receiver.clone().public_key(), receiver.public_key());
            let mut arbitrary = [0; 32];
            rng.fill_bytes(&mut arbitrary);
            let mut one = [0; 32];
            one[0] = 1;
            let mut minus_one = [255; 32];
            minus_one[0] = 236;
            minus_one[31] = 127;
            for public in [[0; 32], one, minus_one, [255; 32], arbitrary] {
                let public = X25519Public::from(public);
                let shared = secret.diffie_hellman(&public).to_bytes();
                for length in [0, 9, 16, 256, 383] {
                    let body = vec![42; length];
                    let iv = [9; 16];
                    let key = derive_key(&shared, &iv);
                    let token = encrypt_aes256_token(&key, &iv, &body, &[]);
                    assert_eq!(receiver.decrypt(&public, &token), Some(body));
                }
            }
        }
    }

    #[test]
    fn precomputed_datagrams_match_existing_wire_bytes() {
        let mut rng = test_rng();
        let mut encryption = SingleDestEncryption::default();
        let mut keys = vec![[0; 32], [255; 32]];
        for first in 0..32 {
            let mut key = [255; 32];
            key[0] = first;
            keys.push(key);
        }
        for _ in 0..64 {
            let mut key = [0; 32];
            rng.fill_bytes(&mut key);
            keys.push(key);
            keys.push(*EphemeralKeyPair::generate(&mut rng).public.as_bytes());
        }
        for bytes in keys {
            let public = X25519Public::from(bytes);
            for length in [0, 9, 16, 256, 383] {
                let body = vec![0x42; length];
                let mut reference = rng.clone();
                let pair = EphemeralKeyPair::generate(&mut reference);
                let shared = pair.secret.diffie_hellman(&public).to_bytes();
                let mut iv = [0; 16];
                reference.fill_bytes(&mut iv);
                let key = derive_key(&shared, &iv);
                let expected = encrypt_aes256_token(&key, &iv, &body, &[]);
                encryption.prepare(&public);
                let mut copied = encryption.clone();
                let mut copied_rng = rng.clone();
                let ciphertext = encryption.encrypt(&mut rng, &public, &body);
                assert_eq!(copied.encrypt(&mut copied_rng, &public, &body), ciphertext);
                assert_eq!(&ciphertext[..32], pair.public.as_bytes());
                assert_eq!(ciphertext[32..], expected);
            }
        }
    }

    #[test]
    fn aes256_matches_nist_cbc_vector() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap()
            .try_into()
            .unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let token = encrypt_aes256_token(&key, &iv, &plaintext, &[]);
        assert_eq!(&token[..16], &iv);
        let ciphertext = &token[16..];
        assert_eq!(
            hex::encode(&ciphertext[..16]),
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        );
        assert_eq!(ciphertext.len(), 32);
        assert_eq!(decrypt_aes256(&key, &iv, ciphertext), Some(plaintext));
    }

    #[test]
    fn aes256_padding_boundaries_and_malformed_blocks() {
        let key = [7; 32];
        let iv = [9; 16];
        for length in 0..=64 {
            let plaintext = vec![0x42; length];
            let token = encrypt_aes256_token(&key, &iv, &plaintext, &[]);
            assert_eq!(&token[..16], &iv);
            let ciphertext = &token[16..];
            assert_eq!(ciphertext.len(), (length / 16 + 1) * 16);
            assert_eq!(decrypt_aes256(&key, &iv, ciphertext), Some(plaintext));
        }
        for length in 0..16 {
            assert_eq!(decrypt_aes256(&key, &iv, &vec![0; length]), None);
        }
        for padding in 0..=255 {
            let mut block = [16; 16];
            block[15] = padding;
            let ciphertext =
                cbc::Encryptor::<aes::Aes256>::new((&key).into(), (&iv).into())
                    .encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&block);
            let expected = match padding {
                1 => Some(vec![16; 15]),
                16 => Some(Vec::new()),
                _ => None,
            };
            assert_eq!(decrypt_aes256(&key, &iv, &ciphertext), expected);
        }
    }

    #[test]
    fn single_destination_ecdh_encrypts_payload() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"hello world";

        let ciphertext =
            SingleDestEncryption::default().encrypt(&mut rng, &dest_keypair.public, plaintext);

        assert_ne!(&ciphertext[32 + AES_IV_LEN..], plaintext);
        assert!(!ciphertext[..32].iter().all(|&b| b == 0));
    }

    #[test]
    fn ephemeral_public_key_included_in_packet() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"test data";

        let mut reference = rng.clone();
        let expected = EphemeralKeyPair::generate(&mut reference);
        let ciphertext =
            SingleDestEncryption::default().encrypt(&mut rng, &dest_keypair.public, plaintext);

        assert_eq!(&ciphertext[..32], expected.public.as_bytes());
    }

    #[test]
    fn new_ephemeral_key_per_packet() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"test";

        let first =
            SingleDestEncryption::default().encrypt(&mut rng, &dest_keypair.public, plaintext);
        let second =
            SingleDestEncryption::default().encrypt(&mut rng, &dest_keypair.public, plaintext);

        assert_ne!(first[..32], second[..32]);
    }

    #[test]
    fn destination_decrypts_with_ecdh() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"secret message";

        let ciphertext =
            SingleDestEncryption::default().encrypt(&mut rng, &dest_keypair.public, plaintext);

        let ephemeral = X25519Public::from(<[u8; 32]>::try_from(&ciphertext[..32]).unwrap());
        let decrypted = X25519Key::from_bytes(dest_keypair.secret.to_bytes())
            .decrypt(&ephemeral, &ciphertext[32..])
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn create_proof_signs_packet_hash() {
        let mut rng = test_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let packet_data = b"packet contents";

        let signature = create_proof(&signing_key, packet_data);
        let expected_hash = sha256(packet_data);

        assert!(
            signing_key
                .verifying_key()
                .verify(&expected_hash, &signature)
                .is_ok()
        );
    }

    #[test]
    fn proof_verifiable_with_public_key() {
        let mut rng = test_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let packet_data = b"original packet";

        let signature = create_proof(&signing_key, packet_data);
        let packet_hash = sha256(packet_data);

        assert!(verify(&verifying_key, &packet_hash, &signature));

        let tampered_hash = sha256(b"tampered");
        assert!(!verify(&verifying_key, &tampered_hash, &signature));
    }

    #[test]
    fn link_encryption_roundtrip() {
        let mut rng = test_rng();
        let shared_key = [0xABu8; 32];
        let link_id = [0xCDu8; 16];
        let plaintext = b"link message";

        let keys = LinkEncryption::derive_keys(&shared_key, &link_id);
        let ciphertext = LinkEncryption::encrypt(&mut rng, &keys, plaintext);
        let decrypted = LinkEncryption::decrypt(&keys, &ciphertext).expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn link_encryption_includes_hmac() {
        let mut rng = test_rng();
        let shared_key = [0xABu8; 32];
        let link_id = [0xCDu8; 16];
        let plaintext = b"test";

        let keys = LinkEncryption::derive_keys(&shared_key, &link_id);
        let ciphertext = LinkEncryption::encrypt(&mut rng, &keys, plaintext);

        assert!(ciphertext.len() >= 16 + 16 + 32);
    }

    #[test]
    fn link_encryption_tampered_hmac_fails() {
        let mut rng = test_rng();
        let shared_key = [0xABu8; 32];
        let link_id = [0xCDu8; 16];
        let plaintext = b"secret";

        let keys = LinkEncryption::derive_keys(&shared_key, &link_id);
        let mut ciphertext = LinkEncryption::encrypt(&mut rng, &keys, plaintext);

        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;

        assert!(LinkEncryption::decrypt(&keys, &ciphertext).is_none());
    }

    #[test]
    fn link_encryption_wrong_key_fails() {
        let mut rng = test_rng();
        let shared_key = [0xABu8; 32];
        let wrong_key = [0xEFu8; 32];
        let link_id = [0xCDu8; 16];
        let plaintext = b"secret";

        let keys = LinkEncryption::derive_keys(&shared_key, &link_id);
        let wrong_keys = LinkEncryption::derive_keys(&wrong_key, &link_id);
        let ciphertext = LinkEncryption::encrypt(&mut rng, &keys, plaintext);

        assert!(LinkEncryption::decrypt(&wrong_keys, &ciphertext).is_none());
    }

    #[test]
    fn hkdf_output_deterministic() {
        let shared_key =
            hex::decode("19c245e0302f723aed3abfdefc08e962b70d6eb97c1f4f4ae63bc8374c44fe40")
                .unwrap();
        let link_id = hex::decode("33f7b2d6c4acb45786abf7a9bb503c45").unwrap();

        let mut shared_arr = [0u8; 32];
        let mut link_arr = [0u8; 16];
        shared_arr.copy_from_slice(&shared_key);
        link_arr.copy_from_slice(&link_id);

        let keys = LinkEncryption::derive_keys(&shared_arr, &link_arr);

        println!("signing_key: {}", hex::encode(keys.signing_key));
        println!("encryption_key: {}", hex::encode(keys.encryption_key));

        let keys2 = LinkEncryption::derive_keys(&shared_arr, &link_arr);
        assert_eq!(keys.signing_key, keys2.signing_key);
        assert_eq!(keys.encryption_key, keys2.encryption_key);
    }
}
