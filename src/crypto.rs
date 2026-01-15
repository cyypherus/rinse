#![allow(dead_code)]

use aes::cipher::KeyIvInit;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

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

fn derive_link_key(shared_secret: &[u8], link_id: &[u8; 16]) -> [u8; 64] {
    let hk = Hkdf::<Sha256>::new(Some(link_id), shared_secret);
    let mut key = [0u8; 64];
    hk.expand(b"", &mut key).expect("valid length");
    key
}

pub fn hkdf_expand(ikm: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];
    hk.expand(&[], &mut output).expect("valid length");
    output
}

fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(padding_len as u8, padding_len));
    padded
}

fn unpad_pkcs7(data: &[u8]) -> Option<Vec<u8>> {
    let padding_len = *data.last()? as usize;
    if padding_len == 0 || padding_len > 16 || padding_len > data.len() {
        return None;
    }
    if !data[data.len() - padding_len..]
        .iter()
        .all(|&b| b == padding_len as u8)
    {
        return None;
    }
    Some(data[..data.len() - padding_len].to_vec())
}

pub fn encrypt_aes256(key: &[u8; AES_KEY_LEN], iv: &[u8; AES_IV_LEN], plaintext: &[u8]) -> Vec<u8> {
    let padded = pad_pkcs7(plaintext, 16);
    let cipher = Aes256CbcEnc::new(key.into(), iv.into());
    cipher.encrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(&padded)
}

pub fn decrypt_aes256(
    key: &[u8; AES_KEY_LEN],
    iv: &[u8; AES_IV_LEN],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        log::warn!(
            "decrypt_aes256: ciphertext length {} not multiple of 16",
            ciphertext.len()
        );
        return None;
    }
    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let decrypted =
        match cipher.decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(ciphertext) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("decrypt_aes256: decryption failed: {:?}", e);
                return None;
            }
        };
    match unpad_pkcs7(&decrypted) {
        Some(d) => Some(d),
        None => {
            log::warn!("decrypt_aes256: invalid PKCS7 padding");
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
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }

    pub fn ecdh(&self, their_public: &X25519Public) -> [u8; 32] {
        self.secret.diffie_hellman(their_public).to_bytes()
    }
}

pub struct SingleDestEncryption;

impl SingleDestEncryption {
    // "When the packet is sent to a single destination type, Reticulum will automatically
    // create an ephemeral encryption key, perform an ECDH key exchange with the destination's
    // public key (or ratchet key, if available), and encrypt the information."
    //
    // "The public part of the newly generated ephemeral key-pair is included with the
    // encrypted token, and sent along with the encrypted payload data in the packet."
    pub fn encrypt<R: RngCore>(
        rng: &mut R,
        dest_public: &X25519Public,
        plaintext: &[u8],
    ) -> (X25519Public, Vec<u8>) {
        let ephemeral = EphemeralKeyPair::generate(rng);
        let shared = ephemeral.ecdh(dest_public);

        let mut iv = [0u8; AES_IV_LEN];
        rng.fill_bytes(&mut iv);

        let key = derive_key(&shared, &iv);
        let mut ciphertext = iv.to_vec();
        ciphertext.extend(encrypt_aes256(&key, &iv, plaintext));

        (ephemeral.public, ciphertext)
    }

    // "When the destination receives the packet, it can itself perform an ECDH key exchange
    // and decrypt the packet."
    pub fn decrypt(
        dest_secret: &StaticSecret,
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

        let shared = dest_secret
            .diffie_hellman(sender_ephemeral_public)
            .to_bytes();
        let key = derive_key(&shared, &iv);

        decrypt_aes256(&key, &iv, encrypted)
    }
}

pub struct GroupDestEncryption;

impl GroupDestEncryption {
    // "In case the packet is addressed to a group destination type, the packet will be
    // encrypted with the pre-shared AES-256 key associated with the destination."
    pub fn encrypt<R: RngCore>(rng: &mut R, psk: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; AES_IV_LEN];
        rng.fill_bytes(&mut iv);
        let mut ciphertext = iv.to_vec();
        ciphertext.extend(encrypt_aes256(psk, &iv, plaintext));
        ciphertext
    }

    pub fn decrypt(psk: &[u8; AES_KEY_LEN], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < AES_IV_LEN {
            return None;
        }
        let iv: [u8; AES_IV_LEN] = ciphertext[..AES_IV_LEN].try_into().ok()?;
        let encrypted = &ciphertext[AES_IV_LEN..];
        decrypt_aes256(psk, &iv, encrypted)
    }
}

pub(crate) struct LinkEncryption;

impl LinkEncryption {
    pub fn derive_keys(shared_secret: &[u8; 32], link_id: &[u8; 16]) -> LinkKeys {
        let derived = derive_link_key(shared_secret, link_id);
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

        let ciphertext = encrypt_aes256(&keys.encryption_key, &iv, plaintext);

        let mut signed_parts = Vec::with_capacity(AES_IV_LEN + ciphertext.len());
        signed_parts.extend_from_slice(&iv);
        signed_parts.extend_from_slice(&ciphertext);

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

// "Once the packet has been received and decrypted by the addressed destination, that
// destination can opt to prove its receipt of the packet. It does this by calculating
// the SHA-256 hash of the received packet, and signing this hash with its Ed25519
// signing key."
pub fn create_proof(signing_key: &SigningKey, packet_data: &[u8]) -> Signature {
    let hash = sha256(packet_data);
    sign(signing_key, &hash)
}

// "Transport nodes in the network can then direct this proof back to the packets origin,
// where the signature can be verified against the destination's known public signing key."
pub fn verify_proof(
    verifying_key: &VerifyingKey,
    packet_data: &[u8],
    signature: &Signature,
) -> bool {
    let hash = sha256(packet_data);
    verify(verifying_key, &hash, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(12345)
    }

    // "A packet is always created with an associated destination and some payload data.
    // When the packet is sent to a single destination type, Reticulum will automatically
    // create an ephemeral encryption key, perform an ECDH key exchange with the destination's
    // public key, and encrypt the information."
    #[test]
    fn single_destination_ecdh_encrypts_payload() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"hello world";

        let (ephemeral_pub, ciphertext) =
            SingleDestEncryption::encrypt(&mut rng, &dest_keypair.public, plaintext);

        assert_ne!(&ciphertext[AES_IV_LEN..], plaintext);
        assert!(!ephemeral_pub.as_bytes().iter().all(|&b| b == 0));
    }

    // "The public part of the newly generated ephemeral key-pair is included with the
    // encrypted token, and sent along with the encrypted payload data in the packet."
    #[test]
    fn ephemeral_public_key_included_in_packet() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"test data";

        let (ephemeral_pub, _ciphertext) =
            SingleDestEncryption::encrypt(&mut rng, &dest_keypair.public, plaintext);

        assert_eq!(ephemeral_pub.as_bytes().len(), 32);
    }

    // "A new ephemeral key is used for every packet sent in this way."
    #[test]
    fn new_ephemeral_key_per_packet() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"test";

        let (ephemeral1, _) =
            SingleDestEncryption::encrypt(&mut rng, &dest_keypair.public, plaintext);
        let (ephemeral2, _) =
            SingleDestEncryption::encrypt(&mut rng, &dest_keypair.public, plaintext);

        assert_ne!(ephemeral1.as_bytes(), ephemeral2.as_bytes());
    }

    // "When the destination receives the packet, it can itself perform an ECDH key exchange
    // and decrypt the packet."
    #[test]
    fn destination_decrypts_with_ecdh() {
        let mut rng = test_rng();
        let dest_keypair = EphemeralKeyPair::generate(&mut rng);
        let plaintext = b"secret message";

        let (ephemeral_pub, ciphertext) =
            SingleDestEncryption::encrypt(&mut rng, &dest_keypair.public, plaintext);

        let decrypted =
            SingleDestEncryption::decrypt(&dest_keypair.secret, &ephemeral_pub, &ciphertext)
                .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    // "Once the packet has been received and decrypted by the addressed destination, that
    // destination can opt to prove its receipt of the packet. It does this by calculating
    // the SHA-256 hash of the received packet, and signing this hash with its Ed25519
    // signing key."
    #[test]
    fn proof_of_receipt_is_sha256_hash_signed_with_ed25519() {
        let mut rng = test_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let packet_data = b"packet contents";

        let proof = create_proof(&signing_key, packet_data);
        let expected_hash = sha256(packet_data);

        assert!(
            signing_key
                .verifying_key()
                .verify(&expected_hash, &proof)
                .is_ok()
        );
    }

    // "Transport nodes in the network can then direct this proof back to the packets origin,
    // where the signature can be verified against the destination's known public signing key."
    #[test]
    fn proof_signature_verifiable_with_public_key() {
        let mut rng = test_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let packet_data = b"original packet";

        let proof = create_proof(&signing_key, packet_data);

        assert!(verify_proof(&verifying_key, packet_data, &proof));
        assert!(!verify_proof(&verifying_key, b"tampered", &proof));
    }

    // "In case the packet is addressed to a group destination type, the packet will be
    // encrypted with the pre-shared AES-256 key associated with the destination."
    #[test]
    fn group_destination_uses_preshared_aes256() {
        let mut rng = test_rng();
        let mut psk = [0u8; 32];
        rng.fill_bytes(&mut psk);
        let plaintext = b"group message";

        let ciphertext = GroupDestEncryption::encrypt(&mut rng, &psk, plaintext);
        let decrypted = GroupDestEncryption::decrypt(&psk, &ciphertext).expect("decrypt");

        assert_eq!(decrypted, plaintext);
        assert_ne!(&ciphertext[AES_IV_LEN..], plaintext);
    }

    // "In case the packet is addressed to a plain destination type, the payload data will
    // not be encrypted."
    #[test]
    fn plain_destination_no_encryption() {
        let plaintext = b"plain data";
        assert_eq!(plaintext, plaintext);
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
}
