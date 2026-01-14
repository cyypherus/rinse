// Announce packet data format
// Reference: rns-reference/RNS/Identity.py validate_announce()
//
// Announce data layout (without ratchet, context_flag = 0):
//   [public_key: 64 bytes] [name_hash: 10 bytes] [random_hash: 10 bytes] [signature: 64 bytes] [app_data: 0+ bytes]
//
// Announce data layout (with ratchet, context_flag = 1):
//   [public_key: 64 bytes] [name_hash: 10 bytes] [random_hash: 10 bytes] [ratchet: 32 bytes] [signature: 64 bytes] [app_data: 0+ bytes]
//
// Where:
//   public_key = encryption_key (32 bytes X25519) || signing_key (32 bytes Ed25519)
//   name_hash = truncated SHA-256 of destination name (10 bytes)
//   random_hash = random(5 bytes) || timestamp(5 bytes)
//   ratchet = X25519 public key for forward secrecy (32 bytes, optional)
//   signature = Ed25519 signature over: destination_hash || public_key || name_hash || random_hash || ratchet || app_data
//   app_data = application-specific data (variable length)
//
// Constants from RNS/Identity.py:
//   KEYSIZE = 512 bits = 64 bytes (32 + 32)
//   NAME_HASH_LENGTH = 80 bits = 10 bytes
//   SIGLENGTH = 512 bits = 64 bytes
//   RATCHETSIZE = 256 bits = 32 bytes

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::PublicKey as X25519Public;

use crate::crypto::sha256;

pub(crate) const ENCRYPTION_KEY_LEN: usize = 32;
pub(crate) const SIGNING_KEY_LEN: usize = 32;
pub(crate) const PUBLIC_KEY_LEN: usize = ENCRYPTION_KEY_LEN + SIGNING_KEY_LEN; // 64
pub(crate) const NAME_HASH_LEN: usize = 10;
pub(crate) const RANDOM_HASH_LEN: usize = 10;
pub(crate) const SIGNATURE_LEN: usize = 64;
pub(crate) const RATCHET_LEN: usize = 32;

pub(crate) const MIN_ANNOUNCE_LEN: usize =
    PUBLIC_KEY_LEN + NAME_HASH_LEN + RANDOM_HASH_LEN + SIGNATURE_LEN; // 148
pub(crate) const MIN_ANNOUNCE_LEN_WITH_RATCHET: usize = MIN_ANNOUNCE_LEN + RATCHET_LEN; // 180

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnnounceData {
    pub encryption_key: [u8; ENCRYPTION_KEY_LEN],
    pub signing_key: [u8; SIGNING_KEY_LEN],
    pub name_hash: [u8; NAME_HASH_LEN],
    pub random_hash: [u8; RANDOM_HASH_LEN],
    pub ratchet: Option<[u8; RATCHET_LEN]>,
    pub signature: [u8; SIGNATURE_LEN],
    pub app_data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnnounceError {
    TooShort,
    InvalidSignature,
    DestinationMismatch,
}

impl AnnounceData {
    pub fn parse(data: &[u8], has_ratchet: bool) -> Result<Self, AnnounceError> {
        let min_len = if has_ratchet {
            MIN_ANNOUNCE_LEN_WITH_RATCHET
        } else {
            MIN_ANNOUNCE_LEN
        };

        if data.len() < min_len {
            return Err(AnnounceError::TooShort);
        }

        let mut pos = 0;

        let mut encryption_key = [0u8; ENCRYPTION_KEY_LEN];
        encryption_key.copy_from_slice(&data[pos..pos + ENCRYPTION_KEY_LEN]);
        pos += ENCRYPTION_KEY_LEN;

        let mut signing_key = [0u8; SIGNING_KEY_LEN];
        signing_key.copy_from_slice(&data[pos..pos + SIGNING_KEY_LEN]);
        pos += SIGNING_KEY_LEN;

        let mut name_hash = [0u8; NAME_HASH_LEN];
        name_hash.copy_from_slice(&data[pos..pos + NAME_HASH_LEN]);
        pos += NAME_HASH_LEN;

        let mut random_hash = [0u8; RANDOM_HASH_LEN];
        random_hash.copy_from_slice(&data[pos..pos + RANDOM_HASH_LEN]);
        pos += RANDOM_HASH_LEN;

        let ratchet = if has_ratchet {
            let mut r = [0u8; RATCHET_LEN];
            r.copy_from_slice(&data[pos..pos + RATCHET_LEN]);
            pos += RATCHET_LEN;
            Some(r)
        } else {
            None
        };

        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&data[pos..pos + SIGNATURE_LEN]);
        pos += SIGNATURE_LEN;

        let app_data = data[pos..].to_vec();

        Ok(Self {
            encryption_key,
            signing_key,
            name_hash,
            random_hash,
            ratchet,
            signature,
            app_data,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.encryption_key);
        out.extend_from_slice(&self.signing_key);
        out.extend_from_slice(&self.name_hash);
        out.extend_from_slice(&self.random_hash);
        if let Some(ref ratchet) = self.ratchet {
            out.extend_from_slice(ratchet);
        }
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.app_data);
        out
    }

    pub fn wire_len(&self) -> usize {
        let base = MIN_ANNOUNCE_LEN + self.app_data.len();
        if self.ratchet.is_some() {
            base + RATCHET_LEN
        } else {
            base
        }
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out[..ENCRYPTION_KEY_LEN].copy_from_slice(&self.encryption_key);
        out[ENCRYPTION_KEY_LEN..].copy_from_slice(&self.signing_key);
        out
    }

    pub fn encryption_public_key(&self) -> X25519Public {
        X25519Public::from(self.encryption_key)
    }

    pub fn signing_public_key(&self) -> Result<VerifyingKey, AnnounceError> {
        VerifyingKey::from_bytes(&self.signing_key).map_err(|_| AnnounceError::InvalidSignature)
    }

    pub fn verify(&self, destination_hash: &[u8; 16]) -> Result<(), AnnounceError> {
        let verifying_key = self.signing_public_key()?;

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(destination_hash);
        signed_data.extend_from_slice(&self.encryption_key);
        signed_data.extend_from_slice(&self.signing_key);
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&self.random_hash);
        if let Some(ref ratchet) = self.ratchet {
            signed_data.extend_from_slice(ratchet);
        }
        signed_data.extend_from_slice(&self.app_data);

        let signature = Signature::from_bytes(&self.signature);

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| AnnounceError::InvalidSignature)
    }

    pub fn verify_destination(&self, destination_hash: &[u8; 16]) -> Result<(), AnnounceError> {
        let identity_hash = &sha256(&self.public_key_bytes())[..16];
        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(&self.name_hash);
        hash_material.extend_from_slice(identity_hash);
        let expected_hash = &sha256(&hash_material)[..16];

        if destination_hash == expected_hash {
            Ok(())
        } else {
            Err(AnnounceError::DestinationMismatch)
        }
    }
}

pub(crate) struct AnnounceBuilder {
    encryption_key: [u8; ENCRYPTION_KEY_LEN],
    signing_key: SigningKey,
    name_hash: [u8; NAME_HASH_LEN],
    random_hash: [u8; RANDOM_HASH_LEN],
    ratchet: Option<[u8; RATCHET_LEN]>,
    app_data: Vec<u8>,
}

impl AnnounceBuilder {
    pub fn new(
        encryption_key: [u8; ENCRYPTION_KEY_LEN],
        signing_key: SigningKey,
        name_hash: [u8; NAME_HASH_LEN],
        random_hash: [u8; RANDOM_HASH_LEN],
    ) -> Self {
        Self {
            encryption_key,
            signing_key,
            name_hash,
            random_hash,
            ratchet: None,
            app_data: Vec::new(),
        }
    }

    pub fn with_ratchet(mut self, ratchet: [u8; RATCHET_LEN]) -> Self {
        self.ratchet = Some(ratchet);
        self
    }

    pub fn with_app_data(mut self, app_data: Vec<u8>) -> Self {
        self.app_data = app_data;
        self
    }

    pub fn build(self, destination_hash: &[u8; 16]) -> AnnounceData {
        let signing_pub_bytes = self.signing_key.verifying_key().to_bytes();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(destination_hash);
        signed_data.extend_from_slice(&self.encryption_key);
        signed_data.extend_from_slice(&signing_pub_bytes);
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&self.random_hash);
        if let Some(ref ratchet) = self.ratchet {
            signed_data.extend_from_slice(ratchet);
        }
        signed_data.extend_from_slice(&self.app_data);

        let signature = self.signing_key.sign(&signed_data);

        AnnounceData {
            encryption_key: self.encryption_key,
            signing_key: signing_pub_bytes,
            name_hash: self.name_hash,
            random_hash: self.random_hash,
            ratchet: self.ratchet,
            signature: signature.to_bytes(),
            app_data: self.app_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors generated from RNS Python implementation:
    // enc_prv = bytes(0..32), sig_prv = bytes(32..64)
    // name = "test.app", random_hash = [1,2,3,4,5,0,0,0,0,0]
    mod rns_vectors {
        pub const DEST_HASH: [u8; 16] = [
            85, 145, 28, 204, 77, 65, 140, 130, 169, 25, 222, 45, 116, 198, 106, 149,
        ];
        pub const NAME_HASH: [u8; 10] = [198, 102, 83, 152, 248, 48, 103, 107, 210, 131];
        pub const RANDOM_HASH: [u8; 10] = [1, 2, 3, 4, 5, 0, 0, 0, 0, 0];
        pub const ANNOUNCE_DATA: [u8; 148] = [
            143, 64, 197, 173, 182, 143, 37, 98, 74, 229, 178, 20, 234, 118, 122, 110, 201, 77,
            130, 157, 61, 123, 94, 26, 209, 186, 111, 62, 33, 56, 40, 95, 41, 172, 186, 225, 65,
            188, 202, 240, 178, 46, 26, 148, 211, 77, 11, 199, 54, 30, 82, 109, 11, 254, 18, 200,
            151, 148, 188, 147, 34, 150, 109, 215, 198, 102, 83, 152, 248, 48, 103, 107, 210, 131,
            1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 37, 19, 171, 110, 170, 166, 74, 183, 71, 168, 176, 5, 46,
            84, 104, 119, 149, 64, 79, 36, 245, 240, 59, 128, 197, 233, 197, 77, 200, 91, 170, 13,
            73, 54, 226, 114, 217, 185, 105, 98, 40, 116, 174, 76, 76, 34, 158, 216, 147, 121, 141,
            205, 8, 83, 164, 8, 108, 77, 140, 85, 127, 145, 26, 5,
        ];
        pub const ANNOUNCE_DATA_WITH_APP: [u8; 153] = [
            143, 64, 197, 173, 182, 143, 37, 98, 74, 229, 178, 20, 234, 118, 122, 110, 201, 77,
            130, 157, 61, 123, 94, 26, 209, 186, 111, 62, 33, 56, 40, 95, 41, 172, 186, 225, 65,
            188, 202, 240, 178, 46, 26, 148, 211, 77, 11, 199, 54, 30, 82, 109, 11, 254, 18, 200,
            151, 148, 188, 147, 34, 150, 109, 215, 198, 102, 83, 152, 248, 48, 103, 107, 210, 131,
            1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 118, 185, 59, 89, 131, 186, 174, 186, 60, 65, 239, 12,
            175, 46, 8, 255, 162, 186, 173, 209, 220, 169, 241, 4, 71, 226, 54, 162, 51, 229, 127,
            134, 107, 175, 77, 36, 202, 191, 189, 44, 53, 80, 113, 225, 57, 70, 88, 54, 125, 188,
            138, 248, 87, 153, 235, 44, 183, 46, 108, 232, 4, 0, 117, 6, 104, 101, 108, 108, 111,
        ];
        pub const APP_DATA: &[u8] = b"hello";

        // Vector 2: Different keys, name="myapp.service"
        pub const DEST_HASH_2: [u8; 16] = [
            117, 251, 200, 95, 21, 214, 33, 220, 41, 114, 99, 202, 132, 2, 61, 225,
        ];
        pub const ANNOUNCE_DATA_2: [u8; 148] = [
            56, 171, 102, 75, 216, 111, 119, 215, 230, 107, 221, 154, 224, 121, 41, 19, 169, 79,
            216, 179, 58, 18, 96, 2, 126, 75, 70, 193, 244, 136, 76, 103, 231, 52, 234, 108, 43,
            98, 87, 222, 114, 53, 94, 71, 42, 160, 90, 76, 72, 126, 107, 70, 60, 2, 158, 211, 6,
            223, 47, 1, 181, 99, 107, 88, 128, 114, 1, 171, 124, 228, 85, 247, 206, 57, 10, 20, 30,
            40, 50, 1, 2, 3, 4, 5, 19, 92, 87, 1, 244, 243, 147, 123, 32, 157, 99, 152, 82, 16,
            235, 105, 176, 144, 120, 1, 176, 190, 194, 177, 211, 221, 91, 169, 225, 178, 109, 69,
            188, 143, 129, 147, 144, 105, 124, 43, 206, 83, 64, 68, 191, 180, 40, 215, 55, 236,
            150, 122, 253, 33, 239, 213, 201, 172, 11, 136, 214, 22, 33, 14,
        ];

        // Vector 3: With ratchet
        pub const DEST_HASH_3: [u8; 16] = [
            5, 42, 133, 142, 158, 10, 202, 58, 106, 117, 167, 110, 60, 36, 196, 38,
        ];
        pub const ANNOUNCE_DATA_3: [u8; 180] = [
            123, 78, 144, 155, 190, 127, 254, 68, 196, 101, 162, 32, 3, 125, 96, 142, 227, 88, 151,
            211, 30, 249, 114, 240, 127, 116, 137, 44, 176, 247, 63, 19, 160, 154, 165, 244, 122,
            103, 89, 128, 47, 249, 85, 248, 220, 45, 42, 20, 165, 201, 157, 35, 190, 151, 248, 100,
            18, 127, 249, 56, 52, 85, 164, 240, 235, 156, 176, 161, 113, 197, 61, 99, 129, 205, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51,
            51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 65, 225, 203, 88,
            205, 63, 193, 246, 189, 188, 96, 61, 150, 40, 156, 254, 67, 33, 128, 232, 188, 166, 78,
            115, 64, 167, 133, 174, 63, 113, 224, 67, 10, 90, 192, 166, 219, 170, 146, 205, 70, 29,
            209, 248, 190, 38, 178, 152, 204, 248, 54, 52, 196, 39, 24, 155, 150, 104, 222, 73, 73,
            197, 26, 3,
        ];

        // Vector 4: With longer app_data
        pub const DEST_HASH_4: [u8; 16] = [
            127, 114, 103, 2, 178, 126, 157, 211, 40, 181, 243, 75, 94, 33, 251, 187,
        ];
        pub const ANNOUNCE_DATA_4: [u8; 201] = [
            28, 245, 121, 171, 164, 90, 16, 186, 29, 30, 240, 109, 145, 252, 162, 170, 158, 208,
            161, 21, 5, 21, 101, 49, 85, 64, 93, 11, 24, 203, 154, 103, 178, 73, 29, 149, 2, 174,
            40, 99, 10, 43, 172, 178, 224, 199, 69, 16, 255, 205, 211, 40, 195, 52, 255, 62, 19,
            147, 231, 91, 45, 49, 231, 220, 48, 14, 105, 159, 86, 23, 167, 220, 44, 76, 99, 98, 97,
            96, 95, 94, 93, 92, 91, 90, 5, 133, 224, 63, 208, 119, 98, 178, 131, 198, 55, 119, 56,
            50, 236, 48, 252, 29, 132, 75, 11, 6, 230, 221, 228, 44, 210, 50, 191, 191, 95, 30, 87,
            226, 87, 13, 50, 223, 71, 180, 199, 159, 92, 53, 236, 183, 201, 129, 32, 47, 83, 22,
            197, 108, 161, 58, 114, 107, 197, 174, 96, 238, 153, 14, 84, 104, 105, 115, 32, 105,
            115, 32, 97, 32, 108, 111, 110, 103, 101, 114, 32, 97, 112, 112, 108, 105, 99, 97, 116,
            105, 111, 110, 32, 100, 97, 116, 97, 32, 112, 97, 121, 108, 111, 97, 100, 32, 102, 111,
            114, 32, 116, 101, 115, 116, 105, 110, 103,
        ];
        pub const APP_DATA_4: &[u8] = b"This is a longer application data payload for testing";
    }

    #[test]
    fn decode_rns_announce() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA, false).unwrap();

        assert_eq!(parsed.name_hash, rns_vectors::NAME_HASH);
        assert_eq!(parsed.random_hash, rns_vectors::RANDOM_HASH);
        assert!(parsed.ratchet.is_none());
        assert!(parsed.app_data.is_empty());

        parsed.verify(&rns_vectors::DEST_HASH).unwrap();
        parsed.verify_destination(&rns_vectors::DEST_HASH).unwrap();
    }

    #[test]
    fn decode_rns_announce_with_app_data() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA_WITH_APP, false).unwrap();

        assert_eq!(parsed.name_hash, rns_vectors::NAME_HASH);
        assert_eq!(parsed.random_hash, rns_vectors::RANDOM_HASH);
        assert_eq!(parsed.app_data, rns_vectors::APP_DATA);

        parsed.verify(&rns_vectors::DEST_HASH).unwrap();
        parsed.verify_destination(&rns_vectors::DEST_HASH).unwrap();
    }

    #[test]
    fn encode_matches_rns() {
        use x25519_dalek::StaticSecret;

        // Same keys used to generate RNS test vectors
        let enc_prv_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let sig_prv_bytes: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);

        let enc_secret = StaticSecret::from(enc_prv_bytes);
        let enc_public = X25519Public::from(&enc_secret);
        let signing_key = SigningKey::from_bytes(&sig_prv_bytes);

        let announce = AnnounceBuilder::new(
            *enc_public.as_bytes(),
            signing_key,
            rns_vectors::NAME_HASH,
            rns_vectors::RANDOM_HASH,
        )
        .build(&rns_vectors::DEST_HASH);

        let encoded = announce.to_bytes();
        assert_eq!(encoded.as_slice(), &rns_vectors::ANNOUNCE_DATA[..]);
    }

    #[test]
    fn encode_with_app_data_matches_rns() {
        use x25519_dalek::StaticSecret;

        let enc_prv_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let sig_prv_bytes: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);

        let enc_secret = StaticSecret::from(enc_prv_bytes);
        let enc_public = X25519Public::from(&enc_secret);
        let signing_key = SigningKey::from_bytes(&sig_prv_bytes);

        let announce = AnnounceBuilder::new(
            *enc_public.as_bytes(),
            signing_key,
            rns_vectors::NAME_HASH,
            rns_vectors::RANDOM_HASH,
        )
        .with_app_data(rns_vectors::APP_DATA.to_vec())
        .build(&rns_vectors::DEST_HASH);

        let encoded = announce.to_bytes();
        assert_eq!(encoded.as_slice(), &rns_vectors::ANNOUNCE_DATA_WITH_APP[..]);
    }

    #[test]
    fn roundtrip() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA, false).unwrap();
        let encoded = parsed.to_bytes();
        assert_eq!(encoded.as_slice(), &rns_vectors::ANNOUNCE_DATA[..]);
    }

    #[test]
    fn invalid_signature_rejected() {
        let mut data = rns_vectors::ANNOUNCE_DATA.to_vec();
        data[84] ^= 0xFF; // Tamper with signature

        let parsed = AnnounceData::parse(&data, false).unwrap();
        assert_eq!(
            parsed.verify(&rns_vectors::DEST_HASH),
            Err(AnnounceError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_dest_hash_rejected() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA, false).unwrap();
        let wrong_hash = [0u8; 16];
        assert_eq!(
            parsed.verify(&wrong_hash),
            Err(AnnounceError::InvalidSignature)
        );
    }

    #[test]
    fn too_short_rejected() {
        assert_eq!(
            AnnounceData::parse(&[0u8; 100], false),
            Err(AnnounceError::TooShort)
        );
    }

    #[test]
    fn decode_rns_vector_2() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA_2, false).unwrap();
        parsed.verify(&rns_vectors::DEST_HASH_2).unwrap();
        parsed
            .verify_destination(&rns_vectors::DEST_HASH_2)
            .unwrap();
    }

    #[test]
    fn decode_rns_vector_3_with_ratchet() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA_3, true).unwrap();
        assert!(parsed.ratchet.is_some());
        assert_eq!(parsed.ratchet.unwrap(), [0x33; 32]);
        parsed.verify(&rns_vectors::DEST_HASH_3).unwrap();
        parsed
            .verify_destination(&rns_vectors::DEST_HASH_3)
            .unwrap();
    }

    #[test]
    fn decode_rns_vector_4_with_long_app_data() {
        let parsed = AnnounceData::parse(&rns_vectors::ANNOUNCE_DATA_4, false).unwrap();
        assert_eq!(parsed.app_data, rns_vectors::APP_DATA_4);
        parsed.verify(&rns_vectors::DEST_HASH_4).unwrap();
        parsed
            .verify_destination(&rns_vectors::DEST_HASH_4)
            .unwrap();
    }
}
