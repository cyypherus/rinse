use std::time::Instant;

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::{LinkEncryption, LinkKeys, sha256, sign, verify};
use crate::packet::Address;

pub type LinkId = [u8; 16];

// Link Request: 83 bytes on wire
// Header Type 2, destination + transport_id addresses
// Data: encryption_public (32) + signing_public (32) = 64 bytes
pub(crate) struct LinkRequest {
    pub encryption_public: X25519Public,
    pub signing_public: [u8; 32],
}

impl LinkRequest {
    pub fn new(encryption_public: X25519Public, signing_public: [u8; 32]) -> Self {
        Self {
            encryption_public,
            signing_public,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(self.encryption_public.as_bytes());
        out.extend_from_slice(&self.signing_public);
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }
        let encryption_public = X25519Public::from(<[u8; 32]>::try_from(&data[..32]).ok()?);
        let signing_public: [u8; 32] = data[32..64].try_into().ok()?;
        Some(Self {
            encryption_public,
            signing_public,
        })
    }

    pub fn link_id(hashable_part: &[u8]) -> LinkId {
        sha256(hashable_part)[..16].try_into().unwrap()
    }
}

// Link Proof: 115 bytes on wire
// Header Type 2, link_id + transport_id addresses
// Context: LinkProof (0xFD)
// Data: signature (64) + encryption_public (32) + signalling_bytes (3) = 99 bytes
pub(crate) struct LinkProof {
    pub encryption_public: X25519Public,
    pub signalling_bytes: [u8; 3],
    pub signature: Signature,
}

impl LinkProof {
    pub fn create(
        link_id: &LinkId,
        responder_encryption_public: &X25519Public,
        responder_signing_key: &SigningKey,
    ) -> Self {
        // signed_data = link_id + pub_bytes + sig_pub_bytes + signalling_bytes
        // For now, use default signalling_bytes (MTU 500, mode 0)
        let signalling_bytes = [0x01, 0xf4, 0x00]; // MTU=500, mode=0
        let mut sign_data = Vec::with_capacity(83);
        sign_data.extend_from_slice(link_id);
        sign_data.extend_from_slice(responder_encryption_public.as_bytes());
        sign_data.extend_from_slice(responder_signing_key.verifying_key().as_bytes());
        sign_data.extend_from_slice(&signalling_bytes);
        let signature = sign(responder_signing_key, &sign_data);
        Self {
            encryption_public: *responder_encryption_public,
            signalling_bytes,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // proof_data = signature + pub_bytes + signalling_bytes
        let mut out = Vec::with_capacity(99);
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(self.encryption_public.as_bytes());
        out.extend_from_slice(&self.signalling_bytes);
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        // proof_data = signature (64) + pub_bytes (32) + signalling_bytes (3)
        if data.len() < 99 {
            return None;
        }
        let signature = Signature::from_bytes(&data[..64].try_into().ok()?);
        let encryption_public = X25519Public::from(<[u8; 32]>::try_from(&data[64..96]).ok()?);
        let signalling_bytes = <[u8; 3]>::try_from(&data[96..99]).ok()?;
        Some(Self {
            encryption_public,
            signalling_bytes,
            signature,
        })
    }

    pub fn verify(&self, link_id: &LinkId, responder_signing_key: &VerifyingKey) -> bool {
        // signed_data = link_id + pub_bytes + sig_pub_bytes + signalling_bytes
        let mut sign_data = Vec::with_capacity(83);
        sign_data.extend_from_slice(link_id);
        sign_data.extend_from_slice(self.encryption_public.as_bytes());
        sign_data.extend_from_slice(responder_signing_key.as_bytes());
        sign_data.extend_from_slice(&self.signalling_bytes);
        verify(responder_signing_key, &sign_data, &self.signature)
    }
}

pub(crate) const KEEPALIVE_REQUEST: u8 = 0xFF;
pub(crate) const KEEPALIVE_RESPONSE: u8 = 0xFE;

const MSGPACK_FLOAT64: u8 = 0xcb;

pub(crate) fn encode_rtt(seconds: f64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(MSGPACK_FLOAT64);
    buf.extend_from_slice(&seconds.to_be_bytes());
    buf
}

pub(crate) fn decode_rtt(data: &[u8]) -> Option<f64> {
    if data.len() >= 9 && data[0] == MSGPACK_FLOAT64 {
        let bytes: [u8; 8] = data[1..9].try_into().ok()?;
        Some(f64::from_be_bytes(bytes))
    } else if data.len() >= 5 && data[0] == 0xca {
        let bytes: [u8; 4] = data[1..5].try_into().ok()?;
        Some(f32::from_be_bytes(bytes) as f64)
    } else {
        None
    }
}

pub(crate) struct PendingLink {
    pub link_id: LinkId,
    pub initiator_encryption_secret: StaticSecret,
    pub destination: Address,
    pub request_time: Instant,
    pub initiating_service: Option<Address>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkState {
    Handshake,
    Active,
    Stale,
    Closed,
}

pub(crate) struct EstablishedLink {
    pub link_id: LinkId,
    pub destination: Address,
    pub is_initiator: bool,
    pub state: LinkState,
    pub activated_at: Option<Instant>,
    pub last_inbound: Instant,
    pub last_outbound: Instant,
    pub last_keepalive_sent: Option<Instant>,
    pub rtt_ms: Option<u64>,
    keys: LinkKeys,
    pub(crate) pending_requests:
        std::collections::HashMap<crate::WireRequestId, (Address, crate::RequestId)>,
}

const KEEPALIVE_MAX_SECS: u64 = 360;
const KEEPALIVE_MIN_SECS: u64 = 5;
const STALE_FACTOR: u64 = 2;

impl EstablishedLink {
    pub fn from_initiator(
        pending: PendingLink,
        responder_public: &X25519Public,
        now: Instant,
    ) -> Self {
        let shared_key = pending
            .initiator_encryption_secret
            .diffie_hellman(responder_public)
            .to_bytes();
        let keys = LinkEncryption::derive_keys(&shared_key, &pending.link_id);
        let rtt_ms = now.duration_since(pending.request_time).as_millis() as u64;
        Self {
            link_id: pending.link_id,
            destination: pending.destination,
            is_initiator: true,
            state: LinkState::Active,
            activated_at: Some(now),
            last_inbound: now,
            last_outbound: now,
            last_keepalive_sent: None,
            rtt_ms: Some(rtt_ms),
            keys,
            pending_requests: std::collections::HashMap::new(),
        }
    }

    pub fn from_responder(
        link_id: LinkId,
        responder_secret: &StaticSecret,
        initiator_public: &X25519Public,
        destination: Address,
        now: Instant,
    ) -> Self {
        let shared_key = responder_secret.diffie_hellman(initiator_public).to_bytes();
        let keys = LinkEncryption::derive_keys(&shared_key, &link_id);
        Self {
            link_id,
            destination,
            is_initiator: false,
            state: LinkState::Handshake,
            activated_at: None,
            last_inbound: now,
            last_outbound: now,
            last_keepalive_sent: None,
            rtt_ms: None,
            keys,
            pending_requests: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn encrypt<R: RngCore>(&self, rng: &mut R, plaintext: &[u8]) -> Vec<u8> {
        LinkEncryption::encrypt(rng, &self.keys, plaintext)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        LinkEncryption::decrypt(&self.keys, ciphertext)
    }

    pub(crate) fn touch_inbound(&mut self, now: Instant) {
        self.last_inbound = now;
        if self.state == LinkState::Stale {
            self.state = LinkState::Active;
        }
    }

    pub(crate) fn touch_outbound(&mut self, now: Instant) {
        self.last_outbound = now;
    }

    pub(crate) fn set_rtt(&mut self, rtt_ms: u64) {
        self.rtt_ms = Some(rtt_ms);
    }

    pub(crate) fn rtt_seconds(&self) -> Option<f64> {
        self.rtt_ms.map(|ms| ms as f64 / 1000.0)
    }

    pub(crate) fn keepalive_interval_secs(&self) -> u64 {
        if let Some(rtt_ms) = self.rtt_ms {
            // rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT) where KEEPALIVE_MAX_RTT = 1.75s = 1750ms
            // = rtt_ms * 360 / 1750
            let scaled = (rtt_ms * KEEPALIVE_MAX_SECS) / 1750;
            scaled.clamp(KEEPALIVE_MIN_SECS, KEEPALIVE_MAX_SECS)
        } else {
            KEEPALIVE_MAX_SECS
        }
    }

    pub(crate) fn stale_time_secs(&self) -> u64 {
        self.keepalive_interval_secs() * STALE_FACTOR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EphemeralKeyPair;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn link_request_roundtrip() {
        let mut rng = test_rng();
        let keypair = EphemeralKeyPair::generate(&mut rng);
        let signing_key = SigningKey::generate(&mut rng);

        let request = LinkRequest::new(keypair.public, signing_key.verifying_key().to_bytes());
        let bytes = request.to_bytes();
        let parsed = LinkRequest::parse(&bytes).unwrap();

        assert_eq!(
            parsed.encryption_public.as_bytes(),
            request.encryption_public.as_bytes()
        );
        assert_eq!(parsed.signing_public, request.signing_public);
    }

    #[test]
    fn link_proof_roundtrip() {
        let mut rng = test_rng();
        let keypair = EphemeralKeyPair::generate(&mut rng);
        let signing_key = SigningKey::generate(&mut rng);
        let link_id: LinkId = [0xCD; 16];

        let proof = LinkProof::create(&link_id, &keypair.public, &signing_key);
        let bytes = proof.to_bytes();
        let parsed = LinkProof::parse(&bytes).unwrap();

        assert_eq!(
            parsed.encryption_public.as_bytes(),
            proof.encryption_public.as_bytes()
        );
        assert!(parsed.verify(&link_id, &signing_key.verifying_key()));
    }

    #[test]
    fn link_proof_invalid_link_id_fails_verification() {
        let mut rng = test_rng();
        let keypair = EphemeralKeyPair::generate(&mut rng);
        let signing_key = SigningKey::generate(&mut rng);
        let link_id: LinkId = [0xCD; 16];
        let wrong_link_id: LinkId = [0xEF; 16];

        let proof = LinkProof::create(&link_id, &keypair.public, &signing_key);
        assert!(!proof.verify(&wrong_link_id, &signing_key.verifying_key()));
    }

    #[test]
    fn link_proof_wrong_key_fails_verification() {
        let mut rng = test_rng();
        let keypair = EphemeralKeyPair::generate(&mut rng);
        let signing_key = SigningKey::generate(&mut rng);
        let other_signing_key = SigningKey::generate(&mut rng);
        let link_id: LinkId = [0xCD; 16];

        let proof = LinkProof::create(&link_id, &keypair.public, &signing_key);
        assert!(!proof.verify(&link_id, &other_signing_key.verifying_key()));
    }

    #[test]
    fn established_link_can_encrypt_decrypt() {
        let mut rng = test_rng();
        let initiator_keypair = EphemeralKeyPair::generate(&mut rng);
        let responder_keypair = EphemeralKeyPair::generate(&mut rng);
        let dest: Address = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];
        let now = Instant::now();

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_keypair.secret,
            destination: dest,
            request_time: now,
            initiating_service: None,
        };

        let initiator_link =
            EstablishedLink::from_initiator(pending, &responder_keypair.public, now);
        let responder_link = EstablishedLink::from_responder(
            link_id,
            &responder_keypair.secret,
            &initiator_keypair.public,
            dest,
            now,
        );

        let plaintext = b"hello over the link";
        let ciphertext = initiator_link.encrypt(&mut rng, plaintext);
        let decrypted = responder_link.decrypt(&ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);

        let response = b"response message";
        let response_ciphertext = responder_link.encrypt(&mut rng, response);
        let response_decrypted = initiator_link
            .decrypt(&response_ciphertext)
            .expect("decrypt");
        assert_eq!(response_decrypted, response);

        assert_eq!(initiator_link.link_id, responder_link.link_id);
    }

    #[test]
    fn full_link_establishment_flow() {
        let mut rng = test_rng();
        let now = Instant::now();

        let initiator_enc = EphemeralKeyPair::generate(&mut rng);
        let initiator_sig = SigningKey::generate(&mut rng);
        let dest: Address = [0xAB; 16];

        let request = LinkRequest::new(
            initiator_enc.public,
            initiator_sig.verifying_key().to_bytes(),
        );
        let link_id = LinkRequest::link_id(&request.to_bytes());

        let responder_enc = EphemeralKeyPair::generate(&mut rng);
        let responder_sig = SigningKey::generate(&mut rng);

        let proof = LinkProof::create(&link_id, &responder_enc.public, &responder_sig);
        assert!(proof.verify(&link_id, &responder_sig.verifying_key()));

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_enc.secret,
            destination: dest,
            request_time: now,
            initiating_service: None,
        };
        let initiator_link = EstablishedLink::from_initiator(pending, &responder_enc.public, now);

        let responder_link = EstablishedLink::from_responder(
            link_id,
            &responder_enc.secret,
            &initiator_enc.public,
            dest,
            now,
        );

        let plaintext = b"full flow test";
        let ciphertext = initiator_link.encrypt(&mut rng, plaintext);
        let decrypted = responder_link.decrypt(&ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn keepalive_constants() {
        assert_eq!(super::KEEPALIVE_REQUEST, 0xFF);
        assert_eq!(super::KEEPALIVE_RESPONSE, 0xFE);
    }

    #[test]
    fn rtt_encode_decode_roundtrip() {
        let rtt = 0.05; // 50ms
        let encoded = super::encode_rtt(rtt);
        assert_eq!(encoded[0], 0xcb); // msgpack float64
        let decoded = super::decode_rtt(&encoded).unwrap();
        assert!((decoded - rtt).abs() < 1e-10);
    }

    #[test]
    fn rtt_decode_float32() {
        // msgpack float32: 0xca + big-endian f32
        let rtt: f32 = 0.025;
        let mut data = vec![0xca];
        data.extend_from_slice(&rtt.to_be_bytes());
        let decoded = super::decode_rtt(&data).unwrap();
        assert!((decoded - 0.025).abs() < 1e-6);
    }

    #[test]
    fn rtt_measured_on_link_establishment() {
        let mut rng = test_rng();
        let initiator_keypair = EphemeralKeyPair::generate(&mut rng);
        let responder_keypair = EphemeralKeyPair::generate(&mut rng);
        let dest: Address = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];

        let request_time = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let proof_time = Instant::now();

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_keypair.secret,
            destination: dest,
            request_time,
            initiating_service: None,
        };

        let link = EstablishedLink::from_initiator(pending, &responder_keypair.public, proof_time);

        assert!(link.rtt_ms.is_some());
        assert!(link.rtt_ms.unwrap() >= 10);
    }

    #[test]
    fn keepalive_interval_scales_with_rtt() {
        let mut rng = test_rng();
        let initiator_keypair = EphemeralKeyPair::generate(&mut rng);
        let responder_keypair = EphemeralKeyPair::generate(&mut rng);
        let dest: Address = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];
        let now = Instant::now();

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_keypair.secret,
            destination: dest,
            request_time: now,
            initiating_service: None,
        };

        let mut link = EstablishedLink::from_initiator(pending, &responder_keypair.public, now);

        // With no/zero RTT, should use max keepalive
        link.rtt_ms = Some(0);
        assert_eq!(link.keepalive_interval_secs(), KEEPALIVE_MIN_SECS);

        // With 1750ms RTT (KEEPALIVE_MAX_RTT), should use max keepalive
        link.rtt_ms = Some(1750);
        assert_eq!(link.keepalive_interval_secs(), KEEPALIVE_MAX_SECS);

        // With 875ms RTT (half of max), should use ~180s (half of max)
        link.rtt_ms = Some(875);
        assert_eq!(link.keepalive_interval_secs(), 180);

        // Stale time is 2x keepalive
        assert_eq!(link.stale_time_secs(), 360);
    }
}
