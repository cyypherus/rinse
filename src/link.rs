use crate::{MonoTime, TimeSpan};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::api::ServiceId;
use crate::crypto::{LinkEncryption, LinkKeys, sha256, sign, verify};
use crate::packet::DestinationAddress;

pub type LinkId = [u8; 16];

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
}

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
        let signalling_bytes = [0x20, 0x01, 0xF4];
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
        let mut out = Vec::with_capacity(99);
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(self.encryption_public.as_bytes());
        out.extend_from_slice(&self.signalling_bytes);
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
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
        let mut sign_data = Vec::with_capacity(83);
        sign_data.extend_from_slice(link_id);
        sign_data.extend_from_slice(self.encryption_public.as_bytes());
        sign_data.extend_from_slice(responder_signing_key.as_bytes());
        sign_data.extend_from_slice(&self.signalling_bytes);
        verify(responder_signing_key, &sign_data, &self.signature)
    }
}

pub(crate) struct LinkIdentify {
    pub public_keys: [u8; 64],
    pub signature: Signature,
}

impl LinkIdentify {
    pub fn create(link_id: &LinkId, encryption_public: [u8; 32], signing_key: &SigningKey) -> Self {
        let mut public_keys = [0; 64];
        public_keys[..32].copy_from_slice(&encryption_public);
        public_keys[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
        let mut sign_data = Vec::with_capacity(80);
        sign_data.extend_from_slice(link_id);
        sign_data.extend_from_slice(&public_keys);
        let signature = sign(signing_key, &sign_data);
        Self {
            public_keys,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&self.public_keys);
        out.extend_from_slice(&self.signature.to_bytes());
        out
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 128 {
            return None;
        }
        let public_keys: [u8; 64] = data[..64].try_into().ok()?;
        let signature = Signature::from_bytes(&data[64..128].try_into().ok()?);
        Some(Self {
            public_keys,
            signature,
        })
    }

    pub fn verify(&self, link_id: &LinkId) -> bool {
        let signing_public: [u8; 32] = self.public_keys[32..64].try_into().unwrap();
        let verifying_key = match VerifyingKey::from_bytes(&signing_public) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let mut sign_data = Vec::with_capacity(80);
        sign_data.extend_from_slice(link_id);
        sign_data.extend_from_slice(&self.public_keys);
        verify(&verifying_key, &sign_data, &self.signature)
    }

    pub fn identity_hash(&self) -> [u8; 16] {
        sha256(&self.public_keys)[..16].try_into().unwrap()
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
    pub initiator_signing_key: SigningKey,
    pub responder_signing_key: VerifyingKey,
    pub destination: DestinationAddress,
    pub local_service: Option<ServiceId>,
    pub request_time: MonoTime,
    pub(crate) open: Option<crate::runtime::PendingOpenLink>,
}

pub(crate) struct LinkResponder<'a> {
    pub(crate) destination: DestinationAddress,
    pub(crate) service: ServiceId,
    pub(crate) encryption_secret: &'a StaticSecret,
    pub(crate) signing_key: SigningKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveLinkRole {
    Initiator { local_service: Option<ServiceId> },
    Responder { local_service: ServiceId },
}

#[derive(Clone, Copy)]
pub(crate) enum LocalIdentityState {
    Anonymous,
    Bound([u8; 16]),
}

pub(crate) struct EstablishedLink {
    pub destination: DestinationAddress,
    pub(crate) rtt: TimeSpan,
    role: ActiveLinkRole,
    pub last_inbound: MonoTime,
    pub last_outbound: MonoTime,
    pub last_keepalive_sent: Option<MonoTime>,
    pub remote_identity: Option<DestinationAddress>,
    pub(crate) local_identity: LocalIdentityState,
    pub receiving_interface: usize,
    pub signing_key: SigningKey,
    pub peer_signing_key: VerifyingKey,
    keys: LinkKeys,
    pub(crate) channel: Option<crate::runtime::RuntimeChannel>,
    pub(crate) events: Option<crate::runtime::LinkEvents>,
    pub(crate) pending_requests: std::collections::HashMap<crate::WireRequestId, crate::RequestId>,
}

const KEEPALIVE_MAX_SECS: u64 = 360;
const KEEPALIVE_MIN_SECS: u64 = 5;
const STALE_FACTOR: u64 = 2;

impl EstablishedLink {
    pub fn from_initiator(
        pending: PendingLink,
        responder_public: &X25519Public,
        receiving_interface: usize,
        now: MonoTime,
    ) -> Self {
        let shared_key = pending
            .initiator_encryption_secret
            .diffie_hellman(responder_public)
            .to_bytes();
        let keys = LinkEncryption::derive_keys(&shared_key, &pending.link_id);
        let rtt_ms = now.duration_since(pending.request_time).as_millis() as u64;
        Self {
            destination: pending.destination,
            rtt: TimeSpan::from_millis(rtt_ms),
            role: ActiveLinkRole::Initiator {
                local_service: pending.local_service,
            },
            last_inbound: now,
            last_outbound: now,
            last_keepalive_sent: None,
            remote_identity: None,
            local_identity: LocalIdentityState::Anonymous,
            receiving_interface,
            signing_key: pending.initiator_signing_key,
            peer_signing_key: pending.responder_signing_key,
            keys,
            channel: None,
            events: None,
            pending_requests: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn from_responder(
        link_id: LinkId,
        responder: LinkResponder<'_>,
        initiator_public: &X25519Public,
        initiator_signing_key: VerifyingKey,
        receiving_interface: usize,
        now: MonoTime,
    ) -> Self {
        let shared_key = responder
            .encryption_secret
            .diffie_hellman(initiator_public)
            .to_bytes();
        let keys = LinkEncryption::derive_keys(&shared_key, &link_id);
        Self {
            destination: responder.destination,
            rtt: TimeSpan::from_millis(0),
            role: ActiveLinkRole::Responder {
                local_service: responder.service,
            },
            last_inbound: now,
            last_outbound: now,
            last_keepalive_sent: None,
            remote_identity: None,
            local_identity: LocalIdentityState::Anonymous,
            receiving_interface,
            signing_key: responder.signing_key,
            peer_signing_key: initiator_signing_key,
            keys,
            channel: None,
            events: None,
            pending_requests: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn encrypt<R: RngCore>(&self, rng: &mut R, plaintext: &[u8]) -> Vec<u8> {
        LinkEncryption::encrypt(rng, &self.keys, plaintext)
    }

    pub(crate) fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        LinkEncryption::decrypt(&self.keys, ciphertext)
    }

    pub(crate) fn is_initiator(&self) -> bool {
        matches!(self.role, ActiveLinkRole::Initiator { .. })
    }

    pub(crate) fn local_service(&self) -> Option<ServiceId> {
        match self.role {
            ActiveLinkRole::Responder { local_service } => Some(local_service),
            ActiveLinkRole::Initiator { local_service } => local_service,
        }
    }

    pub(crate) fn keepalive_interval_secs(&self) -> u64 {
        let scaled = (self.rtt.as_millis() as u64 * KEEPALIVE_MAX_SECS) / 1750;
        scaled.clamp(KEEPALIVE_MIN_SECS, KEEPALIVE_MAX_SECS)
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
        let initiator_signing_key = SigningKey::generate(&mut rng);
        let responder_signing_key = SigningKey::generate(&mut rng);
        let dest: DestinationAddress = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];
        let now = MonoTime::from_micros(1_000_000);

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_keypair.secret,
            initiator_signing_key,
            responder_signing_key: responder_signing_key.verifying_key(),
            destination: dest,
            local_service: None,
            request_time: now,
            open: None,
        };

        let initiator_link =
            EstablishedLink::from_initiator(pending, &responder_keypair.public, 0, now);
        let responder_link = EstablishedLink::from_responder(
            link_id,
            LinkResponder {
                destination: dest,
                service: ServiceId(0),
                encryption_secret: &responder_keypair.secret,
                signing_key: responder_signing_key,
            },
            &initiator_keypair.public,
            initiator_link.signing_key.verifying_key(),
            0,
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
    }

    #[test]
    fn full_link_establishment_flow() {
        use crate::packet::{Packet, RoutedDestination};

        let mut rng = test_rng();
        let now = MonoTime::from_micros(1_000_000);

        let initiator_enc = EphemeralKeyPair::generate(&mut rng);
        let initiator_sig = SigningKey::generate(&mut rng);
        let dest: DestinationAddress = [0xAB; 16];

        let request = LinkRequest::new(
            initiator_enc.public,
            initiator_sig.verifying_key().to_bytes(),
        );
        let request_data = request.to_bytes();
        let packet = Packet::LinkRequest {
            hops: 0,
            destination: RoutedDestination::direct(dest),
            data: request_data.clone().into(),
        };
        let link_id = packet.link_id().unwrap();

        let responder_enc = EphemeralKeyPair::generate(&mut rng);
        let responder_sig = SigningKey::generate(&mut rng);

        let proof = LinkProof::create(&link_id, &responder_enc.public, &responder_sig);
        assert!(proof.verify(&link_id, &responder_sig.verifying_key()));

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_enc.secret,
            initiator_signing_key: initiator_sig,
            responder_signing_key: responder_sig.verifying_key(),
            destination: dest,
            local_service: None,
            request_time: now,
            open: None,
        };
        let initiator_link =
            EstablishedLink::from_initiator(pending, &responder_enc.public, 0, now);

        let responder_link = EstablishedLink::from_responder(
            link_id,
            LinkResponder {
                destination: dest,
                service: ServiceId(0),
                encryption_secret: &responder_enc.secret,
                signing_key: responder_sig,
            },
            &initiator_enc.public,
            initiator_link.signing_key.verifying_key(),
            0,
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
        let rtt = 0.05;
        let encoded = super::encode_rtt(rtt);
        assert_eq!(encoded[0], 0xcb);
        let decoded = super::decode_rtt(&encoded).unwrap();
        assert!((decoded - rtt).abs() < 1e-10);
    }

    #[test]
    fn rtt_decode_float32() {
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
        let initiator_signing_key = SigningKey::generate(&mut rng);
        let responder_signing_key = SigningKey::generate(&mut rng);
        let dest: DestinationAddress = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];

        let request_time = MonoTime::from_micros(1_000_000);
        let proof_time = request_time.checked_add(TimeSpan::from_millis(10)).unwrap();

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_keypair.secret,
            initiator_signing_key,
            responder_signing_key: responder_signing_key.verifying_key(),
            destination: dest,
            local_service: None,
            request_time,
            open: None,
        };

        let link =
            EstablishedLink::from_initiator(pending, &responder_keypair.public, 0, proof_time);

        assert!(link.rtt >= TimeSpan::from_millis(10));
    }

    #[test]
    fn keepalive_interval_scales_with_rtt() {
        let mut rng = test_rng();
        let initiator_keypair = EphemeralKeyPair::generate(&mut rng);
        let responder_keypair = EphemeralKeyPair::generate(&mut rng);
        let initiator_signing_key = SigningKey::generate(&mut rng);
        let responder_signing_key = SigningKey::generate(&mut rng);
        let dest: DestinationAddress = [0xAB; 16];
        let link_id: LinkId = [0xCD; 16];
        let now = MonoTime::from_micros(1_000_000);

        let pending = PendingLink {
            link_id,
            initiator_encryption_secret: initiator_keypair.secret,
            initiator_signing_key,
            responder_signing_key: responder_signing_key.verifying_key(),
            destination: dest,
            local_service: None,
            request_time: now,
            open: None,
        };

        let mut link = EstablishedLink::from_initiator(pending, &responder_keypair.public, 0, now);

        link.rtt = TimeSpan::from_millis(0);
        assert_eq!(link.keepalive_interval_secs(), KEEPALIVE_MIN_SECS);

        link.rtt = TimeSpan::from_millis(1750);
        assert_eq!(link.keepalive_interval_secs(), KEEPALIVE_MAX_SECS);

        link.rtt = TimeSpan::from_millis(875);
        assert_eq!(link.keepalive_interval_secs(), 180);

        assert_eq!(link.stale_time_secs(), 360);
    }
}
