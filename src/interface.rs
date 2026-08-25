use std::collections::BinaryHeap;
use std::io;
use std::task::{Context, Poll};

use ed25519_dalek::SigningKey;

use crate::packet::Packet;

pub struct InterfaceAccessCode {
    signing_key: SigningKey,
    shared_key: Vec<u8>,
    transmitted_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceAccessCodeError {
    EmptyPacketMaskingKey,
    InvalidTransmittedAuthenticationBytes { bytes: usize, max: usize },
}

impl InterfaceAccessCode {
    pub fn new(
        interface_signing_secret: [u8; 32],
        packet_masking_key: Vec<u8>,
        transmitted_authentication_bytes: usize,
    ) -> Result<Self, InterfaceAccessCodeError> {
        if packet_masking_key.is_empty() {
            return Err(InterfaceAccessCodeError::EmptyPacketMaskingKey);
        }
        if !(1..=64).contains(&transmitted_authentication_bytes) {
            return Err(
                InterfaceAccessCodeError::InvalidTransmittedAuthenticationBytes {
                    bytes: transmitted_authentication_bytes,
                    max: 64,
                },
            );
        }
        Ok(Self {
            signing_key: SigningKey::from_bytes(&interface_signing_secret),
            shared_key: packet_masking_key,
            transmitted_bytes: transmitted_authentication_bytes,
        })
    }
}

pub trait Transport: Send {
    fn poll_send(&mut self, cx: &mut Context<'_>, frame: &[u8]) -> Poll<io::Result<()>>;
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>>;
}

impl Transport for Box<dyn Transport> {
    fn poll_send(&mut self, cx: &mut Context<'_>, frame: &[u8]) -> Poll<io::Result<()>> {
        (**self).poll_send(cx, frame)
    }
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        (**self).poll_receive(cx)
    }
}

#[derive(Clone)]
struct QueuedPacket {
    packet: Packet,
    priority: u8,
}

impl PartialEq for QueuedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for QueuedPacket {}

impl PartialOrd for QueuedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedPacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.priority.cmp(&self.priority)
    }
}

pub struct Interface<T> {
    pub(crate) transport: T,
    queue: BinaryHeap<QueuedPacket>,
    closed: bool,
    pub(crate) ifac_size: usize,
    pub(crate) ifac_identity: Option<SigningKey>,
    pub(crate) ifac_key: Option<Vec<u8>>,
}

impl<T: Transport> Interface<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            queue: BinaryHeap::new(),
            closed: false,
            ifac_size: 0,
            ifac_identity: None,
            ifac_key: None,
        }
    }

    pub fn with_interface_access_code(mut self, access_code: InterfaceAccessCode) -> Self {
        self.ifac_identity = Some(access_code.signing_key);
        self.ifac_key = Some(access_code.shared_key);
        self.ifac_size = access_code.transmitted_bytes;
        self
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn send(&mut self, packet: Packet, priority: u8) {
        self.queue.push(QueuedPacket { packet, priority });
    }

    fn validate_and_strip_ifac(&self, raw: &[u8]) -> Option<Vec<u8>> {
        if raw.len() <= 2 {
            return None;
        }

        if let (Some(ifac_identity), Some(ifac_key)) = (&self.ifac_identity, &self.ifac_key) {
            if self.ifac_size == 0 {
                return Some(raw.to_vec());
            }

            // Interface has IFAC enabled - packet MUST have valid IFAC
            if raw[0] & 0x80 != 0x80 {
                return None; // IFAC flag not set
            }
            if raw.len() <= 2 + self.ifac_size {
                return None; // Too short
            }

            // Extract IFAC
            let ifac = &raw[2..2 + self.ifac_size];

            // Generate mask
            let mask = crate::crypto::hkdf_expand(ifac, ifac_key, raw.len());

            // Unmask header and payload (but not IFAC itself)
            let mut unmasked_raw = Vec::with_capacity(raw.len());
            for (i, &byte) in raw.iter().enumerate() {
                if i <= 1 || i > self.ifac_size + 1 {
                    unmasked_raw.push(byte ^ mask[i]);
                } else {
                    unmasked_raw.push(byte);
                }
            }

            // Unset IFAC flag and re-assemble packet without IFAC
            let new_header = [unmasked_raw[0] & 0x7f, unmasked_raw[1]];
            let mut new_raw = Vec::with_capacity(raw.len() - self.ifac_size);
            new_raw.extend_from_slice(&new_header);
            new_raw.extend_from_slice(&unmasked_raw[2 + self.ifac_size..]);

            // Validate: re-compute IFAC and compare
            let signature = crate::crypto::sign(ifac_identity, &new_raw);
            let expected_ifac = &signature.to_bytes()[64 - self.ifac_size..];

            if ifac == expected_ifac {
                Some(new_raw)
            } else {
                None
            }
        } else {
            // Interface does NOT have IFAC enabled - packet must NOT have IFAC flag
            if raw[0] & 0x80 == 0x80 {
                None
            } else {
                Some(raw.to_vec())
            }
        }
    }

    pub(crate) fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        if self.closed {
            return Poll::Pending;
        }
        loop {
            let raw = match self.transport.poll_receive(cx) {
                Poll::Ready(Ok(Some(raw))) => raw,
                Poll::Ready(Ok(None)) => {
                    self.closed = true;
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(error)) => {
                    log::debug!("Interface receive failed: {error}");
                    self.closed = true;
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            };
            if let Some(data) = self.validate_and_strip_ifac(&raw) {
                if let Ok(pkt) = Packet::from_bytes(&data) {
                    log::trace!("[RECV] {}", pkt.log_format());
                } else {
                    log::trace!(
                        "[RECV] raw {} bytes: {}",
                        data.len(),
                        hex::encode(&data[..data.len().min(32)])
                    );
                }
                return Poll::Ready(Some(data));
            }
        }
    }

    fn apply_ifac(&self, raw: &[u8]) -> Vec<u8> {
        if let (Some(ifac_identity), Some(ifac_key)) = (&self.ifac_identity, &self.ifac_key) {
            if self.ifac_size == 0 {
                return raw.to_vec();
            }

            // Calculate packet access code (sign raw, take last ifac_size bytes)
            let signature = crate::crypto::sign(ifac_identity, raw);
            let ifac = &signature.to_bytes()[64 - self.ifac_size..];

            // Generate mask
            let mask = crate::crypto::hkdf_expand(ifac, ifac_key, raw.len() + self.ifac_size);

            // Set IFAC flag (bit 7 of header byte 0)
            let new_header = [raw[0] | 0x80, raw[1]];

            // Assemble new payload: header + ifac + payload
            let mut new_raw = Vec::with_capacity(raw.len() + self.ifac_size);
            new_raw.extend_from_slice(&new_header);
            new_raw.extend_from_slice(ifac);
            new_raw.extend_from_slice(&raw[2..]);

            // Mask payload
            let mut masked_raw = Vec::with_capacity(new_raw.len());
            for (i, &byte) in new_raw.iter().enumerate() {
                if i == 0 {
                    // Mask first header byte, but keep IFAC flag set
                    masked_raw.push((byte ^ mask[i]) | 0x80);
                } else if i == 1 || i > self.ifac_size + 1 {
                    // Mask second header byte and payload
                    masked_raw.push(byte ^ mask[i]);
                } else {
                    // Don't mask the IFAC itself
                    masked_raw.push(byte);
                }
            }

            masked_raw
        } else {
            raw.to_vec()
        }
    }

    pub(crate) fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "interface is closed",
            )));
        }
        while let Some(queued) = self.queue.peek() {
            let raw = queued.packet.to_bytes();
            let frame = self.apply_ifac(&raw);
            match self.transport.poll_send(cx, &frame) {
                Poll::Ready(Ok(())) => {
                    log::trace!("[SEND] {}", queued.packet.log_format());
                    self.queue.pop();
                }
                Poll::Ready(Err(error)) => {
                    self.closed = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::AnnounceDestination;
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    struct MockTransport {
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        bandwidth: bool,
    }

    impl MockTransport {
        fn new(bandwidth: bool) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    sent: sent.clone(),
                    bandwidth,
                },
                sent,
            )
        }
    }

    impl Transport for MockTransport {
        fn poll_send(&mut self, _: &mut Context<'_>, frame: &[u8]) -> Poll<io::Result<()>> {
            if self.bandwidth {
                self.sent.lock().unwrap().push(frame.to_vec());
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }

        fn poll_receive(&mut self, _: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
            Poll::Pending
        }
    }

    fn make_packet(dest: [u8; 16], hops: u8) -> Packet {
        Packet::Announce {
            hops,
            destination: AnnounceDestination::Single(dest),
            has_ratchet: false,
            is_path_response: false,
            data: vec![],
        }
    }

    #[test]
    fn access_code_rejects_invalid_inputs() {
        assert!(matches!(
            InterfaceAccessCode::new([0; 32], Vec::new(), 8),
            Err(InterfaceAccessCodeError::EmptyPacketMaskingKey)
        ));
        assert!(matches!(
            InterfaceAccessCode::new([0; 32], vec![1], 0),
            Err(
                InterfaceAccessCodeError::InvalidTransmittedAuthenticationBytes {
                    bytes: 0,
                    max: 64
                }
            )
        ));
        assert!(matches!(
            InterfaceAccessCode::new([0; 32], vec![1], 65),
            Err(
                InterfaceAccessCodeError::InvalidTransmittedAuthenticationBytes {
                    bytes: 65,
                    max: 64
                }
            )
        ));
    }

    #[test]
    fn priority_queue_sends_lowest_priority_first() {
        let (transport, sent) = MockTransport::new(true);
        let mut iface = Interface::new(transport);

        iface.send(make_packet([1u8; 16], 10), 10);
        iface.send(make_packet([2u8; 16], 2), 2);
        iface.send(make_packet([3u8; 16], 5), 5);

        assert!(
            iface
                .poll_send(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );

        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 3);

        let p1 = Packet::from_bytes(&sent[0]).unwrap();
        let p2 = Packet::from_bytes(&sent[1]).unwrap();
        let p3 = Packet::from_bytes(&sent[2]).unwrap();

        assert_eq!(p1.hops(), 2);
        assert_eq!(p2.hops(), 5);
        assert_eq!(p3.hops(), 10);
    }

    #[test]
    fn send_then_poll_transmits() {
        let (transport, sent) = MockTransport::new(true);
        let mut iface = Interface::new(transport);

        let packet = make_packet([1u8; 16], 5);
        iface.send(packet, 5);

        assert_eq!(sent.lock().unwrap().len(), 0);
        assert!(
            iface
                .poll_send(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn no_bandwidth_queues_packet() {
        let (transport, sent) = MockTransport::new(false);
        let mut iface = Interface::new(transport);

        let packet = make_packet([1u8; 16], 5);
        iface.send(packet, 5);

        assert!(
            iface
                .poll_send(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );

        assert_eq!(sent.lock().unwrap().len(), 0);
        assert_eq!(iface.queue.len(), 1);
    }

    fn make_ifac_interface() -> (Interface<MockTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
        use rand::RngCore;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut rng = StdRng::seed_from_u64(42);
        let mut ifac_identity = [0u8; 32];
        rng.fill_bytes(&mut ifac_identity);
        let ifac_key = vec![0xAB; 32];

        let (transport, sent) = MockTransport::new(true);
        let iface = Interface::new(transport).with_interface_access_code(
            InterfaceAccessCode::new(ifac_identity, ifac_key, 8).unwrap(),
        );
        (iface, sent)
    }

    #[test]
    fn ifac_roundtrip() {
        let (iface, _) = make_ifac_interface();

        let packet = make_packet([1u8; 16], 5);
        let raw = packet.to_bytes();

        let with_ifac = iface.apply_ifac(&raw);
        assert_ne!(with_ifac, raw, "IFAC should modify packet");
        assert_eq!(with_ifac[0] & 0x80, 0x80, "IFAC flag should be set");
        assert_eq!(with_ifac.len(), raw.len() + 8, "should add ifac_size bytes");

        let stripped = iface.validate_and_strip_ifac(&with_ifac);
        assert_eq!(stripped, Some(raw), "round-trip should return original");
    }

    #[test]
    fn ifac_wrong_key_rejected() {
        use rand::RngCore;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let (iface_a, _) = make_ifac_interface();

        // Create interface B with different key
        let mut rng = StdRng::seed_from_u64(99);
        let mut ifac_identity_b = [0u8; 32];
        rng.fill_bytes(&mut ifac_identity_b);
        let ifac_key_b = vec![0xCD; 32]; // different key
        let (transport_b, _) = MockTransport::new(true);
        let iface_b = Interface::new(transport_b).with_interface_access_code(
            InterfaceAccessCode::new(ifac_identity_b, ifac_key_b, 8).unwrap(),
        );

        let packet = make_packet([1u8; 16], 5);
        let raw = packet.to_bytes();

        // A applies IFAC
        let with_ifac = iface_a.apply_ifac(&raw);

        // B tries to validate - should fail
        let result = iface_b.validate_and_strip_ifac(&with_ifac);
        assert!(result.is_none(), "wrong IFAC key should be rejected");
    }

    #[test]
    fn ifac_missing_flag_rejected() {
        let (iface, _) = make_ifac_interface();

        // Raw packet without IFAC flag
        let packet = make_packet([1u8; 16], 5);
        let raw = packet.to_bytes();
        assert_eq!(raw[0] & 0x80, 0, "raw packet should not have IFAC flag");

        let result = iface.validate_and_strip_ifac(&raw);
        assert!(
            result.is_none(),
            "packet without IFAC flag should be rejected on IFAC interface"
        );
    }

    #[test]
    fn ifac_flag_on_non_ifac_interface_rejected() {
        let (transport, _) = MockTransport::new(true);
        let iface = Interface::new(transport); // no IFAC

        // Create a packet with IFAC flag set manually
        let packet = make_packet([1u8; 16], 5);
        let mut raw = packet.to_bytes();
        raw[0] |= 0x80; // set IFAC flag

        let result = iface.validate_and_strip_ifac(&raw);
        assert!(
            result.is_none(),
            "IFAC flag on non-IFAC interface should be rejected"
        );
    }

    #[test]
    fn ifac_correct_key_passes() {
        let (iface, _) = make_ifac_interface();

        let packet = make_packet([1u8; 16], 5);
        let raw = packet.to_bytes();

        let with_ifac = iface.apply_ifac(&raw);
        let result = iface.validate_and_strip_ifac(&with_ifac);

        assert!(result.is_some(), "correct IFAC key should pass");
        assert_eq!(result.unwrap(), raw);
    }
}
