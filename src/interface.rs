use std::collections::BinaryHeap;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::Rng;

use crate::packet::Packet;

pub trait Transport: Send {
    fn send(&mut self, data: &[u8]);
    fn recv(&mut self) -> Option<Vec<u8>>;
    fn bandwidth_available(&self) -> bool;
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

struct DelayedPacket {
    packet: Packet,
    priority: u8,
    send_at: Instant,
}

pub struct Interface<T> {
    pub(crate) transport: T,
    queue: BinaryHeap<QueuedPacket>,
    delayed: Vec<DelayedPacket>,
    pub(crate) ifac_len: usize,
    pub(crate) ifac_size: usize,
    pub(crate) ifac_identity: Option<SigningKey>,
    pub(crate) ifac_key: Option<Vec<u8>>,
    pub(crate) min_delay_ms: u64,
    pub(crate) max_delay_ms: u64,
}

impl<T: Transport> Interface<T> {
    pub fn new(transport: T, ifac_len: usize) -> Self {
        Self {
            transport,
            queue: BinaryHeap::new(),
            delayed: Vec::new(),
            ifac_len,
            ifac_size: 0,
            ifac_identity: None,
            ifac_key: None,
            min_delay_ms: 0,
            max_delay_ms: 500,
        }
    }

    pub fn with_ifac(mut self, identity: SigningKey, key: Vec<u8>, size: usize) -> Self {
        self.ifac_identity = Some(identity);
        self.ifac_key = Some(key);
        self.ifac_size = size;
        self
    }

    fn bandwidth_available(&self) -> bool {
        self.transport.bandwidth_available()
    }

    // "After a randomised delay, the announce will be retransmitted on all interfaces
    // that have bandwidth available for processing announces."
    pub(crate) fn send(&mut self, packet: Packet, priority: u8, rng: &mut impl Rng, now: Instant) {
        let delay_ms = rng.gen_range(self.min_delay_ms..=self.max_delay_ms);
        let send_at = now + std::time::Duration::from_millis(delay_ms);
        self.delayed.push(DelayedPacket {
            packet,
            priority,
            send_at,
        });
    }

    fn queue(&mut self, packet: Packet, priority: u8) {
        self.queue.push(QueuedPacket { packet, priority });
    }

    fn dequeue(&mut self) -> Option<Packet> {
        self.queue.pop().map(|q| q.packet)
    }

    pub(crate) fn recv(&mut self) -> Option<Vec<u8>> {
        let data = self.transport.recv();
        if let Some(ref bytes) = data {
            if let Ok(pkt) = Packet::from_bytes(bytes) {
                log::trace!("[RECV] {}", pkt.log_format());
            } else {
                log::trace!(
                    "[RECV] raw {} bytes: {}",
                    bytes.len(),
                    hex::encode(&bytes[..bytes.len().min(32)])
                );
            }
        }
        data
    }

    pub(crate) fn poll(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.delayed.len() {
            if self.delayed[i].send_at <= now {
                let delayed = self.delayed.swap_remove(i);
                if self.bandwidth_available() {
                    log::trace!("[SEND] {}", delayed.packet.log_format());
                    self.transport.send(&delayed.packet.to_bytes());
                } else {
                    self.queue(delayed.packet, delayed.priority);
                }
            } else {
                i += 1;
            }
        }

        while self.bandwidth_available() {
            if let Some(packet) = self.dequeue() {
                log::trace!("[SEND] {}", packet.log_format());
                self.transport.send(&packet.to_bytes());
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::AnnounceDestination;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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
        fn send(&mut self, data: &[u8]) {
            self.sent.lock().unwrap().push(data.to_vec());
        }

        fn recv(&mut self) -> Option<Vec<u8>> {
            None
        }

        fn bandwidth_available(&self) -> bool {
            self.bandwidth
        }
    }

    fn make_packet(dest: [u8; 16], hops: u8) -> Packet {
        Packet::Announce {
            hops,
            destination: AnnounceDestination::Single(dest),
            has_ratchet: false,
            data: vec![],
        }
    }

    #[test]
    fn bandwidth_delegates_to_transport() {
        let (t_with, _) = MockTransport::new(true);
        let (t_without, _) = MockTransport::new(false);
        let iface_with = Interface::new(t_with, 0);
        let iface_without = Interface::new(t_without, 0);

        assert!(iface_with.bandwidth_available());
        assert!(!iface_without.bandwidth_available());
    }

    #[test]
    fn prioritise_announces_for_destinations_that_are_closest_in_terms_of_hops() {
        let (transport, _) = MockTransport::new(true);
        let mut iface = Interface::new(transport, 0);

        iface.queue(make_packet([1u8; 16], 10), 10);
        iface.queue(make_packet([2u8; 16], 2), 2);
        iface.queue(make_packet([3u8; 16], 5), 5);

        let p1 = iface.dequeue().unwrap();
        let p2 = iface.dequeue().unwrap();
        let p3 = iface.dequeue().unwrap();

        assert_eq!(p1.hops(), 2);
        assert_eq!(p2.hops(), 5);
        assert_eq!(p3.hops(), 10);
    }

    #[test]
    fn send_delays_then_transmits() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let (transport, sent) = MockTransport::new(true);
        let mut iface = Interface::new(transport, 0);
        let mut rng = StdRng::seed_from_u64(1);
        iface.min_delay_ms = 10;
        iface.max_delay_ms = 10;

        let packet = make_packet([1u8; 16], 5);
        let now = Instant::now();
        iface.send(packet, 5, &mut rng, now);

        iface.poll(now);
        assert_eq!(sent.lock().unwrap().len(), 0);

        iface.poll(now + Duration::from_millis(20));
        assert_eq!(sent.lock().unwrap().len(), 1);
    }

    #[test]
    fn no_bandwidth_queues_packet() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let (transport, sent) = MockTransport::new(false);
        let mut iface = Interface::new(transport, 0);
        let mut rng = StdRng::seed_from_u64(1);
        iface.min_delay_ms = 0;
        iface.max_delay_ms = 0;

        let now = Instant::now();
        let packet = make_packet([1u8; 16], 5);
        iface.send(packet, 5, &mut rng, now);

        iface.poll(now);

        assert_eq!(sent.lock().unwrap().len(), 0);
        assert_eq!(iface.queue.len(), 1);
    }
}
