use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::Rng;
use rand::rngs::ThreadRng;

use crate::{Address, Addresses, Interface, Packet, PacketType, Transport};

// "By default, m is set to 128."
const DEFAULT_MAX_HOPS: u8 = 128;
// "By default, r is set to 1."
const DEFAULT_RETRIES: u8 = 1;
const DEFAULT_RETRY_DELAY_MS: u64 = 4000;

struct AnnounceEntry {
    // "record into a table which Transport Node the announce was received from"
    source_interface: usize,
    // "how many times in total it has been retransmitted to get here"
    hops: u8,
    app_data: Vec<u8>,
    retries_remaining: u8,
    retry_at: Option<Instant>,
}

pub struct Node<T, IR = ThreadRng> {
    max_hops: u8,
    retries: u8,
    pub(crate) retry_delay_ms: u64,
    seen_announces: HashMap<Address, AnnounceEntry>,
    interfaces: Vec<Interface<T, IR>>,
}

impl<T: Transport> Node<T, ThreadRng> {
    pub fn new() -> Self {
        Self {
            max_hops: DEFAULT_MAX_HOPS,
            retries: DEFAULT_RETRIES,
            retry_delay_ms: DEFAULT_RETRY_DELAY_MS,
            seen_announces: HashMap::new(),
            interfaces: Vec::new(),
        }
    }
}

impl<T: Transport, IR: Rng> Node<T, IR> {
    pub fn add_interface(&mut self, interface: Interface<T, IR>) -> usize {
        let id = self.interfaces.len();
        self.interfaces.push(interface);
        id
    }

    pub fn inbound(&mut self, packet: &Packet, source: usize, now: Instant) {
        match packet.header.packet_type {
            PacketType::Announce => {
                let dest = match packet.addresses {
                    Addresses::Single(a) | Addresses::Double(a, _) => a,
                };
                let hops = packet.header.hops;

                // "After the announce has been re-transmitted, and if no other nodes are heard
                // retransmitting the announce with a greater hop count than when it left this
                // node, transmitting it will be retried r times."
                if let Some(entry) = self.seen_announces.get_mut(&dest)
                    && hops > entry.hops
                {
                    entry.retries_remaining = 0;
                    entry.retry_at = None;
                }

                if self.process_announce(dest, hops, packet.data.clone(), source) {
                    self.outbound(packet.clone(), Some(source), now);
                }
            }
            PacketType::Data | PacketType::LinkRequest | PacketType::Proof => {}
        }
    }

    // "After a randomised delay, the announce will be retransmitted on all interfaces
    // that have bandwidth available for processing announces."
    //
    // "If any given interface does not have enough bandwidth available for retransmitting
    // the announce, the announce will be assigned a priority inversely proportional to its
    // hop count, and be inserted into a queue managed by the interface."
    //
    // "When the interface has bandwidth available for processing an announce, it will
    // prioritise announces for destinations that are closest in terms of hops, thus
    // prioritising reachability and connectivity of local nodes, even on slow networks
    // that connect to wider and faster networks."
    fn outbound(&mut self, packet: Packet, exclude: Option<usize>, now: Instant) {
        let dest = match packet.addresses {
            Addresses::Single(a) | Addresses::Double(a, _) => a,
        };
        let hops = packet.header.hops;

        for (i, iface) in self.interfaces.iter_mut().enumerate() {
            if Some(i) != exclude {
                iface.send(packet.clone(), hops, now);
            }
        }

        // "After the announce has been re-transmitted, and if no other nodes are heard
        // retransmitting the announce with a greater hop count than when it left this
        // node, transmitting it will be retried r times. By default, r is set to 1."
        if let Some(entry) = self.seen_announces.get_mut(&dest)
            && entry.retries_remaining > 0
        {
            entry.retry_at = Some(now + Duration::from_millis(self.retry_delay_ms));
        }
    }

    pub fn poll(&mut self, now: Instant) {
        for iface in &mut self.interfaces {
            iface.poll(now);
        }

        let mut to_retry = Vec::new();
        for (dest, entry) in &mut self.seen_announces {
            if let Some(retry_at) = entry.retry_at
                && retry_at <= now
                && entry.retries_remaining > 0
            {
                entry.retries_remaining -= 1;
                entry.retry_at = None;
                to_retry.push((
                    *dest,
                    entry.hops,
                    entry.app_data.clone(),
                    entry.source_interface,
                ));
            }
        }

        for (dest, hops, data, source) in to_retry {
            let packet = self.make_announce_packet(dest, hops, data);
            self.outbound(packet, Some(source), now);
        }

        for iface in &mut self.interfaces {
            iface.poll(now);
        }
    }

    fn make_announce_packet(&self, dest: Address, hops: u8, data: Vec<u8>) -> Packet {
        use crate::{
            Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
        };
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        };
        Packet::new(header, None, Addresses::Single(dest), Context::None, data).unwrap()
    }

    fn process_announce(
        &mut self,
        destination: Address,
        hops: u8,
        app_data: Vec<u8>,
        source: usize,
    ) -> bool {
        if let Some(entry) = self.seen_announces.get_mut(&destination) {
            // "If a newer announce from the same destination arrives, while an identical one
            // is already waiting to be transmitted, the newest announce is discarded. If the
            // newest announce contains different application specific data, it will replace
            // the old announce."
            if entry.retry_at.is_some() && entry.app_data == app_data {
                return false;
            }
            if entry.app_data != app_data {
                entry.app_data = app_data;
                entry.hops = hops;
                entry.source_interface = source;
                entry.retries_remaining = self.retries;
                entry.retry_at = None;
                return hops < self.max_hops;
            }
            // "If this exact announce has already been received before, ignore it."
            return false;
        }

        // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
        // By default, m is set to 128."
        if hops > self.max_hops {
            return false;
        }

        // "If not, record into a table which Transport Node the announce was received from,
        // and how many times in total it has been retransmitted to get here."
        self.seen_announces.insert(
            destination,
            AnnounceEntry {
                source_interface: source,
                hops,
                app_data,
                retries_remaining: self.retries,
                retry_at: None,
            },
        );

        hops < self.max_hops
    }
}

impl<T: Transport> Default for Node<T, ThreadRng> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Context, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, PropagationType,
    };
    use std::sync::{Arc, Mutex};

    struct MockTransport {
        bandwidth: bool,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl MockTransport {
        fn new(bandwidth: bool) -> (Self, Arc<Mutex<Vec<Vec<u8>>>>) {
            let sent = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    bandwidth,
                    sent: sent.clone(),
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

    fn make_interface(bandwidth: bool) -> (Interface<MockTransport>, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (transport, sent) = MockTransport::new(bandwidth);
        let mut iface = Interface::new(transport, 0);
        iface.min_delay_ms = 0;
        iface.max_delay_ms = 0;
        (iface, sent)
    }

    fn make_announce(dest: Address, hops: u8, data: Vec<u8>) -> Packet {
        let header = Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type1,
            context_flag: ContextFlag::Unset,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        };
        Packet::new(header, None, Addresses::Single(dest), Context::None, data).unwrap()
    }

    // "If this exact announce has already been received before, ignore it."
    #[test]
    fn if_this_exact_announce_has_already_been_received_before_ignore_it() {
        let mut node: Node<MockTransport> = Node::new();
        let (iface, tx) = make_interface(true);
        let src = node.add_interface(iface);

        let now = Instant::now();
        let packet = make_announce([1u8; 16], 1, vec![0xAB]);
        node.inbound(&packet, src, now);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx.lock().unwrap().len(), 0);
    }

    // "If not, record into a table which Transport Node the announce was received from,
    // and how many times in total it has been retransmitted to get here."
    #[test]
    fn record_into_a_table_which_transport_node_the_announce_was_received_from() {
        let mut node = Node::new();
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let packet = make_announce([2u8; 16], 5, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
    // By default, m is set to 128."
    #[test]
    fn if_the_announce_has_been_retransmitted_m_plus_1_times_it_will_not_be_forwarded() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let packet = make_announce([3u8; 16], 129, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 0);
    }

    // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
    // By default, m is set to 128."
    #[test]
    fn announce_at_exactly_m_hops_is_accepted_but_not_forwarded() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let packet = make_announce([4u8; 16], 128, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 0);
    }

    // "If the announce has been retransmitted m+1 times, it will not be forwarded any more.
    // By default, m is set to 128."
    #[test]
    fn announce_below_m_hops_is_forwarded() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let packet = make_announce([6u8; 16], 127, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "If a newer announce from the same destination arrives, while an identical one is
    // already waiting to be transmitted, the newest announce is discarded."
    #[test]
    fn if_a_newer_announce_from_the_same_destination_arrives_while_an_identical_one_is_already_waiting_the_newest_is_discarded()
     {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        let src1 = node.add_interface(iface1);

        let now = Instant::now();
        let dest = [11u8; 16];
        node.inbound(&make_announce(dest, 1, vec![0x01]), src0, now);
        node.inbound(&make_announce(dest, 2, vec![0x01]), src1, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "If the newest announce contains different application specific data, it will
    // replace the old announce."
    #[test]
    fn if_the_newest_announce_contains_different_application_specific_data_it_will_replace_the_old_announce()
     {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        let src1 = node.add_interface(iface1);

        let now = Instant::now();
        let dest = [7u8; 16];
        node.inbound(&make_announce(dest, 1, vec![0x01]), src0, now);
        node.inbound(&make_announce(dest, 2, vec![0x02]), src1, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 1);
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }

    // "After a randomised delay, the announce will be retransmitted on all interfaces
    // that have bandwidth available for processing announces."
    #[test]
    fn the_announce_will_be_retransmitted_on_all_interfaces_that_have_bandwidth_available() {
        let mut node = Node::new();
        let (iface0, tx0) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let (iface2, tx2) = make_interface(true);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);
        node.add_interface(iface2);

        let now = Instant::now();
        let packet = make_announce([8u8; 16], 1, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx0.lock().unwrap().len(), 0);
        assert_eq!(tx1.lock().unwrap().len(), 1);
        assert_eq!(tx2.lock().unwrap().len(), 1);
    }

    // "If any given interface does not have enough bandwidth available for retransmitting
    // the announce, the announce will be assigned a priority inversely proportional to its
    // hop count, and be inserted into a queue managed by the interface."
    #[test]
    fn if_any_given_interface_does_not_have_enough_bandwidth_the_announce_will_be_inserted_into_a_queue()
     {
        let mut node = Node::new();
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(false);
        let src = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let packet = make_announce([9u8; 16], 1, vec![]);
        node.inbound(&packet, src, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 0);
    }

    // "After the announce has been re-transmitted, and if no other nodes are heard
    // retransmitting the announce with a greater hop count than when it left this node,
    // transmitting it will be retried r times. By default, r is set to 1."
    #[test]
    fn if_no_other_nodes_are_heard_retransmitting_with_greater_hop_count_it_will_be_retried() {
        let mut node = Node::new();
        node.retry_delay_ms = 10;
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        node.add_interface(iface1);

        let now = Instant::now();
        let dest = [13u8; 16];
        node.inbound(&make_announce(dest, 1, vec![]), src0, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 1);

        node.poll(now + Duration::from_millis(50));
        assert_eq!(tx1.lock().unwrap().len(), 2);

        node.poll(now + Duration::from_millis(100));
        assert_eq!(tx1.lock().unwrap().len(), 2);
    }

    // "After the announce has been re-transmitted, and if no other nodes are heard
    // retransmitting the announce with a greater hop count than when it left this node,
    // transmitting it will be retried r times. By default, r is set to 1."
    #[test]
    fn retry_cancelled_when_higher_hop_announce_heard() {
        let mut node = Node::new();
        node.retry_delay_ms = 10;
        let (iface0, _) = make_interface(true);
        let (iface1, tx1) = make_interface(true);
        let src0 = node.add_interface(iface0);
        let src1 = node.add_interface(iface1);

        let now = Instant::now();
        let dest = [14u8; 16];
        node.inbound(&make_announce(dest, 1, vec![]), src0, now);

        node.poll(now);
        assert_eq!(tx1.lock().unwrap().len(), 1);

        node.inbound(&make_announce(dest, 2, vec![]), src1, now);

        node.poll(now + Duration::from_millis(50));
        assert_eq!(tx1.lock().unwrap().len(), 1);
    }
}
