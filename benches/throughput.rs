use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rinse::{
    InboundPacket, Interface, InterfaceError, InterfaceLimits, NodeBuilder, NodeConfig,
    OutboundPacket,
};

struct BurstInterface {
    packets: Mutex<VecDeque<Vec<u8>>>,
    received: Arc<AtomicUsize>,
}

impl Interface for BurstInterface {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        let packet = self.packets.lock().unwrap().pop_front();
        match packet {
            Some(packet) => {
                self.received.fetch_add(1, Ordering::Release);
                Ok(InboundPacket::new(packet))
            }
            None => std::future::pending().await,
        }
    }
    async fn send(&self, _: OutboundPacket) -> Result<(), InterfaceError> {
        Ok(())
    }
    async fn close(&self) -> Result<(), InterfaceError> {
        Ok(())
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let packets = 1_000_000;
    let mut inbound = VecDeque::with_capacity(packets);
    for index in 0..packets {
        let mut raw = vec![0x0c, 0x00];
        raw.extend_from_slice(&(index as u128).to_be_bytes());
        raw.push(1);
        raw.extend_from_slice(&[0; 1024]);
        inbound.push_back(raw);
    }
    let received = Arc::new(AtomicUsize::new(0));
    let builder = NodeBuilder::new(NodeConfig::endpoint()).interface(
        BurstInterface {
            packets: Mutex::new(inbound),
            received: received.clone(),
        },
        InterfaceLimits::new(2048, 256, 1_048_576).unwrap(),
    );
    let (node, task) = builder.build().unwrap();
    let started = Instant::now();
    let runtime = tokio::spawn(task.run());
    while received.load(Ordering::Acquire) != packets {
        tokio::task::yield_now().await;
    }
    let report = node.shutdown().await;
    runtime.await.unwrap().unwrap();
    let elapsed = started.elapsed();
    println!(
        "inbound_inline {packets} packets {:?} {:.0} packets/s shutdown={:?}",
        elapsed,
        packets as f64 / elapsed.as_secs_f64(),
        report.reason
    );
}
