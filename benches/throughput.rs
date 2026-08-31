use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rand::{RngCore, SeedableRng};
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
            Some(bytes) => {
                self.received.fetch_add(1, Ordering::Release);
                Ok(InboundPacket::new(bytes))
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

async fn sample() -> f64 {
    let packets = 250_000;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x5eed);
    let mut inbound = VecDeque::with_capacity(packets);
    for _ in 0..packets {
        let payload_len = match rng.next_u32() % 100 {
            0..=59 => 32 + rng.next_u32() as usize % 225,
            60..=89 => 257 + rng.next_u32() as usize % 768,
            _ => 1025 + rng.next_u32() as usize % 3072,
        };
        let mut raw = Vec::with_capacity(payload_len + 19);
        raw.extend_from_slice(&[0x0c, (rng.next_u32() % 2) as u8]);
        let mut destination = [0; 16];
        rng.fill_bytes(&mut destination);
        raw.extend_from_slice(&destination);
        raw.push(1);
        raw.resize(payload_len + 19, 0);
        rng.fill_bytes(&mut raw[19..]);
        inbound.push_back(raw);
    }
    let received = Arc::new(AtomicUsize::new(0));
    let builder = NodeBuilder::new(NodeConfig::endpoint()).interface(
        BurstInterface {
            packets: Mutex::new(inbound),
            received: received.clone(),
        },
        InterfaceLimits::new(4115, 256, 1_048_576).unwrap(),
    );
    let (node, task) = builder.build().unwrap();
    let started = Instant::now();
    let runtime = tokio::spawn(task.run());
    while received.load(Ordering::Acquire) != packets {
        tokio::task::yield_now().await;
    }
    node.shutdown().await;
    runtime.await.unwrap().unwrap();
    let elapsed = started.elapsed();
    packets as f64 / elapsed.as_secs_f64()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut samples = Vec::with_capacity(7);
    for _ in 0..7 {
        samples.push(sample().await);
    }
    samples.sort_unstable_by(f64::total_cmp);
    println!(
        "inbound_serial random_seed=0x5eed packets=250000 samples=7 min={:.0} median={:.0} max={:.0} packets/s",
        samples[0], samples[3], samples[6]
    );
}
