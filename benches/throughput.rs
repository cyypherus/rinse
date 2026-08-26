use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rinse::{
    Clock, CryptoEntropy, EntropyUnavailable, InboundPacket, Interface, InterfaceError,
    InterfaceLimits, MonoTime, NodeBuilder, NodeConfig, OutboundPacket, PacketWork,
    PacketWorkError, PreparePacket, PreparedPacket,
};

struct TokioClock(std::time::Instant);

impl Clock for TokioClock {
    type Sleep<'a> = std::pin::Pin<Box<tokio::time::Sleep>>;

    fn now(&self) -> MonoTime {
        MonoTime::from_micros(self.0.elapsed().as_micros() as u64)
    }

    fn sleep_until(&self, deadline: MonoTime) -> Self::Sleep<'_> {
        let remaining = deadline
            .checked_duration_since(self.now())
            .unwrap_or_default();
        Box::pin(tokio::time::sleep(remaining))
    }
}

struct OsEntropy;

impl CryptoEntropy for OsEntropy {
    fn fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), EntropyUnavailable> {
        rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, seed).map_err(|_| EntropyUnavailable)
    }
}

struct BurstInterface {
    packets: Mutex<VecDeque<Vec<u8>>>,
}

impl Interface for BurstInterface {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        let packet = self.packets.lock().unwrap().pop_front();
        match packet {
            Some(packet) => Ok(InboundPacket::new(packet)),
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

struct MeasuredWork<W> {
    work: W,
    completed: Arc<AtomicUsize>,
}

impl<W: PacketWork> PacketWork for MeasuredWork<W> {
    async fn prepare(&self, job: PreparePacket) -> Result<PreparedPacket, PacketWorkError> {
        let result = self.work.prepare(job).await;
        if result.is_ok() {
            self.completed.fetch_add(1, Ordering::Release);
        }
        result
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    #[cfg(feature = "std-clock")]
    rinse::EmbassyClock
        .sleep_until(MonoTime::from_micros(1))
        .await;
    let packets = 1_000_000;
    let mut inbound = VecDeque::with_capacity(packets);
    for index in 0..packets {
        let mut raw = vec![0x0c, 0x00];
        raw.extend_from_slice(&(index as u128).to_be_bytes());
        raw.push(1);
        raw.extend_from_slice(&[0; 1024]);
        inbound.push_back(raw);
    }
    let completed = Arc::new(AtomicUsize::new(0));
    let work = rinse::InlinePacketWork;
    let builder = NodeBuilder::new(
        NodeConfig::endpoint(),
        TokioClock(std::time::Instant::now()),
        MeasuredWork {
            work,
            completed: completed.clone(),
        },
        OsEntropy,
    )
    .interface(
        BurstInterface {
            packets: Mutex::new(inbound),
        },
        InterfaceLimits::new(2048, 256, 1_048_576).unwrap(),
    );
    let (node, task) = builder.build().unwrap();
    let started = Instant::now();
    let runtime = tokio::spawn(task.run());
    while completed.load(Ordering::Acquire) != packets {
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
