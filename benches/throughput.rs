use std::collections::VecDeque;
use std::hint::black_box;
use std::task::{Context, Poll};
use std::time::Instant;

use rinse::{Interface, Node, Transport};
use tokio::task::JoinSet;

struct IdleTransport;

impl Transport for IdleTransport {
    fn send(&mut self, _: &[u8]) {}

    fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        Poll::Pending
    }

    fn send_ready(&self) -> bool {
        true
    }
}

struct BurstTransport {
    packets: VecDeque<Vec<u8>>,
}

impl Transport for BurstTransport {
    fn send(&mut self, _: &[u8]) {}

    fn poll_recv(&mut self, _: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        self.packets
            .pop_front()
            .map_or(Poll::Pending, |packet| Poll::Ready(Some(packet)))
    }

    fn send_ready(&self) -> bool {
        true
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let node: Node<IdleTransport> = Node::endpoint();
    let client = node.clone();
    let runtime = tokio::spawn(node.run());
    let clients = 256;
    let reads = 10_000;
    let started = Instant::now();
    let mut tasks = JoinSet::new();

    for _ in 0..clients {
        let node = client.clone();
        tasks.spawn(async move {
            for _ in 0..reads {
                black_box(node.lifetime_stats());
            }
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }

    let operations = clients * reads;
    let elapsed = started.elapsed();
    println!(
        "lifetime_stats {operations} operations {:?} {:.0} ops/s",
        elapsed,
        operations as f64 / elapsed.as_secs_f64()
    );

    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for _ in 0..clients {
        let node = client.clone();
        tasks.spawn(async move {
            for _ in 0..reads {
                black_box(node.destination_snapshot());
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let elapsed = started.elapsed();
    println!(
        "destination_snapshot {operations} operations {:?} {:.0} ops/s",
        elapsed,
        operations as f64 / elapsed.as_secs_f64()
    );
    runtime.abort();
    assert!(runtime.await.unwrap_err().is_cancelled());

    let packets = 100_000;
    let mut inbound = VecDeque::with_capacity(packets);
    for index in 0..packets {
        let mut raw = vec![0x0c, 0x00];
        raw.extend_from_slice(&(index as u128).to_be_bytes());
        raw.push(1);
        raw.extend_from_slice(&[0; 1024]);
        inbound.push_back(raw);
    }

    let node = Node::endpoint();
    node.add_interface(Interface::new(BurstTransport { packets: inbound }));
    let client = node.clone();
    let started = Instant::now();
    let runtime = tokio::spawn(node.run());
    loop {
        if client.lifetime_stats().packets_received == packets as u64 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let elapsed = started.elapsed();
    println!(
        "inbound_parallel {packets} packets {:?} {:.0} packets/s",
        elapsed,
        packets as f64 / elapsed.as_secs_f64()
    );
    runtime.abort();
    assert!(runtime.await.unwrap_err().is_cancelled());
}
