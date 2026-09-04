use std::time::Instant;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rinse::{
    InboundPacket, Interface, InterfaceError, InterfaceLimits, NodeBuilder, NodeConfig,
    OutboundPacket, PrivateIdentity, RatchetAction, ServiceConfig, ServiceEvent, ServiceName,
};

struct MemoryInterface {
    inbound: async_channel::Receiver<Vec<u8>>,
    outbound: async_channel::Sender<Vec<u8>>,
}

impl Interface for MemoryInterface {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        self.inbound
            .recv()
            .await
            .map(InboundPacket::new)
            .map_err(|_| InterfaceError::Closed)
    }

    async fn send(&self, packet: OutboundPacket) -> Result<(), InterfaceError> {
        self.outbound
            .send(packet.into_bytes())
            .await
            .map_err(|_| InterfaceError::Closed)
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        Ok(())
    }
}

fn interfaces() -> (MemoryInterface, MemoryInterface) {
    let (left, left_inbound) = async_channel::unbounded();
    let (right, right_inbound) = async_channel::unbounded();
    (
        MemoryInterface {
            inbound: left_inbound,
            outbound: right,
        },
        MemoryInterface {
            inbound: right_inbound,
            outbound: left,
        },
    )
}

fn node(interface: MemoryInterface) -> (rinse::NodeHandle, rinse::NodeTask) {
    NodeBuilder::new(NodeConfig::endpoint())
        .interface(
            interface,
            InterfaceLimits::new(65_535, 256, 1_048_576).unwrap(),
        )
        .build()
        .unwrap()
}

fn throughput(criterion: &mut Criterion) {
    datagram_throughput(
        criterion,
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        "single_thread",
    );
    datagram_throughput(
        criterion,
        tokio::runtime::Runtime::new().unwrap(),
        "runtime",
    );
}

fn datagram_throughput(criterion: &mut Criterion, runtime: tokio::runtime::Runtime, name: &str) {
    let (client_interface, server_interface) = interfaces();
    let (client_node, client_task) = node(client_interface);
    let (server_node, server_task) = node(server_interface);
    let client_running = runtime.spawn(client_task.run());
    let server_running = runtime.spawn(server_task.run());
    let (client_service, mut server_service) = runtime.block_on(async {
        let mut client_service = client_node
            .register_service(
                ServiceConfig::new(
                    ServiceName::new("benchmark.client").unwrap(),
                    PrivateIdentity::from_secret_bytes([1; 64]).unwrap(),
                    [],
                    None,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let server_service = server_node
            .register_service(
                ServiceConfig::new(
                    ServiceName::new("benchmark.server").unwrap(),
                    PrivateIdentity::from_secret_bytes([2; 64]).unwrap(),
                    [],
                    None,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        server_service
            .announce(Bytes::new(), RatchetAction::Keep)
            .await
            .unwrap();
        loop {
            if matches!(
                client_service.receive().await.unwrap(),
                ServiceEvent::Announce(_)
            ) {
                break;
            }
        }
        (client_service, server_service)
    });
    let destination = server_service.destination();
    let (inflight, delivered) = async_channel::bounded(32);
    let mut group = criterion.benchmark_group(name);
    group.throughput(Throughput::Elements(1));
    for size in [9, 256, rinse::NodeHandle::MAX_DATAGRAM_BYTES] {
        let body = Bytes::from(vec![0x42; size]);
        group.bench_with_input(
            BenchmarkId::new("datagram_stream_end_to_end", size),
            &body,
            |bencher, body| {
                bencher.iter_custom(|packets| {
                    runtime.block_on(async {
                        let started = Instant::now();
                        tokio::join!(
                            async {
                                for _ in 0..packets {
                                    inflight.send(()).await.unwrap();
                                    client_node.send(destination, body.clone()).await.unwrap();
                                }
                            },
                            async {
                                let mut received = 0;
                                while received < packets {
                                    if matches!(
                                        server_service.receive().await.unwrap(),
                                        ServiceEvent::Datagram(_)
                                    ) {
                                        delivered.recv().await.unwrap();
                                        received += 1;
                                    }
                                }
                            }
                        );
                        started.elapsed()
                    })
                });
            },
        );
    }
    group.finish();
    runtime.block_on(async {
        drop(client_service);
        drop(server_service);
        client_node.shutdown().await;
        server_node.shutdown().await;
        client_running.await.unwrap().unwrap();
        server_running.await.unwrap().unwrap();
    });
}

criterion_group!(benches, throughput);
criterion_main!(benches);
