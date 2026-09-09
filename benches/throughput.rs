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

fn node(interface: MemoryInterface, batch_size: usize) -> NodeBuilder {
    NodeBuilder::new(NodeConfig::endpoint()).interface(
        interface,
        InterfaceLimits::new(
            65_535,
            batch_size.max(256),
            (batch_size * 512).max(1_048_576),
        )
        .unwrap(),
    )
}

async fn profile_future<F: std::future::Future>(name: &'static str, future: F) -> F::Output {
    if std::env::var_os("RINSE_ASYNC_PROFILE").is_none() {
        return future.await;
    }
    let mut future = std::pin::pin!(future);
    let started = Instant::now();
    let mut busy = std::time::Duration::ZERO;
    let mut polls = 0u64;
    let mut pending = 0u64;
    let result = std::future::poll_fn(|cx| {
        let entered = Instant::now();
        let result = future.as_mut().poll(cx);
        busy += entered.elapsed();
        polls += 1;
        pending += u64::from(result.is_pending());
        result
    })
    .await;
    eprintln!(
        "async {name}: elapsed={:?} busy={busy:?} polls={polls} pending={pending}",
        started.elapsed()
    );
    result
}

fn throughput(criterion: &mut Criterion) {
    for (name, concurrency) in [("sequential", 1), ("concurrent", 16384)] {
        datagram_throughput(
            criterion,
            tokio::runtime::Runtime::new().unwrap(),
            name,
            concurrency,
        );
    }
}

fn datagram_throughput(
    criterion: &mut Criterion,
    runtime: tokio::runtime::Runtime,
    name: &str,
    window: usize,
) {
    let (client_interface, server_interface) = interfaces();
    let client_builder = node(client_interface, window);
    let server_builder = node(server_interface, window);
    let (client_node, client_task) = client_builder.build().unwrap();
    let (server_node, server_task) = server_builder.build().unwrap();
    let client_running = runtime.spawn(profile_future("client", client_task.run()));
    let server_running = runtime.spawn(profile_future("server", server_task.run()));
    let (client_service, mut server_service) = runtime.block_on(async {
        let mut client_service = client_node
            .register_service(
                ServiceConfig::new(
                    ServiceName::new("benchmark.client").unwrap(),
                    PrivateIdentity::from_secret_bytes([1; 64]).unwrap(),
                    [],
                    None,
                )
                .unwrap()
                .event_capacity(std::num::NonZeroUsize::new(window.max(128)).unwrap()),
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
                .unwrap()
                .event_capacity(std::num::NonZeroUsize::new(window.max(128)).unwrap()),
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
    let (inflight, delivered) = async_channel::bounded(window.max(32));
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
                                if window == 1 {
                                    for _ in 0..packets {
                                        inflight.send(()).await.unwrap();
                                        client_node.send(destination, body.clone()).await.unwrap();
                                    }
                                    return;
                                }
                                use futures_util::StreamExt;
                                let mut sends = futures_util::stream::iter(0..packets)
                                    .map(|_| async {
                                        inflight.send(()).await.unwrap();
                                        client_node.send(destination, body.clone()).await
                                    })
                                    .buffer_unordered(window);
                                while let Some(result) = sends.next().await {
                                    result.unwrap();
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
