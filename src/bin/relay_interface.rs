use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rinse::{InboundPacket, Interface, InterfaceError, OutboundPacket};
use tokio::net::TcpStream;

use super::PersistedStats;

pub struct RelayStats {
    started: Instant,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
}

impl RelayStats {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> PersistedStats {
        PersistedStats {
            total_uptime_secs: self.started.elapsed().as_secs(),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
        }
    }
}

pub struct TcpHdlc {
    inner: rinse::TcpHdlcInterface,
    stats: Arc<RelayStats>,
}

impl TcpHdlc {
    pub fn new(stream: TcpStream, stats: Arc<RelayStats>) -> std::io::Result<Self> {
        Ok(Self {
            inner: rinse::TcpHdlcInterface::new(stream)?,
            stats,
        })
    }
}

impl Interface for TcpHdlc {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        let packet = self.inner.receive().await?;
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Ok(packet)
    }

    async fn send(&self, packet: OutboundPacket) -> Result<(), InterfaceError> {
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        self.inner.send(packet).await
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        self.inner.close().await
    }
}
