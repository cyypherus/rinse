use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rinse::{InboundPacket, Interface, InterfaceError, OutboundPacket};
use tokio::net::TcpStream;

pub struct LifetimeStats {
    pub uptime_secs: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
}

pub struct RelayStats {
    started: Instant,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
}

impl RelayStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        })
    }

    pub fn snapshot(&self) -> LifetimeStats {
        let packets_sent = self.packets_sent.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        LifetimeStats {
            uptime_secs: self.started.elapsed().as_secs(),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent,
            bytes_sent,
        }
    }
}

pub struct TcpHdlc {
    inner: rinse::TcpHdlcInterface,
    stats: Arc<RelayStats>,
}

impl TcpHdlc {
    pub async fn connect(address: &str, stats: Arc<RelayStats>) -> std::io::Result<Self> {
        Self::new(TcpStream::connect(address).await?, stats)
    }

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
