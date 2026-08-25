use std::time::Instant;

#[derive(Debug, Default)]
pub struct Stats {
    start_time: Option<Instant>,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_relayed: u64,
    pub bytes_relayed: u64,
    pub announces_received: u64,
    pub announces_relayed: u64,
    pub proofs_relayed: u64,
    pub link_packets_relayed: u64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn snapshot(&self) -> LifetimeStats {
        let uptime_secs = self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        LifetimeStats {
            uptime_secs,
            packets_received: self.packets_received,
            bytes_received: self.bytes_received,
            packets_sent: self.packets_sent,
            bytes_sent: self.bytes_sent,
            packets_relayed: self.packets_relayed,
            bytes_relayed: self.bytes_relayed,
            announces_received: self.announces_received,
            announces_relayed: self.announces_relayed,
            proofs_relayed: self.proofs_relayed,
            link_packets_relayed: self.link_packets_relayed,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LifetimeStats {
    pub uptime_secs: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_relayed: u64,
    pub bytes_relayed: u64,
    pub announces_received: u64,
    pub announces_relayed: u64,
    pub proofs_relayed: u64,
    pub link_packets_relayed: u64,
}
