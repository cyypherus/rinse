use std::time::Instant;

pub struct Stats {
    started_at: Instant,
    lifetime: LifetimeStats,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            lifetime: LifetimeStats::default(),
        }
    }

    pub fn snapshot(&self) -> LifetimeStats {
        let mut snapshot = self.lifetime.clone();
        snapshot.uptime_secs = self.started_at.elapsed().as_secs();
        snapshot
    }
}

impl std::ops::Deref for Stats {
    type Target = LifetimeStats;

    fn deref(&self) -> &Self::Target {
        &self.lifetime
    }
}

impl std::ops::DerefMut for Stats {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.lifetime
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
