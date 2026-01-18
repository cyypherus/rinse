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

    pub fn snapshot(&self) -> StatsSnapshot {
        let uptime_secs = self.start_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);
        StatsSnapshot {
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
pub struct StatsSnapshot {
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

impl StatsSnapshot {
    pub fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_000_000_000 {
            format!("{:.1}GB", bytes as f64 / 1_000_000_000.0)
        } else if bytes >= 1_000_000 {
            format!("{:.1}MB", bytes as f64 / 1_000_000.0)
        } else if bytes >= 1_000 {
            format!("{:.1}KB", bytes as f64 / 1_000.0)
        } else {
            format!("{}B", bytes)
        }
    }

    pub fn format_uptime(secs: u64) -> String {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        if days > 0 {
            format!("{}d{}h", days, hours)
        } else if hours > 0 {
            format!("{}h{}m", hours, mins)
        } else {
            format!("{}m", mins)
        }
    }
}
