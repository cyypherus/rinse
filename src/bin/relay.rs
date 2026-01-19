use std::fs::File;
use std::path::PathBuf;
use std::time::Duration;

use rinse::config::{Config, InterfaceConfig, data_dir, load_or_generate_identity};
use rinse::{AsyncNode, StatsSnapshot};
use serde::{Deserialize, Serialize};
use simplelog::{Config as LogConfig, LevelFilter, WriteLogger};

const BANNER: &str = r#"
    ____  _
   / __ \(_)___  ________
  / /_/ / / __ \/ ___/ _ \
 / _, _/ / / / (__  )  __/
/_/ |_/_/_/ /_/____/\___/  RELAY
"#;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedStats {
    total_uptime_secs: u64,
    packets_relayed: u64,
    bytes_relayed: u64,
    announces_received: u64,
    announces_relayed: u64,
    proofs_relayed: u64,
    link_packets_relayed: u64,
    packets_received: u64,
    bytes_received: u64,
    packets_sent: u64,
    bytes_sent: u64,
    #[serde(default)]
    announces_milestone: u64,
    #[serde(default)]
    packets_milestone: u64,
    #[serde(default)]
    bytes_milestone: u64,
}

impl PersistedStats {
    fn load(path: &PathBuf) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &PathBuf) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }

    fn merge(&mut self, session: &StatsSnapshot) {
        self.total_uptime_secs += session.uptime_secs;
        self.packets_relayed += session.packets_relayed;
        self.bytes_relayed += session.bytes_relayed;
        self.announces_received += session.announces_received;
        self.announces_relayed += session.announces_relayed;
        self.proofs_relayed += session.proofs_relayed;
        self.link_packets_relayed += session.link_packets_relayed;
        self.packets_received += session.packets_received;
        self.bytes_received += session.bytes_received;
        self.packets_sent += session.packets_sent;
        self.bytes_sent += session.bytes_sent;
    }

    fn combined(&self, session: &StatsSnapshot) -> CombinedStats {
        CombinedStats {
            session_uptime_secs: session.uptime_secs,
            total_uptime_secs: self.total_uptime_secs + session.uptime_secs,
            packets_relayed: self.packets_relayed + session.packets_relayed,
            bytes_relayed: self.bytes_relayed + session.bytes_relayed,
            announces_relayed: self.announces_relayed + session.announces_relayed,
            proofs_relayed: self.proofs_relayed + session.proofs_relayed,
            link_packets_relayed: self.link_packets_relayed + session.link_packets_relayed,
            packets_received: self.packets_received + session.packets_received,
            bytes_received: self.bytes_received + session.bytes_received,
            packets_sent: self.packets_sent + session.packets_sent,
            bytes_sent: self.bytes_sent + session.bytes_sent,
            session_packets_relayed: session.packets_relayed,
            session_bytes_relayed: session.bytes_relayed,
            session_announces_relayed: session.announces_relayed,
        }
    }
}

struct CombinedStats {
    session_uptime_secs: u64,
    total_uptime_secs: u64,
    packets_relayed: u64,
    bytes_relayed: u64,
    announces_relayed: u64,
    proofs_relayed: u64,
    link_packets_relayed: u64,
    packets_received: u64,
    bytes_received: u64,
    packets_sent: u64,
    bytes_sent: u64,
    session_packets_relayed: u64,
    session_bytes_relayed: u64,
    session_announces_relayed: u64,
}

struct RelayDisplay {
    prev_session_packets: u64,
    prev_session_bytes: u64,
    prev_session_announces: u64,
}

impl RelayDisplay {
    fn new() -> Self {
        Self {
            prev_session_packets: 0,
            prev_session_bytes: 0,
            prev_session_announces: 0,
        }
    }

    fn check_milestones(persisted: &mut PersistedStats, combined: &CombinedStats) {
        let announce_milestones = [10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000];
        for &m in &announce_milestones {
            if combined.announces_relayed >= m && persisted.announces_milestone < m {
                persisted.announces_milestone = m;
                Self::celebrate("ANNOUNCER", m, "announces relayed");
            }
        }

        let packet_milestones = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000];
        for &m in &packet_milestones {
            if combined.packets_relayed >= m && persisted.packets_milestone < m {
                persisted.packets_milestone = m;
                Self::celebrate("PACKET PUSHER", m, "packets relayed");
            }
        }

        let byte_milestones = [
            1_000_000,
            10_000_000,
            100_000_000,
            1_000_000_000,
            10_000_000_000,
            100_000_000_000,
        ];
        for &m in &byte_milestones {
            if combined.bytes_relayed >= m && persisted.bytes_milestone < m {
                persisted.bytes_milestone = m;
                Self::celebrate(
                    "DATA MOVER",
                    m,
                    &format!("bytes relayed ({})", Self::format_bytes(m)),
                );
            }
        }
    }

    fn celebrate(title: &str, value: u64, description: &str) {
        println!();
        println!("  ***********************************************");
        println!("  *  ACHIEVEMENT UNLOCKED: {:<20} *", title);
        println!("  *  {} {}!", value, description);
        println!("  ***********************************************");
        println!();
    }

    fn format_bytes(bytes: u64) -> String {
        StatsSnapshot::format_bytes(bytes)
    }

    fn format_rate(bytes_per_sec: f64) -> String {
        if bytes_per_sec >= 1_000_000.0 {
            format!("{:.1} MB/s", bytes_per_sec / 1_000_000.0)
        } else if bytes_per_sec >= 1_000.0 {
            format!("{:.1} KB/s", bytes_per_sec / 1_000.0)
        } else {
            format!("{:.0} B/s", bytes_per_sec)
        }
    }

    fn progress_bar(current: u64, max: u64, width: usize) -> String {
        let ratio = if max > 0 {
            (current as f64 / max as f64).min(1.0)
        } else {
            0.0
        };
        let filled = (ratio * width as f64) as usize;
        let empty = width - filled;
        format!("[{}{}]", "=".repeat(filled), " ".repeat(empty))
    }

    fn display(
        &mut self,
        persisted: &mut PersistedStats,
        combined: &CombinedStats,
        interval_secs: f64,
        upstreams: &[String],
    ) {
        Self::check_milestones(persisted, combined);

        let relayed_delta = combined
            .session_packets_relayed
            .saturating_sub(self.prev_session_packets);
        let bytes_delta = combined
            .session_bytes_relayed
            .saturating_sub(self.prev_session_bytes);
        let announces_delta = combined
            .session_announces_relayed
            .saturating_sub(self.prev_session_announces);

        let bytes_per_sec = bytes_delta as f64 / interval_secs;

        print!("\x1B[2J\x1B[H");

        println!("{}", BANNER);
        println!(
            "  Session: {} | Total: {}",
            StatsSnapshot::format_uptime(combined.session_uptime_secs),
            StatsSnapshot::format_uptime(combined.total_uptime_secs),
        );
        if !upstreams.is_empty() {
            println!(
                "  Upstream:  {} ({})",
                upstreams.join(", "),
                upstreams.len()
            );
        }
        println!();

        println!("  RELAY PERFORMANCE (ALL TIME)");
        println!("  ----------------------------");
        println!(
            "  Packets relayed:   {:>10}  (+{} this interval)",
            combined.packets_relayed, relayed_delta
        );
        println!(
            "  Data relayed:      {:>10}  ({})",
            Self::format_bytes(combined.bytes_relayed),
            Self::format_rate(bytes_per_sec)
        );
        println!();

        println!("  BREAKDOWN");
        println!(
            "    Announces:       {:>10}  (+{})",
            combined.announces_relayed, announces_delta
        );
        println!("    Proofs:          {:>10}", combined.proofs_relayed);
        println!("    Link packets:    {:>10}", combined.link_packets_relayed);
        println!();

        println!("  NETWORK I/O (ALL TIME)");
        println!(
            "    RX: {} pkts / {}",
            combined.packets_received,
            Self::format_bytes(combined.bytes_received)
        );
        println!(
            "    TX: {} pkts / {}",
            combined.packets_sent,
            Self::format_bytes(combined.bytes_sent)
        );
        println!();

        let next_announce_milestone = [10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000]
            .iter()
            .find(|&&m| combined.announces_relayed < m)
            .copied()
            .unwrap_or(500000);

        let next_packet_milestone = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000]
            .iter()
            .find(|&&m| combined.packets_relayed < m)
            .copied()
            .unwrap_or(5000000);

        println!("  PROGRESS TO NEXT MILESTONE");
        println!(
            "    Announces: {} {}/{}",
            Self::progress_bar(combined.announces_relayed, next_announce_milestone, 20),
            combined.announces_relayed,
            next_announce_milestone
        );
        println!(
            "    Packets:   {} {}/{}",
            Self::progress_bar(combined.packets_relayed, next_packet_milestone, 20),
            combined.packets_relayed,
            next_packet_milestone
        );
        println!();

        let relay_score = combined.packets_relayed * 10
            + combined.announces_relayed * 100
            + combined.proofs_relayed * 50
            + combined.link_packets_relayed * 25
            + combined.bytes_relayed / 1000;

        println!(
            "  RELAY SCORE: {} pts  ({:.1} pts/min)",
            relay_score,
            relay_score as f64 / (combined.total_uptime_secs as f64 / 60.0).max(1.0)
        );
        println!();

        self.prev_session_packets = combined.session_packets_relayed;
        self.prev_session_bytes = combined.session_bytes_relayed;
        self.prev_session_announces = combined.session_announces_relayed;
    }
}

fn stats_path() -> PathBuf {
    data_dir().join("relay_stats.json")
}

#[tokio::main]
async fn main() {
    let _ = std::fs::create_dir_all(data_dir());
    let log_file = File::create(data_dir().join("relay.log")).expect("failed to create log file");
    WriteLogger::init(LevelFilter::Trace, LogConfig::default(), log_file)
        .expect("failed to init logger");

    let config = Config::load().expect("failed to load config");
    let identity = load_or_generate_identity().expect("failed to load identity");

    let stats_file = stats_path();
    let mut persisted = PersistedStats::load(&stats_file);
    log::info!(
        "Loaded persisted stats: {} packets relayed, {} uptime",
        persisted.packets_relayed,
        StatsSnapshot::format_uptime(persisted.total_uptime_secs)
    );

    let mut node = AsyncNode::new(true);
    let service = node.add_service("relay.stats", &[], &identity);

    let enabled_interfaces = config.enabled_interfaces();
    if enabled_interfaces.is_empty() {
        eprintln!("No interfaces configured!");
        eprintln!("Add interfaces to .nomad/config.toml");
        eprintln!();
        eprintln!("Example:");
        eprintln!();
        eprintln!("  [interfaces.\"Upstream\"]");
        eprintln!("  type = \"TCPClientInterface\"");
        eprintln!("  target_host = \"amsterdam.connect.reticulum.network\"");
        eprintln!("  target_port = 4965");
        eprintln!();
        std::process::exit(1);
    }

    let mut upstreams = Vec::new();

    for (name, iface_config) in &enabled_interfaces {
        match iface_config {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host, target_port);
                log::info!("Connecting to {} ({})", name, addr);
                if let Err(e) = node.connect(&addr).await {
                    log::warn!("Failed to connect to {}: {}", addr, e);
                } else {
                    upstreams.push(addr);
                }
            }
            InterfaceConfig::TCPServerInterface {
                listen_ip,
                listen_port,
                ..
            } => {
                let addr = format!("{}:{}", listen_ip, listen_port);
                log::info!("Listening on {} ({})", name, addr);
                if let Err(e) = node.listen(&addr).await {
                    log::warn!("Failed to listen on {}: {}", addr, e);
                }
            }
        }
    }

    let stats_interval = Duration::from_secs(5);
    let save_interval = Duration::from_secs(60);

    let mut display = RelayDisplay::new();
    let mut last_save = std::time::Instant::now();

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(stats_interval);
        let mut announce_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(10),
            Duration::from_secs(60),
        );

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    let session_stats = service.stats().await;
                    persisted.merge(&session_stats);
                    persisted.save(&stats_file);

                    println!();
                    println!("  Stats saved to {:?}", stats_file);
                    println!("  Final all-time stats:");
                    println!("    Packets relayed: {}", persisted.packets_relayed);
                    println!(
                        "    Data relayed: {}",
                        RelayDisplay::format_bytes(persisted.bytes_relayed)
                    );
                    println!("    Announces relayed: {}", persisted.announces_relayed);
                    println!(
                        "    Total uptime: {}",
                        StatsSnapshot::format_uptime(persisted.total_uptime_secs)
                    );
                    println!();

                    std::process::exit(0);
                }
                _ = announce_tick.tick() => {
                    service.announce();
                    log::debug!("Announced relay");
                }
                _ = tick.tick() => {
                    let session_stats = service.stats().await;
                    let combined = persisted.combined(&session_stats);
                    display.display(
                        &mut persisted,
                        &combined,
                        stats_interval.as_secs_f64(),
                        &upstreams,
                    );

                    if last_save.elapsed() >= save_interval {
                        let mut save_persisted = persisted.clone();
                        save_persisted.merge(&session_stats);
                        save_persisted.total_uptime_secs = persisted.total_uptime_secs;
                        save_persisted.save(&stats_file);
                        last_save = std::time::Instant::now();
                    }
                }
            }
        }
    });

    node.run().await;
}
