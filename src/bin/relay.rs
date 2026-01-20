use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Layout, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
};
use rinse::config::{Config, InterfaceConfig, data_dir, load_or_generate_identity};
use rinse::{AsyncNode, AsyncTcpTransport, Interface, StatsSnapshot};
use serde::{Deserialize, Serialize};
use simplelog::{Config as LogConfig, LevelFilter, SharedLogger, WriteLogger};
use tokio::net::TcpListener;

const BANNER: &str = r#"    ____  _
   / __ \(_)___  ________
  / /_/ / / __ \/ ___/ _ \
 / _, _/ / / / (__  )  __/
/_/ |_/_/_/ /_/____/\___/  RELAY"#;

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

struct LogEntry {
    level: log::Level,
    message: String,
}

struct TuiLogger {
    buffer: Arc<Mutex<VecDeque<LogEntry>>>,
    file_logger: Box<dyn SharedLogger>,
}

impl TuiLogger {
    fn new(buffer: Arc<Mutex<VecDeque<LogEntry>>>, file_logger: Box<dyn SharedLogger>) -> Self {
        Self {
            buffer,
            file_logger,
        }
    }
}

impl log::Log for TuiLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let entry = LogEntry {
                level: record.level(),
                message: format!("{}", record.args()),
            };
            if let Ok(mut buf) = self.buffer.lock() {
                buf.push_back(entry);
                while buf.len() > 100 {
                    buf.pop_front();
                }
            }
            self.file_logger.log(record);
        }
    }

    fn flush(&self) {
        self.file_logger.flush();
    }
}

impl SharedLogger for TuiLogger {
    fn level(&self) -> LevelFilter {
        LevelFilter::Off
    }

    fn config(&self) -> Option<&LogConfig> {
        None
    }

    fn as_log(self: Box<Self>) -> Box<dyn log::Log> {
        self
    }
}

struct RelayTui {
    prev_session_packets: u64,
    prev_session_bytes: u64,
    prev_session_announces: u64,
    log_buffer: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl RelayTui {
    fn new(log_buffer: Arc<Mutex<VecDeque<LogEntry>>>) -> Self {
        Self {
            prev_session_packets: 0,
            prev_session_bytes: 0,
            prev_session_announces: 0,
            log_buffer,
        }
    }

    fn check_milestones(persisted: &mut PersistedStats, combined: &CombinedStats) -> Vec<String> {
        let mut achievements = Vec::new();

        let announce_milestones = [10, 50, 100, 500, 1000, 5000, 10000, 50000, 100000];
        for &m in &announce_milestones {
            if combined.announces_relayed >= m && persisted.announces_milestone < m {
                persisted.announces_milestone = m;
                achievements.push(format!("ANNOUNCER: {} announces relayed!", m));
            }
        }

        let packet_milestones = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000];
        for &m in &packet_milestones {
            if combined.packets_relayed >= m && persisted.packets_milestone < m {
                persisted.packets_milestone = m;
                achievements.push(format!("PACKET PUSHER: {} packets relayed!", m));
            }
        }

        let byte_milestones = [
            1_000_000,
            10_000_000,
            100_000_000,
            1_000_000_000,     // 1 GB
            10_000_000_000,    // 10 GB
            100_000_000_000,   // 100 GB
            500_000_000_000,   // 500 GB
            1_000_000_000_000, // 1 TB
        ];
        for &m in &byte_milestones {
            if combined.bytes_relayed >= m && persisted.bytes_milestone < m {
                persisted.bytes_milestone = m;
                achievements.push(format!("DATA MOVER: {} relayed!", Self::format_bytes(m)));
            }
        }

        achievements
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

    fn render(
        &mut self,
        frame: &mut Frame,
        combined: &CombinedStats,
        interval_secs: f64,
        upstreams: &[String],
        achievements: &[String],
    ) {
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

        let area = frame.area();

        let chunks = Layout::vertical([
            Constraint::Length(7),
            Constraint::Min(10),
            Constraint::Length(12),
        ])
        .split(area);

        self.render_header(frame, chunks[0], combined, upstreams);
        self.render_stats(
            frame,
            chunks[1],
            combined,
            relayed_delta,
            announces_delta,
            bytes_per_sec,
            achievements,
        );
        self.render_logs(frame, chunks[2]);

        self.prev_session_packets = combined.session_packets_relayed;
        self.prev_session_bytes = combined.session_bytes_relayed;
        self.prev_session_announces = combined.session_announces_relayed;
    }

    fn render_header(
        &self,
        frame: &mut Frame,
        area: Rect,
        combined: &CombinedStats,
        upstreams: &[String],
    ) {
        let mut lines: Vec<Line> = BANNER
            .lines()
            .map(|l| Line::from(Span::styled(l, Style::default().fg(Color::Cyan))))
            .collect();

        lines.push(Line::from(vec![
            Span::styled(" Session: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                StatsSnapshot::format_uptime(combined.session_uptime_secs),
                Style::default().fg(Color::White),
            ),
            Span::styled(" | Total: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                StatsSnapshot::format_uptime(combined.total_uptime_secs),
                Style::default().fg(Color::White),
            ),
            if !upstreams.is_empty() {
                Span::styled(
                    format!(
                        " | Upstream: {} ({})",
                        upstreams.join(", "),
                        upstreams.len()
                    ),
                    Style::default().fg(Color::DarkGray),
                )
            } else {
                Span::raw("")
            },
        ]));

        let para = Paragraph::new(lines);
        frame.render_widget(para, area);
    }

    #[allow(clippy::too_many_arguments)]
    fn render_stats(
        &self,
        frame: &mut Frame,
        area: Rect,
        combined: &CombinedStats,
        relayed_delta: u64,
        announces_delta: u64,
        bytes_per_sec: f64,
        achievements: &[String],
    ) {
        let chunks = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        let left_chunks = Layout::vertical([
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Min(3),
        ])
        .split(chunks[0]);

        let perf_lines = vec![
            Line::from(vec![
                Span::styled("  Packets relayed:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", combined.packets_relayed),
                    Style::default().fg(Color::Green),
                ),
                Span::styled(
                    format!("  (+{})", relayed_delta),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Data relayed:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", Self::format_bytes(combined.bytes_relayed)),
                    Style::default().fg(Color::Green),
                ),
                Span::styled(
                    format!("  ({})", Self::format_rate(bytes_per_sec)),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Announces:        ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", combined.announces_relayed),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("  (+{})", announces_delta),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Proofs:           ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", combined.proofs_relayed),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Link packets:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", combined.link_packets_relayed),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ];

        let perf_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Relay Performance ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        let perf_para = Paragraph::new(perf_lines).block(perf_block);
        frame.render_widget(perf_para, left_chunks[0]);

        let io_lines = vec![
            Line::from(vec![
                Span::styled("  RX: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} pkts", combined.packets_received),
                    Style::default().fg(Color::Blue),
                ),
                Span::styled(" / ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    Self::format_bytes(combined.bytes_received),
                    Style::default().fg(Color::Blue),
                ),
            ]),
            Line::from(vec![
                Span::styled("  TX: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{} pkts", combined.packets_sent),
                    Style::default().fg(Color::Magenta),
                ),
                Span::styled(" / ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    Self::format_bytes(combined.bytes_sent),
                    Style::default().fg(Color::Magenta),
                ),
            ]),
        ];

        let io_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Network I/O ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        let io_para = Paragraph::new(io_lines).block(io_block);
        frame.render_widget(io_para, left_chunks[1]);

        let relay_score = combined.packets_relayed * 10
            + combined.announces_relayed * 100
            + combined.proofs_relayed * 50
            + combined.link_packets_relayed * 25
            + combined.bytes_relayed / 1000;
        let pts_per_min = relay_score as f64 / (combined.total_uptime_secs as f64 / 60.0).max(1.0);

        let score_lines = vec![Line::from(vec![
            Span::styled("  Score: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", relay_score),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" pts  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("({:.1} pts/min)", pts_per_min),
                Style::default().fg(Color::DarkGray),
            ),
        ])];

        let score_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Relay Score ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        let score_para = Paragraph::new(score_lines).block(score_block);
        frame.render_widget(score_para, left_chunks[2]);

        let right_chunks =
            Layout::vertical([Constraint::Length(6), Constraint::Min(3)]).split(chunks[1]);

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

        let announce_ratio =
            (combined.announces_relayed as f64 / next_announce_milestone as f64).min(1.0);
        let packet_ratio =
            (combined.packets_relayed as f64 / next_packet_milestone as f64).min(1.0);

        let milestone_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Progress ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        let milestone_inner = milestone_block.inner(right_chunks[0]);
        frame.render_widget(milestone_block, right_chunks[0]);

        let gauge_chunks =
            Layout::vertical([Constraint::Length(2), Constraint::Length(2)]).split(milestone_inner);

        let announce_gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Yellow).bg(Color::Black))
            .ratio(announce_ratio)
            .label(format!(
                "Announces: {}/{}",
                combined.announces_relayed, next_announce_milestone
            ));
        frame.render_widget(announce_gauge, gauge_chunks[0]);

        let packet_gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
            .ratio(packet_ratio)
            .label(format!(
                "Packets: {}/{}",
                combined.packets_relayed, next_packet_milestone
            ));
        frame.render_widget(packet_gauge, gauge_chunks[1]);

        let achievement_lines: Vec<Line> = achievements
            .iter()
            .map(|a| {
                Line::from(Span::styled(
                    format!("  {} {}", "\u{2605}", a),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ))
            })
            .collect();

        let achievement_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(Span::styled(
                " Achievements ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        let achievement_para = Paragraph::new(achievement_lines).block(achievement_block);
        frame.render_widget(achievement_para, right_chunks[1]);
    }

    fn render_logs(&self, frame: &mut Frame, area: Rect) {
        let entries: Vec<(log::Level, String)> = self
            .log_buffer
            .lock()
            .ok()
            .map(|buf| {
                buf.iter()
                    .rev()
                    .take(area.height.saturating_sub(2) as usize)
                    .map(|e| (e.level, e.message.clone()))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect()
            })
            .unwrap_or_default();

        let lines: Vec<Line> = entries
            .into_iter()
            .map(|(level, message)| {
                let (color, prefix) = match level {
                    log::Level::Error => (Color::Red, "ERR"),
                    log::Level::Warn => (Color::Yellow, "WRN"),
                    log::Level::Info => (Color::Green, "INF"),
                    log::Level::Debug => (Color::Blue, "DBG"),
                    log::Level::Trace => (Color::DarkGray, "TRC"),
                };
                Line::from(vec![
                    Span::styled(format!(" {} ", prefix), Style::default().fg(color)),
                    Span::styled(message, Style::default().fg(Color::White)),
                ])
            })
            .collect();

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Logs ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        let para = Paragraph::new(lines).block(block);
        frame.render_widget(para, area);
    }
}

fn stats_path() -> PathBuf {
    data_dir().join("relay_stats.json")
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) {
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
}

fn log_level_from_env() -> LevelFilter {
    std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "trace" => Some(LevelFilter::Trace),
            "debug" => Some(LevelFilter::Debug),
            "info" => Some(LevelFilter::Info),
            "warn" | "warning" => Some(LevelFilter::Warn),
            "error" => Some(LevelFilter::Error),
            "off" => Some(LevelFilter::Off),
            _ => None,
        })
        .unwrap_or(LevelFilter::Info)
}

#[tokio::main]
async fn main() {
    let _ = std::fs::create_dir_all(data_dir());

    let log_level = log_level_from_env();
    let log_buffer: Arc<Mutex<VecDeque<LogEntry>>> = Arc::new(Mutex::new(VecDeque::new()));

    let log_file = File::create(data_dir().join("relay.log")).expect("failed to create log file");
    let file_logger = WriteLogger::new(log_level, LogConfig::default(), log_file);
    let tui_logger = TuiLogger::new(log_buffer.clone(), file_logger);

    log::set_boxed_logger(Box::new(tui_logger)).expect("failed to set logger");
    log::set_max_level(log_level);

    let config = Config::load().expect("failed to load config");
    let identity = load_or_generate_identity().expect("failed to load identity");

    let stats_file = stats_path();
    let mut persisted = PersistedStats::load(&stats_file);
    log::info!(
        "Loaded persisted stats: {} packets relayed, {} uptime",
        persisted.packets_relayed,
        StatsSnapshot::format_uptime(persisted.total_uptime_secs)
    );

    let mut node: AsyncNode<AsyncTcpTransport> = AsyncNode::new(true);
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
                match AsyncTcpTransport::connect(&addr).await {
                    Ok(transport) => {
                        node.add_interface(Interface::new(transport));
                        upstreams.push(addr);
                    }
                    Err(e) => {
                        log::warn!("Failed to connect to {}: {}", addr, e);
                    }
                }
            }
            InterfaceConfig::TCPServerInterface {
                listen_ip,
                listen_port,
                ..
            } => {
                let addr = format!("{}:{}", listen_ip, listen_port);
                log::info!("Listening on {} ({})", name, addr);
                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        let node_clone = node.clone();
                        tokio::spawn(async move {
                            loop {
                                match listener.accept().await {
                                    Ok((stream, peer)) => {
                                        log::info!("Accepted connection from {}", peer);
                                        if let Ok(transport) =
                                            AsyncTcpTransport::from_stream(peer.to_string(), stream)
                                        {
                                            node_clone.add_interface(Interface::new(transport));
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("Accept error: {}", e);
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::warn!("Failed to listen on {}: {}", addr, e);
                    }
                }
            }
        }
    }

    let mut terminal = setup_terminal().expect("failed to setup terminal");

    let stats_interval = Duration::from_secs(1);
    let save_interval = Duration::from_secs(60);

    let mut tui = RelayTui::new(log_buffer);
    let mut last_save = std::time::Instant::now();
    let mut achievements: Vec<String> = Vec::new();

    let node_handle = node.clone();
    tokio::spawn(async move {
        node.run().await;
    });

    let mut tick = tokio::time::interval(stats_interval);
    let mut announce_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(60),
    );

    loop {
        tokio::select! {
            _ = announce_tick.tick() => {
                node_handle.announce(service);
                log::debug!("Announced relay");
            }
            _ = tick.tick() => {
                let session_stats = node_handle.stats().await;
                let combined = persisted.combined(&session_stats);

                let new_achievements = RelayTui::check_milestones(&mut persisted, &combined);
                achievements.extend(new_achievements);
                while achievements.len() > 5 {
                    achievements.remove(0);
                }

                terminal.draw(|frame| {
                    tui.render(
                        frame,
                        &combined,
                        stats_interval.as_secs_f64(),
                        &upstreams,
                        &achievements,
                    );
                }).ok();

                if last_save.elapsed() >= save_interval {
                    let mut save_persisted = persisted.clone();
                    save_persisted.merge(&session_stats);
                    save_persisted.total_uptime_secs = persisted.total_uptime_secs;
                    save_persisted.save(&stats_file);
                    last_save = std::time::Instant::now();
                }

                if event::poll(Duration::from_millis(0)).unwrap_or(false)
                    && let Ok(Event::Key(key)) = event::read()
                    && key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    let session_stats = node_handle.stats().await;
                    persisted.merge(&session_stats);
                    persisted.save(&stats_file);

                    restore_terminal(&mut terminal);

                    println!();
                    println!("  Stats saved to {:?}", stats_file);
                    println!("  Final all-time stats:");
                    println!("    Packets relayed: {}", persisted.packets_relayed);
                    println!(
                        "    Data relayed: {}",
                        RelayTui::format_bytes(persisted.bytes_relayed)
                    );
                    println!("    Announces relayed: {}", persisted.announces_relayed);
                    println!(
                        "    Total uptime: {}",
                        StatsSnapshot::format_uptime(persisted.total_uptime_secs)
                    );
                    println!();

                    std::process::exit(0);
                }
            }
        }
    }
}
