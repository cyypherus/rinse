use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures_util::StreamExt;
use log::LevelFilter;
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Layout, Rect},
    prelude::CrosstermBackend,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use rinse::config::{Config, InterfaceConfig, load_or_create_persistent_identity};
use rinse::{
    InterfaceLimits, NodeBuilder, NodeConfig, RatchetAction, Service, ServiceConfig, ServiceName,
};
use serde::{Deserialize, Serialize};
use simplelog::{
    ColorChoice, Config as LogConfig, SharedLogger, TermLogger, TerminalMode, WriteLogger,
};
use tokio::net::TcpListener;

mod relay_interface;
use relay_interface::{LifetimeStats, RelayStats, TcpHdlc};

const BANNER: &str = r#"    ____  _
   / __ \(_)___  ________
  / /_/ / / __ \/ ___/ _ \
 / _, _/ / / / (__  )  __/
/_/ |_/_/_/ /_/____/\___/  RELAY"#;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedStats {
    total_uptime_secs: u64,
    packets_received: u64,
    bytes_received: u64,
    packets_sent: u64,
    bytes_sent: u64,
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

    fn merge(&mut self, session: &LifetimeStats) {
        self.total_uptime_secs += session.uptime_secs;
        self.packets_received += session.packets_received;
        self.bytes_received += session.bytes_received;
        self.packets_sent += session.packets_sent;
        self.bytes_sent += session.bytes_sent;
    }

    fn combined(&self, session: &LifetimeStats) -> CombinedStats {
        CombinedStats {
            session_uptime_secs: session.uptime_secs,
            total_uptime_secs: self.total_uptime_secs + session.uptime_secs,
            packets_received: self.packets_received + session.packets_received,
            bytes_received: self.bytes_received + session.bytes_received,
            packets_sent: self.packets_sent + session.packets_sent,
            bytes_sent: self.bytes_sent + session.bytes_sent,
            session_packets_sent: session.packets_sent,
            session_bytes_sent: session.bytes_sent,
        }
    }
}

struct CombinedStats {
    session_uptime_secs: u64,
    total_uptime_secs: u64,
    packets_received: u64,
    bytes_received: u64,
    packets_sent: u64,
    bytes_sent: u64,
    session_packets_sent: u64,
    session_bytes_sent: u64,
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
    log_buffer: Arc<Mutex<VecDeque<LogEntry>>>,
}

impl RelayTui {
    fn new(log_buffer: Arc<Mutex<VecDeque<LogEntry>>>) -> Self {
        Self {
            prev_session_packets: 0,
            prev_session_bytes: 0,
            log_buffer,
        }
    }

    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_000_000_000_000 {
            format!("{:.2} TB", bytes as f64 / 1_000_000_000_000.0)
        } else if bytes >= 1_000_000_000 {
            format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
        } else if bytes >= 1_000_000 {
            format!("{:.2} MB", bytes as f64 / 1_000_000.0)
        } else if bytes >= 1_000 {
            format!("{:.2} KB", bytes as f64 / 1_000.0)
        } else {
            format!("{} B", bytes)
        }
    }

    fn format_uptime(secs: u64) -> String {
        if secs >= 86400 {
            format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
        } else if secs >= 3600 {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        } else if secs >= 60 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}s", secs)
        }
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
    ) {
        let sent_delta = combined
            .session_packets_sent
            .saturating_sub(self.prev_session_packets);
        let bytes_delta = combined
            .session_bytes_sent
            .saturating_sub(self.prev_session_bytes);

        let bytes_per_sec = bytes_delta as f64 / interval_secs;

        let area = frame.area();

        let chunks = Layout::vertical([
            Constraint::Length(7),
            Constraint::Min(10),
            Constraint::Length(12),
        ])
        .split(area);

        self.render_header(frame, chunks[0], combined, upstreams);
        self.render_stats(frame, chunks[1], combined, sent_delta, bytes_per_sec);
        self.render_logs(frame, chunks[2]);

        self.prev_session_packets = combined.session_packets_sent;
        self.prev_session_bytes = combined.session_bytes_sent;
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
                Self::format_uptime(combined.session_uptime_secs),
                Style::default().fg(Color::White),
            ),
            Span::styled(" | Total: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                Self::format_uptime(combined.total_uptime_secs),
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

    fn render_stats(
        &self,
        frame: &mut Frame,
        area: Rect,
        combined: &CombinedStats,
        sent_delta: u64,
        bytes_per_sec: f64,
    ) {
        let sections =
            Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).split(area);

        let perf_lines = vec![
            Line::from(vec![
                Span::styled("  Packets sent:     ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", combined.packets_sent),
                    Style::default().fg(Color::Green),
                ),
                Span::styled(
                    format!("  (+{})", sent_delta),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Data sent:        ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", Self::format_bytes(combined.bytes_sent)),
                    Style::default().fg(Color::Green),
                ),
                Span::styled(
                    format!("  ({})", Self::format_rate(bytes_per_sec)),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Packets received: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", combined.packets_received),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Data received:    ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:>10}", Self::format_bytes(combined.bytes_received)),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ];

        let perf_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(Span::styled(
                " Interface Activity ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        let perf_para = Paragraph::new(perf_lines).block(perf_block);
        frame.render_widget(perf_para, sections[0]);

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
        frame.render_widget(io_para, sections[1]);
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

fn data_dir() -> PathBuf {
    PathBuf::from(".rinse")
}

fn format_uptime(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    } else if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .build()
        .filter()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let headless = args.iter().any(|a| a == "--headless");

    let _ = std::fs::create_dir_all(data_dir());

    let log_level = log_level_from_env();
    let log_buffer: Arc<Mutex<VecDeque<LogEntry>>> = Arc::new(Mutex::new(VecDeque::new()));

    let log_file = File::create(data_dir().join("relay.log")).expect("failed to create log file");
    let file_logger = WriteLogger::new(log_level, LogConfig::default(), log_file);

    if headless {
        let term_logger = TermLogger::new(
            log_level,
            LogConfig::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        );
        simplelog::CombinedLogger::init(vec![term_logger, file_logger])
            .expect("failed to set logger");
    } else {
        let tui_logger = TuiLogger::new(log_buffer.clone(), file_logger);
        log::set_boxed_logger(Box::new(tui_logger)).expect("failed to set logger");
        log::set_max_level(log_level);
    }

    let config = Config::load_from(data_dir().join("config.toml")).expect("failed to load config");
    let identity = load_or_create_persistent_identity(data_dir().join("identity"))
        .expect("failed to load identity");

    let stats_file = stats_path();
    let persisted = PersistedStats::load(&stats_file);
    log::info!(
        "Loaded persisted stats: {} packets sent, {} uptime",
        persisted.packets_sent,
        format_uptime(persisted.total_uptime_secs)
    );

    let stats = RelayStats::new();
    let mut builder = NodeBuilder::new(NodeConfig::relay());

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
    let mut listeners = Vec::new();

    for (name, iface_config) in &enabled_interfaces {
        match iface_config {
            InterfaceConfig::TCPClientInterface {
                target_host,
                target_port,
                ..
            } => {
                let addr = format!("{}:{}", target_host, target_port);
                log::info!("Connecting to {} ({})", name, addr);
                match TcpHdlc::connect(&addr, stats.clone()).await {
                    Ok(interface) => {
                        builder = builder.interface(interface, interface_limits());
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
                        listeners.push(listener);
                    }
                    Err(e) => {
                        log::warn!("Failed to listen on {}: {}", addr, e);
                    }
                }
            }
        }
    }

    let (node, runtime) = builder.build().expect("failed to build relay");
    let running = tokio::spawn(runtime.run());
    for listener in listeners {
        let node = node.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        log::info!("Accepted connection from {}", peer);
                        if let Ok(interface) = TcpHdlc::new(stream, stats.clone())
                            && node
                                .attach_interface(interface, interface_limits())
                                .await
                                .is_err()
                        {
                            return;
                        }
                    }
                    Err(e) => {
                        log::warn!("Accept error: {}", e);
                    }
                }
            }
        });
    }
    let service = node
        .register_service(
            ServiceConfig::new(ServiceName::new("relay.stats").unwrap(), identity, [], None)
                .unwrap(),
        )
        .await
        .expect("failed to register relay service");

    if headless {
        run_headless(service, stats, persisted, stats_file).await;
    } else {
        run_tui(service, stats, persisted, stats_file, log_buffer, upstreams).await;
    }
    node.shutdown().await;
    running.await.unwrap().unwrap();
}

async fn run_headless(
    service: Service,
    stats: Arc<RelayStats>,
    mut persisted: PersistedStats,
    stats_file: PathBuf,
) {
    eprintln!("Relay running in headless mode (Ctrl+C to stop)");

    let save_interval = Duration::from_secs(60);
    let mut last_save = std::time::Instant::now();

    let mut announce_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(60),
    );

    let mut stats_tick = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = announce_tick.tick() => {
                let _ = service.announce(Bytes::new(), RatchetAction::Keep).await;
                log::debug!("Announced relay");
            }
            _ = stats_tick.tick() => {
                let session_stats = stats.snapshot();
                log::info!(
                    "Stats: {} packets received, {} sent",
                    session_stats.packets_received,
                    session_stats.packets_sent
                );

                if last_save.elapsed() >= save_interval {
                    let mut save_persisted = persisted.clone();
                    save_persisted.merge(&session_stats);
                    save_persisted.total_uptime_secs = persisted.total_uptime_secs;
                    save_persisted.save(&stats_file);
                    last_save = std::time::Instant::now();
                }
            }
            _ = tokio::signal::ctrl_c() => {
                let session_stats = stats.snapshot();
                persisted.merge(&session_stats);
                persisted.save(&stats_file);
                eprintln!("\nShutting down. Packets sent: {}", persisted.packets_sent);
                break;
            }
        }
    }
}

async fn run_tui(
    service: Service,
    stats: Arc<RelayStats>,
    mut persisted: PersistedStats,
    stats_file: PathBuf,
    log_buffer: Arc<Mutex<VecDeque<LogEntry>>>,
    upstreams: Vec<String>,
) {
    let mut terminal = setup_terminal().expect("failed to setup terminal");

    let stats_interval = Duration::from_secs(1);
    let save_interval = Duration::from_secs(60);

    let mut tui = RelayTui::new(log_buffer);
    let mut last_save = std::time::Instant::now();
    let mut tick = tokio::time::interval(stats_interval);
    let mut events = EventStream::new();
    let mut announce_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        Duration::from_secs(60),
    );

    loop {
        tokio::select! {
            _ = announce_tick.tick() => {
                let _ = service.announce(Bytes::new(), RatchetAction::Keep).await;
                log::debug!("Announced relay");
            }
            _ = tick.tick() => {
                let session_stats = stats.snapshot();
                let combined = persisted.combined(&session_stats);

                terminal.draw(|frame| {
                    tui.render(
                        frame,
                        &combined,
                        stats_interval.as_secs_f64(),
                        &upstreams,
                    );
                }).ok();

                if last_save.elapsed() >= save_interval {
                    let mut save_persisted = persisted.clone();
                    save_persisted.merge(&session_stats);
                    save_persisted.total_uptime_secs = persisted.total_uptime_secs;
                    save_persisted.save(&stats_file);
                    last_save = std::time::Instant::now();
                }

            }
            event = events.next() => {
                if let Some(Ok(Event::Key(key))) = event
                    && key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    let session_stats = stats.snapshot();
                    persisted.merge(&session_stats);
                    persisted.save(&stats_file);

                    restore_terminal(&mut terminal);

                    println!();
                    println!("  Stats saved to {:?}", stats_file);
                    println!("  Final all-time stats:");
                    println!("    Packets sent: {}", persisted.packets_sent);
                    println!(
                        "    Data sent: {}",
                        RelayTui::format_bytes(persisted.bytes_sent)
                    );
                    println!(
                        "    Total uptime: {}",
                        format_uptime(persisted.total_uptime_secs)
                    );
                    println!();

                    std::process::exit(0);
                }
            }
        }
    }
}

fn interface_limits() -> InterfaceLimits {
    InterfaceLimits::new(65_535, 256, 1_048_576).unwrap()
}
