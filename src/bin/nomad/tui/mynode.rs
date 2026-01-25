use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};
use rinse::StatsSnapshot;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

const HISTORY_SIZE: usize = 60;
const SPARK_CHARS: [char; 8] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇'];

pub struct MyNodeView {
    node_hash: [u8; 16],
    node_name: String,
    last_announce_secs: u64,
    announce_button_area: Option<Rect>,
    stats: Option<StatsSnapshot>,
    last_bytes_relayed: u64,
    bytes_per_sec_history: VecDeque<u64>,
    announces_received: u32,
    announces_sent: u32,
    relay_enabled: bool,
}

impl MyNodeView {
    pub fn new(node_hash: [u8; 16]) -> Self {
        Self {
            node_hash,
            node_name: "Anonymous Peer".to_string(),
            last_announce_secs: 0,
            announce_button_area: None,
            stats: None,
            last_bytes_relayed: 0,
            bytes_per_sec_history: VecDeque::with_capacity(HISTORY_SIZE),
            announces_received: 0,
            announces_sent: 0,
            relay_enabled: false,
        }
    }

    pub fn set_relay_enabled(&mut self, enabled: bool) {
        self.relay_enabled = enabled;
    }

    pub fn set_name(&mut self, name: String) {
        self.node_name = name;
    }

    pub fn increment_announces_received(&mut self) {
        self.announces_received += 1;
    }

    pub fn increment_announces_sent(&mut self) {
        self.announces_sent += 1;
    }

    pub fn set_stats(&mut self, stats: StatsSnapshot) {
        let bytes_delta = stats.bytes_relayed.saturating_sub(self.last_bytes_relayed);
        self.last_bytes_relayed = stats.bytes_relayed;

        self.bytes_per_sec_history.push_back(bytes_delta);
        if self.bytes_per_sec_history.len() > HISTORY_SIZE {
            self.bytes_per_sec_history.pop_front();
        }

        self.stats = Some(stats);
    }

    pub fn update_announce_time(&mut self) {
        self.last_announce_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    pub fn click(&self, x: u16, y: u16) -> bool {
        if let Some(area) = self.announce_button_area {
            x >= area.x && x < area.x + area.width && y >= area.y && y < area.y + area.height
        } else {
            false
        }
    }

    fn format_announce_time(&self) -> String {
        if self.last_announce_secs == 0 {
            return "Never".to_string();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let elapsed = now.saturating_sub(self.last_announce_secs);

        if elapsed < 60 {
            format!("{}s ago", elapsed)
        } else if elapsed < 3600 {
            format!("{}m ago", elapsed / 60)
        } else if elapsed < 86400 {
            format!("{}h ago", elapsed / 3600)
        } else {
            format!("{}d ago", elapsed / 86400)
        }
    }

    fn render_sparkline(&self, width: usize) -> String {
        if self.bytes_per_sec_history.is_empty() {
            return " ".repeat(width);
        }

        let max_val = self
            .bytes_per_sec_history
            .iter()
            .max()
            .copied()
            .unwrap_or(1)
            .max(1);
        let history: Vec<u64> = self.bytes_per_sec_history.iter().copied().collect();
        let start = history.len().saturating_sub(width);
        let visible = &history[start..];

        let mut result = String::with_capacity(width);
        for &val in visible {
            let idx = if max_val > 0 {
                ((val as f64 / max_val as f64) * 7.0) as usize
            } else {
                0
            };
            result.push(SPARK_CHARS[idx.min(7)]);
        }

        while result.chars().count() < width {
            result.insert(0, ' ');
        }

        result
    }

    fn render_identity_card(&mut self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(Line::from(vec![Span::styled(
                " My Identity ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = block.inner(area);
        block.render(area, buf);

        let hash_hex = hex::encode(self.node_hash);

        let content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("   Name: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &self.node_name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "   Hash:",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(vec![
                Span::raw("   "),
                Span::styled(&hash_hex[..16], Style::default().fg(Color::Magenta)),
            ]),
            Line::from(vec![
                Span::raw("   "),
                Span::styled(&hash_hex[16..], Style::default().fg(Color::Magenta)),
            ]),
            Line::from(""),
        ];

        Paragraph::new(content).render(inner, buf);
    }

    fn render_announce_section(&mut self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(Line::from(vec![Span::styled(
                " Announce ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        block.render(area, buf);

        let announce_time = self.format_announce_time();
        let status_color = if self.last_announce_secs == 0 {
            Color::Yellow
        } else {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let elapsed = now.saturating_sub(self.last_announce_secs);
            if elapsed < 300 {
                Color::Green
            } else if elapsed < 1800 {
                Color::Yellow
            } else {
                Color::Red
            }
        };

        let content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("   Last Announced: ", Style::default().fg(Color::DarkGray)),
                Span::styled(announce_time, Style::default().fg(status_color)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "   Broadcasting allows other nodes to",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "   discover and connect to you.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
        ];

        let content_height = content.len() as u16;
        Paragraph::new(content).render(
            Rect::new(
                inner.x,
                inner.y,
                inner.width,
                content_height.min(inner.height),
            ),
            buf,
        );

        if inner.height > content_height + 1 {
            let button_y = inner.y + content_height;
            let button_text = " Announce Now ";
            let button_width = button_text.len() as u16;
            let button_x = inner.x + (inner.width.saturating_sub(button_width)) / 2;

            let button_style = Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD);

            buf.set_string(button_x, button_y, button_text, button_style);

            self.announce_button_area = Some(Rect::new(button_x, button_y, button_width, 1));
        }
    }

    fn render_stats(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(Line::from(vec![Span::styled(
                " Network Stats ",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        block.render(area, buf);

        let content = if let Some(ref stats) = self.stats {
            let uptime = StatsSnapshot::format_uptime(stats.uptime_secs);
            let rx_bytes = StatsSnapshot::format_bytes(stats.bytes_received);
            let tx_bytes = StatsSnapshot::format_bytes(stats.bytes_sent);
            let relay_bytes = StatsSnapshot::format_bytes(stats.bytes_relayed);

            let chart_width = inner.width.saturating_sub(6) as usize;
            let sparkline = self.render_sparkline(chart_width);

            let mut lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("   Uptime: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(uptime, Style::default().fg(Color::White)),
                    Span::styled("   Announces: ", Style::default().fg(Color::DarkGray)),
                    Span::styled("\u{2193}", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!("{} ", self.announces_received),
                        Style::default().fg(Color::White),
                    ),
                    Span::styled("\u{2191}", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("{}", self.announces_sent),
                        Style::default().fg(Color::White),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("   Received: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} pkts", stats.packets_received),
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(" / ", Style::default().fg(Color::DarkGray)),
                    Span::styled(rx_bytes, Style::default().fg(Color::Green)),
                ]),
                Line::from(vec![
                    Span::styled("   Sent:     ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} pkts", stats.packets_sent),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(" / ", Style::default().fg(Color::DarkGray)),
                    Span::styled(tx_bytes, Style::default().fg(Color::Cyan)),
                ]),
                Line::from(""),
            ];

            if self.relay_enabled {
                lines.push(Line::from(vec![
                    Span::styled("   ", Style::default()),
                    Span::styled(
                        "RELAY ENABLED",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("   Relayed:  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{} pkts", stats.packets_relayed),
                        Style::default().fg(Color::Magenta),
                    ),
                    Span::styled(" / ", Style::default().fg(Color::DarkGray)),
                    Span::styled(relay_bytes, Style::default().fg(Color::Magenta)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("   Announces:", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!(" {}", stats.announces_relayed),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled("  Proofs: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}", stats.proofs_relayed),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled("  Links: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}", stats.link_packets_relayed),
                        Style::default().fg(Color::Yellow),
                    ),
                ]));
                lines.push(Line::from(""));
                lines.push(Line::from(vec![
                    Span::styled("   ", Style::default()),
                    Span::styled(
                        "Relay throughput (last 60s):",
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("   ", Style::default()),
                    Span::styled(sparkline, Style::default().fg(Color::Magenta)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled("   Relay: ", Style::default().fg(Color::DarkGray)),
                    Span::styled("disabled", Style::default().fg(Color::DarkGray)),
                ]));
                lines.push(Line::from(Span::styled(
                    "   Enable in config.toml: relay = true",
                    Style::default().fg(Color::DarkGray),
                )));
            }

            lines
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "   Waiting for stats...",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        };

        Paragraph::new(content).render(inner, buf);
    }
}

impl Widget for &mut MyNodeView {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::vertical([
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(12),
        ])
        .split(area);

        self.render_identity_card(chunks[0], buf);
        self.render_announce_section(chunks[1], buf);
        self.render_stats(chunks[2], buf);
    }
}
