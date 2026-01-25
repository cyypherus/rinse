use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub kind: InterfaceKind,
    pub address: String,
    pub connected: bool,
}

#[derive(Debug, Clone)]
pub enum InterfaceKind {
    TcpClient,
    TcpServer,
}

impl InterfaceKind {
    fn label(&self) -> &'static str {
        match self {
            InterfaceKind::TcpClient => "TCP Client",
            InterfaceKind::TcpServer => "TCP Server",
        }
    }

    fn color(&self) -> Color {
        match self {
            InterfaceKind::TcpClient => Color::Cyan,
            InterfaceKind::TcpServer => Color::Magenta,
        }
    }
}

pub struct InterfacesView {
    interfaces: Vec<InterfaceInfo>,
    selected: usize,
    last_button_areas: Vec<(usize, Rect)>,
}

impl InterfacesView {
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            selected: 0,
            last_button_areas: Vec::new(),
        }
    }

    pub fn set_interfaces(&mut self, interfaces: Vec<InterfaceInfo>) {
        self.interfaces = interfaces;
        if self.selected >= self.interfaces.len() && !self.interfaces.is_empty() {
            self.selected = self.interfaces.len() - 1;
        }
    }

    pub fn update_status(&mut self, name: &str, connected: bool) {
        if let Some(iface) = self.interfaces.iter_mut().find(|i| i.name == name) {
            iface.connected = connected;
        }
    }

    pub fn scroll_down(&mut self) {
        if !self.interfaces.is_empty() {
            self.selected = (self.selected + 1) % self.interfaces.len();
        }
    }

    pub fn scroll_up(&mut self) {
        if !self.interfaces.is_empty() {
            self.selected = self
                .selected
                .checked_sub(1)
                .unwrap_or(self.interfaces.len() - 1);
        }
    }

    pub fn selected_interface(&self) -> Option<&InterfaceInfo> {
        self.interfaces.get(self.selected)
    }

    pub fn click_reconnect(&self, x: u16, y: u16) -> Option<String> {
        for (idx, area) in &self.last_button_areas {
            if area.contains((x, y).into()) {
                if let Some(iface) = self.interfaces.get(*idx) {
                    if !iface.connected {
                        return Some(iface.name.clone());
                    }
                }
            }
        }
        None
    }

    pub fn try_reconnect_selected(&self) -> Option<String> {
        self.selected_interface()
            .filter(|i| !i.connected)
            .map(|i| i.name.clone())
    }
}

impl Widget for &mut InterfacesView {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.last_button_areas.clear();

        let block = Block::default()
            .title(Line::from(vec![
                Span::styled(
                    " Interfaces ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("({}) ", self.interfaces.len()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        block.render(area, buf);

        if self.interfaces.is_empty() {
            let empty_lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "No interfaces configured",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Add interfaces in config.toml",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            Paragraph::new(empty_lines)
                .alignment(ratatui::layout::Alignment::Center)
                .render(inner, buf);
            return;
        }

        let row_height = 4u16;
        let selected = self.selected;
        let max_rows = (inner.height / row_height) as usize;

        let rows_to_render: Vec<_> = self
            .interfaces
            .iter()
            .enumerate()
            .take(max_rows)
            .map(|(idx, iface)| (idx, iface.clone(), idx == selected))
            .collect();

        for (i, (idx, iface, is_selected)) in rows_to_render.into_iter().enumerate() {
            let y = inner.y + (i as u16) * row_height;
            let row_area = Rect::new(inner.x, y, inner.width, row_height);
            self.render_interface_row(idx, &iface, row_area, is_selected, buf);
        }
    }
}

impl InterfacesView {
    fn render_interface_row(
        &mut self,
        idx: usize,
        iface: &InterfaceInfo,
        area: Rect,
        selected: bool,
        buf: &mut Buffer,
    ) {
        let border_color = if selected {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color));

        let inner = block.inner(area);
        block.render(area, buf);

        let chunks = Layout::horizontal([Constraint::Min(20), Constraint::Length(14)]).split(inner);

        let status_indicator = if iface.connected {
            Span::styled("\u{25CF} ", Style::default().fg(Color::Green))
        } else {
            Span::styled("\u{25CF} ", Style::default().fg(Color::Red))
        };

        let status_text = if iface.connected {
            "Connected"
        } else {
            "Disconnected"
        };

        let info_lines = vec![
            Line::from(vec![
                status_indicator,
                Span::styled(
                    &iface.name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(iface.kind.label(), Style::default().fg(iface.kind.color())),
                Span::styled(" \u{2192} ", Style::default().fg(Color::DarkGray)),
                Span::styled(&iface.address, Style::default().fg(Color::Gray)),
                Span::styled("  ", Style::default()),
                Span::styled(
                    status_text,
                    Style::default().fg(if iface.connected {
                        Color::Green
                    } else {
                        Color::Red
                    }),
                ),
            ]),
        ];

        Paragraph::new(info_lines).render(chunks[0], buf);

        if !iface.connected {
            let button_text = " Reconnect ";
            let button_width = button_text.len() as u16;
            let button_x = chunks[1].x + (chunks[1].width.saturating_sub(button_width)) / 2;
            let button_y = chunks[1].y;

            let button_style = Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD);

            buf.set_string(button_x, button_y, button_text, button_style);

            self.last_button_areas
                .push((idx, Rect::new(button_x, button_y, button_width, 1)));
        }
    }
}
