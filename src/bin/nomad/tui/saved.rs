use crate::network::NodeInfo;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Widget},
};
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedModalAction {
    None,
    Connect,
    Delete,
    Copy,
    ToggleIdentify,
}

pub struct SavedView {
    nodes: Vec<NodeInfo>,
    selected: usize,
    scroll_offset: usize,
    last_height: usize,
    last_list_area: Rect,
    identify_button_area: Option<Rect>,
    connect_button_area: Option<Rect>,
    copy_button_area: Option<Rect>,
    delete_button_area: Option<Rect>,
}

impl Default for SavedView {
    fn default() -> Self {
        Self::new()
    }
}

impl SavedView {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            last_height: 10,
            last_list_area: Rect::default(),
            identify_button_area: None,
            connect_button_area: None,
            copy_button_area: None,
            delete_button_area: None,
        }
    }

    pub fn add_node(&mut self, node: NodeInfo) {
        if !self.nodes.iter().any(|n| n.hash == node.hash) {
            let pos = self
                .nodes
                .binary_search_by(|n| n.name.to_lowercase().cmp(&node.name.to_lowercase()))
                .unwrap_or_else(|p| p);
            self.nodes.insert(pos, node);
        }
    }

    pub fn select_by_hash(&mut self, hash: [u8; 16]) {
        if let Some(pos) = self.nodes.iter().position(|n| n.hash == hash) {
            self.selected = pos;
            self.adjust_scroll();
        }
    }

    pub fn nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn selected_node(&self) -> Option<&NodeInfo> {
        self.nodes.get(self.selected)
    }

    pub fn select_next(&mut self) {
        if !self.nodes.is_empty() {
            self.selected = (self.selected + 1) % self.nodes.len();
            self.adjust_scroll();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.nodes.is_empty() {
            self.selected = self.selected.checked_sub(1).unwrap_or(self.nodes.len() - 1);
            self.adjust_scroll();
        }
    }

    fn adjust_scroll(&mut self) {
        if self.last_height == 0 {
            return;
        }
        if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        } else if self.selected >= self.scroll_offset + self.last_height {
            self.scroll_offset = self.selected - self.last_height + 1;
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        if self.last_height == 0 {
            return;
        }
        let max_scroll = self.nodes.len().saturating_sub(self.last_height);
        if self.scroll_offset < max_scroll {
            self.scroll_offset += 1;
        }
    }

    pub fn click(&mut self, x: u16, y: u16, _area: Rect) -> Option<usize> {
        let list_inner = Rect::new(
            self.last_list_area.x + 1,
            self.last_list_area.y + 1,
            self.last_list_area.width.saturating_sub(2),
            self.last_list_area.height.saturating_sub(2),
        );

        if !list_inner.contains((x, y).into()) {
            return None;
        }

        let inner_y = y.saturating_sub(list_inner.y);
        let idx = self.scroll_offset + inner_y as usize;

        if idx < self.nodes.len() {
            self.selected = idx;
            Some(idx)
        } else {
            None
        }
    }

    pub fn remove_selected(&mut self) -> Option<NodeInfo> {
        if self.nodes.is_empty() {
            return None;
        }
        let removed = self.nodes.remove(self.selected);
        if self.selected >= self.nodes.len() && !self.nodes.is_empty() {
            self.selected = self.nodes.len() - 1;
        }
        Some(removed)
    }

    pub fn toggle_identify_selected(&mut self) -> Option<&NodeInfo> {
        if let Some(node) = self.nodes.get_mut(self.selected) {
            node.identify = !node.identify;
            Some(node)
        } else {
            None
        }
    }

    pub fn set_identify(&mut self, hash: [u8; 16], enabled: bool) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.hash == hash) {
            node.identify = enabled;
        }
    }

    pub fn update_node_name(&mut self, hash: [u8; 16], name: &str) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.hash == hash) {
            if node.name != name {
                node.name = name.to_string();
            }
        }
    }

    fn render_list(&mut self, area: Rect, buf: &mut Buffer) {
        self.last_list_area = area;

        let block = Block::default()
            .title(Line::from(vec![
                Span::styled(
                    " Saved Nodes ",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("({}) ", self.nodes.len()),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        self.last_height = inner.height as usize;
        block.render(area, buf);

        if self.nodes.is_empty() {
            let empty_lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "No saved nodes yet",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Save nodes from Discovery to see them here",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            Paragraph::new(empty_lines)
                .alignment(ratatui::layout::Alignment::Center)
                .render(inner, buf);
            return;
        }

        for (i, node) in self
            .nodes
            .iter()
            .enumerate()
            .skip(self.scroll_offset)
            .take(inner.height as usize)
        {
            let y = inner.y + (i - self.scroll_offset) as u16;
            let is_selected = i == self.selected;
            let hash_short = format!("{}..{}", &node.hash_hex()[..6], &node.hash_hex()[26..]);

            let (bullet_style, name_style, hash_style, bg) = if is_selected {
                (
                    Style::default().fg(Color::Green).bg(Color::DarkGray),
                    Style::default()
                        .fg(Color::White)
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                    Style::default().fg(Color::Gray).bg(Color::DarkGray),
                    Style::default().bg(Color::DarkGray),
                )
            } else {
                (
                    Style::default().fg(Color::Green),
                    Style::default().fg(Color::Gray),
                    Style::default().fg(Color::DarkGray),
                    Style::default(),
                )
            };

            // Clear the line with background if selected
            if is_selected {
                for x in inner.x..inner.x + inner.width {
                    buf.set_string(x, y, " ", bg);
                }
            }

            buf.set_string(inner.x, y, " \u{2022} ", bullet_style);

            let available = inner.width.saturating_sub(3) as usize;
            let hash_display = format!("  {}", hash_short);
            let hash_len = hash_display.width();
            let name_width = node.name.width();

            if available <= 5 {
                continue;
            }

            let max_name_width = available.saturating_sub(hash_len);
            let (name_display, name_display_width) = if name_width <= max_name_width {
                (node.name.clone(), name_width)
            } else if max_name_width >= 3 {
                let mut truncated = String::new();
                let mut width = 0;
                for c in node.name.chars() {
                    let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
                    if width + cw + 2 > max_name_width {
                        break;
                    }
                    truncated.push(c);
                    width += cw;
                }
                truncated.push_str("..");
                (truncated, width + 2)
            } else {
                (String::new(), 0)
            };

            buf.set_string(inner.x + 3, y, &name_display, name_style);

            let hash_x = inner.x + 3 + name_display_width as u16;
            let remaining = available.saturating_sub(name_display_width);
            if remaining >= hash_len {
                buf.set_string(hash_x, y, &hash_display, hash_style);
            }
        }
    }

    fn render_detail(&mut self, area: Rect, buf: &mut Buffer) {
        self.identify_button_area = None;
        self.connect_button_area = None;
        self.copy_button_area = None;
        self.delete_button_area = None;

        let block = Block::default()
            .title(Line::from(vec![Span::styled(
                " Node Info ",
                Style::default().fg(Color::White),
            )]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        block.render(area, buf);

        let Some(node) = self.selected_node() else {
            let empty = Paragraph::new(Line::from(Span::styled(
                "Select a node to view details",
                Style::default().fg(Color::DarkGray),
            )))
            .alignment(ratatui::layout::Alignment::Center);
            empty.render(inner, buf);
            return;
        };

        let hash_hex = node.hash_hex();
        let identify_enabled = node.identify;

        let content = vec![
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &node.name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled("Hash:", Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(
                &hash_hex[..16],
                Style::default().fg(Color::Cyan),
            )),
            Line::from(Span::styled(
                &hash_hex[16..],
                Style::default().fg(Color::Cyan),
            )),
            Line::from(""),
        ];

        Paragraph::new(content).render(inner, buf);

        // Self-Identify toggle
        let identify_y = inner.y + 7;
        let (identify_text, identify_style) = if identify_enabled {
            (
                " [x] Self-Identify ",
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            (
                " [ ] Self-Identify ",
                Style::default().fg(Color::White).bg(Color::DarkGray),
            )
        };
        let identify_width = identify_text.len() as u16;
        buf.set_string(inner.x, identify_y, identify_text, identify_style);
        self.identify_button_area = Some(Rect::new(inner.x, identify_y, identify_width, 1));

        // Action buttons at bottom: Delete | Copy | Connect
        let button_y = inner.y + inner.height.saturating_sub(1);
        let mut x = inner.x;

        let delete_text = " Delete ";
        let delete_style = Style::default()
            .fg(Color::White)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD);
        buf.set_string(x, button_y, delete_text, delete_style);
        self.delete_button_area = Some(Rect::new(x, button_y, delete_text.len() as u16, 1));
        x += delete_text.len() as u16 + 1;

        let copy_text = " Copy ";
        let copy_style = Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        buf.set_string(x, button_y, copy_text, copy_style);
        self.copy_button_area = Some(Rect::new(x, button_y, copy_text.len() as u16, 1));
        x += copy_text.len() as u16 + 1;

        let connect_text = " Connect ";
        let connect_style = Style::default()
            .fg(Color::Black)
            .bg(Color::Magenta)
            .add_modifier(Modifier::BOLD);
        buf.set_string(x, button_y, connect_text, connect_style);
        self.connect_button_area = Some(Rect::new(x, button_y, connect_text.len() as u16, 1));
    }

    pub fn click_detail(&mut self, x: u16, y: u16) -> SavedModalAction {
        if self.nodes.is_empty() {
            return SavedModalAction::None;
        }

        let in_button = |area: Option<Rect>| -> bool {
            if let Some(a) = area {
                x >= a.x && x < a.x + a.width && y >= a.y && y < a.y + a.height
            } else {
                false
            }
        };

        if in_button(self.identify_button_area) {
            SavedModalAction::ToggleIdentify
        } else if in_button(self.connect_button_area) {
            SavedModalAction::Connect
        } else if in_button(self.copy_button_area) {
            SavedModalAction::Copy
        } else if in_button(self.delete_button_area) {
            SavedModalAction::Delete
        } else {
            SavedModalAction::None
        }
    }
}

impl Widget for &mut SavedView {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = ratatui::layout::Layout::horizontal([
            ratatui::layout::Constraint::Percentage(50),
            ratatui::layout::Constraint::Percentage(50),
        ])
        .split(area);

        self.render_list(chunks[0], buf);
        self.render_detail(chunks[1], buf);
    }
}
