use super::modal::{Modal, ModalButton};
use crate::network::NodeInfo;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Widget},
};

const MODAL_WIDTH: u16 = 50;
const MODAL_HEIGHT: u16 = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalAction {
    None,
    Connect,
    Save,
    Copy,
    Dismiss,
}

pub struct DiscoveryView {
    nodes: Vec<NodeInfo>,
    selected: usize,
    scroll_offset: usize,
    modal_open: bool,
    modal_selected: usize,
    last_height: usize,
    last_modal_area: Rect,
    last_list_area: Rect,
}

impl Default for DiscoveryView {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryView {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            modal_open: false,
            modal_selected: 0,
            last_height: 10,
            last_modal_area: Rect::default(),
            last_list_area: Rect::default(),
        }
    }

    pub fn add_node(&mut self, node: NodeInfo) {
        if let Some(existing) = self.nodes.iter_mut().find(|n| n.hash == node.hash) {
            existing.name = node.name;
        } else {
            self.nodes.push(node);
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

    pub fn is_modal_open(&self) -> bool {
        self.modal_open
    }

    pub fn select_next(&mut self) {
        if self.modal_open {
            self.modal_selected = (self.modal_selected + 1) % 4;
        } else if !self.nodes.is_empty() {
            self.selected = (self.selected + 1) % self.nodes.len();
            self.adjust_scroll();
        }
    }

    pub fn select_prev(&mut self) {
        if self.modal_open {
            self.modal_selected = if self.modal_selected == 0 {
                3
            } else {
                self.modal_selected - 1
            };
        } else if !self.nodes.is_empty() {
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

    pub fn open_modal(&mut self) {
        if !self.nodes.is_empty() {
            self.modal_open = true;
            self.modal_selected = 3;
        }
    }

    pub fn close_modal(&mut self) {
        self.modal_open = false;
    }

    pub fn modal_action(&self) -> ModalAction {
        if !self.modal_open {
            return ModalAction::None;
        }
        match self.modal_selected {
            0 => ModalAction::Dismiss,
            1 => ModalAction::Copy,
            2 => ModalAction::Save,
            3 => ModalAction::Connect,
            _ => ModalAction::None,
        }
    }

    pub fn click(&mut self, x: u16, y: u16, _area: Rect) -> Option<usize> {
        if self.modal_open {
            return None;
        }

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

    pub fn click_modal(&mut self, x: u16, y: u16, _area: Rect) -> ModalAction {
        if !self.modal_open {
            return ModalAction::None;
        }

        let modal = self.build_modal();
        if let Some(idx) = modal.hit_test_buttons(x, y, self.last_modal_area) {
            match idx {
                0 => ModalAction::Dismiss,
                1 => ModalAction::Copy,
                2 => ModalAction::Save,
                3 => ModalAction::Connect,
                _ => ModalAction::None,
            }
        } else {
            ModalAction::None
        }
    }

    fn build_modal(&self) -> Modal<'_> {
        let node = self.selected_node().unwrap();
        let hash_hex = node.hash_hex();

        let content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Name: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &node.name,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "  Hash: ",
                Style::default().fg(Color::DarkGray),
            )]),
            Line::from(vec![Span::styled(
                format!("  {}", &hash_hex[..16]),
                Style::default().fg(Color::Cyan),
            )]),
            Line::from(vec![Span::styled(
                format!("  {}", &hash_hex[16..]),
                Style::default().fg(Color::Cyan),
            )]),
            Line::from(""),
            Line::from(""),
        ];

        Modal::new("Node")
            .content(content)
            .buttons(vec![
                ModalButton::new("Cancel", Color::DarkGray),
                ModalButton::new("Copy", Color::Cyan),
                ModalButton::new("Save", Color::Green),
                ModalButton::new("Connect", Color::Magenta),
            ])
            .selected(self.modal_selected)
    }

    pub fn render_list(&mut self, area: Rect, buf: &mut Buffer) {
        self.last_list_area = area;

        let block = Block::default()
            .title(Line::from(vec![
                Span::styled(
                    " Discovered Nodes ",
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
                    "Listening for announcements...",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Nodes will appear here as they announce",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            Paragraph::new(empty_lines)
                .alignment(ratatui::layout::Alignment::Center)
                .render(inner, buf);
            return;
        }

        let items: Vec<ListItem> = self
            .nodes
            .iter()
            .skip(self.scroll_offset)
            .take(inner.height as usize)
            .map(|node| {
                let hash_short = format!("{}..{}", &node.hash_hex()[..6], &node.hash_hex()[26..]);

                ListItem::new(Line::from(vec![
                    Span::styled(" \u{2022} ", Style::default().fg(Color::Magenta)),
                    Span::styled(&node.name, Style::default().fg(Color::Gray)),
                    Span::styled(
                        format!("  {}", hash_short),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        let list = List::new(items);
        list.render(inner, buf);
    }

    pub fn render_modal(&mut self, area: Rect, buf: &mut Buffer) {
        if !self.modal_open || self.selected_node().is_none() {
            return;
        }

        let modal = self.build_modal();
        self.last_modal_area = modal.render_centered(area, buf, MODAL_WIDTH, MODAL_HEIGHT);
    }
}

impl Widget for &mut DiscoveryView {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_list(area, buf);
        self.render_modal(area, buf);
    }
}
