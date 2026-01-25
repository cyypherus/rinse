use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Widget},
};

pub struct Announce {
    pub hash: String,
    pub name: Option<String>,
}

pub struct DirectoryView {
    announces: Vec<Announce>,
    selected: usize,
}

impl Default for DirectoryView {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryView {
    pub fn new() -> Self {
        Self {
            announces: Vec::new(),
            selected: 0,
        }
    }

    pub fn add_announce(&mut self, hash: String, name: Option<String>) {
        if !self.announces.iter().any(|a| a.hash == hash) {
            self.announces.push(Announce { hash, name });
        }
    }

    pub fn add_node(&mut self, hash: [u8; 16]) {
        let hash_str = hex::encode(hash);
        self.add_announce(hash_str, None);
    }

    pub fn node_count(&self) -> usize {
        self.announces.len()
    }

    pub fn select_next(&mut self) {
        if !self.announces.is_empty() {
            self.selected = (self.selected + 1) % self.announces.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.announces.is_empty() {
            self.selected = self
                .selected
                .checked_sub(1)
                .unwrap_or(self.announces.len() - 1);
        }
    }

    pub fn selected_hash(&self) -> Option<&str> {
        self.announces.get(self.selected).map(|a| a.hash.as_str())
    }
}

impl Widget for &DirectoryView {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let items: Vec<ListItem> = self
            .announces
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let display = match &a.name {
                    Some(n) => format!("{} ({})", n, &a.hash[..8]),
                    None => a.hash[..16].to_string(),
                };
                let style = if i == self.selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(display)).style(style)
            })
            .collect();

        let list = if items.is_empty() {
            List::new(vec![ListItem::new("No nodes discovered yet...")])
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Network Directory"),
                )
                .style(Style::default().fg(Color::DarkGray))
        } else {
            List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Network Directory"),
            )
        };

        list.render(area, buf);
    }
}
