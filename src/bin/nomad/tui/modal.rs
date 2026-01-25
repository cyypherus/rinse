use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};

#[derive(Debug, Clone)]
pub struct ModalButton {
    pub label: String,
    pub color: Color,
}

impl ModalButton {
    pub fn new(label: impl Into<String>, color: Color) -> Self {
        Self {
            label: label.into(),
            color,
        }
    }
}

pub struct Modal<'a> {
    title: String,
    content: Vec<Line<'a>>,
    buttons: Vec<ModalButton>,
    selected: usize,
    border_color: Color,
}

impl<'a> Modal<'a> {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            content: Vec::new(),
            buttons: Vec::new(),
            selected: 0,
            border_color: Color::Magenta,
        }
    }

    pub fn content(mut self, content: Vec<Line<'a>>) -> Self {
        self.content = content;
        self
    }

    pub fn buttons(mut self, buttons: Vec<ModalButton>) -> Self {
        self.buttons = buttons;
        self
    }

    pub fn selected(mut self, selected: usize) -> Self {
        self.selected = selected;
        self
    }

    pub fn border_color(mut self, color: Color) -> Self {
        self.border_color = color;
        self
    }

    pub fn render_centered(&self, area: Rect, buf: &mut Buffer, width: u16, height: u16) -> Rect {
        let popup_width = width.min(area.width.saturating_sub(4));
        let popup_height = height.min(area.height.saturating_sub(4));
        let popup_x = area.x + (area.width.saturating_sub(popup_width)) / 2;
        let popup_y = area.y + (area.height.saturating_sub(popup_height)) / 2;
        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        Clear.render(popup_area, buf);

        let block = Block::default()
            .title(Line::from(vec![Span::styled(
                format!(" {} ", self.title),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.border_color));

        let inner = block.inner(popup_area);
        block.render(popup_area, buf);

        let content_height = inner.height.saturating_sub(2);
        Paragraph::new(self.content.clone()).render(
            Rect::new(inner.x, inner.y, inner.width, content_height),
            buf,
        );

        if !self.buttons.is_empty() {
            let button_y = inner.y + inner.height.saturating_sub(1);
            self.render_buttons(inner.x, button_y, inner.width, buf);
        }

        popup_area
    }

    fn render_buttons(&self, x: u16, y: u16, width: u16, buf: &mut Buffer) {
        let total_len: usize = self.buttons.iter().map(|b| b.label.len() + 2).sum();
        let spacing = 2usize;
        let total_with_spacing = total_len + spacing * (self.buttons.len().saturating_sub(1));

        let start_x = x + (width.saturating_sub(total_with_spacing as u16)) / 2;
        let mut cur_x = start_x;

        for (i, button) in self.buttons.iter().enumerate() {
            let mut style = Style::default().fg(Color::Black).bg(button.color);
            if i == self.selected {
                style = style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
            }

            let label = format!(" {} ", button.label);
            buf.set_string(cur_x, y, &label, style);
            cur_x += label.len() as u16 + spacing as u16;
        }
    }

    pub fn hit_test_buttons(&self, x: u16, y: u16, popup_area: Rect) -> Option<usize> {
        let inner_x = popup_area.x + 1;
        let inner_y = popup_area.y + 1;
        let inner_width = popup_area.width.saturating_sub(2);
        let inner_height = popup_area.height.saturating_sub(2);

        let button_y = inner_y + inner_height.saturating_sub(1);
        if y != button_y {
            return None;
        }

        let total_len: usize = self.buttons.iter().map(|b| b.label.len() + 2).sum();
        let spacing = 2usize;
        let total_with_spacing = total_len + spacing * (self.buttons.len().saturating_sub(1));

        let start_x = inner_x + (inner_width.saturating_sub(total_with_spacing as u16)) / 2;
        let mut cur_x = start_x;

        for (i, button) in self.buttons.iter().enumerate() {
            let label_len = (button.label.len() + 2) as u16;
            if x >= cur_x && x < cur_x + label_len {
                return Some(i);
            }
            cur_x += label_len + spacing as u16;
        }

        None
    }
}
