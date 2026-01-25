use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseButton, MouseEventKind,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    prelude::{CrosstermBackend, Widget},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Terminal,
};
use tokio::sync::mpsc;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

use super::browser_view::BrowserView;
use super::discovery::{DiscoveryView, ModalAction};
use super::interfaces::{InterfaceInfo, InterfacesView};
use super::modal::{Modal, ModalButton};
use super::mynode::MyNodeView;
use super::saved::{SavedModalAction, SavedView};
use super::status_bar::StatusBar;
use super::tabs::{Tab, TabBar};

use crate::network::NodeInfo;

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    NodeAnnounce(NodeInfo),
    AnnounceSent,
    Status(String),
    PageReceived {
        url: String,
        data: Vec<u8>,
    },
    PageFailed {
        url: String,
        reason: String,
    },
    DownloadComplete {
        filename: String,
        path: String,
    },
    DownloadFailed {
        filename: String,
        reason: String,
    },
    RelayStats(rinse::StatsSnapshot),
    ResourceProgress {
        received_bytes: usize,
        total_bytes: usize,
    },
    InterfaceStatus {
        name: String,
        connected: bool,
    },
}

#[derive(Debug, Clone)]
pub enum TuiCommand {
    Announce,
    FetchPage {
        node: NodeInfo,
        path: String,
        form_data: std::collections::HashMap<String, String>,
    },
    DownloadFile {
        node: NodeInfo,
        path: String,
        filename: String,
    },
    Reconnect {
        name: String,
    },
    SaveNode {
        node: NodeInfo,
    },
    RemoveNode {
        hash: [u8; 16],
    },
    ToggleNodeIdentify {
        hash: [u8; 16],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppMode {
    Normal,
    Editing { field_name: String, masked: bool },
    EditingUrl,
    ConfirmDownload { filename: String },
}

#[derive(Debug, Clone)]
struct PendingDownload {
    node: NodeInfo,
    path: String,
    filename: String,
}

pub struct TuiApp {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    running: bool,
    tab: Tab,
    tab_bar: TabBar,
    mode: AppMode,

    discovery: DiscoveryView,
    saved: SavedView,
    mynode: MyNodeView,
    browser: BrowserView,
    interfaces: InterfacesView,
    status_bar: StatusBar,
    input: Input,
    last_edit_popup_area: Rect,
    pending_download: Option<PendingDownload>,
    last_download_popup_area: Rect,

    event_rx: mpsc::Receiver<NetworkEvent>,
    cmd_tx: mpsc::Sender<TuiCommand>,

    last_main_area: Rect,
}

fn truncate_filename(name: &str, max_len: usize) -> String {
    if name.chars().count() <= max_len {
        return name.to_string();
    }
    let truncated: String = name.chars().take(max_len.saturating_sub(3)).collect();
    format!("{}...", truncated)
}

fn parse_page_response(data: &[u8]) -> String {
    if let Ok(response) = rmp_serde::from_slice::<(f64, Vec<u8>, Option<Vec<u8>>)>(data) {
        if let Some(content) = response.2 {
            return String::from_utf8_lossy(&content).into_owned();
        }
    }
    String::from_utf8_lossy(data).into_owned()
}

impl TuiApp {
    pub fn new(
        dest_hash: [u8; 16],
        initial_nodes: Vec<NodeInfo>,
        relay_enabled: bool,
        initial_interfaces: Vec<InterfaceInfo>,
        announced_on_startup: bool,
        event_rx: mpsc::Receiver<NetworkEvent>,
        cmd_tx: mpsc::Sender<TuiCommand>,
    ) -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableMouseCapture,
            Clear(ClearType::All)
        )?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;

        let discovery = DiscoveryView::new();
        let mut saved = SavedView::new();

        for node in initial_nodes {
            saved.add_node(node);
        }

        let mut mynode = MyNodeView::new(dest_hash);
        mynode.set_relay_enabled(relay_enabled);
        if announced_on_startup {
            mynode.update_announce_time();
            mynode.increment_announces_sent();
        }

        let mut interfaces = InterfacesView::new();
        interfaces.set_interfaces(initial_interfaces);

        Ok(Self {
            terminal,
            running: true,
            tab: Tab::default(),
            tab_bar: TabBar::new(Tab::default()),
            mode: AppMode::Normal,
            discovery,
            saved,
            mynode,
            browser: BrowserView::new(),
            interfaces,
            status_bar: StatusBar::new(),
            input: Input::default(),
            last_edit_popup_area: Rect::default(),
            pending_download: None,
            last_download_popup_area: Rect::default(),
            event_rx,
            cmd_tx,
            last_main_area: Rect::default(),
        })
    }

    pub fn run(&mut self) -> io::Result<()> {
        while self.running {
            self.poll_events();
            self.status_bar.tick();
            self.draw()?;
            self.handle_input()?;
        }
        Ok(())
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::NodeAnnounce(node) => {
                    self.discovery.add_node(node.clone());
                    self.mynode.increment_announces_received();

                    if let Some(current) = self.browser.current_node() {
                        if current.hash == node.hash && current.name != node.name {
                            self.browser.set_current_node(node.clone());
                        }
                    }

                    self.saved.update_node_name(node.hash, &node.name);
                }
                NetworkEvent::AnnounceSent => {
                    self.mynode.increment_announces_sent();
                    self.mynode.update_announce_time();
                    self.status_bar.set_status("Announced".into());
                }
                NetworkEvent::Status(msg) => {
                    self.status_bar.set_status(msg);
                }
                NetworkEvent::PageReceived { url, data } => {
                    let content = parse_page_response(&data);
                    self.browser.set_page_content(&url, &content);
                    self.status_bar.clear_status();
                }
                NetworkEvent::PageFailed { url, reason } => {
                    self.browser.clear_loading();
                    self.status_bar
                        .set_status(format!("Failed to load {}: {}", url, reason));
                }
                NetworkEvent::DownloadComplete { filename, path } => {
                    self.status_bar.set_status(format!(
                        "Downloaded {} to {}",
                        truncate_filename(&filename, 20),
                        path
                    ));
                }
                NetworkEvent::DownloadFailed { filename, reason } => {
                    self.status_bar.set_status(format!(
                        "Failed to download {}: {}",
                        truncate_filename(&filename, 20),
                        reason
                    ));
                }
                NetworkEvent::RelayStats(stats) => {
                    self.mynode.set_stats(stats.clone());
                    self.status_bar.set_relay_stats(stats);
                }
                NetworkEvent::ResourceProgress {
                    received_bytes,
                    total_bytes,
                } => {
                    let pct = if total_bytes > 0 {
                        (received_bytes * 100) / total_bytes
                    } else {
                        0
                    };
                    self.status_bar.set_status(format!(
                        "Downloading... {} / {} ({}%)",
                        rinse::StatsSnapshot::format_bytes(received_bytes as u64),
                        rinse::StatsSnapshot::format_bytes(total_bytes as u64),
                        pct
                    ));
                }
                NetworkEvent::InterfaceStatus { name, connected } => {
                    self.interfaces.update_status(&name, connected);
                }
            }
        }
    }

    fn draw(&mut self) -> io::Result<()> {
        let tab = self.tab;
        let mode = self.mode.clone();
        let keybinds = self.keybinds_for_mode();
        let input_value = self.input.value().to_string();
        let input_cursor = self.input.visual_cursor();

        let mut main_area = Rect::default();
        let mut last_edit_popup_area = Rect::default();
        let mut last_download_popup_area = Rect::default();

        self.terminal.draw(|frame| {
            let area = frame.area();

            let chunks = Layout::vertical([
                Constraint::Length(2),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(area);

            let status_width = self.status_bar.required_width().max(30);
            let title_min = 15;
            let available = area.width.saturating_sub(title_min);
            let clamped_status_width = status_width.min(available);

            let header_chunks = Layout::horizontal([
                Constraint::Min(title_min),
                Constraint::Length(clamped_status_width),
            ])
            .split(chunks[0]);

            frame.render_widget(
                &mut self.tab_bar,
                Rect::new(
                    header_chunks[0].x,
                    header_chunks[0].y + 1,
                    header_chunks[0].width,
                    1,
                ),
            );

            let title = Line::from(vec![
                Span::styled(" \u{2726} ", Style::default().fg(Color::Magenta)),
                Span::styled(
                    "NOMAD",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" v0.1", Style::default().fg(Color::DarkGray)),
            ]);
            Paragraph::new(title).render(
                Rect::new(
                    header_chunks[0].x,
                    header_chunks[0].y,
                    header_chunks[0].width,
                    1,
                ),
                frame.buffer_mut(),
            );

            frame.render_widget(
                &self.status_bar,
                Rect::new(
                    header_chunks[1].x,
                    header_chunks[1].y,
                    header_chunks[1].width,
                    2,
                ),
            );

            main_area = chunks[1];

            match tab {
                Tab::Discovery => frame.render_widget(&mut self.discovery, chunks[1]),
                Tab::Saved => frame.render_widget(&mut self.saved, chunks[1]),
                Tab::Browser => frame.render_widget(&mut self.browser, chunks[1]),
                Tab::MyNode => frame.render_widget(&mut self.mynode, chunks[1]),
                Tab::Interfaces => frame.render_widget(&mut self.interfaces, chunks[1]),
            }

            if let AppMode::Editing { field_name, masked } = &mode {
                let inner_width = 50u16.saturating_sub(4);
                let scroll = input_cursor.saturating_sub(inner_width as usize);

                let display_value = if *masked {
                    "*".repeat(input_value.len())
                } else {
                    input_value.clone()
                };

                let scrolled_value: String = display_value.chars().skip(scroll).collect();

                let content = vec![
                    Line::from(Span::styled(
                        scrolled_value,
                        Style::default().fg(Color::White),
                    )),
                    Line::from(""),
                ];

                let modal = Modal::new(field_name)
                    .content(content)
                    .buttons(vec![
                        ModalButton::new("Cancel", Color::DarkGray),
                        ModalButton::new("Confirm", Color::Green),
                    ])
                    .border_color(Color::Cyan);

                let popup_area = modal.render_centered(area, frame.buffer_mut(), 50, 6);
                last_edit_popup_area = popup_area;

                let inner_x = popup_area.x + 1;
                let inner_y = popup_area.y + 1;
                let cursor_x = inner_x + (input_cursor - scroll) as u16;
                frame.set_cursor_position((cursor_x, inner_y));
            }

            if mode == AppMode::EditingUrl {
                let inner_width = 60u16.saturating_sub(4);
                let scroll = input_cursor.saturating_sub(inner_width as usize);
                let scrolled_value: String = input_value.chars().skip(scroll).collect();

                let content = vec![
                    Line::from(Span::styled(
                        scrolled_value,
                        Style::default().fg(Color::White),
                    )),
                    Line::from(""),
                ];

                let modal = Modal::new("Go to URL")
                    .content(content)
                    .buttons(vec![
                        ModalButton::new("Cancel", Color::DarkGray),
                        ModalButton::new("Go", Color::Green),
                    ])
                    .border_color(Color::Cyan);

                let popup_area = modal.render_centered(area, frame.buffer_mut(), 60, 6);
                last_edit_popup_area = popup_area;

                let inner_x = popup_area.x + 1;
                let inner_y = popup_area.y + 1;
                let cursor_x = inner_x + (input_cursor - scroll) as u16;
                frame.set_cursor_position((cursor_x, inner_y));
            }

            if let AppMode::ConfirmDownload { filename } = &mode {
                let content = vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("  File: ", Style::default().fg(Color::DarkGray)),
                        Span::styled(filename.clone(), Style::default().fg(Color::White)),
                    ]),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  Download this file?",
                        Style::default().fg(Color::DarkGray),
                    )),
                    Line::from(""),
                ];

                let modal = Modal::new("Download")
                    .content(content)
                    .buttons(vec![
                        ModalButton::new("Cancel", Color::DarkGray),
                        ModalButton::new("Download", Color::Green),
                    ])
                    .border_color(Color::Yellow);

                last_download_popup_area = modal.render_centered(area, frame.buffer_mut(), 50, 9);
            }

            let footer =
                Paragraph::new(keybinds.clone()).style(Style::default().bg(Color::Rgb(20, 20, 30)));
            frame.render_widget(footer, chunks[2]);
        })?;

        self.last_main_area = main_area;
        self.last_edit_popup_area = last_edit_popup_area;
        self.last_download_popup_area = last_download_popup_area;

        Ok(())
    }

    fn keybinds_for_mode(&self) -> Line<'static> {
        match &self.mode {
            AppMode::ConfirmDownload { .. } => Line::from(vec![
                Span::styled(" [Enter/y]", Style::default().fg(Color::Magenta)),
                Span::raw(" Download  "),
                Span::styled("[Esc/n]", Style::default().fg(Color::Magenta)),
                Span::raw(" Cancel  "),
            ]),
            AppMode::Editing { .. } | AppMode::EditingUrl => Line::from(vec![
                Span::styled(" [Enter]", Style::default().fg(Color::Magenta)),
                Span::raw(" Confirm  "),
                Span::styled("[Esc]", Style::default().fg(Color::Magenta)),
                Span::raw(" Cancel  "),
            ]),
            AppMode::Normal => match self.tab {
                Tab::Discovery => {
                    if self.discovery.is_modal_open() {
                        Line::from(vec![
                            Span::styled(" [j/k]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Switch  "),
                            Span::styled("[Enter]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Select  "),
                            Span::styled("[Esc]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Cancel  "),
                        ])
                    } else {
                        Line::from(vec![
                            Span::styled(" [j/k]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Navigate  "),
                            Span::styled("[Enter]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Open  "),
                            Span::styled("[Tab]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Switch Tab  "),
                            Span::styled("[q]", Style::default().fg(Color::Magenta)),
                            Span::raw(" Quit  "),
                        ])
                    }
                }
                Tab::Saved => Line::from(vec![
                    Span::styled(" [j/k]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Navigate  "),
                    Span::styled("[Enter]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Connect  "),
                    Span::styled("[d]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Remove  "),
                    Span::styled("[Tab]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Switch Tab  "),
                    Span::styled("[q]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Quit  "),
                ]),
                Tab::Browser => Line::from(vec![
                    Span::styled(" [j/k]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Scroll  "),
                    Span::styled("[Tab]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Next  "),
                    Span::styled("[Enter]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Activate  "),
                    Span::styled("[s]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Save  "),
                    Span::styled("[r]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Reload  "),
                    Span::styled("[q]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Quit  "),
                ]),
                Tab::MyNode => Line::from(vec![
                    Span::styled(" [a]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Announce  "),
                    Span::styled("[Tab]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Switch Tab  "),
                    Span::styled("[q]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Quit  "),
                ]),
                Tab::Interfaces => Line::from(vec![
                    Span::styled(" [j/k]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Navigate  "),
                    Span::styled("[r]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Reconnect  "),
                    Span::styled("[Tab]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Switch Tab  "),
                    Span::styled("[q]", Style::default().fg(Color::Magenta)),
                    Span::raw(" Quit  "),
                ]),
            },
        }
    }

    fn handle_input(&mut self) -> io::Result<()> {
        if !event::poll(Duration::from_millis(50))? {
            return Ok(());
        }

        while event::poll(Duration::ZERO)? {
            let evt = event::read()?;

            if let Event::Key(key) = &evt {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

                if key.code == KeyCode::Char('c') && ctrl {
                    self.running = false;
                    return Ok(());
                }

                match &self.mode {
                    AppMode::Editing { .. } => self.handle_editing_key(&evt),
                    AppMode::EditingUrl => self.handle_url_editing_key(&evt),
                    AppMode::ConfirmDownload { .. } => self.handle_download_key(key.code),
                    AppMode::Normal => self.handle_normal_key(key.code, ctrl),
                }
            } else if let Event::Mouse(mouse) = &evt {
                self.handle_mouse(mouse.kind, mouse.column, mouse.row);
            }
        }

        Ok(())
    }

    fn handle_normal_key(&mut self, code: KeyCode, _ctrl: bool) {
        if self.discovery.is_modal_open() {
            match code {
                KeyCode::Esc => self.discovery.close_modal(),
                KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => self.discovery.select_next(),
                KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => self.discovery.select_prev(),
                KeyCode::Enter => {
                    let action = self.discovery.modal_action();
                    self.handle_modal_action(action);
                }
                _ => {}
            }
            return;
        }

        if self.tab == Tab::Browser {
            match code {
                KeyCode::Char('q') => self.running = false,
                KeyCode::Down | KeyCode::Char('j') => self.browser.scroll_down(),
                KeyCode::Up | KeyCode::Char('k') => self.browser.scroll_up(),
                KeyCode::PageDown => self.browser.scroll_page_down(),
                KeyCode::PageUp => self.browser.scroll_page_up(),
                KeyCode::Tab => self.browser.select_next(),
                KeyCode::BackTab => self.browser.select_prev(),
                KeyCode::Left => self.browser.select_prev(),
                KeyCode::Right => self.browser.select_next(),
                KeyCode::Enter => {
                    if let Some(interaction) = self.browser.interact() {
                        self.handle_interaction(interaction);
                    }
                }
                KeyCode::Backspace => {
                    self.browser.go_back();
                }
                KeyCode::Char('r') => {
                    self.reload_page();
                }
                KeyCode::F(12) => {
                    self.debug_save_page();
                }
                _ => {}
            }
            return;
        }

        match code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Tab => {
                self.tab = self.tab.next();
                self.tab_bar = TabBar::new(self.tab);
            }
            KeyCode::BackTab => {
                self.tab = self.tab.prev();
                self.tab_bar = TabBar::new(self.tab);
            }
            KeyCode::Down | KeyCode::Char('j') => self.handle_down(),
            KeyCode::Up | KeyCode::Char('k') => self.handle_up(),
            KeyCode::Enter => self.handle_enter(),
            KeyCode::Char('a') => self.handle_announce(),
            KeyCode::Char('d') => self.handle_delete(),
            KeyCode::Char('r') if self.tab == Tab::Interfaces => self.handle_reconnect(),
            KeyCode::Char('s') if self.tab == Tab::Browser => self.save_current_browser_node(),
            _ => {}
        }
    }

    fn handle_editing_key(&mut self, evt: &Event) {
        if let Event::Key(key) = evt {
            match key.code {
                KeyCode::Enter => {
                    self.confirm_edit();
                }
                KeyCode::Esc => {
                    self.cancel_edit();
                }
                _ => {
                    self.input.handle_event(evt);
                }
            }
        }
    }

    fn confirm_edit(&mut self) {
        if let AppMode::Editing { field_name, .. } = &self.mode {
            let value = self.input.value().to_string();
            let name = field_name.clone();
            self.browser.set_field_value(&name, value);
        }
        self.input.reset();
        self.mode = AppMode::Normal;
    }

    fn cancel_edit(&mut self) {
        self.input.reset();
        self.mode = AppMode::Normal;
    }

    fn handle_url_editing_key(&mut self, evt: &Event) {
        if let Event::Key(key) = evt {
            match key.code {
                KeyCode::Enter => self.confirm_url_edit(),
                KeyCode::Esc => self.cancel_url_edit(),
                _ => {
                    self.input.handle_event(evt);
                }
            }
        }
    }

    fn confirm_url_edit(&mut self) {
        let url = self.input.value().to_string();
        self.input.reset();
        self.mode = AppMode::Normal;
        if !url.is_empty() {
            self.navigate_to_url(&url);
        }
    }

    fn cancel_url_edit(&mut self) {
        self.input.reset();
        self.mode = AppMode::Normal;
    }

    fn navigate_to_url(&mut self, url: &str) {
        let link = micronaut::Link {
            url: url.to_string(),
            fields: vec![],
            form_data: std::collections::HashMap::new(),
        };
        self.navigate_to_link(link);
    }

    fn handle_edit_modal_click(&mut self, x: u16, y: u16) {
        let modal = Modal::new("")
            .buttons(vec![
                ModalButton::new("Cancel", Color::DarkGray),
                ModalButton::new("Confirm", Color::Green),
            ])
            .selected(1);

        if let Some(idx) = modal.hit_test_buttons(x, y, self.last_edit_popup_area) {
            match idx {
                0 => self.cancel_edit(),
                1 => self.confirm_edit(),
                _ => {}
            }
        }
    }

    fn handle_url_modal_click(&mut self, x: u16, y: u16) {
        let modal = Modal::new("").buttons(vec![
            ModalButton::new("Cancel", Color::DarkGray),
            ModalButton::new("Go", Color::Green),
        ]);

        if let Some(idx) = modal.hit_test_buttons(x, y, self.last_edit_popup_area) {
            match idx {
                0 => self.cancel_url_edit(),
                1 => self.confirm_url_edit(),
                _ => {}
            }
        }
    }

    fn handle_download_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.confirm_download();
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                self.cancel_download();
            }
            _ => {}
        }
    }

    fn handle_download_modal_click(&mut self, x: u16, y: u16) {
        let area = self.last_download_popup_area;

        if !area.contains((x, y).into()) {
            self.cancel_download();
            return;
        }

        let modal = Modal::new("")
            .buttons(vec![
                ModalButton::new("Cancel", Color::DarkGray),
                ModalButton::new("Download", Color::Green),
            ])
            .selected(1);

        if let Some(idx) = modal.hit_test_buttons(x, y, area) {
            match idx {
                0 => self.cancel_download(),
                1 => self.confirm_download(),
                _ => {}
            }
        }
    }

    fn confirm_download(&mut self) {
        if let Some(download) = self.pending_download.take() {
            self.status_bar.set_status(format!(
                "Downloading {}...",
                truncate_filename(&download.filename, 20)
            ));
            let _ = self.cmd_tx.blocking_send(TuiCommand::DownloadFile {
                node: download.node,
                path: download.path,
                filename: download.filename,
            });
        }
        self.mode = AppMode::Normal;
    }

    fn cancel_download(&mut self) {
        self.pending_download = None;
        self.mode = AppMode::Normal;
    }

    fn handle_interaction(&mut self, interaction: micronaut::Interaction) {
        match interaction {
            micronaut::Interaction::Link(link) => {
                self.navigate_to_link(link);
            }
            micronaut::Interaction::EditField(field) => {
                self.input = Input::new(field.value);
                self.mode = AppMode::Editing {
                    field_name: field.name,
                    masked: field.masked,
                };
            }
        }
    }

    fn reload_page(&mut self) {
        if let Some(node) = self.browser.current_node().cloned() {
            if let Some(url) = self.browser.current_url() {
                let path = if let Some(idx) = url.find(':') {
                    url[idx + 1..].to_string()
                } else {
                    url.to_string()
                };
                self.browser.set_loading(path.clone());
                let _ = self.cmd_tx.blocking_send(TuiCommand::FetchPage {
                    node,
                    path,
                    form_data: std::collections::HashMap::new(),
                });
            }
        }
    }

    fn save_current_browser_node(&mut self) {
        if let Some(node) = self.browser.current_node().cloned() {
            let already_saved = self.saved.nodes().iter().any(|n| n.hash == node.hash);
            if !already_saved {
                self.saved.add_node(node.clone());
                let _ = self
                    .cmd_tx
                    .blocking_send(TuiCommand::SaveNode { node: node.clone() });
                self.status_bar.set_status(format!("Saved {}", node.name));
            } else {
                self.status_bar
                    .set_status(format!("{} already saved", node.name));
            }
            self.saved.select_by_hash(node.hash);
        } else {
            self.status_bar.set_status("No node to save".into());
        }
    }

    fn toggle_browser_node_identify(&mut self) {
        if let Some(node) = self.browser.current_node().cloned() {
            let hash = node.hash;
            let currently_enabled = self
                .saved
                .nodes()
                .iter()
                .find(|n| n.hash == hash)
                .map(|n| n.identify)
                .unwrap_or(false);

            if !self.saved.nodes().iter().any(|n| n.hash == hash) {
                self.saved.add_node(node.clone());
                let _ = self
                    .cmd_tx
                    .blocking_send(TuiCommand::SaveNode { node: node.clone() });
            }

            for n in self.saved.nodes().iter() {
                if n.hash == hash {
                    let _ = self
                        .cmd_tx
                        .blocking_send(TuiCommand::ToggleNodeIdentify { hash });
                    break;
                }
            }

            // Update local state
            let new_state = !currently_enabled;
            self.saved.set_identify(hash, new_state);
            self.browser.set_identify_enabled(new_state);

            if new_state {
                self.status_bar.set_status("Self-identify enabled".into());
            } else {
                self.status_bar.set_status("Self-identify disabled".into());
            }
        } else {
            self.status_bar.set_status("No node selected".into());
        }
    }

    fn handle_mouse(&mut self, kind: MouseEventKind, x: u16, y: u16) {
        match kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if y == 1 {
                    if let Some(tab) = self.tab_bar.hit_test(x) {
                        self.tab = tab;
                        self.tab_bar = TabBar::new(tab);
                        self.mode = AppMode::Normal;
                        return;
                    }
                }

                match &self.mode {
                    AppMode::Editing { .. } => {
                        self.handle_edit_modal_click(x, y);
                    }
                    AppMode::EditingUrl => {
                        self.handle_url_modal_click(x, y);
                    }
                    AppMode::ConfirmDownload { .. } => {
                        self.handle_download_modal_click(x, y);
                    }
                    AppMode::Normal => {
                        if self.discovery.is_modal_open() {
                            let modal_action =
                                self.discovery.click_modal(x, y, self.last_main_area);
                            if modal_action != ModalAction::None {
                                self.handle_modal_action(modal_action);
                            }
                            return;
                        }

                        match self.tab {
                            Tab::Discovery => {
                                if self.discovery.click(x, y, self.last_main_area).is_some() {
                                    self.discovery.open_modal();
                                }
                            }
                            Tab::Saved => {
                                self.saved.click(x, y, self.last_main_area);
                                let action = self.saved.click_detail(x, y);
                                self.handle_saved_modal_action(action);
                            }
                            Tab::Browser => {
                                use super::browser_view::NavAction;
                                if let Some(nav) = self.browser.click_nav(x, y) {
                                    match nav {
                                        NavAction::Back => {
                                            self.browser.go_back();
                                        }
                                        NavAction::Forward => {
                                            self.browser.go_forward();
                                        }
                                        NavAction::Reload => {
                                            self.reload_page();
                                        }
                                        NavAction::ToggleIdentify => {
                                            self.toggle_browser_node_identify();
                                        }
                                        NavAction::Save => {
                                            self.save_current_browser_node();
                                        }
                                    }
                                } else if self.browser.click_url_bar(x, y) {
                                    let current =
                                        self.browser.current_url().unwrap_or("").to_string();
                                    self.input = Input::new(current);
                                    self.mode = AppMode::EditingUrl;
                                } else if let Some(interaction) = self.browser.click(x, y) {
                                    self.handle_interaction(interaction);
                                }
                            }
                            Tab::MyNode => {
                                if self.mynode.click(x, y) {
                                    self.send_announce();
                                }
                            }
                            Tab::Interfaces => {
                                if let Some(name) = self.interfaces.click_reconnect(x, y) {
                                    self.status_bar
                                        .set_status(format!("Reconnecting to {}...", name));
                                    let _ =
                                        self.cmd_tx.blocking_send(TuiCommand::Reconnect { name });
                                }
                            }
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => match &self.mode {
                AppMode::Normal if self.tab == Tab::Browser => self.browser.scroll_up(),
                AppMode::Normal => self.handle_up(),
                AppMode::Editing { .. } | AppMode::EditingUrl | AppMode::ConfirmDownload { .. } => {
                }
            },
            MouseEventKind::ScrollDown => match &self.mode {
                AppMode::Normal if self.tab == Tab::Browser => self.browser.scroll_down(),
                AppMode::Normal => self.handle_down(),
                AppMode::Editing { .. } | AppMode::EditingUrl | AppMode::ConfirmDownload { .. } => {
                }
            },
            _ => {}
        }
    }

    fn handle_down(&mut self) {
        match self.tab {
            Tab::Discovery => self.discovery.scroll_down(),
            Tab::Saved => self.saved.scroll_down(),
            Tab::Interfaces => self.interfaces.scroll_down(),
            Tab::Browser | Tab::MyNode => {}
        }
    }

    fn handle_up(&mut self) {
        match self.tab {
            Tab::Discovery => self.discovery.scroll_up(),
            Tab::Saved => self.saved.scroll_up(),
            Tab::Interfaces => self.interfaces.scroll_up(),
            Tab::Browser | Tab::MyNode => {}
        }
    }

    fn handle_enter(&mut self) {
        match self.tab {
            Tab::Discovery => {
                self.discovery.open_modal();
            }
            Tab::Saved => {
                if let Some(node) = self.saved.selected_node().cloned() {
                    self.connect_to_node(&node);
                }
            }
            Tab::Browser => {}
            Tab::MyNode => {
                self.send_announce();
            }
            Tab::Interfaces => {
                self.handle_reconnect();
            }
        }
    }

    fn handle_modal_action(&mut self, action: ModalAction) {
        match action {
            ModalAction::Connect => {
                if let Some(node) = self.discovery.selected_node().cloned() {
                    self.discovery.close_modal();
                    self.connect_to_node(&node);
                }
            }
            ModalAction::Save => {
                if let Some(node) = self.discovery.selected_node().cloned() {
                    self.saved.add_node(node.clone());
                    let _ = self.cmd_tx.blocking_send(TuiCommand::SaveNode { node });
                    self.discovery.close_modal();
                    self.status_bar.set_status("Node saved".into());
                }
            }
            ModalAction::Copy => {
                if let Some(node) = self.discovery.selected_node() {
                    self.copy_to_clipboard(&node.hash_hex());
                }
            }
            ModalAction::Dismiss => {
                self.discovery.close_modal();
            }
            ModalAction::None => {}
        }
    }

    fn handle_saved_modal_action(&mut self, action: SavedModalAction) {
        match action {
            SavedModalAction::Connect => {
                if let Some(node) = self.saved.selected_node().cloned() {
                    self.connect_to_node(&node);
                }
            }
            SavedModalAction::Delete => {
                if let Some(removed) = self.saved.remove_selected() {
                    let _ = self
                        .cmd_tx
                        .blocking_send(TuiCommand::RemoveNode { hash: removed.hash });
                    self.status_bar
                        .set_status(format!("Removed {}", removed.name));
                }
            }
            SavedModalAction::Copy => {
                if let Some(node) = self.saved.selected_node() {
                    self.copy_to_clipboard(&node.hash_hex());
                }
            }
            SavedModalAction::ToggleIdentify => {
                if let Some(node) = self.saved.toggle_identify_selected() {
                    let hash = node.hash;
                    let enabled = node.identify;
                    let _ = self
                        .cmd_tx
                        .blocking_send(TuiCommand::ToggleNodeIdentify { hash });
                    if enabled {
                        self.status_bar
                            .set_status("Self-identify enabled for this node".to_string());
                    } else {
                        self.status_bar
                            .set_status("Self-identify disabled for this node".to_string());
                    }
                }
            }
            SavedModalAction::None => {}
        }
    }

    fn connect_to_node(&mut self, node: &NodeInfo) {
        let path = "/page/index.mu".to_string();
        self.browser.set_current_node(node.clone());

        let identify_enabled = self
            .saved
            .nodes()
            .iter()
            .find(|n| n.hash == node.hash)
            .map(|n| n.identify)
            .unwrap_or(false);
        self.browser.set_identify_enabled(identify_enabled);

        self.browser.set_loading(path.clone());
        self.tab = Tab::Browser;
        self.tab_bar = TabBar::new(Tab::Browser);

        let _ = self.cmd_tx.blocking_send(TuiCommand::FetchPage {
            node: node.clone(),
            path,
            form_data: std::collections::HashMap::new(),
        });

        self.status_bar
            .set_status(format!("Connecting to {}...", node.name));
    }

    fn navigate_to_link(&mut self, link: micronaut::Link) {
        let all_nodes: Vec<NodeInfo> = self
            .discovery
            .nodes()
            .iter()
            .chain(self.saved.nodes().iter())
            .cloned()
            .collect();

        use super::link_handler::LinkAction;
        match self.browser.resolve_link(&link, &all_nodes) {
            LinkAction::Navigate { node, path } => {
                self.browser.set_current_node(node.clone());

                let identify_enabled = self
                    .saved
                    .nodes()
                    .iter()
                    .find(|n| n.hash == node.hash)
                    .map(|n| n.identify)
                    .unwrap_or(false);
                self.browser.set_identify_enabled(identify_enabled);

                self.browser.set_loading(path.clone());
                let _ = self.cmd_tx.blocking_send(TuiCommand::FetchPage {
                    node,
                    path,
                    form_data: link.form_data,
                });
            }
            LinkAction::Download {
                node,
                path,
                filename,
            } => {
                self.pending_download = Some(PendingDownload {
                    node,
                    path,
                    filename: filename.clone(),
                });
                self.mode = AppMode::ConfirmDownload { filename };
            }
            LinkAction::Lxmf { hash } => {
                self.status_bar.set_status(format!(
                    "LXMF links not yet supported: {}",
                    hex::encode(hash)
                ));
            }
            LinkAction::Unknown { url } => {
                self.status_bar
                    .set_status(format!("Unknown link type: {}", url));
            }
        }
    }

    fn handle_announce(&mut self) {
        if self.tab == Tab::MyNode {
            self.send_announce();
        }
    }

    fn send_announce(&mut self) {
        self.status_bar.set_status("Sending announce...".into());
        let _ = self.cmd_tx.blocking_send(TuiCommand::Announce);
    }

    fn handle_delete(&mut self) {
        if self.tab == Tab::Saved {
            self.handle_saved_modal_action(SavedModalAction::Delete);
        }
    }

    fn handle_reconnect(&mut self) {
        if let Some(name) = self.interfaces.try_reconnect_selected() {
            self.status_bar
                .set_status(format!("Reconnecting to {}...", name));
            let _ = self.cmd_tx.blocking_send(TuiCommand::Reconnect { name });
        }
    }

    fn copy_to_clipboard(&mut self, text: &str) {
        match cli_clipboard::set_contents(text.to_owned()) {
            Ok(()) => {
                self.status_bar.set_status("Copied to clipboard".into());
            }
            Err(e) => {
                self.status_bar.set_status(format!("Failed to copy: {}", e));
            }
        }
    }

    fn debug_save_page(&mut self) {
        let Some(content) = self.browser.browser.content.as_ref() else {
            self.status_bar.set_status("No page content to save".into());
            return;
        };

        let filename = if let Some(url) = self.browser.browser.url.as_ref() {
            let safe_name: String = url
                .chars()
                .map(|c: char| {
                    if c.is_alphanumeric() || c == '.' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            if safe_name.ends_with(".mu") {
                safe_name
            } else {
                format!("{}.mu", safe_name)
            }
        } else {
            "debug_page.mu".to_string()
        };

        let path = std::path::Path::new(".rinse").join(&filename);
        match std::fs::write(&path, content) {
            Ok(()) => {
                self.status_bar
                    .set_status(format!("Saved to {}", path.display()));
            }
            Err(e) => {
                self.status_bar.set_status(format!("Failed to save: {}", e));
            }
        }
    }
}

impl Drop for TuiApp {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            DisableMouseCapture,
            LeaveAlternateScreen
        );
    }
}
