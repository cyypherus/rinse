use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::PageState;
use rinse::Address;

const INDEX_TEMPLATE: &str = include_str!("templates/index.mu");
const GUESTBOOK_TEMPLATE: &str = include_str!("templates/guestbook.mu");
const ABOUT_TEMPLATE: &str = include_str!("templates/about.mu");
const NOT_FOUND_TEMPLATE: &str = include_str!("templates/404.mu");

fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }
    result
}

pub fn index(
    state: &Arc<Mutex<PageState>>,
    name: &str,
    form_data: &HashMap<String, String>,
    remote_identity: Option<Address>,
) -> String {
    let mut state = state.lock().unwrap();

    if let Some(username) = form_data.get("field_username") {
        if let Some(id) = remote_identity {
            state.set_username(id, username.clone());
        }
    }

    let username = form_data
        .get("field_username")
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.as_str())
        .or_else(|| state.get_username(remote_identity))
        .unwrap_or("Anonymous");

    render(INDEX_TEMPLATE, &[("name", name), ("username", username)])
}

pub fn guestbook(
    state: &Arc<Mutex<PageState>>,
    form_data: &HashMap<String, String>,
    remote_identity: Option<Address>,
) -> String {
    let mut state = state.lock().unwrap();

    if let Some(msg) = form_data.get("field_message") {
        if !msg.trim().is_empty() {
            let author = form_data
                .get("field_author")
                .cloned()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| state.get_username(remote_identity).map(|s| s.to_string()))
                .unwrap_or_else(|| {
                    remote_identity
                        .map(|id| format!("<{}>", &hex::encode(id)[..8]))
                        .unwrap_or_else(|| "Anonymous".to_string())
                });

            if let Some(id) = remote_identity {
                if let Some(name) = form_data
                    .get("field_author")
                    .filter(|s| !s.trim().is_empty())
                {
                    state.set_username(id, name.clone());
                }
            }

            state.messages.push((author, msg.clone()));
            if state.messages.len() > 20 {
                state.messages.remove(0);
            }
        }
    }

    let messages_display = if state.messages.is_empty() {
        "  `F555No messages yet. Be the first to sign!``".to_string()
    } else {
        state
            .messages
            .iter()
            .rev()
            .take(10)
            .map(|(author, msg)| format!("  `B0af{}`` wrote:\n    {}", author, msg))
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    render(GUESTBOOK_TEMPLATE, &[("messages", &messages_display)])
}

pub fn about(name: &str) -> String {
    render(ABOUT_TEMPLATE, &[("name", name)])
}

pub fn not_found(path: &str) -> String {
    render(NOT_FOUND_TEMPLATE, &[("path", path)])
}
