use crate::network::NodeInfo;

const MICRON_EXTENSIONS: &[&str] = &["", "mu", "md", "micron"];

#[derive(Debug, Clone)]
pub enum LinkAction {
    Navigate {
        node: NodeInfo,
        path: String,
    },
    Download {
        node: NodeInfo,
        path: String,
        filename: String,
    },
    Lxmf {
        hash: [u8; 16],
    },
    Unknown {
        url: String,
    },
}

pub fn resolve_link(
    link_url: &str,
    current_node: Option<&NodeInfo>,
    known_nodes: &[NodeInfo],
) -> LinkAction {
    if let Some(hash) = parse_lxmf_link(link_url) {
        return LinkAction::Lxmf { hash };
    }

    if let Some((node, path)) = resolve_node_link(link_url, current_node, known_nodes) {
        if is_download_path(&path) {
            let filename = extract_filename(&path);
            return LinkAction::Download {
                node,
                path,
                filename,
            };
        }
        return LinkAction::Navigate { node, path };
    }

    LinkAction::Unknown {
        url: link_url.to_string(),
    }
}

fn parse_lxmf_link(url: &str) -> Option<[u8; 16]> {
    let rest = url.strip_prefix("lxmf@")?;

    if rest.len() != 32 {
        return None;
    }

    let hash_bytes = hex::decode(rest).ok()?;
    if hash_bytes.len() != 16 {
        return None;
    }

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&hash_bytes);
    Some(hash)
}

fn resolve_node_link(
    link_url: &str,
    current_node: Option<&NodeInfo>,
    known_nodes: &[NodeInfo],
) -> Option<(NodeInfo, String)> {
    if let Some(rest) = link_url.strip_prefix(':') {
        let node = current_node?.clone();
        let path = if rest.is_empty() {
            "/page/index.mu".to_string()
        } else {
            normalize_path(rest)
        };
        return Some((node, path));
    }

    if let Some((hash_hex, path_part)) = parse_hash_link(link_url) {
        if let Ok(hash_bytes) = hex::decode(hash_hex) {
            if hash_bytes.len() == 16 {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&hash_bytes);

                let node = known_nodes
                    .iter()
                    .find(|n| n.hash == hash)
                    .cloned()
                    .or_else(|| current_node.filter(|n| n.hash == hash).cloned())
                    .unwrap_or_else(|| NodeInfo {
                        name: format!("<{}>", &hash_hex[..8]),
                        hash,
                        identify: false,
                    });

                let path = if path_part.is_empty() {
                    "/page/index.mu".to_string()
                } else {
                    normalize_path(path_part)
                };
                return Some((node, path));
            }
        }
    }

    let node = current_node?.clone();
    let path = normalize_path(link_url);
    Some((node, path))
}

fn parse_hash_link(url: &str) -> Option<(&str, &str)> {
    if url.len() == 32 && url.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some((url, ""));
    }
    if url.contains(':') {
        let parts: Vec<&str> = url.splitn(2, ':').collect();
        if parts.len() == 2 && parts[0].len() == 32 {
            return Some((parts[0], parts[1]));
        }
    }
    None
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

fn is_download_path(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or("");
    if !filename.contains('.') {
        return false;
    }

    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    !MICRON_EXTENSIONS.contains(&ext.as_str())
}

fn extract_filename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or("download").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(name: &str, hash: [u8; 16]) -> NodeInfo {
        NodeInfo {
            name: name.to_string(),
            hash,
            identify: false,
        }
    }

    #[test]
    fn test_lxmf_link() {
        let url = "lxmf@0123456789abcdef0123456789abcdef";
        let action = resolve_link(url, None, &[]);
        assert!(matches!(action, LinkAction::Lxmf { .. }));
    }

    #[test]
    fn test_relative_path() {
        let node = make_node("test", [1; 16]);
        let action = resolve_link("/page", Some(&node), &[]);
        assert!(matches!(action, LinkAction::Navigate { path, .. } if path == "/page"));
    }

    #[test]
    fn test_download_detection() {
        let node = make_node("test", [1; 16]);

        let action = resolve_link("/file.pdf", Some(&node), &[]);
        assert!(matches!(action, LinkAction::Download { filename, .. } if filename == "file.pdf"));

        let action = resolve_link("/page.mu", Some(&node), &[]);
        assert!(matches!(action, LinkAction::Navigate { .. }));

        let action = resolve_link("/page", Some(&node), &[]);
        assert!(matches!(action, LinkAction::Navigate { .. }));
    }

    #[test]
    fn test_colon_prefix() {
        let node = make_node("test", [1; 16]);
        let action = resolve_link(":/other", Some(&node), &[]);
        assert!(matches!(action, LinkAction::Navigate { path, .. } if path == "/other"));
    }

    #[test]
    fn test_hash_colon_goes_to_index() {
        let hash = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let node = make_node("remote", hash);
        let action = resolve_link("0123456789abcdef0123456789abcdef:", None, &[node]);
        assert!(matches!(action, LinkAction::Navigate { path, .. } if path == "/page/index.mu"));
    }

    #[test]
    fn test_unknown_hash_creates_node() {
        let action = resolve_link("abcdef0123456789abcdef0123456789:/page/test", None, &[]);
        match action {
            LinkAction::Navigate { node, path } => {
                assert_eq!(path, "/page/test");
                assert_eq!(hex::encode(node.hash), "abcdef0123456789abcdef0123456789");
            }
            _ => panic!("Expected Navigate"),
        }
    }
}
