use crate::network::types::NodeInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default, Serialize, Deserialize)]
struct NodesFile {
    nodes: Vec<NodeInfo>,
}

pub struct NodeRegistry {
    path: PathBuf,
    nodes: HashMap<[u8; 16], NodeInfo>,
}

impl NodeRegistry {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        let nodes = Self::load_from_path(&path);
        Self { path, nodes }
    }

    fn load_from_path(path: &Path) -> HashMap<[u8; 16], NodeInfo> {
        let contents = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };

        let file: NodesFile = match toml::from_str(&contents) {
            Ok(f) => f,
            Err(_) => return HashMap::new(),
        };

        file.nodes.into_iter().map(|n| (n.hash, n)).collect()
    }

    pub fn save(&mut self, node: NodeInfo) {
        self.nodes.insert(node.hash, node);
        self.persist();
    }

    pub fn all(&self) -> Vec<&NodeInfo> {
        self.nodes.values().collect()
    }

    pub fn toggle_identify(&mut self, hash: &[u8; 16]) -> Option<bool> {
        let new_value = if let Some(node) = self.nodes.get_mut(hash) {
            node.identify = !node.identify;
            Some(node.identify)
        } else {
            None
        };
        if new_value.is_some() {
            self.persist();
        }
        new_value
    }

    pub fn remove(&mut self, hash: &[u8; 16]) -> Option<NodeInfo> {
        let removed = self.nodes.remove(hash);
        if removed.is_some() {
            self.persist();
        }
        removed
    }

    fn persist(&self) {
        let file = NodesFile {
            nodes: self.nodes.values().cloned().collect(),
        };

        if let Ok(contents) = toml::to_string_pretty(&file) {
            let _ = fs::write(&self.path, contents);
        }
    }
}
