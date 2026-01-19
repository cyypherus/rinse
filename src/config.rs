use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::identity::Identity;

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    InvalidIdentity,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "io error: {}", e),
            ConfigError::Parse(e) => write!(f, "parse error: {}", e),
            ConfigError::InvalidIdentity => write!(f, "invalid identity data"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        ConfigError::Parse(e)
    }
}

pub fn data_dir() -> PathBuf {
    PathBuf::from(".nomad")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub relay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InterfaceConfig {
    TCPClientInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        target_host: String,
        target_port: u16,
    },
    TCPServerInterface {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default = "default_listen_ip")]
        listen_ip: String,
        listen_port: u16,
    },
}

fn default_listen_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_true() -> bool {
    true
}

impl InterfaceConfig {
    pub fn is_enabled(&self) -> bool {
        match self {
            InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
            InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = Self::config_path();

        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)?;
            Ok(toml::from_str(&contents)?)
        } else {
            let config = Config::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn enabled_interfaces(&self) -> Vec<(&str, &InterfaceConfig)> {
        self.interfaces
            .iter()
            .filter(|(_, iface)| iface.is_enabled())
            .map(|(name, iface)| (name.as_str(), iface))
            .collect()
    }

    pub fn save(&self) -> Result<(), ConfigError> {
        let config_path = Self::config_path();

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let contents = toml::to_string_pretty(self).unwrap();
        fs::write(&config_path, contents)?;
        Ok(())
    }

    fn config_path() -> PathBuf {
        data_dir().join("config.toml")
    }
}

pub fn load_or_generate_identity() -> Result<Identity, ConfigError> {
    let path = data_dir().join("identity");

    if path.exists() {
        let hex_str = fs::read_to_string(&path)?;
        let bytes = hex::decode(hex_str.trim()).map_err(|_| ConfigError::InvalidIdentity)?;
        Identity::from_bytes(&bytes).ok_or(ConfigError::InvalidIdentity)
    } else {
        let identity = Identity::generate(&mut rand::thread_rng());
        save_identity(&identity)?;
        Ok(identity)
    }
}

pub fn save_identity(identity: &Identity) -> Result<(), ConfigError> {
    let path = data_dir().join("identity");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let hex_str = hex::encode(identity.to_bytes());
    fs::write(path, hex_str)?;
    Ok(())
}
