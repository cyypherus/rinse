use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::identity::PrivateIdentity;

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    InvalidIdentity,
    InvalidRatchetSecrets,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "io error: {}", e),
            ConfigError::Parse(e) => write!(f, "parse error: {}", e),
            ConfigError::InvalidIdentity => write!(f, "invalid identity data"),
            ConfigError::InvalidRatchetSecrets => write!(f, "invalid ratchet secret data"),
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
    PathBuf::from(".rinse")
}

const DEFAULT_CONFIG: &str = r#"#

name = "Anonymous Peer"

# [network]
# relay = false # Enable message forwarding

# Data can travel both ways on any interface.
# If you'd like to connect via outbound connections, you can configure a client interface.

# [interfaces."Test Network Example"]
# type = "TCPClientInterface"
# enabled = true
# target_host = "test.network.example"
# target_port = 4242

# If you'd like to accept inbound connections on a port, you can configure a server interface.

# [interfaces.server]
# type = "TCPServerInterface"
# enabled = true
# listen_ip = "0.0.0.0"
# listen_port = 4242


# Various resources curate tcp/ip relays you can use to connect to the network.
# https://unsigned.io/rnode_bootstrap_console/r/connect.html
# https://directory.rns.recipes/

# An entry like this must be converted to TOML as seen above
# [[Test Network Example]]
#   type = TCPClientInterface
#   enabled = yes
#   target_host = test.network.example
#   target_port = 4242
"#;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub name: Option<String>,
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
        enabled: bool,
        target_host: String,
        target_port: u16,
    },
    TCPServerInterface {
        enabled: bool,
        listen_ip: String,
        listen_port: u16,
    },
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
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&config_path, DEFAULT_CONFIG)?;
            Ok(Config::default())
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

pub fn load_or_create_persistent_identity() -> Result<PrivateIdentity, ConfigError> {
    let path = data_dir().join("identity");

    if path.exists() {
        let hex_str = fs::read_to_string(&path)?;
        let bytes = hex::decode(hex_str.trim()).map_err(|_| ConfigError::InvalidIdentity)?;
        PrivateIdentity::from_secret_bytes(&bytes).ok_or(ConfigError::InvalidIdentity)
    } else {
        let identity = PrivateIdentity::generate(&mut rand::thread_rng());
        save_private_identity(&identity)?;
        Ok(identity)
    }
}

pub fn save_private_identity(identity: &PrivateIdentity) -> Result<(), ConfigError> {
    let path = data_dir().join("identity");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let hex_str = hex::encode(identity.to_secret_bytes());
    fs::write(path, hex_str)?;
    Ok(())
}

pub fn ratchet_secrets_path(service_address: &[u8; 16]) -> PathBuf {
    data_dir()
        .join("ratchets")
        .join(hex::encode(service_address))
}

pub fn load_ratchet_secrets(service_address: &[u8; 16]) -> Result<Vec<[u8; 32]>, ConfigError> {
    let path = ratchet_secrets_path(service_address);

    if path.exists() {
        let contents = fs::read_to_string(&path)?;
        let mut ratchets = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bytes = hex::decode(line).map_err(|_| ConfigError::InvalidRatchetSecrets)?;
            if bytes.len() != 32 {
                return Err(ConfigError::InvalidRatchetSecrets);
            }
            ratchets.push(bytes.try_into().unwrap());
        }
        Ok(ratchets)
    } else {
        Ok(Vec::new())
    }
}

pub fn save_ratchet_secrets(
    service_address: &[u8; 16],
    ratchet_secrets: &[[u8; 32]],
) -> Result<(), ConfigError> {
    let path = ratchet_secrets_path(service_address);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let contents: String = ratchet_secrets
        .iter()
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, contents)?;
    Ok(())
}
