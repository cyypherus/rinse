use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] toml::de::Error),
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
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)?;
            Ok(toml::from_str(&contents)?)
        } else {
            let config = Config::default_with_example_interface();
            config.save()?;
            Ok(config)
        }
    }

    fn default_with_example_interface() -> Self {
        let mut interfaces = HashMap::new();
        interfaces.insert(
            "Default TCP".to_string(),
            InterfaceConfig::TCPClientInterface {
                enabled: true,
                target_host: "amsterdam.connect.reticulum.network".to_string(),
                target_port: 4965,
            },
        );
        Self {
            network: NetworkConfig::default(),
            interfaces,
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
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let contents = toml::to_string_pretty(self).unwrap();
        fs::write(&config_path, contents)?;
        Ok(())
    }

    pub fn data_dir() -> Result<PathBuf, ConfigError> {
        Ok(PathBuf::from(".rinse"))
    }

    fn config_path() -> Result<PathBuf, ConfigError> {
        Ok(Self::data_dir()?.join("config.toml"))
    }
}
