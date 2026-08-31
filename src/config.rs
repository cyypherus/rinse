use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::{Destination, RatchetSecret, identity::PrivateIdentity};

#[derive(Debug)]
pub struct ConfigError(ConfigErrorKind);

#[derive(Debug)]
enum ConfigErrorKind {
    Io(std::io::Error),
    InvalidToml(toml::de::Error),
    InvalidIdentity,
    InvalidRatchetSecrets,
}

impl ConfigError {
    fn io(error: std::io::Error) -> Self {
        Self(ConfigErrorKind::Io(error))
    }

    fn invalid_identity() -> Self {
        Self(ConfigErrorKind::InvalidIdentity)
    }

    fn invalid_ratchet_secrets() -> Self {
        Self(ConfigErrorKind::InvalidRatchetSecrets)
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ConfigErrorKind::Io(error) => write!(f, "io error: {error}"),
            ConfigErrorKind::InvalidToml(error) => write!(f, "invalid toml: {error}"),
            ConfigErrorKind::InvalidIdentity => write!(f, "invalid identity data"),
            ConfigErrorKind::InvalidRatchetSecrets => write!(f, "invalid ratchet secret data"),
        }
    }
}

impl std::error::Error for ConfigError {}

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
# https:
# https:

# An entry like this must be converted to TOML as seen above
# [[Test Network Example]]
#   type = TCPClientInterface
#   enabled = yes
#   target_host = test.network.example
#   target_port = 4242
"#;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub interfaces: HashMap<String, InterfaceConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub relay: bool,
}

#[derive(Debug, Clone, Deserialize)]
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
            InterfaceConfig::TCPClientInterface { enabled, .. }
            | InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
        }
    }
}

impl Config {
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        if path.exists() {
            let contents = fs::read_to_string(path).map_err(ConfigError::io)?;
            toml::from_str(&contents)
                .map_err(|error| ConfigError(ConfigErrorKind::InvalidToml(error)))
        } else {
            create_parent_directory(path).map_err(ConfigError::io)?;
            fs::write(path, DEFAULT_CONFIG).map_err(ConfigError::io)?;
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
}

pub fn load_or_create_persistent_identity(
    path: impl AsRef<Path>,
) -> Result<PrivateIdentity, ConfigError> {
    let path = path.as_ref();

    if path.exists() {
        let hex_str = fs::read_to_string(path).map_err(ConfigError::io)?;
        let bytes = hex::decode(hex_str.trim()).map_err(|_| ConfigError::invalid_identity())?;
        PrivateIdentity::from_secret_bytes(
            bytes
                .try_into()
                .map_err(|_| ConfigError::invalid_identity())?,
        )
        .ok_or_else(ConfigError::invalid_identity)
    } else {
        let identity = PrivateIdentity::generate(&mut rand::thread_rng());
        save_private_identity(path, &identity)?;
        Ok(identity)
    }
}

pub fn save_private_identity(
    path: impl AsRef<Path>,
    identity: &PrivateIdentity,
) -> Result<(), ConfigError> {
    let path = path.as_ref();
    create_parent_directory(path).map_err(ConfigError::io)?;
    let hex_str = hex::encode(identity.to_secret_bytes());
    fs::write(path, hex_str).map_err(ConfigError::io)?;
    Ok(())
}

pub fn load_ratchet_keys_for_restart(
    storage_directory: impl AsRef<Path>,
    service: Destination,
) -> Result<Vec<RatchetSecret>, ConfigError> {
    let path = storage_directory
        .as_ref()
        .join(hex::encode(service.as_bytes()));

    if path.exists() {
        let contents = fs::read_to_string(&path).map_err(ConfigError::io)?;
        let mut ratchets = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bytes = hex::decode(line).map_err(|_| ConfigError::invalid_ratchet_secrets())?;
            if bytes.len() != 32 {
                return Err(ConfigError::invalid_ratchet_secrets());
            }
            ratchets.push(
                RatchetSecret::from_bytes(bytes.try_into().unwrap())
                    .ok_or_else(ConfigError::invalid_ratchet_secrets)?,
            );
        }
        Ok(ratchets)
    } else {
        Ok(Vec::new())
    }
}

pub fn save_ratchet_keys_for_restart(
    storage_directory: impl AsRef<Path>,
    service: Destination,
    ratchet_keys: &[RatchetSecret],
) -> Result<(), ConfigError> {
    let path = storage_directory
        .as_ref()
        .join(hex::encode(service.as_bytes()));

    create_parent_directory(&path).map_err(ConfigError::io)?;
    let contents: String = ratchet_keys
        .iter()
        .map(RatchetSecret::to_bytes)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, contents).map_err(ConfigError::io)?;
    Ok(())
}

fn create_parent_directory(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn test_directory() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rinse-config-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn config_path_is_selected_by_caller() {
        let directory = test_directory();
        let path = directory.join("node.toml");
        assert!(Config::load_from(&path).unwrap().name.is_none());
        assert_eq!(
            Config::load_from(&path).unwrap().name.as_deref(),
            Some("Anonymous Peer")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn identity_path_is_selected_by_caller() {
        let directory = test_directory();
        let path = directory.join("node.identity");
        let generated = load_or_create_persistent_identity(&path).unwrap();
        let loaded = load_or_create_persistent_identity(&path).unwrap();

        assert_eq!(generated.to_secret_bytes(), loaded.to_secret_bytes());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ratchet_files_are_bound_to_service_address() {
        let directory = test_directory();
        let first_service = Destination::from_bytes([1; 16]);
        let second_service = Destination::from_bytes([2; 16]);
        let persisted = [RatchetSecret::from_bytes([3; 32]).unwrap()];

        save_ratchet_keys_for_restart(&directory, first_service, &persisted).unwrap();

        assert_eq!(
            load_ratchet_keys_for_restart(&directory, first_service)
                .unwrap()
                .into_iter()
                .map(|secret| secret.to_bytes())
                .collect::<Vec<_>>(),
            vec![[3; 32]]
        );
        assert!(
            load_ratchet_keys_for_restart(&directory, second_service)
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
