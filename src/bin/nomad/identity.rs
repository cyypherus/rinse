use rinse::Identity as RinseIdentity;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

use crate::config::Config;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("config error: {0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid identity data")]
    InvalidData,
}

pub struct Identity {
    inner: RinseIdentity,
}

impl Identity {
    pub fn load_or_generate() -> Result<Self, IdentityError> {
        let path = Self::identity_path()?;

        if path.exists() {
            Self::load(&path)
        } else {
            let identity = Self::generate();
            identity.save(&path)?;
            Ok(identity)
        }
    }

    pub fn generate() -> Self {
        Self {
            inner: RinseIdentity::generate(&mut rand::thread_rng()),
        }
    }

    fn load(path: &PathBuf) -> Result<Self, IdentityError> {
        let hex_str = fs::read_to_string(path)?;
        let bytes = hex::decode(hex_str.trim()).map_err(|_| IdentityError::InvalidData)?;
        let inner = RinseIdentity::from_bytes(&bytes).ok_or(IdentityError::InvalidData)?;
        Ok(Self { inner })
    }

    fn save(&self, path: &PathBuf) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let hex_str = hex::encode(self.inner.to_bytes());
        fs::write(path, hex_str)?;
        Ok(())
    }

    fn identity_path() -> Result<PathBuf, IdentityError> {
        Ok(Config::data_dir()?.join("identity"))
    }

    pub fn inner(&self) -> &RinseIdentity {
        &self.inner
    }
}
