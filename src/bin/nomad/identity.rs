use rinse::Identity as RinseIdentity;
use rinse::config::{ConfigError, load_or_generate_identity};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
}

pub struct Identity {
    inner: RinseIdentity,
}

impl Identity {
    pub fn load_or_generate() -> Result<Self, IdentityError> {
        let inner = load_or_generate_identity()?;
        Ok(Self { inner })
    }

    pub fn inner(&self) -> &RinseIdentity {
        &self.inner
    }
}
