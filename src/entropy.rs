use rand_chacha::ChaCha20Rng;

pub trait CryptoEntropy {
    fn fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), EntropyUnavailable>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntropyUnavailable;

#[cfg(feature = "std-clock")]
#[derive(Clone, Copy, Default)]
pub struct SystemEntropy;

#[cfg(feature = "std-clock")]
impl CryptoEntropy for SystemEntropy {
    fn fill_seed(&mut self, seed: &mut [u8; 32]) -> Result<(), EntropyUnavailable> {
        rand_core::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, seed)
            .map_err(|_| EntropyUnavailable)
    }
}

pub(crate) type ProtocolRng = ChaCha20Rng;
