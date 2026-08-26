use std::future::Future;
use std::io;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use futures_util::future::BoxFuture;

#[derive(Debug)]
pub enum InterfaceError {
    Closed,
    Io(io::Error),
}

pub struct InboundPacket {
    bytes: Vec<u8>,
}

impl InboundPacket {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

pub struct OutboundPacket {
    bytes: Vec<u8>,
}

impl OutboundPacket {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

pub trait Interface: Send + Sync {
    fn receive(&self) -> impl Future<Output = Result<InboundPacket, InterfaceError>> + Send;
    fn send(
        &self,
        packet: OutboundPacket,
    ) -> impl Future<Output = Result<(), InterfaceError>> + Send;
    fn close(&self) -> impl Future<Output = Result<(), InterfaceError>> + Send;
}

pub(crate) trait ErasedInterface: Send + Sync {
    fn receive(&self) -> BoxFuture<'_, Result<InboundPacket, InterfaceError>>;
    fn send(&self, packet: OutboundPacket) -> BoxFuture<'_, Result<(), InterfaceError>>;
    fn close(&self) -> BoxFuture<'_, Result<(), InterfaceError>>;
}

impl<I: Interface> ErasedInterface for I {
    fn receive(&self) -> BoxFuture<'_, Result<InboundPacket, InterfaceError>> {
        Box::pin(Interface::receive(self))
    }

    fn send(&self, packet: OutboundPacket) -> BoxFuture<'_, Result<(), InterfaceError>> {
        Box::pin(Interface::send(self, packet))
    }

    fn close(&self) -> BoxFuture<'_, Result<(), InterfaceError>> {
        Box::pin(Interface::close(self))
    }
}

pub(crate) type AttachedInterface = Arc<dyn ErasedInterface + 'static>;

pub struct InterfaceAccessCode {
    signing_key: SigningKey,
    shared_key: Vec<u8>,
    transmitted_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceAccessCodeError {
    EmptyPacketMaskingKey,
    InvalidTransmittedAuthenticationBytes { bytes: usize, max: usize },
}

impl InterfaceAccessCode {
    pub fn new(
        interface_signing_secret: [u8; 32],
        packet_masking_key: Vec<u8>,
        transmitted_authentication_bytes: usize,
    ) -> Result<Self, InterfaceAccessCodeError> {
        if packet_masking_key.is_empty() {
            return Err(InterfaceAccessCodeError::EmptyPacketMaskingKey);
        }
        if !(1..=64).contains(&transmitted_authentication_bytes) {
            return Err(
                InterfaceAccessCodeError::InvalidTransmittedAuthenticationBytes {
                    bytes: transmitted_authentication_bytes,
                    max: 64,
                },
            );
        }
        Ok(Self {
            signing_key: SigningKey::from_bytes(&interface_signing_secret),
            shared_key: packet_masking_key,
            transmitted_bytes: transmitted_authentication_bytes,
        })
    }
}

pub struct AccessControlledInterface<I> {
    inner: I,
    access: InterfaceAccessCode,
}

impl<I> AccessControlledInterface<I> {
    pub fn new(inner: I, access: InterfaceAccessCode) -> Self {
        Self { inner, access }
    }

    fn receive(&self, raw: Vec<u8>) -> Option<Vec<u8>> {
        let size = self.access.transmitted_bytes;
        if raw.len() <= 2 + size || raw[0] & 0x80 == 0 {
            return None;
        }
        let ifac = raw[2..2 + size].to_vec();
        let mask = crate::crypto::hkdf_expand(&ifac, &self.access.shared_key, raw.len());
        let mut packet = raw;
        for (index, byte) in packet.iter_mut().enumerate() {
            if index <= 1 || index > size + 1 {
                *byte ^= mask[index];
            }
        }
        packet[0] &= 0x7f;
        packet.drain(2..2 + size);
        let signature = crate::crypto::sign(&self.access.signing_key, &packet);
        (ifac == signature.to_bytes()[64 - size..]).then_some(packet)
    }

    fn send(&self, raw: Vec<u8>) -> Vec<u8> {
        let size = self.access.transmitted_bytes;
        let signature = crate::crypto::sign(&self.access.signing_key, &raw);
        let ifac = &signature.to_bytes()[64 - size..];
        let mask = crate::crypto::hkdf_expand(ifac, &self.access.shared_key, raw.len() + size);
        let mut packet = Vec::with_capacity(raw.len() + size);
        packet.extend_from_slice(&[raw[0] | 0x80, raw[1]]);
        packet.extend_from_slice(ifac);
        packet.extend_from_slice(&raw[2..]);
        for (index, byte) in packet.iter_mut().enumerate() {
            if index == 0 {
                *byte = (*byte ^ mask[index]) | 0x80;
            } else if index == 1 || index > size + 1 {
                *byte ^= mask[index];
            }
        }
        packet
    }
}

impl<I: Interface> Interface for AccessControlledInterface<I> {
    async fn receive(&self) -> Result<InboundPacket, InterfaceError> {
        loop {
            let packet = self.inner.receive().await?;
            if let Some(bytes) = self.receive(packet.into_bytes()) {
                return Ok(InboundPacket::new(bytes));
            }
        }
    }

    async fn send(&self, packet: OutboundPacket) -> Result<(), InterfaceError> {
        let packet = self.send(packet.into_bytes());
        self.inner.send(OutboundPacket::new(packet)).await
    }

    async fn close(&self) -> Result<(), InterfaceError> {
        self.inner.close().await
    }
}
