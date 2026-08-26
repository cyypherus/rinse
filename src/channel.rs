use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

pub(crate) const CHANNEL_MDU: usize = 425;
const MAX_WINDOW: u16 = 48;
const MAX_TRIES: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMessage {
    message_type: ChannelMessageType,
    data: Vec<u8>,
}

impl ChannelMessage {
    pub fn new(
        message_type: ChannelMessageType,
        data: Vec<u8>,
    ) -> Result<Self, ChannelMessageTooLarge> {
        if data.len() > CHANNEL_MDU {
            return Err(ChannelMessageTooLarge {
                size: data.len(),
                max: CHANNEL_MDU,
            });
        }
        Ok(Self { message_type, data })
    }

    pub fn message_type(&self) -> ChannelMessageType {
        self.message_type
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMessageType(u16);

impl ChannelMessageType {
    pub fn new(value: u16) -> Result<Self, InvalidChannelMessageType> {
        if value >= 0xf000 {
            return Err(InvalidChannelMessageType);
        }
        Ok(Self(value))
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidChannelMessageType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelMessageTooLarge {
    pub size: usize,
    pub max: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelSendError {
    LinkNotFound,
    LinkNotActive,
    RuntimeStopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QueueChannelError {
    LinkNotFound,
    LinkNotActive,
    WindowFull,
}

struct OutboundEnvelope {
    packet: crate::packet::Packet,
    sent_at: Instant,
    tries: u8,
}

pub(crate) struct ChannelState {
    next_sequence: u16,
    next_rx_sequence: u16,
    rx: BTreeMap<u16, (u16, Vec<u8>)>,
    outbound: VecDeque<OutboundEnvelope>,
    window: usize,
}

impl ChannelState {
    pub(crate) fn new() -> Self {
        Self {
            next_sequence: 0,
            next_rx_sequence: 0,
            rx: BTreeMap::new(),
            outbound: VecDeque::new(),
            window: 2,
        }
    }

    pub(crate) fn prepare(
        &mut self,
        message_type: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, QueueChannelError> {
        debug_assert!(data.len() <= CHANNEL_MDU);
        if self.outbound.len() >= self.window {
            return Err(QueueChannelError::WindowFull);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let mut raw = Vec::with_capacity(6 + data.len());
        raw.extend_from_slice(&message_type.to_be_bytes());
        raw.extend_from_slice(&sequence.to_be_bytes());
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
        Ok(raw)
    }

    pub(crate) fn track(&mut self, packet: crate::packet::Packet, now: Instant) {
        self.outbound.push_back(OutboundEnvelope {
            packet,
            sent_at: now,
            tries: 1,
        });
    }

    pub(crate) fn delivered(&mut self, packet_hash: &[u8; 32]) -> bool {
        let Some(index) = self
            .outbound
            .iter()
            .position(|envelope| &envelope.packet.packet_hash() == packet_hash)
        else {
            return false;
        };
        self.outbound.remove(index);
        self.window = (self.window + 1).min(MAX_WINDOW as usize);
        true
    }

    pub(crate) fn receive(&mut self, raw: &[u8]) -> Vec<(u16, Vec<u8>)> {
        if raw.len() < 6 {
            return Vec::new();
        }
        let message_type = u16::from_be_bytes([raw[0], raw[1]]);
        let sequence = u16::from_be_bytes([raw[2], raw[3]]);
        let length = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        if raw.len() != 6 + length || self.rx.contains_key(&sequence) {
            return Vec::new();
        }
        let ahead = sequence.wrapping_sub(self.next_rx_sequence);
        if ahead > MAX_WINDOW {
            return Vec::new();
        }
        self.rx.insert(sequence, (message_type, raw[6..].to_vec()));
        let mut messages = Vec::new();
        while let Some(message) = self.rx.remove(&self.next_rx_sequence) {
            messages.push(message);
            self.next_rx_sequence = self.next_rx_sequence.wrapping_add(1);
        }
        messages
    }

    fn retry_timeout(tries: u8, rtt: Duration, ring_len: usize) -> Duration {
        let base = rtt.mul_f64(2.5).max(Duration::from_millis(25));
        base.mul_f64(1.5_f64.powi(tries.saturating_sub(1) as i32))
            .mul_f64(ring_len as f64 + 1.5)
    }

    pub(crate) fn retries(
        &mut self,
        now: Instant,
        rtt: Duration,
    ) -> (Vec<crate::packet::Packet>, bool) {
        let ring_len = self.outbound.len();
        let mut retry = Vec::new();
        let mut failed = false;
        for envelope in &mut self.outbound {
            let timeout = Self::retry_timeout(envelope.tries, rtt, ring_len);
            if now.saturating_duration_since(envelope.sent_at) >= timeout {
                if envelope.tries >= MAX_TRIES {
                    failed = true;
                } else {
                    envelope.tries += 1;
                    envelope.sent_at = now;
                    retry.push(envelope.packet.clone());
                }
            }
        }
        (retry, failed)
    }

    pub(crate) fn next_retry(&self, rtt: Duration) -> Option<Instant> {
        let ring_len = self.outbound.len();
        self.outbound
            .iter()
            .map(|envelope| envelope.sent_at + Self::retry_timeout(envelope.tries, rtt, ring_len))
            .min()
    }

    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        self.outbound.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_envelope_layout() {
        let mut channel = ChannelState::new();
        assert_eq!(
            channel.prepare(0x0101, b"hello").unwrap(),
            [0x01, 0x01, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']
        );
    }

    #[test]
    fn out_of_order_messages_are_delivered_in_order() {
        let mut channel = ChannelState::new();
        let second = [0, 2, 0, 1, 0, 1, b'b'];
        let first = [0, 2, 0, 0, 0, 1, b'a'];
        assert!(channel.receive(&second).is_empty());
        assert_eq!(
            channel.receive(&first),
            [(2, b"a".to_vec()), (2, b"b".to_vec())]
        );
    }

    #[test]
    fn rejects_reserved_and_oversized_user_messages() {
        assert_eq!(
            ChannelMessageType::new(0xf000),
            Err(InvalidChannelMessageType)
        );
        let message_type = ChannelMessageType::new(1).unwrap();
        assert_eq!(
            ChannelMessage::new(message_type, vec![0; CHANNEL_MDU + 1]),
            Err(ChannelMessageTooLarge {
                size: CHANNEL_MDU + 1,
                max: CHANNEL_MDU,
            })
        );
    }

    #[test]
    fn rejects_malformed_and_duplicate_envelopes() {
        let mut channel = ChannelState::new();
        assert!(channel.receive(&[0, 1, 0, 0, 0, 2, 1]).is_empty());
        let raw = [0, 1, 0, 0, 0, 1, 1];
        assert_eq!(channel.receive(&raw).len(), 1);
        assert!(channel.receive(&raw).is_empty());
    }
}
