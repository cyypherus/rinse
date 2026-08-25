use std::io::{Read, Write};

use bzip2::Compression;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;

use crate::channel::CHANNEL_MDU;

pub(crate) const STREAM_MESSAGE_TYPE: u16 = 0xff00;
const STREAM_MDU: usize = CHANNEL_MDU - 2;
const MAX_CHUNK_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkBufferStreamChunk {
    stream_id: LinkBufferStreamId,
    data: Vec<u8>,
    end_of_stream: bool,
}

impl LinkBufferStreamChunk {
    pub fn stream_id(&self) -> LinkBufferStreamId {
        self.stream_id
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn ends_stream_after_data(&self) -> bool {
        self.end_of_stream
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkBufferStreamId(u16);

impl LinkBufferStreamId {
    pub const MAX_VALUE: u16 = 0x3fff;

    pub fn new(value: u16) -> Result<Self, InvalidLinkBufferStreamId> {
        if value > Self::MAX_VALUE {
            return Err(InvalidLinkBufferStreamId);
        }
        Ok(Self(value))
    }

    pub fn as_u16(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidLinkBufferStreamId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuedLinkBufferStreamData {
    pub input_prefix_bytes_queued: usize,
}

pub(crate) fn encode(
    stream_id: LinkBufferStreamId,
    data: &[u8],
    end_of_stream: bool,
) -> (Vec<u8>, usize) {
    let source = &data[..data.len().min(MAX_CHUNK_LEN)];
    let mut selected = None;
    if source.len() > 32 {
        for divisor in 1..4 {
            let length = source.len() / divisor;
            let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
            if encoder.write_all(&source[..length]).is_ok()
                && let Ok(compressed) = encoder.finish()
                && compressed.len() < STREAM_MDU
                && compressed.len() < length
            {
                selected = Some((compressed, length));
                break;
            }
        }
    }
    let (payload, processed, compressed) = if let Some((compressed, length)) = selected {
        (compressed, length, true)
    } else {
        let length = source.len().min(STREAM_MDU);
        (source[..length].to_vec(), length, false)
    };
    let mut header = stream_id.as_u16();
    if end_of_stream && processed == data.len() {
        header |= 0x8000;
    }
    if compressed {
        header |= 0x4000;
    }
    let mut raw = Vec::with_capacity(2 + payload.len());
    raw.extend_from_slice(&header.to_be_bytes());
    raw.extend_from_slice(&payload);
    (raw, processed)
}

pub(crate) fn decode(raw: &[u8]) -> Option<LinkBufferStreamChunk> {
    if raw.len() < 2 {
        return None;
    }
    let header = u16::from_be_bytes([raw[0], raw[1]]);
    let compressed = header & 0x4000 != 0;
    let data = if compressed {
        let mut decoder = BzDecoder::new(&raw[2..]);
        let mut decoded = Vec::new();
        decoder
            .by_ref()
            .take(MAX_CHUNK_LEN as u64 + 1)
            .read_to_end(&mut decoded)
            .ok()?;
        if decoded.len() > MAX_CHUNK_LEN {
            return None;
        }
        decoded
    } else {
        raw[2..].to_vec()
    };
    Some(LinkBufferStreamChunk {
        stream_id: LinkBufferStreamId(header & LinkBufferStreamId::MAX_VALUE),
        data,
        end_of_stream: header & 0x8000 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_header_matches_python() {
        let (raw, processed) = encode(LinkBufferStreamId::new(7).unwrap(), b"abc", true);
        assert_eq!(processed, 3);
        assert_eq!(raw, [0x80, 0x07, b'a', b'b', b'c']);
        assert_eq!(
            decode(&raw).unwrap(),
            LinkBufferStreamChunk {
                stream_id: LinkBufferStreamId::new(7).unwrap(),
                data: b"abc".to_vec(),
                end_of_stream: true,
            }
        );
    }

    #[test]
    fn compresses_repeated_data() {
        let data = vec![b'x'; 4096];
        let (raw, processed) = encode(LinkBufferStreamId::new(1).unwrap(), &data, false);
        assert_eq!(processed, data.len());
        assert_ne!(u16::from_be_bytes([raw[0], raw[1]]) & 0x4000, 0);
        assert_eq!(decode(&raw).unwrap().data, data);
    }

    #[test]
    fn partial_chunk_does_not_end_stream() {
        let data = vec![b'x'; MAX_CHUNK_LEN + 1];
        let (raw, processed) = encode(LinkBufferStreamId::new(1).unwrap(), &data, true);
        assert!(processed < data.len());
        assert!(!decode(&raw).unwrap().end_of_stream);
    }

    #[test]
    fn rejects_invalid_streams_and_messages() {
        assert_eq!(
            LinkBufferStreamId::new(LinkBufferStreamId::MAX_VALUE)
                .unwrap()
                .as_u16(),
            LinkBufferStreamId::MAX_VALUE
        );
        assert_eq!(
            LinkBufferStreamId::new(LinkBufferStreamId::MAX_VALUE + 1),
            Err(InvalidLinkBufferStreamId)
        );
        assert_eq!(decode(&[0]), None);
        assert_eq!(decode(&[0x40, 0, 1, 2, 3]), None);
    }
}
