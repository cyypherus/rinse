use std::io::{Read, Write};

use bzip2::Compression;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;

use crate::channel::CHANNEL_MDU;

pub(crate) const STREAM_MESSAGE_TYPE: u16 = 0xff00;
const STREAM_ID_MAX: u16 = 0x3fff;
const STREAM_MDU: usize = CHANNEL_MDU - 2;
const MAX_CHUNK_LEN: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferChunk {
    pub stream_id: u16,
    pub data: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    InvalidStreamId,
    InvalidMessage,
    DecompressionFailed,
    Channel(crate::ChannelError),
}

impl From<crate::ChannelError> for BufferError {
    fn from(error: crate::ChannelError) -> Self {
        Self::Channel(error)
    }
}

pub(crate) fn encode(
    stream_id: u16,
    data: &[u8],
    eof: bool,
) -> Result<(Vec<u8>, usize), BufferError> {
    if stream_id > STREAM_ID_MAX {
        return Err(BufferError::InvalidStreamId);
    }
    let source = &data[..data.len().min(MAX_CHUNK_LEN)];
    let mut selected = None;
    if source.len() > 32 {
        for divisor in 1..4 {
            let length = source.len() / divisor;
            let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
            encoder
                .write_all(&source[..length])
                .map_err(|_| BufferError::DecompressionFailed)?;
            let compressed = encoder
                .finish()
                .map_err(|_| BufferError::DecompressionFailed)?;
            if compressed.len() < STREAM_MDU && compressed.len() < length {
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
    let mut header = stream_id;
    if eof {
        header |= 0x8000;
    }
    if compressed {
        header |= 0x4000;
    }
    let mut raw = Vec::with_capacity(2 + payload.len());
    raw.extend_from_slice(&header.to_be_bytes());
    raw.extend_from_slice(&payload);
    Ok((raw, processed))
}

pub(crate) fn decode(raw: &[u8]) -> Result<BufferChunk, BufferError> {
    if raw.len() < 2 {
        return Err(BufferError::InvalidMessage);
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
            .map_err(|_| BufferError::DecompressionFailed)?;
        if decoded.len() > MAX_CHUNK_LEN {
            return Err(BufferError::DecompressionFailed);
        }
        decoded
    } else {
        raw[2..].to_vec()
    };
    Ok(BufferChunk {
        stream_id: header & STREAM_ID_MAX,
        data,
        eof: header & 0x8000 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_header_matches_python() {
        let (raw, processed) = encode(7, b"abc", true).unwrap();
        assert_eq!(processed, 3);
        assert_eq!(raw, [0x80, 0x07, b'a', b'b', b'c']);
        assert_eq!(
            decode(&raw).unwrap(),
            BufferChunk {
                stream_id: 7,
                data: b"abc".to_vec(),
                eof: true,
            }
        );
    }

    #[test]
    fn compresses_repeated_data() {
        let data = vec![b'x'; 4096];
        let (raw, processed) = encode(1, &data, false).unwrap();
        assert_eq!(processed, data.len());
        assert_ne!(u16::from_be_bytes([raw[0], raw[1]]) & 0x4000, 0);
        assert_eq!(decode(&raw).unwrap().data, data);
    }

    #[test]
    fn rejects_invalid_streams_and_messages() {
        assert_eq!(
            encode(STREAM_ID_MAX + 1, b"", false),
            Err(BufferError::InvalidStreamId)
        );
        assert_eq!(decode(&[0]), Err(BufferError::InvalidMessage));
        assert_eq!(
            decode(&[0x40, 0, 1, 2, 3]),
            Err(BufferError::DecompressionFailed)
        );
    }
}
