use std::io::{Read, Write};

use bzip2::Compression;
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;

use crate::channel::CHANNEL_MDU;
use crate::{BufferChunk, StreamId};

pub(crate) const STREAM_MESSAGE_TYPE: u16 = 0xff00;
const STREAM_MDU: usize = CHANNEL_MDU - 2;
pub(crate) const MAX_INPUT_BYTES: usize = 16 * 1024;

pub(crate) fn encode(stream_id: StreamId, data: &[u8], end_of_stream: bool) -> (Vec<u8>, usize) {
    let source = &data[..data.len().min(MAX_INPUT_BYTES)];
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
    let mut header = stream_id.get();
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

pub(crate) fn decode(raw: &[u8]) -> Option<(StreamId, BufferChunk)> {
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
            .take(MAX_INPUT_BYTES as u64 + 1)
            .read_to_end(&mut decoded)
            .ok()?;
        if decoded.len() > MAX_INPUT_BYTES {
            return None;
        }
        decoded
    } else {
        raw[2..].to_vec()
    };
    let stream = StreamId::new(header & StreamId::MAX).ok()?;
    let chunk = if header & 0x8000 == 0 {
        BufferChunk::Data(data.into())
    } else {
        BufferChunk::End(data.into())
    };
    Some((stream, chunk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_header_matches_python() {
        let (raw, processed) = encode(StreamId::new(7).unwrap(), b"abc", true);
        assert_eq!(processed, 3);
        assert_eq!(raw, [0x80, 0x07, b'a', b'b', b'c']);
        assert_eq!(
            decode(&raw).unwrap(),
            (
                StreamId::new(7).unwrap(),
                BufferChunk::End(b"abc".as_slice().into())
            )
        );
    }

    #[test]
    fn compresses_repeated_data() {
        let data = vec![b'x'; 4096];
        let (raw, processed) = encode(StreamId::new(1).unwrap(), &data, false);
        assert_eq!(processed, data.len());
        assert_ne!(u16::from_be_bytes([raw[0], raw[1]]) & 0x4000, 0);
        assert_eq!(decode(&raw).unwrap().1, BufferChunk::Data(data.into()));
    }

    #[test]
    fn partial_chunk_does_not_end_stream() {
        let data = vec![b'x'; MAX_INPUT_BYTES + 1];
        let (raw, processed) = encode(StreamId::new(1).unwrap(), &data, true);
        assert!(processed < data.len());
        assert!(matches!(decode(&raw).unwrap().1, BufferChunk::Data(_)));
    }

    #[test]
    fn rejects_invalid_streams_and_messages() {
        assert_eq!(StreamId::new(StreamId::MAX).unwrap().get(), StreamId::MAX);
        assert_eq!(
            StreamId::new(StreamId::MAX + 1),
            Err(crate::StreamIdOutOfRange)
        );
        assert_eq!(decode(&[0]), None);
        assert_eq!(decode(&[0x40, 0, 1, 2, 3]), None);
    }
}
