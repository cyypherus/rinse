use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::crypto::sha256;

pub type RequestId = [u8; 16];
pub type PathHash = [u8; 16];

pub fn path_hash(path: &str) -> PathHash {
    let hash = sha256(path.as_bytes());
    hash[..16].try_into().unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub timestamp: f64,
    pub path_hash: PathHash,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl Request {
    pub fn new(path: &str, data: Vec<u8>) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
            path_hash: path_hash(path),
            data,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        rmp_serde::to_vec(&(
            self.timestamp,
            ByteBuf::from(self.path_hash.to_vec()),
            ByteBuf::from(self.data.clone()),
        ))
        .unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (timestamp, path_hash_buf, data_buf): (f64, ByteBuf, ByteBuf) =
            rmp_serde::from_slice(bytes).ok()?;
        if path_hash_buf.len() != 16 {
            return None;
        }
        let mut path_hash = [0u8; 16];
        path_hash.copy_from_slice(&path_hash_buf);
        Some(Self {
            timestamp,
            path_hash,
            data: data_buf.into_vec(),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub request_id: RequestId,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl Response {
    pub fn new(request_id: RequestId, data: Vec<u8>) -> Self {
        Self { request_id, data }
    }

    pub fn encode(&self) -> Vec<u8> {
        rmp_serde::to_vec(&(
            ByteBuf::from(self.request_id.to_vec()),
            ByteBuf::from(self.data.clone()),
        ))
        .unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (request_id_buf, data_buf): (ByteBuf, ByteBuf) = rmp_serde::from_slice(bytes).ok()?;
        if request_id_buf.len() != 16 {
            return None;
        }
        let mut request_id = [0u8; 16];
        request_id.copy_from_slice(&request_id_buf);
        Some(Self {
            request_id,
            data: data_buf.into_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = Request::new("test/path", b"hello".to_vec());
        let encoded = req.encode();
        let decoded = Request::decode(&encoded).unwrap();
        assert_eq!(decoded.path_hash, req.path_hash);
        assert_eq!(decoded.data, b"hello");
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response::new([0xAB; 16], b"world".to_vec());
        let encoded = resp.encode();
        let decoded = Response::decode(&encoded).unwrap();
        assert_eq!(decoded.request_id, [0xAB; 16]);
        assert_eq!(decoded.data, b"world");
    }

    #[test]
    fn path_hash_deterministic() {
        let h1 = path_hash("foo/bar");
        let h2 = path_hash("foo/bar");
        assert_eq!(h1, h2);
    }

    #[test]
    fn path_hash_matches_python() {
        // Python: truncated_hash("test/path".encode('utf-8')).hex() = "b04c3b75c4731c02f72d2ea9afcd7b66"
        let h = path_hash("test/path");
        assert_eq!(hex::encode(h), "b04c3b75c4731c02f72d2ea9afcd7b66");
    }

    #[test]
    fn request_decode_from_python() {
        // Python output: 93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b66c40568656c6c6f
        let python_packed =
            hex::decode("93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b66c40568656c6c6f")
                .unwrap();
        let req = Request::decode(&python_packed).unwrap();
        assert!((req.timestamp - 1234567890.123).abs() < 0.001);
        assert_eq!(
            hex::encode(req.path_hash),
            "b04c3b75c4731c02f72d2ea9afcd7b66"
        );
        assert_eq!(req.data, b"hello");
    }

    #[test]
    fn response_decode_from_python() {
        // Python output: 92c410ababababababababababababababababc405776f726c64
        let python_packed =
            hex::decode("92c410ababababababababababababababababc405776f726c64").unwrap();
        let resp = Response::decode(&python_packed).unwrap();
        assert_eq!(resp.request_id, [0xAB; 16]);
        assert_eq!(resp.data, b"world");
    }

    #[test]
    fn response_encode_matches_python() {
        let resp = Response::new([0xAB; 16], b"world".to_vec());
        let encoded = resp.encode();
        // Python: 92c410ababababababababababababababababc405776f726c64
        assert_eq!(
            hex::encode(&encoded),
            "92c410ababababababababababababababababc405776f726c64"
        );
    }

    #[test]
    fn request_encode_matches_python() {
        let mut req = Request::new("test/path", b"hello".to_vec());
        req.timestamp = 1234567890.123;
        let encoded = req.encode();
        // Python: 93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b66c40568656c6c6f
        assert_eq!(
            hex::encode(&encoded),
            "93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b66c40568656c6c6f"
        );
    }
}
