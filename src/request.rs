use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::crypto::sha256;
use rmpv::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WireRequestId(pub [u8; 16]);

pub type PathHash = [u8; 16];

pub(crate) fn path_hash(path: &str) -> PathHash {
    let hash = sha256(path.as_bytes());
    hash[..16].try_into().unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub timestamp: f64,
    pub path_hash: PathHash,
    pub data: Option<Vec<u8>>,
}

impl Request {
    pub fn new(path: &str, data: Vec<u8>) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
            path_hash: path_hash(path),
            data: if data.is_empty() { None } else { Some(data) },
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let data_value: Value = match &self.data {
            Some(d) => {
                // If data is valid msgpack (e.g. a pre-encoded dict), embed it directly.
                // Otherwise treat as raw binary (matches Python msgpack behavior).
                // Must consume entire input to be valid msgpack.
                let mut cursor = &d[..];
                match rmpv::decode::read_value(&mut cursor) {
                    Ok(v) if cursor.is_empty() => v,
                    _ => Value::Binary(d.clone()),
                }
            }
            None => Value::Nil,
        };
        let arr = Value::Array(vec![
            Value::F64(self.timestamp),
            Value::Binary(self.path_hash.to_vec()),
            data_value,
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &arr).unwrap();
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let value = rmpv::decode::read_value(&mut &bytes[..]).ok()?;
        let arr = value.as_array()?;
        if arr.len() != 3 {
            return None;
        }
        let timestamp = arr[0].as_f64()?;
        let path_hash_bytes = arr[1].as_slice()?;
        if path_hash_bytes.len() != 16 {
            return None;
        }
        let mut path_hash = [0u8; 16];
        path_hash.copy_from_slice(path_hash_bytes);
        let data = match &arr[2] {
            Value::Nil => None,
            Value::Binary(b) => Some(b.clone()),
            other => {
                let mut buf = Vec::new();
                rmpv::encode::write_value(&mut buf, other).ok()?;
                Some(buf)
            }
        };
        Some(Self {
            timestamp,
            path_hash,
            data,
        })
    }
}

pub struct Response {
    pub request_id: WireRequestId,
    pub data: Vec<u8>,
}

impl Response {
    pub fn new(request_id: WireRequestId, data: Vec<u8>) -> Self {
        Self { request_id, data }
    }

    pub fn encode(&self) -> Vec<u8> {
        rmp_serde::to_vec(&(
            ByteBuf::from(self.request_id.0.to_vec()),
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
            request_id: WireRequestId(request_id),
            data: data_buf.into_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn request_roundtrip_no_data() {
        let req = Request::new("test/path", vec![]);
        let encoded = req.encode();
        let decoded = Request::decode(&encoded).unwrap();
        assert_eq!(decoded.path_hash, req.path_hash);
        assert_eq!(decoded.data, None);
    }

    #[test]
    fn request_roundtrip_with_dict() {
        let mut form_data = HashMap::new();
        form_data.insert("field_username".to_string(), "alice".to_string());
        let data = rmp_serde::to_vec(&form_data).unwrap();

        let req = Request::new("test/path", data);
        let encoded = req.encode();
        let decoded = Request::decode(&encoded).unwrap();
        assert_eq!(decoded.path_hash, req.path_hash);

        let decoded_form: HashMap<String, String> =
            rmp_serde::from_slice(&decoded.data.unwrap()).unwrap();
        assert_eq!(decoded_form.get("field_username").unwrap(), "alice");
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response::new(WireRequestId([0xAB; 16]), b"world".to_vec());
        let encoded = resp.encode();
        let decoded = Response::decode(&encoded).unwrap();
        assert_eq!(decoded.request_id, WireRequestId([0xAB; 16]));
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
        let h = path_hash("test/path");
        assert_eq!(hex::encode(h), "b04c3b75c4731c02f72d2ea9afcd7b66");
    }

    #[test]
    fn request_no_data_matches_python() {
        // Python: import umsgpack; umsgpack.packb([1234567890.123, bytes.fromhex("b04c3b75c4731c02f72d2ea9afcd7b66"), None]).hex()
        // = "93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b66c0"
        let mut req = Request::new("test/path", vec![]);
        req.timestamp = 1234567890.123;
        let encoded = req.encode();
        assert_eq!(
            hex::encode(&encoded),
            "93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b66c0"
        );
    }

    #[test]
    fn request_with_dict_matches_python() {
        // Python: import umsgpack; umsgpack.packb([1234567890.123, bytes.fromhex("b04c3b75c4731c02f72d2ea9afcd7b66"), {"field_username": "alice"}]).hex()
        // = "93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b6681ae6669656c645f757365726e616d65a5616c696365"
        let mut form_data = HashMap::new();
        form_data.insert("field_username".to_string(), "alice".to_string());
        let data = rmp_serde::to_vec(&form_data).unwrap();

        let mut req = Request::new("test/path", data);
        req.timestamp = 1234567890.123;
        let encoded = req.encode();
        assert_eq!(
            hex::encode(&encoded),
            "93cb41d26580b487df3bc410b04c3b75c4731c02f72d2ea9afcd7b6681ae6669656c645f757365726e616d65a5616c696365"
        );
    }

    #[test]
    fn response_decode_from_python() {
        let python_packed =
            hex::decode("92c410ababababababababababababababababc405776f726c64").unwrap();
        let resp = Response::decode(&python_packed).unwrap();
        assert_eq!(resp.request_id, WireRequestId([0xAB; 16]));
        assert_eq!(resp.data, b"world");
    }

    #[test]
    fn response_encode_matches_python() {
        let resp = Response::new(WireRequestId([0xAB; 16]), b"world".to_vec());
        let encoded = resp.encode();
        assert_eq!(
            hex::encode(&encoded),
            "92c410ababababababababababababababababc405776f726c64"
        );
    }
}
