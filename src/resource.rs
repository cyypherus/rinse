use crate::link::EstablishedLink;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub(crate) const MAPHASH_LEN: usize = 4;
pub(crate) const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub(crate) const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;
pub(crate) const HASHMAP_MAX_LEN: usize = 74;

const WINDOW: usize = 10;

const SDU: usize = 470;

pub(crate) const MAX_EFFICIENT_SIZE: usize = 1024 * 1024 - 1;

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub(crate) struct OutboundResource {
    pub hash: [u8; 32],
    pub random_hash: [u8; 4],
    expected_proof: [u8; 32],
    has_metadata: bool,
    pub compressed: bool,
    pub request_id: Option<Vec<u8>>,
    parts: Vec<Vec<u8>>,
    hashmap: Vec<[u8; MAPHASH_LEN]>,
    hashmap_sent: usize,
}

impl OutboundResource {
    pub fn new_segment<R: RngCore>(
        rng: &mut R,
        link: &EstablishedLink,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
        request_id: Option<Vec<u8>>,
    ) -> Self {
        let has_metadata = metadata.is_some();

        let (to_send, compressed) = if compress {
            if let Some(compressed_data) = bz2_compress(&data) {
                (compressed_data, true)
            } else {
                (data.as_slice().into(), false)
            }
        } else {
            (data.as_slice().into(), false)
        };

        let mut encryption_padding = [0u8; 4];
        rng.fill_bytes(&mut encryption_padding);

        let mut plaintext = encryption_padding.to_vec();
        if let Some(ref meta) = metadata {
            let len = meta.len();
            plaintext.push((len >> 16) as u8);
            plaintext.push((len >> 8) as u8);
            plaintext.push(len as u8);
            plaintext.extend(meta);
        }
        plaintext.extend(&to_send);

        let encrypted = link.encrypt(rng, &plaintext);
        let parts: Vec<Vec<u8>> = encrypted.chunks(SDU).map(|c| c.to_vec()).collect();

        let mut random_hash = [0u8; 4];
        rng.fill_bytes(&mut random_hash);

        let hash = hash_parts(&[data.as_slice(), random_hash.as_slice()]);
        let expected_proof = hash_parts(&[data.as_slice(), hash.as_slice()]);

        let hashmap: Vec<[u8; MAPHASH_LEN]> = parts
            .iter()
            .map(|p| {
                let h = hash_parts(&[p.as_slice(), random_hash.as_slice()]);
                [h[0], h[1], h[2], h[3]]
            })
            .collect();

        Self {
            hash,
            random_hash,
            expected_proof,
            has_metadata,
            compressed,
            request_id,
            parts,
            hashmap,
            hashmap_sent: 0,
        }
    }

    pub fn get_part(&self, hash: &[u8; MAPHASH_LEN]) -> Option<&[u8]> {
        self.hashmap
            .iter()
            .position(|h| h == hash)
            .map(|i| self.parts[i].as_slice())
    }

    pub fn advertisement(&mut self, max_hashmap_len: usize) -> ResourceAdvertisement {
        let transfer_size = self.parts.iter().map(Vec::len).sum();
        let hashmap_chunk: Vec<u8> = self.hashmap[..self.hashmap.len().min(max_hashmap_len)]
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        self.hashmap_sent = hashmap_chunk.len() / MAPHASH_LEN;
        ResourceAdvertisement {
            transfer_size,
            data_size: transfer_size,
            num_parts: self.parts.len(),
            hash: self.hash,
            random_hash: self.random_hash,
            original_hash: self.hash,
            segment_index: 1,
            total_segments: 1,
            hashmap: hashmap_chunk,
            compressed: self.compressed,
            has_metadata: self.has_metadata,
            request_id: self.request_id.clone(),
        }
    }

    pub fn hashmap_update(&mut self) -> Option<(usize, Vec<u8>)> {
        if self.hashmap_sent >= self.hashmap.len() {
            return None;
        }
        let segment = self.hashmap_sent / HASHMAP_MAX_LEN;
        let start = segment * HASHMAP_MAX_LEN;
        let end = ((segment + 1) * HASHMAP_MAX_LEN).min(self.hashmap.len());
        let chunk: Vec<u8> = self.hashmap[start..end]
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        self.hashmap_sent = end;
        Some((segment, chunk))
    }

    pub fn verify_proof(&self, proof: &[u8]) -> bool {
        proof == self.expected_proof
    }
}

pub(crate) struct InboundResource {
    pub hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub compressed: bool,
    pub has_metadata: bool,
    pub request_id: Option<Vec<u8>>,
    hashmap: Vec<Option<[u8; MAPHASH_LEN]>>,
    hashmap_height: usize,
    parts: Vec<Option<Vec<u8>>>,
    requested: Vec<bool>,
    received_count: usize,
    outstanding_parts: usize,
    completed_prefix: usize,
}

impl InboundResource {
    pub fn from_advertisement(adv: &ResourceAdvertisement) -> Self {
        let received_hashes: Vec<[u8; MAPHASH_LEN]> = adv
            .hashmap
            .chunks_exact(MAPHASH_LEN)
            .map(|c| [c[0], c[1], c[2], c[3]])
            .collect();

        let hashmap_height = received_hashes.len();

        let mut hashmap = vec![None; adv.num_parts];
        for (slot, hash) in hashmap.iter_mut().zip(received_hashes) {
            *slot = Some(hash);
        }

        Self {
            hash: adv.hash,
            random_hash: adv.random_hash,
            compressed: adv.compressed,
            has_metadata: adv.has_metadata,
            request_id: adv.request_id.clone(),
            hashmap,
            hashmap_height,
            parts: (0..adv.num_parts).map(|_| None).collect(),
            requested: vec![false; adv.num_parts],
            received_count: 0,
            outstanding_parts: 0,
            completed_prefix: 0,
        }
    }

    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let h = hash_parts(&[data.as_slice(), self.random_hash.as_slice()]);
        let part_hash = [h[0], h[1], h[2], h[3]];

        let search_start = self.completed_prefix;
        let search_end = (search_start + WINDOW).min(self.hashmap_height);

        for i in search_start..search_end {
            if self.hashmap[i] == Some(part_hash) && self.parts[i].is_none() {
                self.parts[i] = Some(data);
                self.received_count += 1;
                self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                while self.completed_prefix < self.parts.len()
                    && self.parts[self.completed_prefix].is_some()
                {
                    self.completed_prefix += 1;
                }

                return true;
            }
        }

        false
    }

    pub fn receive_hashmap_update(&mut self, start_index: usize, data: &[u8]) {
        let new_hashes: Vec<[u8; MAPHASH_LEN]> = data
            .chunks_exact(MAPHASH_LEN)
            .map(|c| [c[0], c[1], c[2], c[3]])
            .collect();

        log::debug!(
            "HMU: received {} hashes at start_index={}, current height={}",
            new_hashes.len(),
            start_index,
            self.hashmap_height
        );

        for (index, hash) in (start_index..).zip(new_hashes) {
            if index < self.hashmap.len() {
                self.hashmap[index] = Some(hash);
            }
        }

        while self.hashmap_height < self.hashmap.len()
            && self.hashmap[self.hashmap_height].is_some()
        {
            self.hashmap_height += 1;
        }
    }

    pub fn needed_hashes(&mut self) -> (Vec<[u8; MAPHASH_LEN]>, bool) {
        let mut needed = Vec::new();
        let mut hashmap_exhausted = false;

        let search_start = self.completed_prefix;
        let search_end = (search_start + WINDOW).min(self.parts.len());

        for i in search_start..search_end {
            if self.parts[i].is_some() || self.requested[i] {
                continue;
            }
            if let Some(hash) = self.hashmap[i] {
                needed.push(hash);
                self.requested[i] = true;
                self.outstanding_parts += 1;
            } else {
                hashmap_exhausted = true;
                break;
            }

            if self.outstanding_parts >= WINDOW {
                break;
            }
        }

        (needed, hashmap_exhausted)
    }

    pub fn last_hashmap_hash(&self) -> Option<[u8; MAPHASH_LEN]> {
        self.hashmap_height
            .checked_sub(1)
            .and_then(|index| self.hashmap[index])
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.parts.len()
    }

    pub fn outstanding_parts(&self) -> usize {
        self.outstanding_parts
    }

    pub fn received_count(&self) -> usize {
        self.received_count
    }

    pub fn num_parts(&self) -> usize {
        self.parts.len()
    }

    pub fn assemble_segment(&self, link: &EstablishedLink) -> Option<(Vec<u8>, [u8; 32])> {
        if !self.is_complete() {
            log::warn!("Resource assemble_segment called but not complete");
            return None;
        }

        let encrypted: Vec<u8> = self
            .parts
            .iter()
            .filter_map(Option::as_ref)
            .flat_map(|data| data.iter().copied())
            .collect();

        let plaintext = match link.decrypt(&encrypted) {
            Some(p) => p,
            None => {
                log::warn!(
                    "Resource assemble_segment: stream decryption failed ({} bytes)",
                    encrypted.len()
                );
                return None;
            }
        };

        log::debug!(
            "Decrypted {} bytes, first 16: {:02x?}",
            plaintext.len(),
            &plaintext[..plaintext.len().min(16)]
        );

        if plaintext.len() < 4 {
            log::warn!(
                "Resource assemble_segment: plaintext too short ({})",
                plaintext.len()
            );
            return None;
        }
        let data = &plaintext[4..];

        let result = if self.compressed {
            match bz2_decompress(data) {
                Some(d) => d,
                None => {
                    log::warn!("Resource assemble_segment: bz2 decompression failed");
                    return None;
                }
            }
        } else {
            data.to_vec()
        };

        let calculated_hash = hash_parts(&[result.as_slice(), self.random_hash.as_slice()]);
        if calculated_hash != self.hash {
            log::warn!(
                "Resource assemble_segment: hash mismatch (calculated {} expected {})",
                hex::encode(calculated_hash),
                hex::encode(self.hash)
            );
            return None;
        }

        let proof = hash_parts(&[result.as_slice(), self.hash.as_slice()]);

        log::info!(
            "Segment {}/{} assembled: {} bytes compressed={}",
            1,
            1,
            result.len(),
            self.compressed
        );

        Some((result, proof))
    }
}

#[derive(Debug, Clone)]
pub struct ResourceAdvertisement {
    pub transfer_size: usize,
    pub data_size: usize,
    pub num_parts: usize,
    pub hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub original_hash: [u8; 32],
    pub segment_index: usize,
    pub total_segments: usize,
    pub hashmap: Vec<u8>,
    pub compressed: bool,
    pub has_metadata: bool,
    pub request_id: Option<Vec<u8>>,
}

impl ResourceAdvertisement {
    pub fn encode(&self) -> Vec<u8> {
        use rmpv::Value;

        let flags: u8 = (1 << 0)
            | if self.compressed { 1 << 1 } else { 0 }
            | if self.total_segments > 1 { 1 << 2 } else { 0 }
            | if self.request_id.is_some() { 1 << 4 } else { 0 }
            | if self.has_metadata { 1 << 5 } else { 0 };

        let pairs = vec![
            (
                Value::String("t".into()),
                Value::Integer((self.transfer_size as u64).into()),
            ),
            (
                Value::String("d".into()),
                Value::Integer((self.data_size as u64).into()),
            ),
            (
                Value::String("n".into()),
                Value::Integer((self.num_parts as u64).into()),
            ),
            (Value::String("h".into()), Value::Binary(self.hash.to_vec())),
            (
                Value::String("r".into()),
                Value::Binary(self.random_hash.to_vec()),
            ),
            (
                Value::String("o".into()),
                Value::Binary(self.original_hash.to_vec()),
            ),
            (
                Value::String("i".into()),
                Value::Integer((self.segment_index as u64).into()),
            ),
            (
                Value::String("l".into()),
                Value::Integer((self.total_segments as u64).into()),
            ),
            (
                Value::String("q".into()),
                match &self.request_id {
                    Some(id) => Value::Binary(id.clone()),
                    None => Value::Nil,
                },
            ),
            (Value::String("f".into()), Value::Integer(flags.into())),
            (
                Value::String("m".into()),
                Value::Binary(self.hashmap.clone()),
            ),
        ];

        let map = Value::Map(pairs);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &map).expect("encoding should not fail");
        buf
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let value: rmpv::Value = rmpv::decode::read_value(&mut &data[..]).ok()?;
        let map = value.as_map()?;

        let mut adv = Self {
            transfer_size: 0,
            data_size: 0,
            num_parts: 0,
            hash: [0u8; 32],
            random_hash: [0u8; 4],
            original_hash: [0u8; 32],
            segment_index: 1,
            total_segments: 1,
            hashmap: Vec::new(),
            compressed: false,
            has_metadata: false,
            request_id: None,
        };

        let mut response_flag = false;
        for (key, val) in map {
            let key_str = key.as_str()?;
            match key_str {
                "t" => adv.transfer_size = val.as_u64()? as usize,
                "d" => adv.data_size = val.as_u64()? as usize,
                "n" => adv.num_parts = val.as_u64()? as usize,
                "h" => adv.hash.copy_from_slice(val.as_slice()?.get(..32)?),
                "r" => adv.random_hash.copy_from_slice(val.as_slice()?.get(..4)?),
                "o" => adv
                    .original_hash
                    .copy_from_slice(val.as_slice()?.get(..32)?),
                "i" => adv.segment_index = val.as_u64()? as usize,
                "l" => adv.total_segments = val.as_u64()? as usize,
                "q" => {
                    if !val.is_nil() {
                        adv.request_id = Some(val.as_slice()?.to_vec());
                    }
                }
                "f" => {
                    let flags = val.as_u64()? as u8;
                    adv.compressed = (flags & (1 << 1)) != 0;
                    response_flag = (flags & (1 << 4)) != 0;
                    adv.has_metadata = (flags & (1 << 5)) != 0;
                }
                "m" => {
                    adv.hashmap = val.as_slice()?.to_vec();
                }
                _ => {}
            }
        }

        if response_flag != adv.request_id.is_some() {
            log::warn!("ResourceAdv response flag and request ID disagree");
            return None;
        }
        if adv.num_parts == 0
            || adv.segment_index != 1
            || adv.total_segments != 1
            || adv.hashmap.len() > adv.num_parts * MAPHASH_LEN
            || !adv.hashmap.len().is_multiple_of(MAPHASH_LEN)
        {
            return None;
        }
        Some(adv)
    }
}

fn bz2_compress(data: &[u8]) -> Option<Vec<u8>> {
    use bzip2::Compression;
    use bzip2::read::BzEncoder;
    use std::io::Read;

    let mut encoder = BzEncoder::new(data, Compression::best());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).ok()?;
    if compressed.len() < data.len() {
        Some(compressed)
    } else {
        None
    }
}

fn bz2_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use bzip2::read::BzDecoder;
    use std::io::Read;

    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).ok()?;
    Some(decompressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_roundtrip() {
        let adv = ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            hash: [1u8; 32],
            random_hash: [2u8; 4],
            original_hash: [3u8; 32],
            segment_index: 1,
            total_segments: 1,
            hashmap: vec![0, 1, 2, 3, 4, 5, 6, 7],
            compressed: true,
            has_metadata: false,
            request_id: Some(vec![0xaa; 16]),
        };

        let encoded = adv.encode();
        let decoded = ResourceAdvertisement::decode(&encoded).unwrap();

        assert_eq!(decoded.transfer_size, adv.transfer_size);
        assert_eq!(decoded.data_size, adv.data_size);
        assert_eq!(decoded.num_parts, adv.num_parts);
        assert_eq!(decoded.hash, adv.hash);
        assert_eq!(decoded.random_hash, adv.random_hash);
        assert_eq!(decoded.original_hash, adv.original_hash);
        assert_eq!(decoded.segment_index, adv.segment_index);
        assert_eq!(decoded.total_segments, adv.total_segments);
        assert_eq!(decoded.hashmap, adv.hashmap);
        assert_eq!(decoded.compressed, adv.compressed);
        assert_eq!(decoded.has_metadata, adv.has_metadata);
        assert_eq!(decoded.request_id, adv.request_id);
    }

    #[test]
    fn out_of_order_hashmap_updates() {
        let adv = ResourceAdvertisement {
            transfer_size: 50000,
            data_size: 49000,
            num_parts: 200,
            hash: [1u8; 32],
            random_hash: [2u8; 4],
            original_hash: [3u8; 32],
            segment_index: 1,
            total_segments: 1,
            hashmap: vec![0xAA; HASHMAP_MAX_LEN * MAPHASH_LEN],
            compressed: false,
            has_metadata: false,
            request_id: None,
        };

        let mut resource = InboundResource::from_advertisement(&adv);
        assert_eq!(resource.hashmap_height, HASHMAP_MAX_LEN);

        let segment2_start = 2 * HASHMAP_MAX_LEN;
        let segment2_hashes: Vec<u8> = vec![0xCC; 52 * MAPHASH_LEN];
        resource.receive_hashmap_update(segment2_start, &segment2_hashes);

        assert_eq!(
            resource.hashmap_height, HASHMAP_MAX_LEN,
            "hashmap_height should stay at {} when segment 1 is missing",
            HASHMAP_MAX_LEN
        );

        assert_eq!(resource.hashmap[segment2_start], Some([0xCC; 4]));

        let segment1_start = HASHMAP_MAX_LEN;
        let segment1_hashes: Vec<u8> = vec![0xBB; HASHMAP_MAX_LEN * MAPHASH_LEN];
        resource.receive_hashmap_update(segment1_start, &segment1_hashes);

        assert_eq!(
            resource.hashmap_height, 200,
            "hashmap_height should advance to cover all segments"
        );

        assert_eq!(resource.hashmap[0], Some([0xAA; 4]));
        assert_eq!(resource.hashmap[HASHMAP_MAX_LEN], Some([0xBB; 4]));
        assert_eq!(resource.hashmap[segment2_start], Some([0xCC; 4]));
    }

    #[test]
    fn advertisement_rejects_multiple_segments() {
        let adv = ResourceAdvertisement {
            transfer_size: 2000000,
            data_size: 1900000,
            num_parts: 100,
            hash: [0xAAu8; 32],
            random_hash: [0xBBu8; 4],
            original_hash: [0xCCu8; 32],
            segment_index: 3,
            total_segments: 5,
            hashmap: vec![0xDD; 40],
            compressed: true,
            has_metadata: true,
            request_id: Some(vec![0xEE; 16]),
        };

        let encoded = adv.encode();
        assert!(ResourceAdvertisement::decode(&encoded).is_none());
    }
}
