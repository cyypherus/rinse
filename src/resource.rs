use crate::crypto::sha256;
use crate::link::EstablishedLink;
use rand::RngCore;
use std::time::Instant;

pub(crate) const MAPHASH_LEN: usize = 4;
pub(crate) const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub(crate) const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

const WINDOW_DEFAULT: usize = 4;
const WINDOW_MIN: usize = 2;
pub(crate) const WINDOW_MAX_SLOW: usize = 10;
const WINDOW_MAX_VERY_SLOW: usize = 4;
const WINDOW_MAX_FAST: usize = 75;

const FAST_RATE_THRESHOLD: usize = 4; // WINDOW_MAX_SLOW - WINDOW - 2 = 10 - 4 - 2 = 4
const VERY_SLOW_RATE_THRESHOLD: usize = 2;
const WINDOW_FLEXIBILITY: usize = 4;

const RATE_FAST: f64 = 6250.0; // (50*1000) / 8 bytes/sec
const RATE_VERY_SLOW: f64 = 250.0; // (2*1000) / 8 bytes/sec

const SDU: usize = 470;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceStatus {
    Queued,
    Advertised,
    Transferring,
}

pub(crate) struct OutboundResource {
    pub hash: [u8; 32],
    pub random_hash: [u8; 4],
    expected_proof: [u8; 32],
    pub status: ResourceStatus,
    pub metadata: Option<Vec<u8>>,
    pub compressed: bool,
    pub is_response: bool,
    pub request_id: Option<Vec<u8>>,
    parts: Vec<Vec<u8>>,
    hashmap: Vec<[u8; MAPHASH_LEN]>,
    hashmap_sent: usize,
}

impl OutboundResource {
    pub fn new<R: RngCore>(
        rng: &mut R,
        link: &EstablishedLink,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
        is_response: bool,
        request_id: Option<Vec<u8>>,
    ) -> Self {
        // Compress for transmission if beneficial
        let (to_send, compressed) = if compress {
            if let Some(compressed_data) = bz2_compress(&data) {
                (compressed_data, true)
            } else {
                (data.clone(), false)
            }
        } else {
            (data.clone(), false)
        };

        // First random hash: prepended to data before encryption (discarded on receive)
        let mut encryption_padding = [0u8; 4];
        rng.fill_bytes(&mut encryption_padding);

        let mut plaintext = encryption_padding.to_vec();
        plaintext.extend(&to_send);

        let encrypted = link.encrypt(rng, &plaintext);
        let parts: Vec<Vec<u8>> = encrypted.chunks(SDU).map(|c| c.to_vec()).collect();

        // Second random hash: used for hashmap and verification (goes in advertisement)
        let mut random_hash = [0u8; 4];
        rng.fill_bytes(&mut random_hash);

        // hash = SHA256(original_data + random_hash) - always over uncompressed original
        let mut hash_input = data.clone();
        hash_input.extend(&random_hash);
        let hash: [u8; 32] = sha256(&hash_input);

        // expected_proof = SHA256(original_data + hash) - always over uncompressed original
        let mut proof_input = data;
        proof_input.extend(&hash);
        let expected_proof: [u8; 32] = sha256(&proof_input);

        let hashmap: Vec<[u8; MAPHASH_LEN]> = parts
            .iter()
            .map(|p| {
                let mut hasher_input = p.clone();
                hasher_input.extend(&random_hash);
                let h = sha256(&hasher_input);
                [h[0], h[1], h[2], h[3]]
            })
            .collect();

        Self {
            hash,
            random_hash,
            expected_proof,
            status: ResourceStatus::Queued,
            metadata,
            compressed,
            is_response,
            request_id,
            parts,
            hashmap,
            hashmap_sent: 0,
        }
    }

    pub fn transfer_size(&self) -> usize {
        self.parts.iter().map(|p| p.len()).sum()
    }

    pub fn get_part(&self, hash: &[u8; MAPHASH_LEN]) -> Option<&[u8]> {
        self.hashmap
            .iter()
            .position(|h| h == hash)
            .map(|i| self.parts[i].as_slice())
    }

    pub fn advertisement(&mut self, max_hashmap_len: usize) -> ResourceAdvertisement {
        let hashmap_chunk: Vec<u8> = self.hashmap[..self.hashmap.len().min(max_hashmap_len)]
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        self.hashmap_sent = hashmap_chunk.len() / MAPHASH_LEN;
        self.status = ResourceStatus::Advertised;

        ResourceAdvertisement {
            transfer_size: self.transfer_size(),
            data_size: self.parts.iter().map(|p| p.len()).sum(),
            num_parts: self.parts.len(),
            hash: self.hash,
            random_hash: self.random_hash,
            original_hash: self.hash, // Same as hash for non-segmented resources
            segment_index: 1,
            total_segments: 1,
            hashmap: hashmap_chunk,
            compressed: self.compressed,
            split: false,
            is_request: false,
            is_response: self.is_response,
            has_metadata: self.metadata.is_some(),
            request_id: self.request_id.clone(),
        }
    }

    pub fn hashmap_update(&mut self, max_len: usize) -> Option<Vec<u8>> {
        if self.hashmap_sent >= self.hashmap.len() {
            return None;
        }
        let end = (self.hashmap_sent + max_len).min(self.hashmap.len());
        let chunk: Vec<u8> = self.hashmap[self.hashmap_sent..end]
            .iter()
            .flat_map(|h| h.iter().copied())
            .collect();
        self.hashmap_sent = end;
        Some(chunk)
    }

    pub fn mark_transferring(&mut self) {
        self.status = ResourceStatus::Transferring;
    }

    pub fn verify_proof(&self, proof: &[u8]) -> bool {
        proof == self.expected_proof
    }
}

pub(crate) struct InboundResource {
    pub hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub status: ResourceStatus,
    pub compressed: bool,
    pub is_response: bool,
    pub request_id: Option<Vec<u8>>,
    num_parts: usize,
    hashmap: Vec<[u8; MAPHASH_LEN]>,
    hashmap_height: usize,
    parts: Vec<Option<Vec<u8>>>,
    requested: Vec<bool>,
    received_count: usize,
    outstanding_parts: usize,
    last_batch_received_count: usize,
    batch_window: usize,
    pub(crate) window: usize,
    pub(crate) window_max: usize,
    pub(crate) window_min: usize,
    waiting_for_hmu: bool,
    consecutive_completed_height: i32,
    bytes_received: usize,
    bytes_at_req_sent: usize,
    fast_rate_rounds: usize,
    very_slow_rate_rounds: usize,
    req_sent: Option<Instant>,
}

impl InboundResource {
    pub fn from_advertisement(adv: &ResourceAdvertisement) -> Self {
        let received_hashes: Vec<[u8; MAPHASH_LEN]> = adv
            .hashmap
            .chunks_exact(MAPHASH_LEN)
            .map(|c| [c[0], c[1], c[2], c[3]])
            .collect();

        let hashmap_height = received_hashes.len();

        let mut hashmap = vec![[0u8; MAPHASH_LEN]; adv.num_parts];
        for (i, hash) in received_hashes.iter().enumerate() {
            if i < hashmap.len() {
                hashmap[i] = *hash;
            }
        }

        Self {
            hash: adv.hash,
            random_hash: adv.random_hash,
            status: ResourceStatus::Queued,
            compressed: adv.compressed,
            is_response: adv.is_response,
            request_id: adv.request_id.clone(),
            num_parts: adv.num_parts,
            hashmap,
            hashmap_height,
            parts: vec![None; adv.num_parts],
            requested: vec![false; adv.num_parts],
            received_count: 0,
            outstanding_parts: 0,
            last_batch_received_count: 0,
            batch_window: WINDOW_DEFAULT,
            window: WINDOW_DEFAULT,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            waiting_for_hmu: false,
            consecutive_completed_height: -1,
            bytes_received: 0,
            bytes_at_req_sent: 0,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            req_sent: None,
        }
    }

    fn get_map_hash(&self, data: &[u8]) -> [u8; MAPHASH_LEN] {
        let mut hasher_input = data.to_vec();
        hasher_input.extend(&self.random_hash);
        let h = sha256(&hasher_input);
        [h[0], h[1], h[2], h[3]]
    }

    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let part_hash = self.get_map_hash(&data);

        let search_start = if self.consecutive_completed_height >= 0 {
            self.consecutive_completed_height as usize
        } else {
            0
        };
        let search_end = (search_start + self.window).min(self.hashmap_height);

        for i in search_start..search_end {
            if i < self.hashmap.len() && self.hashmap[i] == part_hash && self.parts[i].is_none() {
                self.bytes_received += data.len();
                self.parts[i] = Some(data);
                self.received_count += 1;
                self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                // Update consecutive completed height
                if i as i32 == self.consecutive_completed_height + 1 {
                    self.consecutive_completed_height = i as i32;
                }

                // Advance consecutive height past any already-received parts
                let mut cp = (self.consecutive_completed_height + 1) as usize;
                while cp < self.parts.len() && self.parts[cp].is_some() {
                    self.consecutive_completed_height = cp as i32;
                    cp += 1;
                }

                return true;
            }
        }
        false
    }

    pub fn receive_hashmap_update(&mut self, data: &[u8]) {
        let new_hashes: Vec<[u8; MAPHASH_LEN]> = data
            .chunks_exact(MAPHASH_LEN)
            .map(|c| [c[0], c[1], c[2], c[3]])
            .collect();

        for (i, hash) in new_hashes.iter().enumerate() {
            let idx = self.hashmap_height + i;
            if idx < self.hashmap.len() {
                self.hashmap[idx] = *hash;
            }
        }
        self.hashmap_height += new_hashes.len();
        self.waiting_for_hmu = false;
    }

    pub fn needed_hashes(&mut self) -> (Vec<[u8; MAPHASH_LEN]>, bool) {
        let mut needed = Vec::new();
        let mut hashmap_exhausted = false;

        let search_start = (self.consecutive_completed_height + 1) as usize;
        let search_end = (search_start + self.window).min(self.parts.len());

        for i in search_start..search_end {
            // Skip parts we've already received or requested
            if self.parts[i].is_some() || self.requested[i] {
                continue;
            }

            if i < self.hashmap_height {
                needed.push(self.hashmap[i]);
                self.requested[i] = true;
                self.outstanding_parts += 1;
            } else {
                hashmap_exhausted = true;
                break;
            }

            if self.outstanding_parts >= self.window {
                break;
            }
        }

        if hashmap_exhausted {
            self.waiting_for_hmu = true;
        }

        (needed, hashmap_exhausted)
    }

    pub fn last_hashmap_hash(&self) -> Option<[u8; MAPHASH_LEN]> {
        if self.hashmap_height > 0 {
            Some(self.hashmap[self.hashmap_height - 1])
        } else {
            None
        }
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.num_parts
    }

    pub fn outstanding_parts(&self) -> usize {
        self.outstanding_parts
    }

    pub fn batch_complete(&self) -> bool {
        // A batch is complete when we've received batch_window parts since last batch
        self.received_count - self.last_batch_received_count >= self.batch_window
    }

    pub fn received_count(&self) -> usize {
        self.received_count
    }

    pub fn num_parts(&self) -> usize {
        self.num_parts
    }

    pub fn assemble(&self, link: &EstablishedLink) -> Option<(Vec<u8>, [u8; 32])> {
        if !self.is_complete() {
            log::warn!("Resource assemble called but not complete");
            return None;
        }

        let encrypted: Vec<u8> = self
            .parts
            .iter()
            .filter_map(|p| p.as_ref())
            .flat_map(|p| p.iter().copied())
            .collect();

        log::debug!(
            "Assembling resource: {} parts, {} encrypted bytes",
            self.parts.len(),
            encrypted.len()
        );

        let plaintext = match link.decrypt(&encrypted) {
            Some(p) => p,
            None => {
                log::warn!(
                    "Resource assemble: stream decryption failed ({} bytes)",
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

        // Strip off 4-byte random padding (not verified - just discarded like Python does)
        if plaintext.len() < 4 {
            log::warn!(
                "Resource assemble: plaintext too short ({})",
                plaintext.len()
            );
            return None;
        }
        let data = &plaintext[4..];

        let result = if self.compressed {
            match bz2_decompress(data) {
                Some(d) => d,
                None => {
                    log::warn!("Resource assemble: bz2 decompression failed");
                    return None;
                }
            }
        } else {
            data.to_vec()
        };

        // Verify hash = SHA256(plaintext + random_hash)
        let mut hash_input = result.clone();
        hash_input.extend(&self.random_hash);
        let calculated_hash = sha256(&hash_input);
        if calculated_hash != self.hash {
            log::warn!(
                "Resource assemble: hash mismatch (calculated {} expected {})",
                hex::encode(calculated_hash),
                hex::encode(self.hash)
            );
            return None;
        }

        // Compute proof = SHA256(plaintext + hash)
        let mut proof_input = result.clone();
        proof_input.extend(&self.hash);
        let proof = sha256(&proof_input);

        log::info!(
            "Resource assembled successfully: {} bytes decompressed={}",
            result.len(),
            self.compressed
        );

        Some((result, proof))
    }

    pub fn mark_transferring(&mut self) {
        self.status = ResourceStatus::Transferring;
    }

    pub fn mark_req_sent(&mut self, now: Instant) {
        // Only mark if this is the start of a new batch (req_sent is None)
        // With pipelining, we send requests frequently but only measure rate per batch
        if self.req_sent.is_none() {
            self.bytes_at_req_sent = self.bytes_received;
            self.req_sent = Some(now);
        }
    }

    pub fn complete_batch(&mut self, now: Instant) {
        // Mark batch as complete, record current window for next batch BEFORE growth
        self.last_batch_received_count = self.received_count;
        self.batch_window = self.window;

        // Grow window (after recording batch_window)
        if self.window < self.window_max {
            self.window += 1;
            // window_min trails window by at most WINDOW_FLEXIBILITY-1
            if (self.window - self.window_min) > (WINDOW_FLEXIBILITY - 1) {
                self.window_min += 1;
            }
        }

        // Calculate rate if we have a request timestamp
        if let Some(req_sent) = self.req_sent {
            let rtt = now.duration_since(req_sent);
            let rtt_secs = rtt.as_secs_f64();
            let bytes_this_batch = self.bytes_received - self.bytes_at_req_sent;
            let rate = if rtt_secs > 0.0 {
                bytes_this_batch as f64 / rtt_secs
            } else {
                0.0
            };

            log::debug!(
                "complete_batch: rtt={:.4}s bytes={} rate={:.0} B/s fast_rounds={} window_max={}",
                rtt_secs,
                bytes_this_batch,
                rate,
                self.fast_rate_rounds,
                self.window_max
            );

            if rate > RATE_FAST && self.fast_rate_rounds < FAST_RATE_THRESHOLD {
                self.fast_rate_rounds += 1;
                log::debug!("Fast rate detected, fast_rate_rounds={}", self.fast_rate_rounds);
                if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                    self.window_max = WINDOW_MAX_FAST;
                    log::debug!("Reached fast threshold, window_max={}", self.window_max);
                }
            }

            if self.fast_rate_rounds == 0
                && rate < RATE_VERY_SLOW
                && self.very_slow_rate_rounds < VERY_SLOW_RATE_THRESHOLD
            {
                self.very_slow_rate_rounds += 1;
                if self.very_slow_rate_rounds == VERY_SLOW_RATE_THRESHOLD {
                    self.window_max = WINDOW_MAX_VERY_SLOW;
                }
            }

            // Reset for next batch
            self.req_sent = None;
        }
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
    pub split: bool,
    pub is_request: bool,
    pub is_response: bool,
    pub has_metadata: bool,
    pub request_id: Option<Vec<u8>>,
}

impl ResourceAdvertisement {
    pub fn encode(&self) -> Vec<u8> {
        use rmpv::Value;

        let flags: u8 = (1 << 0)  // encrypted (always)
            | if self.compressed { 1 << 1 } else { 0 }
            | if self.split { 1 << 2 } else { 0 }
            | if self.is_request { 1 << 3 } else { 0 }
            | if self.is_response { 1 << 4 } else { 0 }
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
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
            request_id: None,
        };

        for (key, val) in map {
            let key_str = key.as_str()?;
            match key_str {
                "t" => adv.transfer_size = val.as_u64()? as usize,
                "d" => adv.data_size = val.as_u64()? as usize,
                "n" => adv.num_parts = val.as_u64()? as usize,
                "h" => {
                    let bytes = val.as_slice()?;
                    if bytes.len() >= 32 {
                        adv.hash.copy_from_slice(&bytes[..32]);
                    }
                }
                "r" => {
                    let bytes = val.as_slice()?;
                    if bytes.len() >= 4 {
                        adv.random_hash.copy_from_slice(&bytes[..4]);
                    }
                }
                "o" => {
                    let bytes = val.as_slice()?;
                    if bytes.len() >= 32 {
                        adv.original_hash.copy_from_slice(&bytes[..32]);
                    }
                }
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
                    adv.split = (flags & (1 << 2)) != 0;
                    adv.is_request = (flags & (1 << 3)) != 0;
                    adv.is_response = (flags & (1 << 4)) != 0;
                    adv.has_metadata = (flags & (1 << 5)) != 0;
                }
                "m" => {
                    adv.hashmap = val.as_slice()?.to_vec();
                }
                _ => {}
            }
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
            split: false,
            is_request: false,
            is_response: true,
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
        assert_eq!(decoded.split, adv.split);
        assert_eq!(decoded.is_request, adv.is_request);
        assert_eq!(decoded.is_response, adv.is_response);
        assert_eq!(decoded.has_metadata, adv.has_metadata);
        assert_eq!(decoded.request_id, adv.request_id);
    }
}
