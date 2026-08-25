use crate::crypto::sha256;
use crate::link::EstablishedLink;
use rand::RngCore;
use std::time::Instant;

pub(crate) const MAPHASH_LEN: usize = 4;
pub(crate) const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub(crate) const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;
pub(crate) const HASHMAP_MAX_LEN: usize = 74; // floor((Link.MDU - 134) / MAPHASH_LEN)

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

pub(crate) const MAX_EFFICIENT_SIZE: usize = 1024 * 1024 - 1;

pub(crate) struct OutboundResource {
    pub hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub original_hash: [u8; 32],
    expected_proof: [u8; 32],
    has_metadata: bool,
    pub compressed: bool,
    pub is_response: bool,
    pub segment_index: usize,
    pub total_segments: usize,
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
        is_response: bool,
        request_id: Option<Vec<u8>>,
        segment_index: usize,
        original_hash: Option<[u8; 32]>,
        total_data_size: Option<usize>,
    ) -> Self {
        let metadata_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        let has_metadata = metadata.is_some();
        let total_size = total_data_size.unwrap_or(data.len()) + metadata_size;
        let total_segments = if total_size <= MAX_EFFICIENT_SIZE {
            1
        } else {
            (total_size - 1) / MAX_EFFICIENT_SIZE + 1
        };

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

        // Second random hash: used for hashmap and verification (goes in advertisement)
        let mut random_hash = [0u8; 4];
        rng.fill_bytes(&mut random_hash);

        // hash = SHA256(original_data + random_hash) - always over uncompressed original
        let mut hash_input = data.clone();
        hash_input.extend(&random_hash);
        let hash: [u8; 32] = sha256(&hash_input);

        // original_hash is the hash of the first segment (used to correlate segments)
        let original_hash = original_hash.unwrap_or(hash);

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
            original_hash,
            expected_proof,
            has_metadata,
            compressed,
            is_response,
            segment_index,
            total_segments,
            request_id,
            parts,
            hashmap,
            hashmap_sent: 0,
        }
    }

    pub fn is_last_segment(&self) -> bool {
        self.segment_index == self.total_segments
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
        ResourceAdvertisement {
            transfer_size: self.transfer_size(),
            data_size: self.parts.iter().map(|p| p.len()).sum(),
            num_parts: self.parts.len(),
            hash: self.hash,
            random_hash: self.random_hash,
            original_hash: self.original_hash,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            hashmap: hashmap_chunk,
            compressed: self.compressed,
            split: self.total_segments > 1,
            is_request: false,
            is_response: self.is_response,
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
    pub original_hash: [u8; 32],
    pub compressed: bool,
    pub is_response: bool,
    pub has_metadata: bool,
    pub segment_index: usize,
    pub total_segments: usize,
    pub request_id: Option<Vec<u8>>,
    num_parts: usize,
    hashmap: Vec<Option<[u8; MAPHASH_LEN]>>,
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
    completed_prefix: usize,
    bytes_received: usize,
    #[cfg(test)]
    total_bytes: usize,
    bytes_at_req_sent: usize,
    fast_rate_rounds: usize,
    very_slow_rate_rounds: usize,
    req_sent: Option<Instant>,
}

impl InboundResource {
    pub fn from_advertisement(adv: &ResourceAdvertisement) -> Self {
        let mut hashmap: Vec<Option<[u8; MAPHASH_LEN]>> = vec![None; adv.num_parts];
        let hashmap_height = adv.hashmap.chunks_exact(MAPHASH_LEN).count();
        for (slot, hash) in hashmap
            .iter_mut()
            .zip(adv.hashmap.chunks_exact(MAPHASH_LEN))
        {
            *slot = Some(hash.try_into().unwrap());
        }

        Self {
            hash: adv.hash,
            random_hash: adv.random_hash,
            original_hash: adv.original_hash,
            compressed: adv.compressed,
            is_response: adv.is_response,
            has_metadata: adv.has_metadata,
            segment_index: adv.segment_index,
            total_segments: adv.total_segments,
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
            completed_prefix: 0,
            bytes_received: 0,
            #[cfg(test)]
            total_bytes: adv.transfer_size,
            bytes_at_req_sent: 0,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            req_sent: None,
        }
    }

    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let mut hasher_input = data.to_vec();
        hasher_input.extend(&self.random_hash);
        let h = sha256(&hasher_input);
        let part_hash = [h[0], h[1], h[2], h[3]];

        // Must align with needed_hashes() which uses cch+1 as start
        let search_start = self.completed_prefix;
        let search_end = (search_start + self.window).min(self.hashmap_height);

        for i in search_start..search_end {
            if self.hashmap[i] == Some(part_hash) && self.parts[i].is_none() {
                self.bytes_received += data.len();
                self.parts[i] = Some(data);
                self.received_count += 1;
                self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                // Update consecutive completed height
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
        // Write hashes at the specified start index
        for (i, hash) in data.chunks_exact(MAPHASH_LEN).enumerate() {
            let idx = start_index + i;
            if idx < self.hashmap.len() {
                self.hashmap[idx] = Some(hash.try_into().unwrap());
            }
        }

        // Recalculate hashmap_height: highest contiguous filled index
        // This makes HMU order-independent - same end state regardless of arrival order
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
        let search_end = (search_start + self.window).min(self.parts.len());

        for i in search_start..search_end {
            // Skip parts we've already received or requested
            if self.parts[i].is_some() || self.requested[i] {
                continue;
            }

            // Check if we have the hash for this part (like Python's `if part_hash != None`)
            if let Some(hash) = self.hashmap[i] {
                needed.push(hash);
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

        (needed, hashmap_exhausted)
    }

    pub fn last_hashmap_hash(&self) -> Option<[u8; MAPHASH_LEN]> {
        self.hashmap_height
            .checked_sub(1)
            .and_then(|index| self.hashmap[index])
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.num_parts
    }

    pub fn batch_complete(&self) -> bool {
        // A batch is complete when we've received batch_window parts since last batch
        self.received_count - self.last_batch_received_count >= self.batch_window
    }

    #[cfg(test)]
    pub fn received_count(&self) -> usize {
        self.received_count
    }

    #[cfg(test)]
    pub fn num_parts(&self) -> usize {
        self.num_parts
    }

    #[cfg(test)]
    pub fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn is_last_segment(&self) -> bool {
        self.segment_index == self.total_segments
    }

    pub fn assemble_segment(&self, link: &EstablishedLink) -> Option<(Vec<u8>, [u8; 32])> {
        if !self.is_complete() {
            return None;
        }

        let encrypted: Vec<u8> = self.parts.iter().flatten().flatten().copied().collect();

        let plaintext = link.decrypt(&encrypted)?;

        if plaintext.len() < 4 {
            return None;
        }
        let data = &plaintext[4..];

        let result = if self.compressed {
            bz2_decompress(data)?
        } else {
            data.to_vec()
        };

        let mut hash_input = result.clone();
        hash_input.extend(&self.random_hash);
        let calculated_hash = sha256(&hash_input);
        if calculated_hash != self.hash {
            return None;
        }

        let mut proof_input = result.clone();
        proof_input.extend(&self.hash);
        let proof = sha256(&proof_input);

        Some((result, proof))
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

            if rate > RATE_FAST && self.fast_rate_rounds < FAST_RATE_THRESHOLD {
                self.fast_rate_rounds += 1;
                if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                    self.window_max = WINDOW_MAX_FAST;
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

        let field = |key: &'static str, value| (Value::String(key.into()), value);
        let map = Value::Map(vec![
            field("t", Value::from(self.transfer_size as u64)),
            field("d", Value::from(self.data_size as u64)),
            field("n", Value::from(self.num_parts as u64)),
            field("h", Value::Binary(self.hash.to_vec())),
            field("r", Value::Binary(self.random_hash.to_vec())),
            field("o", Value::Binary(self.original_hash.to_vec())),
            field("i", Value::from(self.segment_index as u64)),
            field("l", Value::from(self.total_segments as u64)),
            field(
                "q",
                self.request_id.clone().map_or(Value::Nil, Value::Binary),
            ),
            field("f", Value::from(flags)),
            field("m", Value::Binary(self.hashmap.clone())),
        ]);
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

        for (key, value) in map {
            match key.as_str()? {
                "t" => adv.transfer_size = value.as_u64()? as usize,
                "d" => adv.data_size = value.as_u64()? as usize,
                "n" => adv.num_parts = value.as_u64()? as usize,
                "h" => adv.hash.copy_from_slice(value.as_slice()?.get(..32)?),
                "r" => adv.random_hash.copy_from_slice(value.as_slice()?.get(..4)?),
                "o" => adv
                    .original_hash
                    .copy_from_slice(value.as_slice()?.get(..32)?),
                "i" => adv.segment_index = value.as_u64()? as usize,
                "l" => adv.total_segments = value.as_u64()? as usize,
                "q" if !value.is_nil() => adv.request_id = Some(value.as_slice()?.to_vec()),
                "f" => {
                    let flags = value.as_u64()? as u8;
                    adv.compressed = (flags & (1 << 1)) != 0;
                    adv.split = (flags & (1 << 2)) != 0;
                    adv.is_request = (flags & (1 << 3)) != 0;
                    adv.is_response = (flags & (1 << 4)) != 0;
                    adv.has_metadata = (flags & (1 << 5)) != 0;
                }
                "m" => adv.hashmap = value.as_slice()?.to_vec(),
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
            hashmap: vec![0xAA; HASHMAP_MAX_LEN * MAPHASH_LEN], // segment 0
            compressed: false,
            split: false,
            is_request: false,
            is_response: false,
            has_metadata: false,
            request_id: None,
        };

        let mut resource = InboundResource::from_advertisement(&adv);
        assert_eq!(resource.hashmap_height, HASHMAP_MAX_LEN);

        // Segment 2 arrives before segment 1 (out of order)
        let segment2_start = 2 * HASHMAP_MAX_LEN;
        let segment2_hashes: Vec<u8> = vec![0xCC; 52 * MAPHASH_LEN]; // 52 hashes for segment 2
        resource.receive_hashmap_update(segment2_start, &segment2_hashes);

        // hashmap_height should NOT advance - there's a gap at segment 1
        assert_eq!(
            resource.hashmap_height, HASHMAP_MAX_LEN,
            "hashmap_height should stay at {} when segment 1 is missing",
            HASHMAP_MAX_LEN
        );

        // Verify segment 2 hashes are stored correctly
        assert_eq!(resource.hashmap[segment2_start], Some([0xCC; 4]));

        // Now segment 1 arrives
        let segment1_start = HASHMAP_MAX_LEN;
        let segment1_hashes: Vec<u8> = vec![0xBB; HASHMAP_MAX_LEN * MAPHASH_LEN];
        resource.receive_hashmap_update(segment1_start, &segment1_hashes);

        // Now hashmap_height should jump to include both segments
        assert_eq!(
            resource.hashmap_height,
            200, // all parts now have hashes
            "hashmap_height should advance to cover all segments"
        );

        // Verify all hashes are in correct positions
        assert_eq!(resource.hashmap[0], Some([0xAA; 4])); // segment 0
        assert_eq!(resource.hashmap[HASHMAP_MAX_LEN], Some([0xBB; 4])); // segment 1
        assert_eq!(resource.hashmap[segment2_start], Some([0xCC; 4])); // segment 2
    }

    #[test]
    fn is_last_segment_single_segment() {
        let adv = ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            hash: [1u8; 32],
            random_hash: [2u8; 4],
            original_hash: [1u8; 32],
            segment_index: 1,
            total_segments: 1,
            hashmap: vec![0; 12],
            compressed: false,
            split: false,
            is_request: false,
            is_response: true,
            has_metadata: false,
            request_id: Some(vec![0xaa; 16]),
        };

        let resource = InboundResource::from_advertisement(&adv);
        assert!(resource.is_last_segment());
        assert_eq!(resource.segment_index, 1);
        assert_eq!(resource.total_segments, 1);
    }

    #[test]
    fn is_last_segment_multi_segment_first() {
        let adv = ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            hash: [1u8; 32],
            random_hash: [2u8; 4],
            original_hash: [0u8; 32],
            segment_index: 1,
            total_segments: 3,
            hashmap: vec![0; 12],
            compressed: false,
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: true,
            request_id: Some(vec![0xaa; 16]),
        };

        let resource = InboundResource::from_advertisement(&adv);
        assert!(!resource.is_last_segment());
        assert_eq!(resource.segment_index, 1);
        assert_eq!(resource.total_segments, 3);
        assert!(resource.has_metadata);
    }

    #[test]
    fn is_last_segment_multi_segment_middle() {
        let adv = ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            hash: [2u8; 32],
            random_hash: [2u8; 4],
            original_hash: [0u8; 32],
            segment_index: 2,
            total_segments: 3,
            hashmap: vec![0; 12],
            compressed: false,
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: false,
            request_id: Some(vec![0xaa; 16]),
        };

        let resource = InboundResource::from_advertisement(&adv);
        assert!(!resource.is_last_segment());
        assert_eq!(resource.segment_index, 2);
        assert_eq!(resource.total_segments, 3);
    }

    #[test]
    fn is_last_segment_multi_segment_last() {
        let adv = ResourceAdvertisement {
            transfer_size: 1000,
            data_size: 950,
            num_parts: 3,
            hash: [3u8; 32],
            random_hash: [2u8; 4],
            original_hash: [0u8; 32],
            segment_index: 3,
            total_segments: 3,
            hashmap: vec![0; 12],
            compressed: false,
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: false,
            request_id: Some(vec![0xaa; 16]),
        };

        let resource = InboundResource::from_advertisement(&adv);
        assert!(resource.is_last_segment());
        assert_eq!(resource.segment_index, 3);
        assert_eq!(resource.total_segments, 3);
    }

    #[test]
    fn from_advertisement_copies_segment_fields() {
        let adv = ResourceAdvertisement {
            transfer_size: 5000,
            data_size: 4800,
            num_parts: 10,
            hash: [0x11u8; 32],
            random_hash: [0x22u8; 4],
            original_hash: [0x33u8; 32],
            segment_index: 2,
            total_segments: 5,
            hashmap: vec![0; 40],
            compressed: true,
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: true,
            request_id: Some(vec![0xbb; 16]),
        };

        let resource = InboundResource::from_advertisement(&adv);
        assert_eq!(resource.hash, adv.hash);
        assert_eq!(resource.random_hash, adv.random_hash);
        assert_eq!(resource.original_hash, adv.original_hash);
        assert_eq!(resource.segment_index, 2);
        assert_eq!(resource.total_segments, 5);
        assert!(resource.compressed);
        assert!(resource.is_response);
        assert!(resource.has_metadata);
    }

    #[test]
    fn advertisement_roundtrip_multi_segment() {
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
            split: true,
            is_request: false,
            is_response: true,
            has_metadata: true,
            request_id: Some(vec![0xEE; 16]),
        };

        let encoded = adv.encode();
        let decoded = ResourceAdvertisement::decode(&encoded).unwrap();

        assert_eq!(decoded.segment_index, 3);
        assert_eq!(decoded.total_segments, 5);
        assert_eq!(decoded.original_hash, [0xCCu8; 32]);
        assert!(decoded.split);
        assert!(decoded.has_metadata);
    }
}
