use crate::crypto::sha256;
use crate::link::EstablishedLink;
use rand::RngCore;

pub(crate) const MAPHASH_LEN: usize = 4;
const WINDOW_MIN: usize = 2;
const WINDOW_MAX_SLOW: usize = 10;
const WINDOW_MAX_FAST: usize = 75;
const SDU: usize = 470;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceStatus {
    Queued,
    Advertised,
    Transferring,
    AwaitingProof,
    Assembling,
    Complete,
    Failed,
}

pub(crate) struct OutboundResource {
    pub hash: [u8; 32],
    pub original_hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub status: ResourceStatus,
    pub metadata: Option<Vec<u8>>,
    pub compressed: bool,
    parts: Vec<Vec<u8>>,
    hashmap: Vec<[u8; MAPHASH_LEN]>,
    hashmap_sent: usize,
    window: usize,
}

impl OutboundResource {
    pub fn new<R: RngCore>(
        rng: &mut R,
        link: &EstablishedLink,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        compress: bool,
    ) -> Self {
        let original_hash: [u8; 32] = sha256(&data);

        let processed = if compress {
            bz2_compress(&data).unwrap_or(data)
        } else {
            data
        };

        let mut random_hash = [0u8; 4];
        rng.fill_bytes(&mut random_hash);

        let mut plaintext = random_hash.to_vec();
        plaintext.extend(&processed);

        let encrypted = link.encrypt(rng, &plaintext);

        let hash: [u8; 32] = sha256(&encrypted);

        let parts: Vec<Vec<u8>> = encrypted.chunks(SDU).map(|c| c.to_vec()).collect();

        let hashmap: Vec<[u8; MAPHASH_LEN]> = parts
            .iter()
            .map(|p| {
                let h = sha256(p);
                [h[0], h[1], h[2], h[3]]
            })
            .collect();

        Self {
            hash,
            original_hash,
            random_hash,
            status: ResourceStatus::Queued,
            metadata,
            compressed: compress,
            parts,
            hashmap,
            hashmap_sent: 0,
            window: WINDOW_MIN,
        }
    }

    pub fn num_parts(&self) -> usize {
        self.parts.len()
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
            original_hash: self.original_hash,
            hashmap: hashmap_chunk,
            compressed: self.compressed,
            has_metadata: self.metadata.is_some(),
            metadata: self.metadata.clone(),
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

    pub fn mark_awaiting_proof(&mut self) {
        self.status = ResourceStatus::AwaitingProof;
    }

    pub fn verify_proof(&self, proof: &[u8]) -> bool {
        let mut proof_material = self.hash.to_vec();
        proof_material.extend(&self.original_hash);
        let expected = sha256(&proof_material);
        proof == expected
    }

    pub fn mark_complete(&mut self) {
        self.status = ResourceStatus::Complete;
    }

    pub fn mark_failed(&mut self) {
        self.status = ResourceStatus::Failed;
    }
}

pub(crate) struct InboundResource {
    pub hash: [u8; 32],
    pub original_hash: [u8; 32],
    pub random_hash: [u8; 4],
    pub status: ResourceStatus,
    pub metadata: Option<Vec<u8>>,
    pub compressed: bool,
    num_parts: usize,
    transfer_size: usize,
    hashmap: Vec<[u8; MAPHASH_LEN]>,
    parts: Vec<Option<Vec<u8>>>,
    received_count: usize,
    window: usize,
    hashmap_exhausted: bool,
    last_hashmap_hash: Option<[u8; MAPHASH_LEN]>,
}

impl InboundResource {
    pub fn from_advertisement(adv: &ResourceAdvertisement) -> Self {
        let hashmap: Vec<[u8; MAPHASH_LEN]> = adv
            .hashmap
            .chunks_exact(MAPHASH_LEN)
            .map(|c| [c[0], c[1], c[2], c[3]])
            .collect();

        let last_hashmap_hash = hashmap.last().copied();

        Self {
            hash: adv.hash,
            original_hash: adv.original_hash,
            random_hash: adv.random_hash,
            status: ResourceStatus::Queued,
            metadata: adv.metadata.clone(),
            compressed: adv.compressed,
            num_parts: adv.num_parts,
            transfer_size: adv.transfer_size,
            hashmap,
            parts: vec![None; adv.num_parts],
            received_count: 0,
            window: WINDOW_MIN,
            hashmap_exhausted: false,
            last_hashmap_hash,
        }
    }

    pub fn progress(&self) -> f32 {
        if self.num_parts == 0 {
            return 1.0;
        }
        self.received_count as f32 / self.num_parts as f32
    }

    pub fn receive_part(&mut self, data: Vec<u8>) -> bool {
        let hash = sha256(&data);
        let part_hash: [u8; MAPHASH_LEN] = [hash[0], hash[1], hash[2], hash[3]];

        if let Some(idx) = self.hashmap.iter().position(|h| h == &part_hash) {
            if self.parts[idx].is_none() {
                self.parts[idx] = Some(data);
                self.received_count += 1;
                self.window = (self.window + 1).min(WINDOW_MAX_FAST);
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
        self.last_hashmap_hash = new_hashes.last().copied();
        self.hashmap.extend(new_hashes);
        self.hashmap_exhausted = false;
    }

    pub fn needed_hashes(&mut self) -> Vec<[u8; MAPHASH_LEN]> {
        let mut needed = Vec::new();
        for (i, part) in self.parts.iter().enumerate() {
            if part.is_none() && i < self.hashmap.len() {
                needed.push(self.hashmap[i]);
                if needed.len() >= self.window {
                    break;
                }
            }
        }
        if needed.is_empty() && self.received_count < self.num_parts {
            self.hashmap_exhausted = true;
        }
        needed
    }

    pub fn is_hashmap_exhausted(&self) -> bool {
        self.hashmap_exhausted
    }

    pub fn last_hashmap_hash(&self) -> Option<[u8; MAPHASH_LEN]> {
        self.last_hashmap_hash
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.num_parts
    }

    pub fn assemble(&self, link: &EstablishedLink) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        let encrypted: Vec<u8> = self
            .parts
            .iter()
            .filter_map(|p| p.as_ref())
            .flat_map(|p| p.iter().copied())
            .collect();

        let hash: [u8; 32] = sha256(&encrypted);
        if hash != self.hash {
            return None;
        }

        let plaintext = link.decrypt(&encrypted)?;

        if plaintext.len() < 4 {
            return None;
        }
        let random_hash: [u8; 4] = plaintext[..4].try_into().ok()?;
        if random_hash != self.random_hash {
            return None;
        }

        let data = &plaintext[4..];

        let result = if self.compressed {
            bz2_decompress(data)?
        } else {
            data.to_vec()
        };

        let original_hash: [u8; 32] = sha256(&result);
        if original_hash != self.original_hash {
            return None;
        }

        Some(result)
    }

    pub fn generate_proof(&self) -> [u8; 32] {
        let mut proof_material = self.hash.to_vec();
        proof_material.extend(&self.original_hash);
        sha256(&proof_material)
    }

    pub fn mark_transferring(&mut self) {
        self.status = ResourceStatus::Transferring;
    }

    pub fn mark_complete(&mut self) {
        self.status = ResourceStatus::Complete;
    }

    pub fn mark_failed(&mut self) {
        self.status = ResourceStatus::Failed;
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
    pub hashmap: Vec<u8>,
    pub compressed: bool,
    pub has_metadata: bool,
    pub metadata: Option<Vec<u8>>,
}

impl ResourceAdvertisement {
    pub fn encode(&self) -> Vec<u8> {
        let flags: u8 = (1 << 0)  // encrypted (always)
            | if self.compressed { 1 << 1 } else { 0 }
            | if self.has_metadata { 1 << 5 } else { 0 };

        let mut out = Vec::new();
        out.push(b't');
        out.extend(&(self.transfer_size as u32).to_be_bytes());
        out.push(b'd');
        out.extend(&(self.data_size as u32).to_be_bytes());
        out.push(b'n');
        out.extend(&(self.num_parts as u16).to_be_bytes());
        out.push(b'h');
        out.extend(&self.hash);
        out.push(b'r');
        out.extend(&self.random_hash);
        out.push(b'o');
        out.extend(&self.original_hash);
        out.push(b'f');
        out.push(flags);
        out.push(b'm');
        out.extend(&(self.hashmap.len() as u16).to_be_bytes());
        out.extend(&self.hashmap);
        if let Some(ref meta) = self.metadata {
            out.push(b'M');
            out.extend(&(meta.len() as u16).to_be_bytes());
            out.extend(meta);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut transfer_size = 0;
        let mut data_size = 0;
        let mut num_parts = 0;
        let mut hash = [0u8; 32];
        let mut random_hash = [0u8; 4];
        let mut original_hash = [0u8; 32];
        let mut flags = 0u8;
        let mut hashmap = Vec::new();
        let mut metadata = None;

        let mut i = 0;
        while i < data.len() {
            let tag = data[i];
            i += 1;
            match tag {
                b't' if i + 4 <= data.len() => {
                    transfer_size =
                        u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
                            as usize;
                    i += 4;
                }
                b'd' if i + 4 <= data.len() => {
                    data_size = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
                        as usize;
                    i += 4;
                }
                b'n' if i + 2 <= data.len() => {
                    num_parts = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                    i += 2;
                }
                b'h' if i + 32 <= data.len() => {
                    hash.copy_from_slice(&data[i..i + 32]);
                    i += 32;
                }
                b'r' if i + 4 <= data.len() => {
                    random_hash.copy_from_slice(&data[i..i + 4]);
                    i += 4;
                }
                b'o' if i + 32 <= data.len() => {
                    original_hash.copy_from_slice(&data[i..i + 32]);
                    i += 32;
                }
                b'f' if i < data.len() => {
                    flags = data[i];
                    i += 1;
                }
                b'm' if i + 2 <= data.len() => {
                    let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                    i += 2;
                    if i + len <= data.len() {
                        hashmap = data[i..i + len].to_vec();
                        i += len;
                    }
                }
                b'M' if i + 2 <= data.len() => {
                    let len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
                    i += 2;
                    if i + len <= data.len() {
                        metadata = Some(data[i..i + len].to_vec());
                        i += len;
                    }
                }
                _ => break,
            }
        }

        Some(Self {
            transfer_size,
            data_size,
            num_parts,
            hash,
            random_hash,
            original_hash,
            hashmap,
            compressed: (flags & (1 << 1)) != 0,
            has_metadata: (flags & (1 << 5)) != 0,
            metadata,
        })
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
            hashmap: vec![0, 1, 2, 3, 4, 5, 6, 7],
            compressed: true,
            has_metadata: true,
            metadata: Some(b"test metadata".to_vec()),
        };

        let encoded = adv.encode();
        let decoded = ResourceAdvertisement::decode(&encoded).unwrap();

        assert_eq!(decoded.transfer_size, adv.transfer_size);
        assert_eq!(decoded.data_size, adv.data_size);
        assert_eq!(decoded.num_parts, adv.num_parts);
        assert_eq!(decoded.hash, adv.hash);
        assert_eq!(decoded.random_hash, adv.random_hash);
        assert_eq!(decoded.original_hash, adv.original_hash);
        assert_eq!(decoded.hashmap, adv.hashmap);
        assert_eq!(decoded.compressed, adv.compressed);
        assert_eq!(decoded.has_metadata, adv.has_metadata);
        assert_eq!(decoded.metadata, adv.metadata);
    }
}
