use std::collections::{HashSet, VecDeque};

pub(crate) struct PacketHashlist {
    limit: usize,
    order: VecDeque<[u8; 32]>,
    members: HashSet<[u8; 32]>,
}

impl PacketHashlist {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            order: VecDeque::new(),
            members: HashSet::new(),
        }
    }

    pub(crate) fn contains(&self, hash: &[u8; 32]) -> bool {
        self.members.contains(hash)
    }

    pub(crate) fn insert(&mut self, hash: [u8; 32]) -> bool {
        if self.members.contains(&hash) {
            return false;
        }
        if self.order.len() == self.limit {
            let oldest = self.order.pop_front().unwrap();
            self.members.remove(&oldest);
        }
        self.members.insert(hash);
        self.order.push_back(hash);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_does_not_refresh_eviction_order() {
        let mut hashes = PacketHashlist::new(2);
        assert!(hashes.insert([1; 32]));
        assert!(hashes.insert([2; 32]));
        assert!(!hashes.insert([1; 32]));
        assert!(hashes.insert([3; 32]));
        assert!(!hashes.contains(&[1; 32]));
        assert!(hashes.contains(&[2; 32]));
        assert!(hashes.contains(&[3; 32]));
    }
}
