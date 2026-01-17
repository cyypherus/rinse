use std::collections::HashSet;

pub(crate) struct PacketHashlist {
    current: HashSet<[u8; 32]>,
    prev: HashSet<[u8; 32]>,
    max_size: usize,
}

impl PacketHashlist {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            current: HashSet::new(),
            prev: HashSet::new(),
            max_size,
        }
    }

    pub(crate) fn contains(&self, hash: &[u8; 32]) -> bool {
        self.current.contains(hash) || self.prev.contains(hash)
    }

    pub(crate) fn insert(&mut self, hash: [u8; 32]) {
        if self.current.len() > self.max_size / 2 {
            std::mem::swap(&mut self.current, &mut self.prev);
            self.current.clear();
        }
        self.current.insert(hash);
    }
}
