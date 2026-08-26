use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap};

use crate::MonoTime;
use crate::node::{ProtocolTimer, ScheduledTimer};

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum TimerKey {
    Protocol(ProtocolTimer),
    InboundRequest([u8; 16], [u8; 16]),
    Shutdown,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TimerEntry {
    at: MonoTime,
    key: TimerKey,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum TimerEvent {
    Protocol(ScheduledTimer),
    InboundRequest { link: [u8; 16], request: [u8; 16] },
    Shutdown,
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.key.cmp(&self.key))
    }
}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
pub(crate) struct TimerQueue {
    heap: BinaryHeap<TimerEntry>,
    deadlines: BTreeMap<TimerKey, MonoTime>,
}

impl TimerQueue {
    pub(crate) fn schedule(&mut self, timer: ScheduledTimer) {
        let key = TimerKey::Protocol(timer.event);
        self.insert(timer.at, key);
    }

    pub(crate) fn schedule_inbound_request(
        &mut self,
        at: MonoTime,
        link: [u8; 16],
        request: [u8; 16],
    ) {
        self.insert(at, TimerKey::InboundRequest(link, request));
    }

    pub(crate) fn cancel_inbound_request(&mut self, link: [u8; 16], request: [u8; 16]) {
        self.deadlines
            .remove(&TimerKey::InboundRequest(link, request));
    }

    pub(crate) fn schedule_shutdown(&mut self, at: MonoTime) {
        self.insert(at, TimerKey::Shutdown);
    }

    fn insert(&mut self, at: MonoTime, key: TimerKey) {
        self.deadlines.insert(key, at);
        self.heap.push(TimerEntry { at, key });
    }

    pub(crate) fn next_deadline(&mut self) -> Option<MonoTime> {
        self.discard_superseded();
        self.heap.peek().map(|entry| entry.at)
    }

    pub(crate) fn pop_due(&mut self, now: MonoTime) -> Option<TimerEvent> {
        self.discard_superseded();
        let entry = self.heap.peek().copied()?;
        if entry.at > now {
            return None;
        }
        self.heap.pop();
        self.deadlines.remove(&entry.key);
        Some(match entry.key {
            TimerKey::Protocol(event) => TimerEvent::Protocol(ScheduledTimer {
                at: entry.at,
                event,
            }),
            TimerKey::InboundRequest(link, request) => TimerEvent::InboundRequest { link, request },
            TimerKey::Shutdown => TimerEvent::Shutdown,
        })
    }

    fn discard_superseded(&mut self) {
        while self
            .heap
            .peek()
            .is_some_and(|entry| self.deadlines.get(&entry.key).copied() != Some(entry.at))
        {
            self.heap.pop();
        }
    }
}
