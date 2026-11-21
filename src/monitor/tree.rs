//! Platform-pure process-tree filter shared by the OS backends.
//!
//! Events for one pid arrive in order, but the start of a child can arrive
//! before the start of its parent within the same source batch. Such events
//! are parked in `pending`, keyed by parent pid, and reconciled when the
//! parent's start arrives; a drained start can itself unblock further pending
//! events (grandchildren). Events of processes outside the tree are dropped;
//! their pending entries are never reclaimed, which stays negligible at
//! system-wide process churn rates.

use std::collections::{HashMap, HashSet};

/// Tree-membership view of a raw lifecycle event from an OS-specific source.
pub trait Event {
    fn pid(&self) -> u32;
    /// Parent pid of a start event; `None` for a stop event.
    fn parent_pid(&self) -> Option<u32>;
}

/// Filters raw source events down to the monitored tree.
pub struct TreeFilter<E> {
    root: u32,
    /// Pids belonging to the tree, including stopped ones (kept so a stop
    /// delivered before a child's start in the same batch does not lose the
    /// child; a new start after a stop is treated as PID reuse).
    known: HashSet<u32>,
    /// Tree pids for which a stop was already emitted.
    stopped: HashSet<u32>,
    /// pid -> parent pid for every start seen, known or pending.
    parent_of: HashMap<u32, u32>,
    /// Parent pid -> events parked until that parent joins the tree.
    pending: HashMap<u32, Vec<E>>,
}

impl<E: Event> TreeFilter<E> {
    pub fn new(root: u32) -> Self {
        Self {
            root,
            known: HashSet::from([root]),
            stopped: HashSet::new(),
            parent_of: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Pre-register pids as tree members (attach-mode snapshot seeding).
    // Used by the Linux backend only.
    #[cfg_attr(windows, allow(dead_code))]
    pub fn seed(&mut self, pids: impl IntoIterator<Item = u32>) {
        self.known.extend(pids);
    }

    /// Feed one raw event; tree-member events are appended to `out` in order.
    // pid/ppid are the domain names; similar_names does not apply here
    #[allow(clippy::similar_names)]
    pub fn on_event(&mut self, raw: E, out: &mut Vec<E>) {
        if let Some(ppid) = raw.parent_pid() {
            let pid = raw.pid();
            self.parent_of.insert(pid, ppid);
            if self.known.contains(&ppid) || pid == self.root {
                self.adopt(raw, out);
            } else {
                self.pending.entry(ppid).or_default().push(raw);
            }
            return;
        }
        let pid = raw.pid();
        if self.known.contains(&pid) {
            if self.stopped.insert(pid) {
                // The pid's lineage is no longer needed.
                self.parent_of.remove(&pid);
                out.push(raw);
            }
        } else if let Some(&ppid) = self.parent_of.get(&pid) {
            // Stop for a child whose start is still pending: park it behind
            // the same parent.
            self.pending.entry(ppid).or_default().push(raw);
        }
        // Stops for processes never seen starting are outside the tree.
    }

    // pid/ppid are the domain names; similar_names does not apply here
    #[allow(clippy::similar_names)]
    fn adopt(&mut self, raw: E, out: &mut Vec<E>) {
        let pid = raw.pid();
        if self.known.contains(&pid) && !self.stopped.contains(&pid) {
            return; // duplicate start (live event plus a source snapshot)
        }
        // A start for a pid seen as stopped means the pid was recycled.
        self.stopped.remove(&pid);
        self.known.insert(pid);
        out.push(raw);
        if let Some(parked) = self.pending.remove(&pid) {
            for event in parked {
                self.on_event(event, out);
            }
        }
    }
}

// pid/ppid are the domain names; similar_names does not apply here
#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    enum TestEvent {
        Start { pid: u32, ppid: u32 },
        Stop { pid: u32 },
    }

    impl Event for TestEvent {
        fn pid(&self) -> u32 {
            match self {
                Self::Start { pid, .. } | Self::Stop { pid } => *pid,
            }
        }

        fn parent_pid(&self) -> Option<u32> {
            match self {
                Self::Start { ppid, .. } => Some(*ppid),
                Self::Stop { .. } => None,
            }
        }
    }

    fn start(pid: u32, ppid: u32) -> TestEvent {
        TestEvent::Start { pid, ppid }
    }

    fn stop(pid: u32) -> TestEvent {
        TestEvent::Stop { pid }
    }

    fn pids(out: &[TestEvent]) -> Vec<u32> {
        out.iter().map(Event::pid).collect()
    }

    #[test]
    fn drops_events_outside_the_tree() {
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        filter.on_event(start(2, 1), &mut out); // child of root
        filter.on_event(start(3, 99), &mut out); // unrelated
        filter.on_event(stop(3), &mut out); // unrelated stop
        filter.on_event(stop(2), &mut out);
        assert_eq!(pids(&out), vec![2, 2]);
    }

    #[test]
    fn reconciles_child_start_arriving_before_parent_start() {
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        // Grandchild arrives before its parent (same batch reorder).
        filter.on_event(start(3, 2), &mut out);
        filter.on_event(stop(3), &mut out);
        assert!(out.is_empty());
        filter.on_event(start(2, 1), &mut out);
        assert_eq!(pids(&out), vec![2, 3, 3]);
    }

    #[test]
    fn dedups_snapshot_and_live_starts() {
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        filter.on_event(start(2, 1), &mut out);
        filter.on_event(start(2, 1), &mut out); // duplicate
        filter.on_event(stop(2), &mut out);
        filter.on_event(stop(2), &mut out); // duplicate
        assert_eq!(pids(&out), vec![2, 2]);
    }

    #[test]
    fn dedups_snapshot_start_for_root_and_adopts_existing_children() {
        // The root's own start arrives via the source snapshot while it was
        // already registered; pre-existing children have a known parent and
        // are adopted.
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        filter.on_event(start(1, 99), &mut out); // snapshot start for root itself
        assert!(out.is_empty());
        filter.on_event(start(2, 1), &mut out);
        assert_eq!(pids(&out), vec![2]);
    }

    #[test]
    fn start_after_stop_means_pid_reuse() {
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        filter.on_event(start(2, 1), &mut out);
        filter.on_event(stop(2), &mut out);
        filter.on_event(start(2, 1), &mut out); // recycled pid
        filter.on_event(stop(2), &mut out);
        assert_eq!(pids(&out), vec![2, 2, 2, 2]);
    }
}
