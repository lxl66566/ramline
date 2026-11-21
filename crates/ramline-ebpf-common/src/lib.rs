#![no_std]

/// Lifecycle event kind carried by the `kind` field of every event record.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    /// sched/sched_process_fork: a new thread-group leader appeared.
    Fork = 1,
    /// sched/sched_process_exit: a thread-group leader exited.
    Exit = 2,
}

/// A fork event: a new process appeared.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ForkEvent {
    pub kind: EventKind,
    pub pid: u32,
    /// Parent thread-group id.
    pub ppid: u32,
    /// NUL-padded `comm` of the forked process.
    pub comm: [u8; 16],
}

/// An exit event: a thread-group leader exited. The pid identifies the
/// process; its name is already known from the fork event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExitEvent {
    pub kind: EventKind,
    pub pid: u32,
}

/// Slots of the EVENT_STATS per-CPU counter map.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatKind {
    /// Events the eBPF programs tried to push to the ring buffer.
    Attempted = 0,
    /// Events dropped because the ring buffer was full.
    Dropped = 1,
}

// The userspace reader parses the ring buffer records by fixed offsets; keep
// the layouts stable and dense (no padding).
const _: () = assert!(size_of::<ForkEvent>() == 28);
const _: () = assert!(align_of::<ForkEvent>() == 4);
const _: () = assert!(size_of::<ExitEvent>() == 8);
const _: () = assert!(align_of::<ExitEvent>() == 4);
