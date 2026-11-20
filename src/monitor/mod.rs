//! Platform abstraction for process discovery, sampling and termination.

use std::{path::PathBuf, time::Duration};

use anyhow::Result;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

/// A process lifecycle event produced by an [`EventSource`].
#[derive(Debug)]
pub enum ProcessEvent {
    /// A process belonging to the monitored tree started.
    Spawned {
        pid: u32,
        ppid: u32,
        name: String,
        exe: Option<PathBuf>,
    },
    /// A tracked process exited.
    // Constructed only by real event sources (ETW/eBPF), not the placeholder.
    #[allow(dead_code)]
    Exited { pid: u32 },
}

/// Identifies the root of the monitored process tree.
#[derive(Debug, Clone, Copy)]
pub struct RootInfo {
    pub pid: u32,
    /// Parent pid; 0 when unknown (attach mode).
    pub ppid: u32,
}

/// Event-driven source of process lifecycle events.
///
/// Contract: the source MUST pre-filter events to the monitored tree rooted at
/// [`RootInfo::pid`]; the engine trusts every event it receives and does not
/// re-check tree membership.
pub trait EventSource {
    /// Start producing events for the tree rooted at `root`.
    ///
    /// # Errors
    /// Returns an error if the root process cannot be registered.
    fn start(&mut self, root: RootInfo) -> Result<()>;
    /// Return the next pending event, waiting at most `timeout`.
    /// `None` means the timeout elapsed.
    fn recv_timeout(&mut self, timeout: Duration) -> Option<ProcessEvent>;
}

/// A single memory snapshot of one process, without a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySample {
    pub rss_bytes: u64,
    pub private_bytes: u64,
    pub page_faults: u64,
}

/// Timer-driven sampling and termination of individual processes.
pub trait ProcessOps {
    /// Sample memory counters of `pid`. `None` means the process is gone or
    /// cannot be sampled; the engine treats it as exited.
    fn sample(&mut self, pid: u32) -> Option<MemorySample>;
    /// Terminate `pid`. Best effort: the process may already be gone.
    ///
    /// # Errors
    /// Returns an error if the termination request fails.
    fn kill(&mut self, pid: u32) -> Result<()>;
    /// Exit code of a terminated process, if available.
    fn exit_code(&mut self, pid: u32) -> Option<i32>;
}

/// A complete platform backend: event source plus sampling/termination.
pub trait Backend: EventSource + ProcessOps {}
impl<T: EventSource + ProcessOps> Backend for T {}

/// Construct the backend for the current platform.
#[cfg(windows)]
pub fn default_backend() -> impl Backend {
    windows::WindowsBackend::new()
}

/// Construct the backend for the current platform.
#[cfg(target_os = "linux")]
pub fn default_backend() -> impl Backend {
    linux::LinuxBackend
}
