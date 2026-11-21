//! Platform abstraction for process discovery, sampling and termination.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result};

#[cfg(target_os = "linux")]
pub mod linux;
/// Platform-pure process-tree filter shared by the backends.
mod tree;
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
        /// Raw Windows filetime of the process creation, when the source
        /// provides it. Backends compare it against the opened handle to
        /// reject stale events from a recycled pid.
        create_time: Option<u64>,
    },
    /// A tracked process exited.
    Exited {
        pid: u32,
        exit_code: Option<i32>,
        /// Peak commit (private bytes) of the process at exit, when the
        /// source provides it. Only memory data point for processes too
        /// short-lived to be sampled.
        commit_peak_bytes: Option<u64>,
    },
}

/// Identifies the root of the monitored process tree.
#[derive(Debug, Clone, Copy)]
pub struct RootInfo {
    pub pid: u32,
    /// Parent pid; 0 when unknown (attach mode). Attach mode also relies on
    /// the provider rundown to discover existing descendants.
    pub ppid: u32,
}

/// Event-driven source of process lifecycle events.
///
/// Contract: the source MUST pre-filter events to the monitored tree rooted at
/// [`RootInfo::pid`]; the engine trusts every event it receives and does not
/// re-check tree membership.
pub trait EventSource {
    /// Validate that monitoring can start (privileges, event session, ...)
    /// before any process is spawned. Called first by the engine, so an
    /// early failure cannot leave an orphaned child behind. The default is
    /// a no-op.
    ///
    /// # Errors
    /// Returns an error if monitoring cannot start at all.
    fn preflight(&mut self) -> Result<()> {
        Ok(())
    }

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
    /// Spawn the root process of the monitored tree and return its pid.
    /// Implementations may place it under an OS-enforced memory limit
    /// (`max_rss`); the exit code is read back via [`ProcessOps::exit_code`].
    ///
    /// The default spawns through std with no OS-level limiting.
    ///
    /// # Errors
    /// Returns an error if the process cannot be spawned.
    fn spawn_root(&mut self, argv: &[String], _max_rss: Option<u64>) -> Result<u32> {
        let (program, rest) = argv.split_first().context("empty command")?;
        let child = std::process::Command::new(program)
            .args(rest)
            .spawn()
            .with_context(|| format!("failed to spawn `{program}`"))?;
        Ok(child.id())
    }

    /// Peak memory of the OS-enforced process group (Windows job object
    /// commit, Linux cgroup usage); `Some` only while such a group is
    /// active. OS accounting includes processes that already exited, so
    /// this peak can exceed the sampled peak. Informational: limit
    /// classification uses [`ProcessOps::os_limit_tripped`].
    fn job_peak_memory_bytes(&self) -> Option<u64> {
        None
    }

    /// Whether the OS-enforced memory limit actually tripped during the
    /// run. The engine classifies a naturally-ended tree as `os_job_limit`
    /// only when this returns true: a peak near the limit is no proof
    /// (cgroup accounting includes reclaimable page cache).
    fn os_limit_tripped(&self) -> bool {
        false
    }

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
    linux::LinuxBackend::new()
}
