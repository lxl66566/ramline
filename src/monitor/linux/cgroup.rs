//! cgroup v2 memory-limit enforcement: the Linux analog of the Windows job
//! object.

use std::{
    ffi::CString,
    fs, io,
    os::unix::{ffi::OsStrExt as _, process::CommandExt as _},
    path::PathBuf,
    process::Command,
    thread::sleep,
    time::Duration,
};

use anyhow::{Context as _, Result};
use log::warn;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// A cgroup v2 directory enforcing a `memory.max` limit on its members.
///
/// Created in spawn mode with `--max-memory`; the root process joins it
/// through a `pre_exec` hook (before its first instruction, so the move is
/// race-free) and descendants inherit it. On drop the remaining members are
/// killed and the directory removed.
///
/// The directory is named after the ramline process (unique per run):
/// cgroupfs forbids renaming directories and the root pid is unknown before
/// the spawn.
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create `/sys/fs/cgroup/ramline-<pid>` with `memory.max = limit_bytes`.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created or the limit
    /// cannot be written.
    pub fn create(limit_bytes: u64) -> Result<Self> {
        let path = PathBuf::from(format!("{CGROUP_ROOT}/ramline-{}", std::process::id()));
        fs::create_dir(&path)
            .with_context(|| format!("failed to create cgroup {}", path.display()))?;
        if let Err(e) = fs::write(path.join("memory.max"), limit_bytes.to_string()) {
            // No Self yet to run the Drop cleanup; remove the empty directory.
            let _ = fs::remove_dir(&path);
            return Err(e)
                .with_context(|| format!("failed to set memory.max on {}", path.display()));
        }
        Ok(Self { path })
    }

    /// Register a `pre_exec` hook on `command` that moves the spawned process
    /// into this cgroup before exec.
    pub fn hook_into_spawn(&self, command: &mut Command) {
        let procs = CString::new(self.path.join("cgroup.procs").as_os_str().as_bytes())
            .expect("cgroup path contains a NUL byte");
        // Safety: the closure runs between fork and exec and stays
        // async-signal-safe: libc open/write/close only, no allocation.
        unsafe {
            command.pre_exec(move || {
                let pid = libc::getpid();
                let mut buf = [0u8; 12];
                let digits = fmt_pid(pid, &mut buf);
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let rc = libc::write(fd, digits.as_ptr().cast(), digits.len());
                let err = io::Error::last_os_error();
                libc::close(fd);
                if rc < 0 { Err(err) } else { Ok(()) }
            });
        }
    }

    /// Peak memory usage of the cgroup (`memory.peak`), including exited
    /// members.
    pub fn peak_memory_bytes(&self) -> Option<u64> {
        fs::read_to_string(self.path.join("memory.peak"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// OOM kills in the cgroup (`memory.events` `oom_kill`); the evidence
    /// that the `memory.max` limit actually tripped.
    pub fn oom_kills(&self) -> Option<u64> {
        let events = fs::read_to_string(self.path.join("memory.events")).ok()?;
        parse_oom_kills(&events)
    }
}

/// Value of the `oom_kill` field in `memory.events` content.
fn parse_oom_kills(events: &str) -> Option<u64> {
    events
        .lines()
        .find_map(|line| line.strip_prefix("oom_kill "))?
        .trim()
        .parse()
        .ok()
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // cgroup.kill SIGKILLs exactly the current members in one atomic
        // operation (kernel 5.14+); killing raw pids from cgroup.procs
        // could hit a recycled pid. Best effort, like the rmdir below.
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
        // Killed members take a moment to die and be reaped; retry briefly.
        for _ in 0..20 {
            if fs::remove_dir(&self.path).is_ok() {
                return;
            }
            sleep(Duration::from_millis(50));
        }
        warn!("failed to remove cgroup {}", self.path.display());
    }
}

/// Format `pid` into `buf` without allocation (async-signal-safe context).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn fmt_pid(pid: i32, buf: &mut [u8; 12]) -> &[u8] {
    let mut n = pid;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_pid_writes_digits() {
        let mut buf = [0u8; 12];
        assert_eq!(fmt_pid(7, &mut buf), b"7");
        assert_eq!(fmt_pid(4_194_304, &mut buf), b"4194304");
    }

    #[test]
    fn parses_oom_kill_field() {
        let events = "low 0\nhigh 0\nmax 3\noom 2\noom_kill 1\noom_group_kill 0\n";
        assert_eq!(parse_oom_kills(events), Some(1));
        assert_eq!(parse_oom_kills("low 0\n"), None);
    }
}
