//! Linux backend: eBPF tracepoints (aya) for process-tree discovery, /proc
//! for sampling, pidfd for termination.
//!
//! Discovery attaches to sched/sched_process_fork and
//! sched/sched_process_exit. Unlike the Windows ETW session there is no
//! capture-state rundown equivalent, so attach mode seeds the
//! already-running descendants from a one-shot /proc scan at `start()`.
//! Events flow through a ring buffer to a dedicated thread running a
//! current-thread tokio runtime, then over a crossfire channel.
//!
//! PID reuse: the tracepoints carry no creation time, so there is no
//! create-time guard like on Windows. Instead every tracked pid is pinned
//! by a /proc/<pid> directory fd (sampling keeps hitting the same process
//! instance) and a pidfd (kill can never hit a recycled pid).
//!
//! A full ring buffer drops events; the eBPF programs count attempted and
//! dropped events in a per-CPU map and the drop path warns from it: a lost
//! fork means an untracked child escaping the memory limit.

mod cgroup;

use std::{
    collections::{HashMap, VecDeque},
    ffi::CString,
    fs::{self, File},
    io::{self, Read as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::process::ExitStatusExt as _,
    },
    path::{Path, PathBuf},
    process::Child,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use aya::{
    Ebpf,
    maps::{MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use crossfire::{MTx, Rx, mpsc::List};
use log::{error, warn};
use ramline_ebpf_common::{EventKind, ExitEvent, ForkEvent, StatKind};

use super::{EventSource, MemorySample, ProcessEvent, ProcessOps, RootInfo, tree::TreeFilter};

/// eBPF object compiled from the ramline-ebpf crate by build.rs.
const EBPF_OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ramline"));

/// A process lifecycle event from the eBPF event thread, before tree
/// filtering.
#[derive(Debug)]
enum RawEvent {
    Fork {
        pid: u32,
        ppid: u32,
        name: String,
        exe: Option<PathBuf>,
    },
    Exit {
        pid: u32,
    },
}

impl super::tree::Event for RawEvent {
    fn pid(&self) -> u32 {
        match self {
            Self::Fork { pid, .. } | Self::Exit { pid } => *pid,
        }
    }

    fn parent_pid(&self) -> Option<u32> {
        match self {
            Self::Fork { ppid, .. } => Some(*ppid),
            Self::Exit { .. } => None,
        }
    }
}

/// Owns the loaded eBPF object and the event-pumping thread. Dropping it
/// stops the thread and detaches the tracepoints.
struct EbpfSession {
    ebpf: Option<Ebpf>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for EbpfSession {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            if let Err(e) = thread.join() {
                error!("eBPF event thread panicked: {e:?}");
            }
        }
        if let Some(ebpf) = &self.ebpf {
            report_dropped_events(ebpf);
        }
        // Detaches the tracepoints by closing the program and link fds.
        drop(self.ebpf.take());
    }
}

/// (attempted, dropped) event counts from the eBPF programs, summed over
/// the per-CPU slots of the EVENT_STATS map.
fn event_stats(ebpf: &Ebpf) -> Option<(u64, u64)> {
    let stats = PerCpuArray::<_, u64>::try_from(ebpf.map("EVENT_STATS")?).ok()?;
    let sum =
        |kind: StatKind| -> Option<u64> { Some(stats.get(&(kind as u32), 0).ok()?.iter().sum()) };
    Some((sum(StatKind::Attempted)?, sum(StatKind::Dropped)?))
}

/// Warn about fork/exit events lost to a full ring buffer.
fn report_dropped_events(ebpf: &Ebpf) {
    let Some((attempted, dropped)) = event_stats(ebpf) else {
        return;
    };
    if dropped > 0 {
        warn!(
            "lost {dropped} of {attempted} fork/exit events (ring buffer full); a lost fork means \
             an untracked child process that escapes the memory limit"
        );
    }
}

/// Per-pid handles pinning the process instance: a /proc/<pid> directory fd
/// for sampling and a pidfd for termination.
struct ProcHandle {
    dir: File,
    pidfd: OwnedFd,
}

/// Linux backend.
pub struct LinuxBackend {
    raw_tx: MTx<List<RawEvent>>,
    raw_rx: Rx<List<RawEvent>>,
    /// Filtered events waiting to be returned by `recv_timeout`.
    ready: VecDeque<ProcessEvent>,
    filter: Option<TreeFilter<RawEvent>>,
    session: Option<EbpfSession>,
    procs: HashMap<u32, ProcHandle>,
    /// Spawn-mode root child, kept for `exit_code` and reaped on drop.
    root_child: Option<Child>,
    /// cgroup enforcing the OS-level memory limit (spawn mode with
    /// `--max-memory`); the Linux analog of the Windows job object.
    cgroup: Option<cgroup::Cgroup>,
}

impl LinuxBackend {
    pub fn new() -> Self {
        let (raw_tx, raw_rx) = crossfire::mpsc::unbounded_blocking::<RawEvent>();
        Self {
            raw_tx,
            raw_rx,
            ready: VecDeque::new(),
            filter: None,
            session: None,
            procs: HashMap::new(),
            root_child: None,
            cgroup: None,
        }
    }

    /// Open and cache the /proc dir fd and pidfd for `pid`; a process that
    /// vanished before the opens is skipped (sampling reports it as dead).
    fn register(&mut self, pid: u32) {
        if self.procs.contains_key(&pid) {
            return;
        }
        let (Ok(dir), Ok(pidfd)) = (File::open(format!("/proc/{pid}")), pidfd_open(pid)) else {
            return;
        };
        self.procs.insert(pid, ProcHandle { dir, pidfd });
    }

    /// Run one raw event through the tree filter and convert the accepted
    /// ones into [`ProcessEvent`]s.
    fn on_raw(&mut self, raw: RawEvent) {
        let mut accepted = Vec::new();
        if let Some(filter) = &mut self.filter {
            filter.on_event(raw, &mut accepted);
        }
        for raw in accepted {
            match raw {
                RawEvent::Fork {
                    pid,
                    ppid,
                    name,
                    exe,
                } => {
                    self.register(pid);
                    self.ready.push_back(ProcessEvent::Spawned {
                        pid,
                        ppid,
                        name,
                        exe,
                        // The tracepoints carry no creation time; pid reuse is
                        // handled by pinning fds instead.
                        create_time: None,
                    });
                },
                RawEvent::Exit { pid } => {
                    self.procs.remove(&pid);
                    self.ready.push_back(ProcessEvent::Exited {
                        pid,
                        // The exit tracepoint reports no exit code; the root's
                        // code comes from the spawned Child instead.
                        exit_code: None,
                        // No commit-peak equivalent on Linux.
                        commit_peak_bytes: None,
                    });
                },
            }
        }
    }
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl LinuxBackend {
    /// (attempted, dropped) eBPF event counters; `None` before `preflight`.
    pub(crate) fn event_stats(&self) -> Option<(u64, u64)> {
        event_stats(self.session.as_ref()?.ebpf.as_ref()?)
    }
}

impl Drop for LinuxBackend {
    fn drop(&mut self) {
        // Reap the spawn-mode root so it cannot linger as a zombie.
        if let Some(child) = &mut self.root_child {
            let _ = child.try_wait();
        }
    }
}

impl EventSource for LinuxBackend {
    /// Load and attach the tracepoint programs before any child is spawned:
    /// a failure here must not leave an orphaned child behind, and attach
    /// mode must not miss forks happening before `start()`.
    fn preflight(&mut self) -> Result<()> {
        ensure_privileges()?;
        // Probe pidfd support on this process: without it `register` would
        // skip every process and the tree would look instantly dead.
        pidfd_open(std::process::id()).context(
            "pidfd_open is unavailable; the Linux backend needs kernel 5.3+ with the pidfd_open \
             syscall permitted",
        )?;
        if !Path::new("/sys/kernel/btf/vmlinux").exists() {
            bail!(
                "kernel BTF not found at /sys/kernel/btf/vmlinux; the eBPF backend needs a kernel \
                 built with CONFIG_DEBUG_INFO_BTF"
            );
        }
        let mut ebpf = Ebpf::load(EBPF_OBJECT).context("failed to load the eBPF object")?;
        for (program_name, category, event) in [
            ("sched_process_fork", "sched", "sched_process_fork"),
            ("sched_process_exit", "sched", "sched_process_exit"),
        ] {
            let program: &mut TracePoint = ebpf
                .program_mut(program_name)
                .with_context(|| format!("program `{program_name}` missing from the eBPF object"))?
                .try_into()?;
            program
                .load()
                .with_context(|| format!("failed to load eBPF program `{program_name}`"))?;
            program
                .attach(category, event)
                .with_context(|| format!("failed to attach to {category}/{event}"))?;
        }
        let events = ebpf
            .take_map("EVENTS")
            .context("EVENTS map missing from the eBPF object")?;
        let ring_buf = RingBuf::try_from(events).context("EVENTS is not a ring buffer")?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = {
            let tx = self.raw_tx.clone();
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                if let Err(e) = run_event_loop(ring_buf, tx, shutdown) {
                    error!("eBPF event thread failed: {e:#}");
                }
            })
        };
        self.session = Some(EbpfSession {
            ebpf: Some(ebpf),
            shutdown,
            thread: Some(thread),
        });
        Ok(())
    }

    fn start(&mut self, root: RootInfo) -> Result<()> {
        let mut filter = TreeFilter::new(root.pid);
        // Attach mode (ppid 0): tracepoints have no rundown equivalent, so
        // take a one-shot /proc snapshot of the already-running descendants.
        // Forks racing the scan still arrive live and are deduped by the
        // tree filter.
        let existing = if root.ppid == 0 { scan_tree(root.pid) } else { Vec::new() };
        filter.seed(existing.iter().map(|e| e.pid));
        self.filter = Some(filter);

        self.register(root.pid);
        let (name, exe) = proc_name_exe(root.pid);
        self.ready.push_back(ProcessEvent::Spawned {
            pid: root.pid,
            ppid: root.ppid,
            name,
            exe,
            create_time: None,
        });
        for entry in existing {
            self.register(entry.pid);
            self.ready.push_back(ProcessEvent::Spawned {
                pid: entry.pid,
                ppid: entry.ppid,
                name: entry.name,
                exe: entry.exe,
                create_time: None,
            });
        }
        Ok(())
    }

    fn recv_timeout(&mut self, timeout: Duration) -> Option<ProcessEvent> {
        let deadline = Instant::now().checked_add(timeout)?;
        loop {
            if let Some(event) = self.ready.pop_front() {
                return Some(event);
            }
            let remaining = deadline.checked_duration_since(Instant::now())?;
            let raw = self.raw_rx.recv_timeout(remaining).ok()?;
            self.on_raw(raw);
        }
    }
}

impl ProcessOps for LinuxBackend {
    fn spawn_root(&mut self, argv: &[String], max_rss: Option<u64>) -> Result<u32> {
        let (program, rest) = argv.split_first().context("empty command")?;
        let mut command = std::process::Command::new(program);
        command.args(rest);
        // The cgroup limit (memory.max, usage-based) backstops the engine's
        // RSS-based software limiter: it trips between two samples and also
        // protects the tree when ramline dies mid-run.
        let cgroup = match max_rss {
            Some(limit) => {
                let cgroup = cgroup::Cgroup::create(limit)?;
                cgroup.hook_into_spawn(&mut command);
                Some(cgroup)
            },
            None => None,
        };
        let child = command
            .spawn()
            .with_context(|| format!("failed to spawn `{program}`"))?;
        let pid = child.id();
        self.cgroup = cgroup;
        self.root_child = Some(child);
        Ok(pid)
    }

    fn job_peak_memory_bytes(&self) -> Option<u64> {
        self.cgroup
            .as_ref()
            .and_then(cgroup::Cgroup::peak_memory_bytes)
    }

    fn os_limit_tripped(&self) -> bool {
        self.cgroup
            .as_ref()
            .and_then(cgroup::Cgroup::oom_kills)
            .is_some_and(|kills| kills > 0)
    }

    fn sample(&mut self, pid: u32) -> Option<MemorySample> {
        let entry = self.procs.get(&pid)?;
        let status = read_file_at(&entry.dir, "status")?;
        // A zombie reports no VmRSS line; treat it as gone.
        let rss_kib = status_field_kib(&status, "VmRSS:")?;
        let anon_kib = status_field_kib(&status, "RssAnon:").unwrap_or(0);
        let swap_kib = status_field_kib(&status, "VmSwap:").unwrap_or(0);
        let stat = read_file_at(&entry.dir, "stat")?;
        Some(MemorySample {
            rss_bytes: rss_kib * 1024,
            private_bytes: (anon_kib + swap_kib) * 1024,
            page_faults: parse_stat_page_faults(&stat)?,
        })
    }

    fn kill(&mut self, pid: u32) -> Result<()> {
        let Some(entry) = self.procs.get(&pid) else {
            return Ok(()); // already gone
        };
        // Safety: the pidfd pins the exact process instance opened at Spawned
        // time; pid reuse cannot redirect the signal. libc exposes no
        // pidfd_send_signal wrapper, so the syscall is invoked directly.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                entry.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null_mut::<libc::c_void>(),
                0,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(()); // already gone
        }
        Err(err).with_context(|| format!("pidfd_send_signal failed for pid {pid}"))
    }

    fn exit_code(&mut self, pid: u32) -> Option<i32> {
        let child = self.root_child.as_mut()?;
        if child.id() != pid {
            return None; // attach mode or a non-root process
        }
        let status = child.try_wait().ok()??;
        // A process reaped after a signal has no code; report the
        // conventional 128 + signal.
        status.code().or_else(|| status.signal().map(|s| 128 + s))
    }
}

/// Poll the ring buffer and forward parsed events until shutdown or channel
/// disconnect.
fn run_event_loop(
    mut ring_buf: RingBuf<MapData>,
    tx: MTx<List<RawEvent>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build the tokio runtime")?;
    runtime.block_on(async move {
        // Safety: ring_buf stays owned by this task and outlives the
        // registration, keeping the fd valid.
        let fd = ring_buf.as_raw_fd();
        let async_fd = unsafe { tokio::io::unix::AsyncFd::register(fd) }
            .context("failed to register the ring buffer fd")?;
        while !shutdown.load(Ordering::Relaxed) {
            // The timeout bounds the shutdown latency: a closed ring buffer
            // fd does not reliably wake an epoll waiter.
            let Ok(readiness) =
                tokio::time::timeout(Duration::from_millis(200), async_fd.readable()).await
            else {
                continue;
            };
            let mut guard = readiness.context("ring buffer poll failed")?;
            while let Some(item) = ring_buf.next() {
                if let Some(raw) = parse_record(&item) {
                    if tx.send(raw).is_err() {
                        return Ok(()); // backend dropped
                    }
                }
            }
            guard.clear_ready();
        }
        Ok(())
    })
}

/// Parse one ring buffer record; `None` for malformed records and for events
/// of non-leader tasks (threads), which ramline does not track.
// pid/ppid are the domain names; similar_names does not apply here
#[allow(clippy::similar_names)]
fn parse_record(bytes: &[u8]) -> Option<RawEvent> {
    if bytes.len() < size_of::<ExitEvent>() {
        return None;
    }
    let kind = field_u32(bytes, 0)?;
    let pid = field_u32(bytes, 4)?;
    if kind == EventKind::Exit as u32 {
        return Some(RawEvent::Exit { pid });
    }
    if kind != EventKind::Fork as u32 || bytes.len() < size_of::<ForkEvent>() {
        return None;
    }
    let ppid = field_u32(bytes, 8)?;
    // The fork tracepoint carries no child tgid; threads (pid != tgid) are
    // filtered out here. A process that already exited is kept: sampling
    // treats it as exited.
    if !is_process_leader(pid) {
        return None;
    }
    let comm = bytes.get(12..size_of::<ForkEvent>())?;
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]).into_owned();
    let name = if name.is_empty() { String::from("unknown") } else { name };
    // Best effort: the process may exec or exit at any time.
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
    Some(RawEvent::Fork {
        pid,
        ppid,
        name,
        exe,
    })
}

/// `bytes[offset..offset + 4]` as a native-endian u32.
fn field_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// True if `pid` is a thread-group leader (Tgid == pid); a vanished process
/// counts as a leader so its event is not lost.
fn is_process_leader(pid: u32) -> bool {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return true;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .is_none_or(|tgid| tgid == pid)
}

/// Name (comm) and exe path of a live process, best effort.
fn proc_name_exe(pid: u32) -> (String, Option<PathBuf>) {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
    let name = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| String::from("unknown"));
    (name, exe)
}

/// A process found by the attach-mode /proc scan.
struct ScanEntry {
    pid: u32,
    ppid: u32,
    name: String,
    exe: Option<PathBuf>,
}

/// Snapshot of the process subtree rooted at `root`, parents before
/// children. Single pass: a fork during the scan may be missed here, but
/// its live fork event still arrives over the ring buffer.
// pid/ppid are the domain names; similar_names does not apply here
#[allow(clippy::similar_names)]
fn scan_tree(root: u32) -> Vec<ScanEntry> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut parent_of: Vec<(u32, u32)> = Vec::new();
    for entry in dir {
        let Ok(entry) = entry else { continue };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some(ppid) = parse_stat_ppid(&stat) else {
            continue
        };
        parent_of.push((pid, ppid));
    }
    // Depth-first scan from the root; parents precede children.
    let mut tree = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for &(pid, ppid) in &parent_of {
            if ppid == parent && pid != root {
                frontier.push(pid);
                let (name, exe) = proc_name_exe(pid);
                tree.push(ScanEntry {
                    pid,
                    ppid,
                    name,
                    exe,
                });
            }
        }
    }
    tree
}

/// Read a file below a /proc/<pid> directory fd; `None` if the process is
/// gone (openat fails once the directory is dead).
fn read_file_at(dir: &File, name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    // Safety: dir is a valid directory fd and name is NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    // Safety: fd is freshly returned by openat and owned by the File.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;
    Some(content)
}

/// Value of a `Field: N kB` line in /proc/<pid>/status, in kibibytes.
fn status_field_kib(status: &str, field: &str) -> Option<u64> {
    let line = status.lines().find(|line| line.starts_with(field))?;
    line[field.len()..].split_whitespace().next()?.parse().ok()
}

/// Field 4 (ppid) of /proc/<pid>/stat.
fn parse_stat_ppid(stat: &str) -> Option<u32> {
    stat_fields(stat)?.nth(1)?.parse().ok()
}

/// minflt + majflt (fields 10 and 12) of /proc/<pid>/stat.
fn parse_stat_page_faults(stat: &str) -> Option<u64> {
    let fields: Vec<&str> = stat_fields(stat)?.collect();
    let minflt = fields.get(7)?.parse::<u64>().ok()?;
    let majflt = fields.get(9)?.parse::<u64>().ok()?;
    Some(minflt + majflt)
}

/// Fields 3+ of /proc/<pid>/stat; the comm field in parentheses may contain
/// spaces, so fields are split after the last ')'.
fn stat_fields(stat: &str) -> Option<std::str::SplitWhitespace<'_>> {
    Some(stat.rsplit_once(") ")?.1.split_whitespace())
}

/// Open a pidfd for `pid` (kernel 5.3+).
fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // libc exposes no pidfd_open wrapper; call the syscall directly.
    // Safety: no preconditions; returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid_t(pid), 0) };
    let Ok(fd) = i32::try_from(fd) else {
        return Err(io::Error::last_os_error());
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // Safety: fd is freshly returned by pidfd_open and owned.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn pid_t(pid: u32) -> libc::pid_t {
    libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX)
}

/// eBPF tracepoint attach needs CAP_BPF + CAP_PERFMON (kernel 5.8+); root
/// short-circuits the capability check.
fn ensure_privileges() -> Result<()> {
    const CAP_BPF: u64 = 1 << 39;
    const CAP_PERFMON: u64 = 1 << 38;
    // Safety: no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    let status =
        fs::read_to_string("/proc/self/status").context("failed to read /proc/self/status")?;
    let capeff = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .context("CapEff missing from /proc/self/status")?;
    if capeff & CAP_BPF != 0 && capeff & CAP_PERFMON != 0 {
        Ok(())
    } else {
        bail!(
            "process monitoring on Linux uses eBPF tracepoints, which require CAP_BPF + \
             CAP_PERFMON; run ramline as root"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_fields() {
        let status = "Name:\tpython3\nTgid:\t123\nVmRSS:\t   12345 kB\nRssAnon:\t\t100 kB\n";
        assert_eq!(status_field_kib(status, "VmRSS:"), Some(12345));
        assert_eq!(status_field_kib(status, "RssAnon:"), Some(100));
        assert_eq!(status_field_kib(status, "VmSwap:"), None);
    }

    #[test]
    fn parses_stat_with_spaces_in_comm() {
        // Fields after comm: state ppid pgrp session tty_nr tpgid flags
        // minflt cminflt majflt.
        let stat = "1234 (my proc) S 100 200 300 0 0 0 55 66 77 88 0 0 0 0";
        assert_eq!(parse_stat_ppid(stat), Some(100));
        assert_eq!(parse_stat_page_faults(stat), Some(55 + 77));
    }
}
