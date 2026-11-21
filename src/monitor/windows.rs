//! Windows backend: ETW (ferrisetw2) for process-tree discovery, Win32 for
//! sampling and termination.
//!
//! Discovery uses a `UserTrace` session on the manifest provider
//! Microsoft-Windows-Kernel-Process, keyword `WINEVENT_KEYWORD_PROCESS`
//! (events 1=Start, 2=Stop, 15=Rundown). Events arrive up to ~1 s late: the
//! session flush timer has 1 s granularity and a low-rate stream never fills
//! a buffer. The engine's grace window and the sampler-based liveness probe
//! absorb that delay.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsString,
    iter::once,
    mem::size_of,
    os::windows::ffi::OsStringExt as _,
    panic::AssertUnwindSafe,
    path::PathBuf,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use crossfire::{MTx, Rx, mpsc::List};
use ferrisetw2::{
    EventRecord,
    native::time::FileTime,
    parser::Parser,
    provider::Provider,
    schema_locator::SchemaLocator,
    trace::{TraceTrait as _, UserTrace},
};
use log::{debug, error};
use windows::{
    Win32::{
        Foundation::{CloseHandle, FILETIME, HANDLE, STILL_ACTIVE},
        Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW},
        System::{
            Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
            Threading::{
                CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
                GetProcessTimes, OpenProcess, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
                PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
                QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
                TerminateProcess,
            },
        },
        UI::Shell::IsUserAnAdmin,
    },
    core::{PCWSTR, PWSTR},
};

use self::job::Job;
use super::{EventSource, MemorySample, ProcessEvent, ProcessOps, RootInfo};

mod job;

const BUF_LEN: u32 = 1024;

/// Microsoft-Windows-Kernel-Process.
const KERNEL_PROCESS_PROVIDER: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
/// `WINEVENT_KEYWORD_PROCESS`: selects only the process lifecycle events.
const KEYWORD_PROCESS: u64 = 0x10;
const EVENT_PROCESS_START: u16 = 1;
const EVENT_PROCESS_STOP: u16 = 2;
const EVENT_PROCESS_RUNDOWN: u16 = 15;

const SECONDS_BETWEEN_1601_AND_1970: i64 = 11_644_473_600;

/// A process lifecycle event straight from the ETW callback, before tree
/// filtering.
#[derive(Debug)]
enum RawEvent {
    Start {
        pid: u32,
        ppid: u32,
        /// Raw Windows filetime of process creation, when the event carries it.
        create_time: Option<u64>,
        /// NT device path (`\Device\HarddiskVolumeX\...`).
        image: String,
    },
    Stop {
        pid: u32,
        exit_code: Option<i32>,
        commit_peak_bytes: Option<u64>,
    },
}

impl RawEvent {
    fn pid(&self) -> u32 {
        match self {
            Self::Start { pid, .. } | Self::Stop { pid, .. } => *pid,
        }
    }
}

/// Filters raw ETW events down to the monitored tree.
///
/// Events for one pid arrive in order, but the Start of a child can arrive
/// before the Start of its parent within the same flush batch. Such events
/// are parked in `pending`, keyed by parent pid, and reconciled when the
/// parent's Start arrives; a drained Start can itself unblock further pending
/// events (grandchildren). Events of processes outside the tree are dropped;
/// their pending entries are never reclaimed, which stays negligible at
/// system-wide process churn rates.
struct TreeFilter {
    root: u32,
    /// Pids belonging to the tree, including stopped ones (kept so a Stop
    /// delivered before a child's Start in the same batch does not lose the
    /// child; a new Start after a Stop is treated as PID reuse).
    known: HashSet<u32>,
    /// Tree pids for which a Stop was already emitted.
    stopped: HashSet<u32>,
    /// pid -> parent pid for every Start seen, known or pending.
    parent_of: HashMap<u32, u32>,
    /// Parent pid -> events parked until that parent joins the tree.
    pending: HashMap<u32, Vec<RawEvent>>,
}

impl TreeFilter {
    fn new(root: u32) -> Self {
        Self {
            root,
            known: HashSet::from([root]),
            stopped: HashSet::new(),
            parent_of: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Feed one raw event; tree-member events are appended to `out` in order.
    // pid/ppid are the domain names; similar_names does not apply here
    #[allow(clippy::similar_names)]
    fn on_event(&mut self, raw: RawEvent, out: &mut Vec<RawEvent>) {
        match raw {
            RawEvent::Start { pid, ppid, .. } => {
                self.parent_of.insert(pid, ppid);
                if self.known.contains(&ppid) || pid == self.root {
                    self.adopt(raw, out);
                } else {
                    self.pending.entry(ppid).or_default().push(raw);
                }
            },
            RawEvent::Stop { pid, .. } => {
                if self.known.contains(&pid) {
                    if self.stopped.insert(pid) {
                        // The pid's lineage is no longer needed.
                        self.parent_of.remove(&pid);
                        out.push(raw);
                    }
                } else if let Some(&ppid) = self.parent_of.get(&pid) {
                    // Stop for a child whose Start is still pending: park it
                    // behind the same parent.
                    self.pending.entry(ppid).or_default().push(raw);
                }
                // Stops for processes never seen starting are outside the tree.
            },
        }
    }

    // pid/ppid are the domain names; similar_names does not apply here
    #[allow(clippy::similar_names)]
    fn adopt(&mut self, raw: RawEvent, out: &mut Vec<RawEvent>) {
        let pid = raw.pid();
        if self.known.contains(&pid) && !self.stopped.contains(&pid) {
            return; // duplicate Start (live event plus rundown)
        }
        // A Start for a pid seen as stopped means the pid was recycled.
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

/// Owns the ETW session. Dropping the trace stops the session (ferrisetw2
/// Drop = CloseTrace + ControlTrace STOP), which unblocks the processing
/// thread; the thread is then joined.
struct EtwTrace {
    trace: Option<UserTrace>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for EtwTrace {
    fn drop(&mut self) {
        drop(self.trace.take());
        // No let-chains: rust-version is 1.85.
        if let Some(thread) = self.thread.take() {
            if let Err(e) = thread.join() {
                error!("ETW processing thread panicked: {e:?}");
            }
        }
    }
}

/// Windows backend. Process handles are opened lazily and cached per pid.
pub struct WindowsBackend {
    handles: HashMap<u32, HANDLE>,
    /// Pids whose Stop event was accepted; they are never re-opened by pid
    /// afterwards, since the pid may have been recycled.
    exited: HashSet<u32>,
    raw_tx: MTx<List<RawEvent>>,
    raw_rx: Rx<List<RawEvent>>,
    /// Filtered events waiting to be returned by `recv_timeout`.
    ready: VecDeque<ProcessEvent>,
    filter: Option<TreeFilter>,
    trace: Option<EtwTrace>,
    /// Root pid and its full-access `CreateProcessW` handle (spawn mode).
    /// Kept out of `handles` so the sampler closing a dead entry cannot
    /// invalidate the exit-code read.
    root: Option<(u32, HANDLE)>,
    /// Job object enforcing the OS-level commit limit (spawn mode with
    /// `--max-memory`).
    job: Option<Job>,
}

impl WindowsBackend {
    pub fn new() -> Self {
        let (raw_tx, raw_rx) = crossfire::mpsc::unbounded_blocking::<RawEvent>();
        Self {
            handles: HashMap::new(),
            exited: HashSet::new(),
            raw_tx,
            raw_rx,
            ready: VecDeque::new(),
            filter: None,
            trace: None,
            root: None,
            job: None,
        }
    }

    /// Open and cache a handle for `pid`; `None` if the process cannot be opened.
    fn handle(&mut self, pid: u32) -> Option<HANDLE> {
        if let Some(handle) = self.handles.get(&pid) {
            return Some(*handle);
        }
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
        // Safety: the returned handle is owned by the cache and closed exactly once.
        let handle = unsafe { OpenProcess(access, false, pid) }.ok()?;
        self.handles.insert(pid, handle);
        Some(handle)
    }

    fn close(&mut self, pid: u32) {
        if let Some(handle) = self.handles.remove(&pid) {
            // Safety: the handle was removed from the cache, so it cannot be closed twice.
            let _ = unsafe { CloseHandle(handle) };
        }
    }

    /// Resolve the image path of a process via its handle.
    fn query_image(handle: HANDLE) -> Option<(String, PathBuf)> {
        let mut buf = [0u16; BUF_LEN as usize];
        let mut len = BUF_LEN;
        // Safety: buf is writable for BUF_LEN u16s and len is its in/out element count.
        unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &raw mut len,
            )
        }
        .ok()?;
        let exe = PathBuf::from(OsString::from_wide(&buf[..len as usize]));
        let name = exe.file_name()?.to_string_lossy().into_owned();
        Some((name, exe))
    }

    /// Raw exit code; `None` while the process is still running.
    fn raw_exit_code(handle: HANDLE) -> Option<u32> {
        let mut code = 0u32;
        // Safety: handle is a live process handle; code is a valid out pointer.
        unsafe { GetExitCodeProcess(handle, &raw mut code) }.ok()?;
        (code != STILL_ACTIVE.0 as u32).then_some(code)
    }

    /// Run one raw event through the tree filter and convert the accepted
    /// ones into [`ProcessEvent`]s.
    // pid/ppid are the domain names; similar_names does not apply here
    #[allow(clippy::similar_names)]
    fn on_raw(&mut self, raw: RawEvent) {
        let mut accepted = Vec::new();
        if let Some(filter) = &mut self.filter {
            filter.on_event(raw, &mut accepted);
        }
        for raw in accepted {
            match raw {
                RawEvent::Start {
                    pid,
                    ppid,
                    create_time,
                    image,
                } => {
                    // Cache the handle unconditionally: kill() must never
                    // re-resolve a pid that may have been recycled. The
                    // handle also feeds the PID-reuse guard.
                    let handle = self.handle(pid);
                    // PID-reuse guard: a Start delivered late can refer to a
                    // pid that already exited and was recycled by an
                    // unrelated process.
                    let stale = create_time.is_some_and(|expected| {
                        handle
                            .and_then(creation_time)
                            .is_some_and(|actual| actual != expected)
                    });
                    if stale {
                        debug!("ignoring stale Start for pid {pid}: creation time mismatch");
                        self.close(pid);
                        continue;
                    }
                    // A recycled pid is alive again.
                    self.exited.remove(&pid);
                    let (name, exe) = image_name_parts(&image);
                    self.ready.push_back(ProcessEvent::Spawned {
                        pid,
                        ppid,
                        name,
                        exe,
                        create_time,
                    });
                },
                RawEvent::Stop {
                    pid,
                    exit_code,
                    commit_peak_bytes,
                } => {
                    self.exited.insert(pid);
                    // The process is gone: release the cached handle instead
                    // of keeping it until backend drop.
                    self.close(pid);
                    self.ready.push_back(ProcessEvent::Exited {
                        pid,
                        exit_code,
                        commit_peak_bytes,
                    });
                },
            }
        }
    }
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        if let Some((_, handle)) = self.root.take() {
            // Safety: the spawn handle is owned by this backend and closed once.
            let _ = unsafe { CloseHandle(handle) };
        }
        for (_, handle) in self.handles.drain() {
            // Safety: each cached handle is owned by this backend and drained once.
            let _ = unsafe { CloseHandle(handle) };
        }
    }
}

impl EventSource for WindowsBackend {
    /// ETW requires elevation; start the session here, before any child is
    /// spawned, so a failure cannot orphan a running process.
    fn preflight(&mut self) -> Result<()> {
        ensure_elevated()?;

        let session = format!("ramline-{}", std::process::id());
        let tx = self.raw_tx.clone();
        let callback = move |record: &EventRecord, locator: &SchemaLocator| {
            // Keep the callback cheap (TDH parsing + channel send): ProcessTrace
            // delivery is serialized, so a slow callback loses buffers. A panic
            // would unwind across the FFI boundary (abort); log it instead.
            if let Err(e) = std::panic::catch_unwind(AssertUnwindSafe(|| {
                if let Some(raw) = parse_event(record, locator) {
                    let _ = tx.send(raw);
                }
            })) {
                error!("ETW callback panicked: {e:?}");
            }
        };
        let builder = Provider::by_guid(KERNEL_PROCESS_PROVIDER)
            .any(KEYWORD_PROCESS)
            .add_callback(callback);
        // Always request a capture-state rundown at trace start: in attach
        // mode it discovers already-running descendants, in spawn mode it
        // picks up children spawned between process creation and session
        // start. Event 15 feeds the same Start path; the TreeFilter dedups
        // rundown Starts against live ones.
        let builder = builder.request_capture_state();
        let (trace, handle) = UserTrace::new()
            .named(session.clone())
            .enable(builder.build())
            .start()
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to start ETW session `{session}`: {e:?}; ETW requires elevation, run \
                     ramline as administrator (e.g. via sudo)"
                )
            })?;
        let thread = std::thread::spawn(move || {
            if let Err(e) = UserTrace::process_from_handle(handle) {
                error!("ETW processing thread failed: {e:?}");
            }
        });
        self.trace = Some(EtwTrace {
            trace: Some(trace),
            thread: Some(thread),
        });
        Ok(())
    }

    fn start(&mut self, root: RootInfo) -> Result<()> {
        self.filter = Some(TreeFilter::new(root.pid));

        // Register the root explicitly: its ETW Start (live or rundown) can
        // arrive up to ~1 s late, and the TreeFilter drops that duplicate.
        let handle = self
            .handle(root.pid)
            .with_context(|| format!("cannot open root process (pid {})", root.pid))?;
        let (name, exe) = Self::query_image(handle)
            .map_or_else(|| (String::from("unknown"), None), |(n, e)| (n, Some(e)));
        self.ready.push_back(ProcessEvent::Spawned {
            pid: root.pid,
            ppid: root.ppid,
            name,
            exe,
            create_time: None,
        });
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

impl ProcessOps for WindowsBackend {
    fn spawn_root(&mut self, argv: &[String], max_rss: Option<u64>) -> Result<u32> {
        // The job limit is commit-based (JobMemoryLimit), the engine's
        // software limiter is RSS-based; both stay active, the job is the
        // backstop for races and for ramline dying mid-run.
        let job = max_rss.map(Job::new).transpose()?;
        let (pid, handle) = spawn_process(argv, job.as_ref())?;
        self.job = job;
        self.root = Some((pid, handle));
        Ok(pid)
    }

    fn job_peak_memory_bytes(&self) -> Option<u64> {
        self.job.as_ref().and_then(Job::peak_memory_bytes)
    }

    fn sample(&mut self, pid: u32) -> Option<MemorySample> {
        let handle = self.handle(pid)?;
        // GetExitCodeProcess doubles as a liveness probe: a terminated process
        // stays openable while we hold a handle, so query failure alone cannot
        // detect exit.
        if Self::raw_exit_code(handle).is_some() {
            self.close(pid);
            return None;
        }
        let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS_EX>()).unwrap_or(u32::MAX);
        let mut counters = PROCESS_MEMORY_COUNTERS_EX {
            cb: size,
            ..Default::default()
        };
        // Safety: counters is a valid out buffer of the size advertised in cb.
        unsafe { GetProcessMemoryInfo(handle, (&raw mut counters).cast(), size) }.ok()?;
        Some(MemorySample {
            rss_bytes: counters.WorkingSetSize as u64,
            private_bytes: counters.PrivateUsage as u64,
            page_faults: u64::from(counters.PageFaultCount),
        })
    }

    fn kill(&mut self, pid: u32) -> Result<()> {
        let Some(handle) = self.handle(pid) else {
            return Ok(()); // already gone
        };
        // Safety: handle is a live process handle opened with PROCESS_TERMINATE.
        unsafe { TerminateProcess(handle, 1) }
            .with_context(|| format!("TerminateProcess failed for pid {pid}"))?;
        self.close(pid);
        Ok(())
    }

    fn exit_code(&mut self, pid: u32) -> Option<i32> {
        let handle = match self.root {
            // The spawn-mode root handle pins the process object and stays
            // valid after exit.
            Some((root, handle)) if root == pid => handle,
            // A pid whose Stop was accepted may have been recycled; the
            // ETW event's exit code (delivered to the engine) is
            // authoritative for it.
            _ if self.exited.contains(&pid) => return None,
            _ => self.handle(pid)?,
        };
        Self::raw_exit_code(handle).map(|code| i32::from_ne_bytes(code.to_ne_bytes()))
    }
}

/// Spawn the monitored command via `CreateProcessW`.
///
/// With a `job` the process is created suspended, assigned to the job, then
/// resumed, so it never runs outside the job and its descendants inherit the
/// job. Returns the pid and the process handle (kept for exit-code reads).
fn spawn_process(argv: &[String], job: Option<&Job>) -> Result<(u32, HANDLE)> {
    let program = argv.first().context("empty command")?;
    // CreateProcessW may rewrite the command line: it must be a mutable,
    // null-terminated buffer.
    let mut cmdline: Vec<u16> = build_command_line(argv)
        .encode_utf16()
        .chain(once(0))
        .collect();
    // Pass the std handles explicitly: without STARTF_USESTDHANDLES a
    // redirected (piped) parent stdout would not propagate to the child.
    let startup = STARTUPINFOW {
        cb: u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX),
        dwFlags: STARTF_USESTDHANDLES,
        // Safety: GetStdHandle returns a borrowed standard handle; no ownership is taken.
        hStdInput: unsafe { GetStdHandle(STD_INPUT_HANDLE) }.unwrap_or_default(),
        // Safety: GetStdHandle returns a borrowed standard handle; no ownership is taken.
        hStdOutput: unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.unwrap_or_default(),
        // Safety: GetStdHandle returns a borrowed standard handle; no ownership is taken.
        hStdError: unsafe { GetStdHandle(STD_ERROR_HANDLE) }.unwrap_or_default(),
        ..Default::default()
    };
    let creation_flags = CREATE_UNICODE_ENVIRONMENT
        | job.map_or(PROCESS_CREATION_FLAGS::default(), |_| CREATE_SUSPENDED);
    let mut pi = PROCESS_INFORMATION::default();
    // Safety: cmdline is a mutable null-terminated UTF-16 buffer; startup and
    // pi are valid in/out pointers.
    unsafe {
        CreateProcessW(
            PWSTR::null(), // application name resolved from the first command-line token
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            true, // inherit the std handles above
            creation_flags,
            None,          // inherit the parent environment
            PWSTR::null(), // inherit the working directory
            &raw const startup,
            &raw mut pi,
        )
    }
    .with_context(|| format!("failed to spawn `{program}`"))?;

    // On failure after CreateProcessW succeeded, never leave a suspended
    // process behind.
    let setup = (|| -> Result<()> {
        if let Some(job) = job {
            job.assign(pi.hProcess)?;
            // Safety: pi.hThread is a valid thread handle returned by CreateProcessW.
            if unsafe { ResumeThread(pi.hThread) } == u32::MAX {
                bail!("ResumeThread failed for `{program}`");
            }
        }
        Ok(())
    })();
    // Safety: pi.hThread is owned and closed exactly once.
    let _ = unsafe { CloseHandle(pi.hThread) };
    if let Err(e) = setup {
        // Safety: pi.hProcess is a valid owned process handle.
        let _ = unsafe { TerminateProcess(pi.hProcess, 1) };
        // Safety: pi.hProcess is closed exactly once on this error path.
        let _ = unsafe { CloseHandle(pi.hProcess) };
        return Err(e);
    }
    Ok((pi.dwProcessId, pi.hProcess))
}

/// Join argv into a single `CreateProcessW` command line.
fn build_command_line(argv: &[String]) -> String {
    let mut out = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        push_quoted_arg(&mut out, arg);
    }
    out
}

/// Append one argument, quoting it with the MSVCRT command-line rules:
/// arguments containing spaces, tabs or quotes (and empty arguments) are
/// wrapped in double quotes, backslashes are doubled before a quote, and a
/// quote itself is backslash-escaped.
fn push_quoted_arg(out: &mut String, arg: &str) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(2 * backslashes + 1));
                out.push('"');
                backslashes = 0;
            },
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            },
        }
    }
    // Trailing backslashes run into the closing quote: double them.
    out.push_str(&"\\".repeat(2 * backslashes));
    out.push('"');
}

fn ensure_elevated() -> Result<()> {
    // Safety: no preconditions.
    if unsafe { IsUserAnAdmin() }.as_bool() {
        Ok(())
    } else {
        bail!(
            "process monitoring on Windows uses ETW, which requires elevation; run ramline as \
             administrator (e.g. `sudo ramline ...`)"
        )
    }
}

/// Parse the fields ramline needs out of a Kernel-Process event; `None` for
/// events outside the process keyword selection.
// pid/ppid are the domain names; similar_names does not apply here
#[allow(clippy::similar_names)]
fn parse_event(record: &EventRecord, locator: &SchemaLocator) -> Option<RawEvent> {
    match record.event_id() {
        EVENT_PROCESS_START | EVENT_PROCESS_RUNDOWN => {
            let schema = locator.event_schema(record).ok()?;
            let parser = Parser::create(record, &schema);
            Some(RawEvent::Start {
                pid: parser.try_parse("ProcessID").unwrap_or(0),
                ppid: parser.try_parse("ParentProcessID").unwrap_or(0),
                create_time: parse_create_time(&parser),
                image: parser.try_parse("ImageName").unwrap_or_default(),
            })
        },
        EVENT_PROCESS_STOP => {
            let schema = locator.event_schema(record).ok()?;
            let parser = Parser::create(record, &schema);
            Some(RawEvent::Stop {
                pid: parser.try_parse("ProcessID").unwrap_or(0),
                exit_code: parser
                    .try_parse::<u32>("ExitCode")
                    .ok()
                    .map(|c| i32::from_ne_bytes(c.to_ne_bytes())),
                commit_peak_bytes: parser.try_parse("CommitPeak").ok(),
            })
        },
        _ => None,
    }
}

/// `CreateTime` is a FILETIME field; accept a plain integer too in case a
/// schema version reports it as one.
fn parse_create_time(parser: &Parser) -> Option<u64> {
    if let Ok(t) = parser.try_parse::<u64>("CreateTime") {
        return Some(t);
    }
    let ft = parser.try_parse::<FileTime>("CreateTime").ok()?;
    // Exact roundtrip: unix nanos = raw filetime * 100 - epoch offset.
    let nanos =
        ft.as_unix_timestamp_nanos() + i128::from(SECONDS_BETWEEN_1601_AND_1970) * 1_000_000_000;
    u64::try_from(nanos / 100).ok()
}

/// Process creation time of an opened handle as a raw filetime.
fn creation_time(handle: HANDLE) -> Option<u64> {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // Safety: handle is a live process handle; all four out pointers
    // reference valid FILETIMEs.
    unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
        .ok()?;
    }
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// Split an ETW `ImageName` (NT device path) into a process name and a Win32
/// path. Falls back to the device path when no drive letter maps onto it.
fn image_name_parts(image: &str) -> (String, Option<PathBuf>) {
    if image.is_empty() {
        return (String::from("unknown"), None);
    }
    let path = device_to_win32_path(image).unwrap_or_else(|| image.to_owned());
    let exe = PathBuf::from(path);
    let name = exe.file_name().map_or_else(
        || String::from("unknown"),
        |n| n.to_string_lossy().into_owned(),
    );
    (name, Some(exe))
}

/// Convert an NT device path (`\Device\HarddiskVolumeX\...`) to a Win32 path
/// using the current drive-letter mapping; `None` when no drive matches.
fn device_to_win32_path(image: &str) -> Option<String> {
    // Safety: no preconditions; returns a drive bitmask.
    let drives = unsafe { GetLogicalDrives() };
    for i in 0..26u8 {
        if drives & (1 << i) == 0 {
            continue;
        }
        let letter = b'A' + i;
        let Some(device) = query_dos_device(letter) else {
            continue;
        };
        if image
            .get(..device.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&device))
        {
            return Some(format!("{}:{}", char::from(letter), &image[device.len()..]));
        }
    }
    None
}

/// Device path (`\Device\HarddiskVolumeX`) backing a drive letter, via
/// `QueryDosDeviceW`.
fn query_dos_device(letter: u8) -> Option<String> {
    let name = [u16::from(letter), u16::from(b':'), 0];
    let mut buf = [0u16; BUF_LEN as usize];
    // Safety: name is null-terminated; buf is writable for BUF_LEN u16s.
    let len = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) } as usize;
    if len == 0 {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..len.min(BUF_LEN as usize)]);
    Some(s.trim_end_matches('\0').to_owned())
}

// pid/ppid are the domain names; similar_names does not apply here
#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    fn start(pid: u32, ppid: u32) -> RawEvent {
        RawEvent::Start {
            pid,
            ppid,
            create_time: None,
            image: String::new(),
        }
    }

    fn stop(pid: u32) -> RawEvent {
        RawEvent::Stop {
            pid,
            exit_code: Some(0),
            commit_peak_bytes: None,
        }
    }

    fn pids(out: &[RawEvent]) -> Vec<u32> {
        out.iter().map(RawEvent::pid).collect()
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
        // Grandchild arrives before its parent (same flush batch reorder).
        filter.on_event(start(3, 2), &mut out);
        filter.on_event(stop(3), &mut out);
        assert!(out.is_empty());
        filter.on_event(start(2, 1), &mut out);
        assert_eq!(pids(&out), vec![2, 3, 3]);
    }

    #[test]
    fn dedups_rundown_and_live_starts() {
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        filter.on_event(start(2, 1), &mut out);
        filter.on_event(start(2, 1), &mut out); // duplicate
        filter.on_event(stop(2), &mut out);
        filter.on_event(stop(2), &mut out); // duplicate
        assert_eq!(pids(&out), vec![2, 2]);
    }

    #[test]
    fn dedups_rundown_start_for_root_and_adopts_existing_children() {
        // Spawn-mode rundown: the root's own Start arrives via rundown while
        // it was already registered; pre-existing children have a known
        // parent and are adopted.
        let mut filter = TreeFilter::new(1);
        let mut out = Vec::new();
        filter.on_event(start(1, 99), &mut out); // rundown Start for root itself
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

    #[test]
    fn quotes_command_line_args_per_msvcrt_rules() {
        let argv = |args: &[&str]| args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        // Plain arguments stay bare.
        assert_eq!(
            build_command_line(&argv(&["powershell", "-NoProfile"])),
            "powershell -NoProfile"
        );
        // Spaces and empty arguments are quoted.
        assert_eq!(
            build_command_line(&argv(&["cmd", "a b", ""])),
            r#"cmd "a b" """#
        );
        // Backslashes are doubled only before a quote; embedded quotes are escaped.
        assert_eq!(
            build_command_line(&argv(&[r"C:\a b\", r#"x\"y"#])),
            r#""C:\a b\\" "x\\\"y""#
        );
    }

    #[test]
    fn converts_device_paths_to_win32() {
        // Relies only on the system drive letter mapping existing.
        let sys_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_owned());
        let device = query_dos_device(sys_drive.as_bytes()[0]).unwrap();
        let image = format!(r"{device}\Windows\System32\cmd.exe");
        let converted = device_to_win32_path(&image).unwrap();
        assert_eq!(converted, format!(r"{sys_drive}\Windows\System32\cmd.exe"));
        let (name, exe) = image_name_parts(&image);
        assert_eq!(name, "cmd.exe");
        assert_eq!(exe.unwrap(), PathBuf::from(converted));
    }
}
