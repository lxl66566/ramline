# ramline ETW research: ferrisetw2 for process-lifecycle monitoring

Research date: 2026-11-21. Sources: `ferrisetw2` source (github.com/lxl66566/ferrisetw2, cloned with `--filter=blob:none`), live Windows manifests on this machine (`wevtutil gp`, `root\wmi` MOF classes, embedded TDH templates in `C:\Windows\System32\Microsoft-Windows-System-Events.dll`), and Microsoft ETW documentation.

## 1. ferrisetw2: identity, version, status

- crates.io: `ferrisetw2 = "2.0.0"` ("Safe Rust abstractions over the ETW consumer APIs, fork of ferrisetw"). Repository: https://github.com/lxl66566/ferrisetw2. This is the v2 line; upstream `n4r1b/ferrisetw` is effectively unmaintained (the fork README describes ~40 bug fixes and new features "implemented by AI coding agents under human direction", `README.md`).
- Edition / MSRV: `edition = "2024"` (Cargo.toml), so Rust >= 1.85. No explicit `rust-version` field.
- Key dependencies (Cargo.toml): `windows = "0.62"` (features `Win32_System_Diagnostics_Etw` etc.), `bitflags 2`, `widestring 1.2`, `once_cell 1.21`, `rustc-hash 2`, `memchr 2`, `zerocopy 0.8`, optional `serde`/`time`. Optional features: `serde`, `time_rs`, `admin_tests` (gates live-session tests; the comment notes "creating an ETW trace session is admin-only").
- Examples in repo (`examples/`): `kernel_trace.rs` (KernelTrace + IMAGE_LOAD_PROVIDER), `user_trace.rs` (UserTrace + manifest provider `22fb2cd6-...` = Microsoft-Windows-Kernel-Process), `dns.rs`, `multiple_providers.rs`, `sys_info.rs`, `file_trace.rs`. Tests in `tests/` include live-session `kernel_trace.rs`, `trace_lifetime.rs`, `dynamic_providers.rs` (all `admin_tests`-gated).

## 2. Process lifecycle provider and subscription

### 2a. Kernel trace vs manifest provider

Two viable sources for process start/stop:

1. Classic kernel logger: `KernelTrace` + `Provider::kernel(&kernel_providers::PROCESS_PROVIDER)` (`src/provider/kernel_providers.rs`). GUID `3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c`, `EnableFlags` bit `EVENT_TRACE_FLAG_PROCESS = 0x1`. Decoded via WMI MOF classes (`root\wmi`, class `Process_V4_TypeGroup1` etc.). Advantage: Start event payload includes `CommandLine` (verified below).
2. Manifest provider `Microsoft-Windows-Kernel-Process` (`22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716`) on a `UserTrace`. Advantage: normal per-provider enablement (no shared system-logger constraints), keyword filtering (`WINEVENT_KEYWORD_PROCESS = 0x10`), per-provider runtime enable/disable, and ferrisetw2's own example uses it. Disadvantage: no `CommandLine` field (verified below).

ferrisetw2 supports both well. The crate handles the kernel-trace specifics: on Windows 8+ it sets `EVENT_TRACE_SYSTEM_LOGGER_MODE` (`PrivateRealTimeTraceTrait for KernelTrace::augmented_file_mode`, `src/trace.rs`) so a named system-logger session can be used instead of the singleton "NT Kernel Logger"; on Windows 8+ multiple kernel sessions can coexist. On pre-Win8 the name is forced to "NT Kernel Logger" (`TraceBuilder::named`, `src/trace.rs`).

Minimal working snippet, adapted from `examples/user_trace.rs`, with start/stop and clean cross-thread shutdown:

```rust
use std::sync::mpsc::Sender;
use ferrisetw2::{EventRecord, parser::Parser, provider::*, schema_locator::SchemaLocator, trace::*};

const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716; // Microsoft-Windows-Kernel-Process
const KEYWORD_PROCESS: u64 = 0x10; // WINEVENT_KEYWORD_PROCESS
const EVENT_PROCESS_START: u16 = 1;
const EVENT_PROCESS_STOP: u16 = 2;
const EVENT_PROCESS_RUNDOWN: u16 = 15;

#[derive(Debug)]
pub enum ProcEvent { Start { pid: u32, parent: u32, image: String }, Stop { pid: u32 } }

fn start_trace(tx: Sender<ProcEvent>) -> UserTrace {
    let cb = move |record: &EventRecord, locator: &SchemaLocator| {
        let Ok(schema) = locator.event_schema(record) else { return };
        let parser = Parser::create(record, &schema);
        match record.event_id() {
            EVENT_PROCESS_START | EVENT_PROCESS_RUNDOWN => {
                let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                let parent: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                let image: String = parser.try_parse("ImageName").unwrap_or_default();
                let _ = tx.send(ProcEvent::Start { pid, parent, image });
            },
            EVENT_PROCESS_STOP => {
                let pid: u32 = parser.try_parse("ProcessID").unwrap_or(0);
                let _ = tx.send(ProcEvent::Stop { pid });
            },
            _ => {},
        }
    };

    let provider = Provider::by_guid(KERNEL_PROCESS)
        .any(KEYWORD_PROCESS) // only Process keyword: events 1/2/15, skips Thread/Image/etc.
        .add_callback(cb)
        .build();

    UserTrace::new()
        .named(String::from("ramline-procmon"))
        .enable(provider)
        .start_and_process() // spawns the ProcessTrace thread, returns immediately
        .unwrap()
    // The returned UserTrace is !Send + !Sync; keep it on this thread.
    // Dropping it (or trace.stop()) stops the session and unblocks the
    // processing thread cleanly (Windows reports ERROR_CANCELLED, mapped to Ok).
}
```

Kernel-trace variant (for `CommandLine`), adapted from `examples/kernel_trace.rs`:

```rust
let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
    .add_callback(cb) // opcode: 1=Start, 2=Stop, 3=DCStart, 4=DCEnd
    .build();
let trace = KernelTrace::new()
    .named(String::from("ramline-procmon")) // Win8+: named system logger session
    .enable(provider)
    .start_and_process()
    .unwrap();
```

Cleanup semantics (evidence): `TraceTrait::stop` consumes the trace; "The same result is achieved by dropping `Self`" (`src/trace.rs`). `impl Drop` runs `non_consuming_stop`, which always both `CloseTrace`s the consumer and `ControlTraceW(EVENT_TRACE_CONTROL_STOP)`s the session. `tests/trace_lifetime.rs` asserts via `logman query -ets` that after drop the session no longer exists, and that the processing thread reports `Ok` after `stop()`. A `StartedSessionGuard` stops a half-started session if `start()` fails midway. So panic/drop cleanup is handled by the crate; no session leak.

### 2b. Event schema and field access

Field access: `schema_locator.event_schema(record)` -> `Parser::create(record, &schema)` -> `parser.try_parse::<T>("FieldName")` (`src/parser.rs`, `examples/user_trace.rs`). Record-level accessors: `record.event_id()`, `record.opcode()`, `record.version()`, `record.process_id()`, `record.timestamp()` (`src/native/etw_types/event_record.rs`).

Manifest provider (`Microsoft-Windows-Kernel-Process`, live manifest via `wevtutil gp`):

| Event | Task | Opcode | Meaning |
|---|---|---|---|
| 1 | ProcessStart | win:Start (1) | process started |
| 2 | ProcessStop | win:Stop (2) | process stopped |
| 15 | ProcessRundown | win:Info (0) | rundown of already-running process |

All carry keyword `0x8000000000000010` (`WINEVENT_KEYWORD_PROCESS = 0x10`), so `.any(0x10)` selects exactly these.

Field lists, extracted from the embedded TDH binary templates in `Microsoft-Windows-System-Events.dll` (this is what TDH/ferrisetw2 actually decodes against; the manifest itself ships no `<template>` section):

- Event 1 (ProcessStart), by `record.version()`:
  - v0: `ProcessID, CreateTime, ParentProcessID, SessionID, ImageName`
  - v1: adds `Flags`
  - v2: adds `ImageChecksum, TimeDateStamp, PackageFullName, PackageRelativeAppId`
  - v3: restructured to `ProcessID, ProcessSequenceNumber, CreateTime, ParentProcessID, ParentProcessSequenceNumber, SessionID, Flags, ProcessTokenElevationType, ProcessTokenIsElevated, MandatoryLabel, ImageName, ...`
  - v4: adds `SecurityMitigations`
- Event 2 (ProcessStop): v0/v1 `ProcessID, CreateTime, ExitTime, ExitCode, TokenElevationType, HandleCount, CommitCharge, CommitPeak, ImageName`; v2 adds `ProcessSequenceNumber, CPUCycleCount, ReadOperationCount, WriteOperationCount, ReadTransferKiloBytes, WriteTransferKiloBytes, HardFaultCount`.
- Event 15 (ProcessRundown): same field layout as ProcessStart (manifest message strings match, "Enumerated process ...").

No `CommandLine` in any version of the manifest provider. `ferrisetw2`'s own example parses `ProcessID`, `ExitCode`, `ImageName` from event 2 (`examples/user_trace.rs`), confirming TDH decoding works through this shim despite the template-less manifest.

Classic kernel provider (`PROCESS_PROVIDER`, opcode 1=Start / 2=Stop / 3=DCStart / 4=DCEnd), decoded via `root\wmi` MOF classes (verified on this machine):

- Start, `Process_V4_TypeGroup1`: `ProcessId, ParentId, ImageFileName, Flags, UserSID, DirectoryTableBase, UniqueProcessKey, SessionId, ExitStatus, CommandLine, PackageFullName, ApplicationId` (V2 and V3 already include `CommandLine`).
- Stop, `Process_Terminate_TypeGroup1`: `ProcessId, Flags` (ExitStatus lives on the versioned variants).

So: if `CommandLine` matters, use the KernelTrace variant; the event's own `CommandLine` is empty for processes you cannot read anyway (system processes), and for PIDs you can simply call `NtQueryInformationProcess`/`QueryFullProcessImageNameW` + read PEB instead.

Note on `ImageFileName` (kernel) vs `ImageName` (manifest): both are the full device-style path (`\Device\HarddiskVolumeX\...`) or plain name depending on version; convert with `QueryDosDeviceW` if a Win32 path is needed.

### 2c. Rundown / attach-to-existing

- Kernel trace: enabling `EVENT_TRACE_FLAG_PROCESS` automatically emits ProcessRundown as DCStart (opcode 3) events for every already-running process when the session starts, and DCEnd (opcode 4) when it stops. ferrisetw2 delivers these to the callback; `tests/kernel_trace.rs` documents that kernel rundown events are delivered session-wide regardless of PID filters, some with placeholder PIDs like `0xFFFFFFFF`.
- Manifest provider: event 15 `ProcessRundown` is emitted for running processes. Additionally ferrisetw2 supports explicit capture-state rundown: `ProviderBuilder::request_capture_state()` sends `EVENT_CONTROL_CODE_CAPTURE_STATE` on enable (`src/provider.rs`, `src/native/evntrace.rs::capture_provider_state`), and `UserTrace::request_capture_state()` re-requests a rundown on a running trace. A rundown is automatically requested at trace start for providers built with `request_capture_state()`.

For ramline's use case (monitor one command and its descendants started after launch), rundown is not strictly needed, but it is the correct answer for an "attach to existing pid" mode: enumerate via rundown events, then keep the live 1/2 stream.

### 2d. Elevation verdict

Elevation is mandatory for every ETW path here:

- Starting any trace controller session (`StartTraceW`) requires the user to be in Performance Log Users / Administrators; for kernel/system loggers and for enabling kernel providers, administrator privileges are required in practice. ferrisetw2 encodes this directly: the Cargo.toml comment on the `admin_tests` feature says "creating an ETW trace session is admin-only", and all live-session tests (`tests/kernel_trace.rs`, `tests/trace_lifetime.rs`, `tests/dynamic_providers.rs`) are gated behind it.
- `Microsoft-Windows-Kernel-Process` is a kernel-mode provider; consuming it requires starting an elevated trace session.
- There is no non-elevated ETW path for process start/stop. The non-elevated alternatives are poll-based (Toolhelp `CreateToolhelp32Snapshot`, `NtQuerySystemInformation`) or WMI `Win32_ProcessStartTrace` (itself requires admin and is slow).

Verdict: ramline must require admin (or Performance Log Users membership plus testing) for ETW. A sane fallback is the poll-based snapshot loop when ETW init fails with access denied.

### 2e. Latency and buffering

- `TraceProperties::default()` (`src/trace.rs`): 32 KB buffers, `flush_timer = 1s`, `log_file_mode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING`, QPC timestamps.
- The `FlushTimer` field of `EVENT_TRACE_PROPERTIES` is expressed in whole seconds; ferrisetw2 rounds to the nearest second and clamps to a minimum of 1 (`src/native/etw_types.rs`, `FlushTimer` computation and test `flush_timer_is_rounded_to_the_closest_second`). Sub-second flush is not reachable through ferrisetw2's API.
- Consequence: ETW delivers a buffer to the real-time consumer when it fills or when the flush timer fires. Process start/stop is a low-rate event stream, so a 32 KB buffer essentially never fills; delivery latency is bounded by the flush timer: expect 0–1 s, worst case ~1 s. The event record's timestamp (`record.timestamp()`) is accurate at occurrence time, so the delay is a notification delay, not a measurement error.
- Mitigations: none inside ferrisetw2 for <1 s flush. Options: accept ~1 s (fine for lifecycle bookkeeping), or complement ETW with a fast initial polling loop (Toolhelp snapshot of descendants every ~100 ms for the first seconds, then back off) to catch short-lived children for RSS sampling. RSS sampling itself is timer-based anyway, so a child living <1 s may simply get zero ETW-driven samples; the polling fallback is what closes that hole.
- Health monitoring: `RealTimeTraceTrait::statistics()` (live `ControlTraceW` QUERY) exposes `events_lost` / `real_time_buffers_lost` if loss ever becomes a concern.

## 3. Per-process memory ETW events

Nothing usable for continuous per-process RSS/working-set monitoring exists:

- `PROCESS_COUNTER_PROVIDER` (`EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x8`, `src/provider/kernel_providers.rs`): ProcessCounter events carry working set / pagefile counters per process, but they are emitted at rundown and at process exit, not continuously.
- `Microsoft-Windows-Kernel-Memory` (`d1d93ef7-e1f2-4f45-9943-03d245fe6c00`, checked via `Get-WinEvent -ListProvider`): its events are MemInfo-style snapshots (system-wide counters; MemInfoWS lists per-process working sets), generated on capture-state/periodic-capture, not on memory changes.
- ferrisetw2's `ExtendedKernelGroup` (`src/trace.rs`) exposes the fine-grained kernel memory groups — `Memory`, `MemInfo`, `MemInfoWorkingSet`, `WorkingSet`, `Footprint`, `WorkingSetDetail`, ... — all of which are page-fault/working-set instrumentation or snapshot-style data, far too noisy or too coarse for "RSS of a process tree" accounting.
- PageFault kernel events (`MEMORY_PAGE_FAULT_PROVIDER`, `MEMORY_HARD_FAULT_PROVIDER`; MOF classes `PageFault_*`) are per-fault events, not RSS.
- The one freebie: manifest `ProcessStop` (event 2) carries `CommitCharge`/`CommitPeak` (private bytes at exit). Useful as a final data point for short-lived processes that exited before any RSS sample, but it is commit, not working set.

Conclusion: timer-based `GetProcessMemoryInfo` sampling (`K32GetProcessMemoryInfo` / `PROCESS_MEMORY_COUNTERS_EX::WorkingSetSize` + `PrivateUsage`) is the right design. ETW should be used only for discovery (who is in the tree, when it died).

## 4. Alternative: Job Objects

The OS can enforce memory limits itself via Job Objects (`windows` crate, `Win32::System::JobObjects`):

- `CreateJobObjectW(None, None)` -> `SetInformationJobObject(h, JobObjectExtendedLimitInformation, &JOBOBJECT_EXTENDED_LIMIT_INFORMATION { BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION { LimitFlags: JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, .. }, ProcessMemoryLimit, JobMemoryLimit, .. })` -> `AssignProcessToJobObject(job, process)`.
- `QueryInformationJobObject` with `JobObjectExtendedLimitInformation` returns live `PeakProcessMemoryUsed` / `PeakJobMemoryUsed`; `JobObjectBasicAndIoAccountingInformation` gives I/O and total CPU. Job accounting aggregates across all processes ever in the job, including exited ones — this also answers the "child exited before we sampled it" problem for peaks.
- Event-driven notifications: `CreateIoCompletionPort` + `SetInformationJobObject(JobObjectAssociateCompletionPortInformation)` yields messages such as `JOB_OBJECT_MSG_JOB_MEMORY_LIMIT`, `JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT`, `JOB_OBJECT_MSG_NEW_PROCESS`, `JOB_OBJECT_MSG_EXIT_PROCESS`, `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO`. `NEW_PROCESS`/`EXIT_PROCESS` notifications are an elevation-free alternative to ETW for tree discovery, but only for processes that stay in the job.
- Catches: children created with `CREATE_BREAKAWAY_FROM_JOB` escape when the job allows it (`JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` / `BREAKAWAY_OK`) — do not set those flags, but a process already inside another job with breakaway-allowed semantics may still split off; processes that spawn children before being assigned leave those children outside; nested jobs are supported only on Windows 8+ (on older versions `AssignProcessToJobObject` fails for a process already in a job); on modern Windows some processes (UWP/MSIX, some services) are already in jobs and nesting mostly works, but edge cases exist.

Job objects are complementary, not a replacement: use them for OS-enforced kill-on-limit and aggregate peaks; keep ETW + timer sampling for attribution and reporting. Note ramline also *starts* the monitored command, so it can assign the root process to the job before `ResumeThread`, eliminating the assignment race for the root (descendants inherit the job by default).

## 5. Recommended integration design

Provider: manifest `Microsoft-Windows-Kernel-Process` (`22fb2cd6-...`) on a `UserTrace`, `.any(0x10)`, events 1 (Start), 2 (Stop), 15 (Rundown). Add `KernelTrace` + `PROCESS_PROVIDER` only if `CommandLine` from the event itself becomes a hard requirement — do not run both.

Architecture:

1. Spawn the ETW thread first: build provider + `UserTrace::new().named("ramline-procmon-<pid>")`, call `start()` (not `start_and_process`), spawn `UserTrace::process_from_handle(handle)` on a dedicated thread. Keep the `UserTrace` value on the owning thread (it is `!Send + !Sync`) and drop it for cleanup. `stop_if_exist(true)` (default) plus a unique session name avoids collisions.
2. Callback -> channel: the callback does only TDH parsing (microseconds) and `tx.try_send(ProcEvent)` into an unbounded `std::sync::mpsc` channel (or `crossbeam`). Never do `OpenProcess`/memory sampling inside the callback: `ProcessTrace` delivery is serialized, and a slow callback loses buffers.
3. Monitor thread consumes events and maintains a `HashMap<u32 /*pid*/, ProcEntry { parent, image, handle: Option<HANDLE>, samples }>` seeded with the root pid. On `Start { pid, parent, image }`: if `parent` is in the map, insert `pid` and immediately `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)` (also gives you a waitable handle for exit detection without waiting for event 2). If `parent` is not tracked yet, store it in a `pending: HashMap<u32 /*parent*/, Vec<ProcEvent>>` map and reconcile when the parent's Start arrives (events for a pid arrive in order per pid, but parent/child ordering across pids is not guaranteed within one flush batch).
4. Short-lived race handling: a Start event may arrive up to ~1 s after the process exited. `OpenProcess` on such a pid fails with `ERROR_INVALID_PARAMETER` — treat as "already dead, record with zero samples"; optionally keep the `CommitPeak` from its Stop event when it arrives as its final private-bytes data point. Guard against PID reuse by comparing `CreateTime` from the event against `GetProcessTimes` on the opened handle.
5. Stop events: mark the entry dead, take a final `GetProcessMemoryInfo` attempt (usually already fails), and free the entry after reporting. Rely on the waitable handle from step 3 (`WaitForSingleObject(..., 0)`) as the fast path for exit of tracked processes, since event 2 is also delayed up to ~1 s.
6. Sampler thread: every N ms, iterate tracked entries, `K32GetProcessMemoryInfo(handle, &mut PROCESS_MEMORY_COUNTERS_EX)` for `WorkingSetSize` (RSS) and `PrivateUsage`. This is confirmed the right design (section 3); optionally fold in Job Object peaks (section 4) for exited children.
7. Shutdown: drop the `UserTrace` (Drop = CloseTrace + ControlTrace STOP, verified by `tests/trace_lifetime.rs` via `logman`), join the processing thread (it exits with `Ok` on stop), drain the channel. On panic, unwinding drops the trace; no session leak. Optionally poll `trace.statistics()` for `events_lost`.
8. Rundown/attach mode: build the provider with `.request_capture_state()` (or call `trace.request_capture_state()` after start) and feed event-15 records through the same `ProcEvent::Start` path before trusting the live stream.

Residual caveats: admin is mandatory (2d); event latency up to ~1 s with no sub-second option in ferrisetw2 (2e); `ImageName` device paths need conversion; PID-reuse guard recommended.
