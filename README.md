# ramline

Cross-platform memory monitor for a command and all its spawned descendant processes.

On Windows, ramline requires **elevation** (administrator): process discovery uses an ETW trace session, which is admin-only. Run it elevated, e.g. `sudo ramline -- ...`.

On Linux, ramline requires **root** (or CAP_BPF + CAP_PERFMON), a kernel with BTF (`/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF`) and pidfd support (kernel 5.3+). `--max-memory` enforcement additionally requires cgroup v2 (`/sys/fs/cgroup`) and kernel 5.19+ (`memory.peak`, `cgroup.kill`).

## Usage

```sh
# Spawn and monitor a command
ramline --json report.json --chart chart.svg -- my-command --its-args

# Kill the whole process tree when total RSS exceeds a limit
ramline --max-memory 2G -- my-command

# Attach to an existing process tree
ramline --pid 1234 --json report.json
```

Options:

- `--interval/-i <ms>`: RSS sampling interval (default 100)
- `--max-memory/-m <SIZE>`: hard limit (e.g. `512M`, `2G`, `1048576`); exceeding it kills the whole tree, ramline exits with code 3
- `--json <PATH>`: JSON report (per-process series, totals timeline, outcome, summary)
- `--chart <PATH>`: SVG line chart (total RSS, top processes, limit line)
- `--verbose/-v`: debug logging

Otherwise ramline exits with the monitored command's exit code.

## Design

- Process discovery is event-driven: the platform backend emits `Spawned`/`Exited` events through a crossfire channel; RSS sampling is timer-driven at `--interval`.
- The event source contract pre-filters events to the monitored tree; the engine trusts every event it receives.
- Backends implement `EventSource` + `ProcessOps` (see `src/monitor/mod.rs`). Sampling failure doubles as a liveness probe, so an `Exited` event is never strictly required.
- Windows: discovery uses ETW (ferrisetw2): a `UserTrace` session (`ramline-<pid>`) on the manifest provider Microsoft-Windows-Kernel-Process, keyword `WINEVENT_KEYWORD_PROCESS` (Start/Stop/Rundown events). A capture-state rundown (event 15) is requested at session start: attach mode (`--pid`) discovers already-running descendants through it, and spawn mode picks up children that started before the session was up. The backend filters events down to the monitored tree (parking events whose parent has not arrived yet), guards against PID reuse via the event's create time, and converts `ImageName` device paths to Win32 paths. Sampling/kill are plain Win32 (`GetProcessMemoryInfo`, `TerminateProcess`).
  - Event latency: ETW delivers events when a buffer fills or the 1 s flush timer fires, so Start/Stop notifications arrive up to ~1 s late. ramline absorbs this with a post-exit grace window and the sampler-based liveness probe. A process too short-lived to be sampled still gets its peak commit at exit recorded as `final_commit_peak_bytes` in the JSON report.
- Linux: discovery uses eBPF tracepoints (aya): programs on sched/sched_process_fork and sched/sched_process_exit push (child pid, parent tgid, comm) / (pid) records through a 1 MiB ring buffer, which a dedicated thread polls on a current-thread tokio runtime. The fork record carries no child tgid, so thread forks are filtered in userspace; the exit path uses the record's `group_dead` field. The kernel counts attempted and dropped events in a per-CPU map; on shutdown a nonzero drop count is logged as a warning, since a lost fork means an untracked child escaping the memory limit. The platform-pure tree filter (`src/monitor/tree.rs`) drops events outside the monitored tree. Attach mode has no tracepoint rundown equivalent: already-running descendants are seeded from a one-shot /proc scan at start, and forks racing the scan still arrive live. Sampling reads /proc/<pid>/status (VmRSS; RssAnon + VmSwap as private bytes) and /proc/<pid>/stat (page faults) through a pinned directory fd, and kill goes through a pidfd, so a recycled pid is never sampled or signaled by mistake (the tracepoints carry no creation time, hence no create-time guard like on Windows). A process too short-lived to be sampled still appears in the report with its exit time, but without a commit peak (Linux has no equivalent).

## Memory-limit enforcement

`--max-memory` is enforced on two layers (spawn mode):

- Software limiter: the engine compares total sampled RSS against the limit every `--interval` tick and kills the tree, producing the `killed` outcome with reason `memory_limit_exceeded` and a full report.
- OS backstop, tripping between two samples and also when ramline dies mid-run:
  - Windows: the root process is created suspended, assigned to a job object with `JOB_OBJECT_LIMIT_JOB_MEMORY` (a job-wide commit limit), then resumed; descendants inherit the job. The job also has `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: if ramline dies or crashes mid-run, the OS closes the job handle and terminates the tree.
  - Linux: the root process joins a cgroup v2 directory `/sys/fs/cgroup/ramline-<ramline pid>` (named after the ramline process: cgroupfs forbids renaming directories and the root pid is unknown before the spawn) with `memory.max` set to the limit, via an async-signal-safe `pre_exec` hook before its first instruction, so descendants inherit the limit race-free. When cgroup usage exceeds the limit the kernel OOM-kills the offender. The directory is removed on exit (remaining members are SIGKILLed first).

The two limits measure differently (Windows commit vs RSS; cgroup usage vs RSS), so when the OS backstop trips first the engine only observes an all-dead tree or an OOM-killed offender; the outcome is then reported as `killed` with reason `os_job_limit` when the OS backstop confirms the trip: on Windows when the job's peak commit reached the limit, on Linux when the cgroup's `memory.events` `oom_kill` count is nonzero. (cgroup usage includes reclaimable page cache, so a `memory.peak` at the limit alone does not imply an OOM kill.) The JSON summary carries `job_peak_memory_bytes`; OS accounting includes exited processes, so it can exceed the sampled RSS peak. Attach mode (`--pid`) skips the OS backstop: a running foreign tree cannot be reliably reassigned.

Exit-code parity gap in attach mode: on Windows the ETW Stop event carries the root's exit code; on Linux the exit tracepoint carries no code and a pidfd cannot reap a non-child, so the report's outcome code is `null` and ramline exits 0 when the attached tree finished without a kill.

## Build

```sh
cargo build --release
```

Building for Linux additionally requires a nightly toolchain with `rust-src` (`rustup component add rust-src`) and `bpf-linker`; `build.rs` compiles the `ramline-ebpf` crate via aya-build and embeds the object into the binary. Reproducible bpf-linker install:

```sh
cargo install bpf-linker --locked --version 0.13.0 --no-default-features --features llvm-23
```

bpf-linker links against LLVM via llvm-config; the LLVM major (23 for the `llvm-23` feature) must be at least as new as the LLVM rustc uses to emit bitcode, and llvm-config must be discoverable (on PATH or via `LLVM_SYS_231_PREFIX`). NixOS: use `llvmPackages_23`, put the dev output's llvm-config on PATH (or set `LLVM_SYS_231_PREFIX`) and set `LLVM_SYS_231_LIBDIR` to the lib output so the installed binary finds libLLVM.

## Test

```sh
cargo nextest run
```

Live ETW integration tests are gated behind the `admin-tests` feature and require elevation. Build unelevated, then run the produced test binary as administrator:

```sh
cargo test --features admin-tests --no-run
sudo <target>/debug/deps/ramline-<hash>.exe etw_tests --test-threads=1
```

The Linux equivalents (`ebpf_tests`) require root:

```sh
cargo test --features admin-tests --no-run
sudo <test-binary> ebpf_tests --test-threads=1
```

The test-binary path depends on the cargo version: recent cargo (new build-dir layout, e.g. nightly 1.102) places it at `target/debug/build/ramline/<hash>/out/ramline-<hash>`, older cargo at `target/debug/deps/ramline-<hash>`. `cargo test --no-run` prints the exact path.
