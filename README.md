# ramline

Cross-platform memory monitor for a command and all its spawned descendant processes. Windows-first; Linux planned.

On Windows, ramline requires **elevation** (administrator): process discovery uses an ETW trace session, which is admin-only. Run it elevated, e.g. `sudo ramline -- ...`.

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
- Linux: stub only; planned via aya eBPF.

## Memory-limit enforcement

`--max-memory` is enforced on two layers (Windows, spawn mode):

- Software limiter: the engine compares total sampled RSS against the limit every `--interval` tick and kills the tree, producing the `killed` outcome with reason `memory_limit_exceeded` and a full report.
- Job-object backstop: the root process is created suspended, assigned to a job object with `JOB_OBJECT_LIMIT_JOB_MEMORY` (a job-wide commit limit), then resumed; descendants inherit the job. If the commit limit trips between two samples, Windows kills the whole tree on its own. The job also has `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: if ramline dies or crashes mid-run, the OS closes the job handle and terminates the tree.

The two limits measure differently (commit vs RSS), so when the job trips first the engine only observes an all-dead tree; the outcome is then reported as `killed` with reason `os_job_limit` when the job's peak commit reached the limit. The JSON summary carries `job_peak_memory_bytes`, the job's peak commit; job accounting includes exited processes, so it can exceed the sampled RSS peak. Attach mode (`--pid`) skips job creation: a running foreign tree cannot be reliably reassigned.

## Build

```sh
cargo build --release
```

## Test

```sh
cargo nextest run
```

Live ETW integration tests are gated behind the `admin-tests` feature and require elevation. Build unelevated, then run the produced test binary as administrator:

```sh
cargo test --features admin-tests --no-run
sudo <target>/debug/deps/ramline-<hash>.exe etw_tests --test-threads=1
```
