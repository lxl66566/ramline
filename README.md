# ramline

Cross-platform memory monitor for a command and all its spawned descendant processes. Windows-first; Linux planned.

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
- Windows: sampling/kill implemented via Win32 (`GetProcessMemoryInfo`, `TerminateProcess`). The current event source is a placeholder registering only the root pid; it will be replaced by an ETW kernel trace (ferrisetw2) in the next milestone, which will require elevation.
- Linux: stub only; planned via aya eBPF.

## Build

```sh
cargo build --release
```
