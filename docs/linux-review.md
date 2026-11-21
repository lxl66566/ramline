# Independent review: ramline Linux backend

Commits under review: 9e0c681 (tree-filter refactor), 40425d5 (eBPF backend), 041b320 (cgroup).
Reviewer: independent; did not write the code. Reviewed on the target host (NixOS, kernel 7.2.6-zen2, nightly 1.102, bpf-linker 0.13.0).

## Verification re-run (all flock-wrapped, on the remote)

| Check | Result |
|---|---|
| `cargo fmt --all --check` | clean |
| `cargo clippy --all-targets --features admin-tests` | 0 warnings (the 38 `warning:` lines are aya-build's nested-cargo echoes, not lint warnings) |
| `cargo test` | 22 passed, 0 failed |
| `cargo check --target x86_64-pc-windows-msvc` | clean |
| `ebpf_tests` as root, `--test-threads=1` | 5 passed, 0 failed (15.87 s) |
| Leftovers after tests | none: no `/sys/fs/cgroup/ramline-*`, no ramline pins in `/sys/fs/bpf`, no leaked test processes |
| Probe cgroup | created/removed cleanly; kernel exposes `memory.peak`, `cgroup.kill`, `memory.events` with `oom_kill` |

Note: the test binary lands at `target/debug/build/ramline-<hash>/out/ramline-<hash>` on this host (confirmed via `cargo test --features admin-tests --no-run`), not under `deps/` as the README says.

## Verified OK (no findings)

- **Tracepoint offsets**: `child_comm` __data_loc at 16, `child_pid` at 20 match `/sys/kernel/tracing/events/sched/sched_process_fork/format` exactly. `bpf_probe_read_kernel_str_bytes` into a 16-byte buffer is bounded; no loops; verifier-safe.
- **Event layout**: `ProcEvent` is `repr(C)`, 28 bytes, align 4, with const asserts in `ramline-ebpf-common`; userspace parses with the same fixed offsets and `from_ne_bytes` (same host endianness as the kernel — correct here).
- **Reserve/submit API** usage is correct; ring size 256 KiB is a valid power of two.
- **`AsyncFd::register` soundness**: the `RingBuf` is owned by the async task and outlives the `AsyncFd` (drop order: `AsyncFd` first), fd lifetime is safe; 200 ms poll bounds shutdown latency; thread is joined and `Ebpf` dropped in `EbpfSession::drop`. aya 0.16 stores the tracepoint link in the program's `LinkList` (verified in the aya source), so dropping `Ebpf` detaches; nothing is pinned.
- **pidfd**: syscall numbers come from libc constants (arch-correct); `ESRCH` handled; the pidfd pins the process instance, so kill of a recycled pid is impossible through this path.
- **/proc dir-fd caching**: after death `openat` fails permanently (the fd pins the dead entry), so a recycled pid is never sampled through a stale fd. Correct.
- **/proc/<pid>/stat parsing**: `rsplit_once(") ")` is correct even when comm contains spaces/parens (the real terminator is the last `") "`; nothing after it can contain `)`). Field indices (ppid=nth(1), minflt=get(7), majflt=get(9) post-comm) verified against proc(5). Missing VmRSS (zombie/kernel thread) → treated as dead — correct.
- **`pre_exec` async-signal-safety**: closure calls only libc getpid/open/write/close; `fmt_pid` allocates nothing; the captured `CString` is moved in before fork, no allocation inside the closure. Sound.
- **Refactor fidelity**: diffed 9e0c681 — the extracted `TreeFilter` is logic-identical to the Windows original (only Start/Stop renamed to the `Event` trait and "rundown"→"snapshot" wording). Windows cfg-gating of `windows`/`ferrisetw2` preserves all features; windows-msvc check passes.
- **Crate compliance**: crossfire is the preferred channel; no banned crates; unsafe blocks carry safety comments; clippy pedantic+cargo clean.
- **Engine integration**: GRACE_PERIOD 1200 ms >> 200 ms poll; spawn-mode root is reaped (`try_wait`); exit-code mapping (signal → 128+n) correct.

## Findings

### Critical — none.

### Major

**M1. Silent ring-buffer event loss; no lost-event accounting** — `crates/ramline-ebpf/src/main.rs:62` (`emit`: `let Some(mut entry) = EVENTS.reserve::<ProcEvent>(0) else { return; }`).
When the ring is full the fork/exit event is dropped silently. A lost fork means the child never gets a `Spawned`, is never sampled and never killed — it escapes the software RSS limiter (its later exit is also dropped by the tree filter as unknown). The kernel ringbuf has no lost-record mechanism (unlike perf buffer), and userspace never checks. Two amplifiers:
- `try_fork` emits for **every clone system-wide**, including `CLONE_THREAD` thread creation (the leader check happens in userspace, `linux.rs:447`), inflating churn far beyond process churn; at ~40 bytes/record the 256 KiB ring holds ~6.5k records.
- The consumer is slowest exactly under load: every fork event triggers a `/proc/<pid>/status` read+parse (`is_process_leader`) on the event thread, plus a `read_link` for accepted events.
Fix: bump an in-kernel counter (aya `Array` map) in the reserve-failure branch, read it per drain in userspace and `warn!` on loss; optionally move thread filtering into the kernel (raw tracepoint gives the child `task_struct`, CO-RE read its tgid).

**M2. `memory.peak` misclassifies clean exits as `os_job_limit`** — `src/monitor/linux/cgroup.rs:76` + `src/engine.rs:200` (`classify_natural_end` 98 % rule).
`memory.peak` is the peak of `memory.current`, which charges **page cache and tmpfs** to the cgroup. An I/O-heavy tree pushes usage (and thus peak) to ≥98 % of `memory.max` while the kernel simply reclaims cache — no OOM, clean exit — and ramline reports `killed/os_job_limit` with exit code 3 for a successful run. The Windows analogue (commit peak) has a much narrower false-positive band. The e2e value 62914560 == limit is the *post-OOM* semantics (usage clamps at `memory.max`) and is reliable only when an OOM actually happened.
Fix: gate the `OsJobLimit` classification on real OOM evidence — read `memory.events` `oom_kill` (present on the target kernel, verified) after the run and require `oom_kill > 0` (or a diff vs. start); keep `memory.peak` informational.

**M3. Linux CI is red by construction** — `.github/workflows/test.yml`, `.github/workflows/release.yml`.
`test.yml` runs `cargo clippy --all-targets --all-features --locked` on `ubuntu-latest` with `dtolnay/rust-toolchain@nightly` (components: clippy, rustfmt only). On Linux targets `build.rs` unconditionally compiles `ramline-ebpf` via aya-build, which requires the `rust-src` component and a `bpf-linker` binary in PATH — neither is installed in CI, so every Linux job fails. `release.yml` cross-builds four Linux targets with the same problem. The implementation report flagged this but shipped it.
Fix: add `rust-src` to the components and install bpf-linker (e.g. `cargo binstall bpf-linker`) in both workflows before the cargo invocations.

### Minor

**m4. cgroup cleanup kills raw pids from `cgroup.procs`** — `src/monitor/linux/cgroup.rs:94-106`.
A member can exit and its pid be recycled between the read and `libc::kill(pid, SIGKILL)`, signaling an innocent process — the exact bug class the pidfd work eliminated elsewhere. Fix: write `1` to `cgroup.kill` (kernel 5.14+, verified present), which atomically SIGKILLs exactly the current members, then `rmdir`.

**m5. `Cgroup::create` leaks the directory when the `memory.max` write fails** — `src/monitor/linux/cgroup.rs:43-48`.
`create_dir` succeeds, `fs::write` fails, `?` returns before `Self` exists, so `Drop` never runs and `/sys/fs/cgroup/ramline-<pid>` is left behind. Fix: construct `Self` immediately after `create_dir` and set the limit through a method that cleans up on error.

**m6. pidfd unsupported → silent total degradation** — `src/monitor/linux.rs:152-161` (`register`).
If `pidfd_open` fails (ENOSYS on <5.3, seccomp, fd exhaustion), the pid is silently skipped; `sample` then returns `None` and the engine marks every process — including the root — as exited, reporting an instantly-dead tree with no error. Fix: probe `pidfd_open(getpid())` in `preflight` and bail with a clear message.

**m7. Attach mode never yields an exit code → ramline exits 1 on clean attach runs** — `src/monitor/linux.rs:330` (`exit_code` only handles the spawn-mode `Child`) + `src/engine.rs` (`exit_code_u8(None) == 1`).
Windows parity gap (ETW Stop carries the exit code). The exit tracepoint has no code field, so this is largely inherent — but the behavior (clean attach run exits 1) should at least be documented in the README.

**m8. README not reproducible on this host** —
- Test-binary path: README says `sudo <target>/debug/deps/ramline-<hash>`; cargo actually emits `target/debug/build/ramline-<hash>/out/ramline-<hash>` here (verified).
- bpf-linker: plain `cargo install bpf-linker` failed on NixOS (needed an rpath workaround to the `-lib` store output); the README presents the plain install as sufficient.

### Nit

**n1.** `scan_tree` comment says "BFS" but uses `Vec::pop` (DFS) — `linux.rs:477`. The parents-before-children guarantee is unaffected; fix the comment.
**n2.** `TreeFilter::seed`'s `#[allow(dead_code)]` is only needed on Windows; harmless, could be `cfg_attr`.
**n3.** Exit events spend 16 zero bytes on `comm` in every record; a 12-byte variant would relieve ring pressure (relevant to M1).
**n4.** `sched_process_exit`'s `group_dead` record field (offset 32) could replace the `pid == tgid` helper check in-kernel; current approach is equivalent.

## Top-3 must-fix

1. **M1** — in-kernel lost-event counter + userspace warning; silent fork loss defeats the memory limiter.
2. **M2** — classify `os_job_limit` from `memory.events` `oom_kill`, not `memory.peak` ≥ 98 %.
3. **M3** — repair Linux CI/release workflows (rust-src + bpf-linker).

## Verdict

**No-ship** for the Linux milestone until M1–M3 land. The core design (tracepoints + ringbuf, pinned dir fd + pidfd, cgroup backstop, faithful refactor) is sound and well-tested; the gaps are in failure-mode observability (M1), outcome correctness (M2), and deliverability (M3).
