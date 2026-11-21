//! Orchestration loop: spawn/attach, event-driven discovery, tick-based
//! sampling, limit enforcement.

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::Result;
use log::{debug, info, warn};

use crate::{
    model::{KillReason, Outcome, ProcessSeries, Report, Sample, Summary, TotalSample},
    monitor::{Backend, ProcessEvent, RootInfo},
};

/// Exit code of the ramline process when the tree was killed by the limiter.
pub const EXIT_CODE_KILLED: u8 = 3;

/// How long to keep collecting events after the tree appears empty. ETW
/// delivers events up to ~1 s late (its flush timer has 1 s granularity), so
/// a late Spawned can arrive after the last Exited; cancelled by any Spawned.
const GRACE_PERIOD: Duration = Duration::from_millis(1200);

/// What to monitor.
pub enum Target {
    /// Spawn this argv as the root process.
    Spawn(Vec<String>),
    /// Attach to an existing process.
    Attach(u32),
}

pub struct Engine<'a> {
    backend: &'a mut dyn Backend,
    target: Target,
    interval: Duration,
    max_rss: Option<u64>,
}

impl<'a> Engine<'a> {
    pub fn new(
        backend: &'a mut dyn Backend,
        target: Target,
        interval: Duration,
        max_rss: Option<u64>,
    ) -> Self {
        Self {
            backend,
            target,
            interval,
            max_rss,
        }
    }

    pub fn run(self) -> Result<(Report, u8)> {
        // Validate monitoring preconditions (elevation, event session)
        // before spawning: a failure here must not leave an orphaned child.
        self.backend.preflight()?;
        let root = match &self.target {
            Target::Spawn(argv) => {
                let pid = self.backend.spawn_root(argv, self.max_rss)?;
                info!("spawned `{}` (pid {pid})", argv.join(" "));
                RootInfo {
                    pid,
                    ppid: std::process::id(),
                }
            },
            Target::Attach(pid) => {
                info!("attaching to pid {pid}");
                if self.max_rss.is_some() {
                    warn!(
                        "attach mode: no OS-enforced job limit (a running foreign tree cannot be \
                         reassigned); the software limiter stays active"
                    );
                }
                RootInfo { pid: *pid, ppid: 0 }
            },
        };
        let command = match &self.target {
            Target::Spawn(argv) => argv.clone(),
            Target::Attach(_) => Vec::new(),
        };

        self.backend.start(root)?;

        let mut registry = Registry::new(root.pid);
        let mut totals: Vec<TotalSample> = Vec::new();
        let mut peak_rss = 0u64;
        let mut peak_private = 0u64;
        let mut grace_since: Option<Instant> = None;
        let mut root_exit_code: Option<i32> = None;

        let start = Instant::now();
        let mut next_tick = start + self.interval;
        let killed = loop {
            // Drain events until the next tick is due.
            loop {
                let now = Instant::now();
                if now >= next_tick {
                    break;
                }
                let Some(event) = self.backend.recv_timeout(next_tick - now) else {
                    break
                };
                let t = millis(start.elapsed());
                match event {
                    ProcessEvent::Spawned {
                        pid,
                        ppid,
                        name,
                        exe,
                        // Tree filtering and the PID-reuse guard happen inside
                        // the backend; the engine trusts the event. The
                        // create time is kept on the event for diagnostics.
                        create_time,
                    } => {
                        debug!(
                            "spawned: {name} (pid {pid}, ppid {ppid}, create_time {create_time:?})"
                        );
                        registry.on_spawned(pid, ppid, name, exe, t);
                        // Late spawn: the tree is alive again, cancel the grace window.
                        grace_since = None;
                    },
                    ProcessEvent::Exited {
                        pid,
                        exit_code,
                        commit_peak_bytes,
                    } => {
                        debug!("exited: pid {pid}");
                        registry.on_exited(pid, t, commit_peak_bytes);
                        if pid == root.pid {
                            root_exit_code = exit_code;
                        }
                    },
                }
            }

            let t = start.elapsed();
            let t_ms = millis(t);
            let (total_rss, total_private, alive) = registry.sample_all(self.backend, t_ms);
            totals.push(TotalSample {
                t_ms,
                rss_bytes: total_rss,
                private_bytes: total_private,
                alive_processes: alive,
            });
            peak_rss = peak_rss.max(total_rss);
            peak_private = peak_private.max(total_private);

            if should_kill(total_rss, self.max_rss) {
                warn!("total RSS {total_rss} bytes exceeds limit, killing process tree");
                registry.kill_all(self.backend, t_ms);
                break Some(Outcome::Killed {
                    reason: KillReason::MemoryLimitExceeded,
                    t_ms,
                    total_rss_at_kill: total_rss,
                });
            }

            if registry.root_exited()
                && alive == 0
                && grace_elapsed(&mut grace_since, Instant::now())
            {
                break None;
            }
            next_tick += self.interval;
        };

        let duration_ms = millis(start.elapsed());
        let job_peak = self.backend.job_peak_memory_bytes();
        let (outcome, exit_code) = if let Some(outcome) = killed {
            (outcome, EXIT_CODE_KILLED)
        } else {
            // Prefer the ETW event's exit code: a handle re-opened by pid
            // may resolve to a recycled process.
            let code = root_exit_code.or_else(|| self.backend.exit_code(root.pid));
            classify_natural_end(
                self.backend.os_limit_tripped(),
                duration_ms,
                peak_rss,
                code,
                matches!(self.target, Target::Attach(_)),
            )
        };

        let report = Report {
            command,
            root_pid: root.pid,
            processes: registry.into_processes(),
            totals,
            outcome,
            summary: Summary {
                peak_total_rss_bytes: peak_rss,
                peak_total_private_bytes: peak_private,
                duration_ms,
                job_peak_memory_bytes: job_peak,
            },
        };
        Ok((report, exit_code))
    }
}

/// The limiter decision, isolated for testing.
fn should_kill(total_rss: u64, max_rss: Option<u64>) -> bool {
    max_rss.is_some_and(|max| total_rss > max)
}

/// Advance the post-exit grace window, called on ticks where the tree is
/// empty. The first call starts the window; returns true once it has fully
/// elapsed.
fn grace_elapsed(grace_since: &mut Option<Instant>, now: Instant) -> bool {
    match *grace_since {
        None => {
            *grace_since = Some(now);
            false
        },
        Some(t) => now.duration_since(t) >= GRACE_PERIOD,
    }
}

/// Classify a run that ended with an empty tree and no limiter kill.
///
/// When the OS backstop (job object / cgroup) trips, the OS kills the tree
/// between two samples and the engine only observes all-dead; the backend
/// reports the trip through `os_limit_tripped`.
fn classify_natural_end(
    os_limit_tripped: bool,
    duration_ms: u64,
    peak_rss: u64,
    exit_code: Option<i32>,
    attach: bool,
) -> (Outcome, u8) {
    if os_limit_tripped {
        return (
            Outcome::Killed {
                reason: KillReason::OsJobLimit,
                t_ms: duration_ms,
                total_rss_at_kill: peak_rss,
            },
            EXIT_CODE_KILLED,
        );
    }
    // Attach mode cannot always recover the root's exit code (a pidfd
    // cannot reap a non-child), so a finished tree without a code counts
    // as success there; in spawn mode a missing code is a lost code.
    let code = if exit_code.is_none() && attach { 0 } else { exit_code_u8(exit_code) };
    (Outcome::Exited { code: exit_code }, code)
}

/// Map a process exit code to ramline's exit code: 0 stays 0, any nonzero
/// code maps to a nonzero u8 (Windows failure codes are negative i32).
fn exit_code_u8(code: Option<i32>) -> u8 {
    match code {
        None => 1,
        Some(0) => 0,
        Some(c) => u8::try_from(c).unwrap_or(255).max(1),
    }
}

fn millis(t: Duration) -> u64 {
    u64::try_from(t.as_millis()).unwrap_or(u64::MAX)
}

/// Tracks all known processes of the monitored tree in spawn order.
struct Registry {
    processes: Vec<ProcessSeries>,
    index: HashMap<u32, usize>,
    root_pid: u32,
}

impl Registry {
    fn new(root_pid: u32) -> Self {
        Self {
            processes: Vec::new(),
            index: HashMap::new(),
            root_pid,
        }
    }

    // pid/ppid are the domain names; similar_names does not apply here
    #[allow(clippy::similar_names)]
    fn on_spawned(&mut self, pid: u32, ppid: u32, name: String, exe: Option<PathBuf>, t_ms: u64) {
        if let Some(&i) = self.index.get(&pid) {
            // Duplicate events for a live process are ignored.
            if self.processes[i].exit_ms.is_none() {
                return;
            }
            // PID reuse: the exited series keeps its samples in
            // `processes`; the index is rebound to the fresh series below,
            // so sampling and kill_all cover the recycled process.
        }
        self.index.insert(pid, self.processes.len());
        self.processes.push(ProcessSeries {
            pid,
            ppid,
            name,
            exe,
            spawn_ms: t_ms,
            exit_ms: None,
            final_commit_peak_bytes: None,
            samples: Vec::new(),
        });
    }

    fn on_exited(&mut self, pid: u32, t_ms: u64, commit_peak_bytes: Option<u64>) {
        if let Some(p) = self.get_mut(pid) {
            p.exit_ms = Some(t_ms);
            if commit_peak_bytes.is_some() {
                p.final_commit_peak_bytes = commit_peak_bytes;
            }
        }
    }

    /// Sample every alive process. A failed sample is treated as an exit: the
    /// placeholder event source never emits `Exited`, and even with ETW the
    /// sampler is the fallback liveness probe.
    /// Returns (total rss, total private bytes, alive count).
    fn sample_all(&mut self, backend: &mut dyn Backend, t_ms: u64) -> (u64, u64, u32) {
        let (mut rss, mut private, mut alive) = (0, 0, 0);
        for p in &mut self.processes {
            if p.exit_ms.is_some() {
                continue;
            }
            match backend.sample(p.pid) {
                Some(m) => {
                    p.samples.push(Sample {
                        t_ms,
                        rss_bytes: m.rss_bytes,
                        private_bytes: m.private_bytes,
                        page_faults: m.page_faults,
                    });
                    rss += m.rss_bytes;
                    private += m.private_bytes;
                    alive += 1;
                },
                None => p.exit_ms = Some(t_ms),
            }
        }
        (rss, private, alive)
    }

    fn kill_all(&mut self, backend: &mut dyn Backend, t_ms: u64) {
        for p in &mut self.processes {
            if p.exit_ms.is_some() {
                continue;
            }
            if let Err(e) = backend.kill(p.pid) {
                warn!("failed to kill pid {}: {e:#}", p.pid);
            }
            p.exit_ms = Some(t_ms);
        }
    }

    fn root_exited(&self) -> bool {
        self.get(self.root_pid).is_some_and(|p| p.exit_ms.is_some())
    }

    fn get(&self, pid: u32) -> Option<&ProcessSeries> {
        self.index.get(&pid).map(|&i| &self.processes[i])
    }

    fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessSeries> {
        self.index.get(&pid).map(|&i| &mut self.processes[i])
    }

    fn into_processes(self) -> Vec<ProcessSeries> {
        self.processes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::monitor::MemorySample;

    struct FakeOps {
        alive: HashSet<u32>,
        rss: u64,
        killed: Vec<u32>,
    }

    impl crate::monitor::EventSource for FakeOps {
        fn start(&mut self, _root: RootInfo) -> Result<()> {
            Ok(())
        }

        fn recv_timeout(&mut self, _timeout: Duration) -> Option<ProcessEvent> {
            None
        }
    }

    impl crate::monitor::ProcessOps for FakeOps {
        fn sample(&mut self, pid: u32) -> Option<MemorySample> {
            self.alive.contains(&pid).then_some(MemorySample {
                rss_bytes: self.rss,
                private_bytes: self.rss / 2,
                page_faults: 1,
            })
        }

        fn kill(&mut self, pid: u32) -> Result<()> {
            self.killed.push(pid);
            self.alive.remove(&pid);
            Ok(())
        }

        fn exit_code(&mut self, _pid: u32) -> Option<i32> {
            None
        }
    }

    #[test]
    fn aggregates_totals_and_detects_exit_via_failed_sample() {
        let mut reg = Registry::new(1);
        let mut ops = FakeOps {
            alive: HashSet::from([1, 2]),
            rss: 100,
            killed: Vec::new(),
        };
        reg.on_spawned(1, 0, "root".to_owned(), None, 0);
        reg.on_spawned(2, 1, "child".to_owned(), None, 0);

        let (rss, private, alive) = reg.sample_all(&mut ops, 100);
        assert_eq!((rss, private, alive), (200, 100, 2));
        assert_eq!(reg.get(2).unwrap().samples.len(), 1);

        // Process 2 dies without an Exited event; the failed sample marks it.
        ops.alive.remove(&2);
        let (rss, _, alive) = reg.sample_all(&mut ops, 200);
        assert_eq!((rss, alive), (100, 1));
        assert_eq!(reg.get(2).unwrap().exit_ms, Some(200));
        assert!(!reg.root_exited());

        // Dead processes are not sampled again.
        ops.rss = 1000;
        let (rss, _, alive) = reg.sample_all(&mut ops, 300);
        assert_eq!((rss, alive), (1000, 1));
        assert_eq!(reg.get(2).unwrap().samples.len(), 1);
    }

    #[test]
    fn kill_all_marks_and_terminates_alive_processes() {
        let mut reg = Registry::new(1);
        let mut ops = FakeOps {
            alive: HashSet::from([1, 2, 3]),
            rss: 100,
            killed: Vec::new(),
        };
        for pid in 1..=3 {
            reg.on_spawned(pid, 0, "p".to_owned(), None, 0);
        }
        reg.on_exited(3, 50, None);
        reg.kill_all(&mut ops, 100);
        assert_eq!(ops.killed, vec![1, 2]);
        assert!(reg.processes.iter().all(|p| p.exit_ms.is_some()));
        assert!(reg.root_exited());
    }

    #[test]
    fn limit_decision() {
        assert!(!should_kill(100, None));
        assert!(!should_kill(100, Some(100)));
        assert!(should_kill(101, Some(100)));
    }

    #[test]
    fn grace_period_must_fully_elapse() {
        let mut since = None;
        let t0 = Instant::now();
        // The first empty-tree tick starts the window.
        assert!(!grace_elapsed(&mut since, t0));
        assert_eq!(since, Some(t0));
        // Still within the window.
        assert!(!grace_elapsed(&mut since, t0));
        assert!(grace_elapsed(&mut since, t0 + GRACE_PERIOD));
    }

    #[test]
    fn recycled_pid_gets_a_fresh_series() {
        let mut reg = Registry::new(1);
        let mut ops = FakeOps {
            alive: HashSet::from([1, 2]),
            rss: 100,
            killed: Vec::new(),
        };
        reg.on_spawned(1, 0, "root".to_owned(), None, 0);
        reg.on_spawned(2, 1, "old".to_owned(), None, 0);
        reg.on_exited(2, 50, None);
        // The pid is recycled; a duplicate Start for a live pid is ignored.
        reg.on_spawned(2, 1, "new".to_owned(), None, 100);
        reg.on_spawned(2, 1, "dup".to_owned(), None, 110);

        assert_eq!(reg.processes.len(), 3);
        let retired = &reg.processes[1];
        assert_eq!(retired.name, "old");
        assert_eq!(retired.exit_ms, Some(50));
        let live = reg.get(2).unwrap();
        assert_eq!(live.name, "new");
        assert_eq!(live.exit_ms, None);

        // Sampling and kill_all cover the recycled process.
        let (rss, _, alive) = reg.sample_all(&mut ops, 200);
        assert_eq!((rss, alive), (200, 2));
        assert_eq!(reg.get(2).unwrap().samples.len(), 1);
        reg.kill_all(&mut ops, 300);
        assert_eq!(ops.killed, vec![1, 2]);
    }

    #[test]
    fn clean_exit_is_exited() {
        // The OS limit did not trip. On Linux a cgroup memory.peak at the
        // limit still reaches here as `false` when no OOM kill happened:
        // cgroup accounting includes reclaimable page cache.
        let (outcome, code) = classify_natural_end(false, 10, 90, Some(0), false);
        assert_eq!(outcome, Outcome::Exited { code: Some(0) });
        assert_eq!(code, 0);
    }

    #[test]
    fn tripped_os_limit_is_os_job_limit() {
        let (outcome, code) = classify_natural_end(true, 10, 90, None, false);
        assert!(matches!(outcome, Outcome::Killed {
            reason: KillReason::OsJobLimit,
            ..
        }));
        assert_eq!(code, EXIT_CODE_KILLED);
    }

    #[test]
    fn attach_without_exit_code_exits_zero() {
        // Attach mode cannot always recover the root's exit code (Linux:
        // a pidfd cannot reap a non-child); a finished tree without a kill
        // counts as success. Spawn mode keeps the lost-code failure.
        let (outcome, code) = classify_natural_end(false, 10, 0, None, true);
        assert_eq!(outcome, Outcome::Exited { code: None });
        assert_eq!(code, 0);
        let (_, code) = classify_natural_end(false, 10, 0, None, false);
        assert_eq!(code, 1);
    }

    #[test]
    fn exit_code_mapping_keeps_failures_nonzero() {
        assert_eq!(exit_code_u8(None), 1);
        assert_eq!(exit_code_u8(Some(0)), 0);
        assert_eq!(exit_code_u8(Some(1)), 1);
        assert_eq!(exit_code_u8(Some(255)), 255);
        assert_eq!(exit_code_u8(Some(256)), 255);
        // 0xC0000005 (access violation) is a negative i32.
        assert_eq!(exit_code_u8(Some(-1_073_741_819)), 255);
        let (outcome, code) = classify_natural_end(false, 10, 0, Some(-1_073_741_819), false);
        assert_eq!(outcome, Outcome::Exited {
            code: Some(-1_073_741_819)
        });
        assert_ne!(code, 0);
    }
}
