//! Orchestration loop: spawn/attach, event-driven discovery, tick-based
//! sampling, limit enforcement.

use std::{
    collections::HashMap,
    path::PathBuf,
    process::{Child, Command},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use log::{debug, info, warn};

use crate::{
    model::{KillReason, Outcome, ProcessSeries, Report, Sample, Summary, TotalSample},
    monitor::{Backend, ProcessEvent, RootInfo},
};

/// Exit code of the ramline process when the tree was killed by the limiter.
pub const EXIT_CODE_KILLED: u8 = 3;

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
    /// Ticks to wait after the tree looks empty before finishing. An Exited
    /// event for the root can arrive before the Spawned events of its last
    /// children, so late events are still collected during the grace window.
    grace_ticks: u32,
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
            grace_ticks: 2,
        }
    }

    pub fn run(self) -> Result<(Report, u8)> {
        let mut child: Option<Child> = None;
        let root = match &self.target {
            Target::Spawn(argv) => {
                let (program, rest) = argv.split_first().context("empty command")?;
                let spawned = Command::new(program)
                    .args(rest)
                    .spawn()
                    .with_context(|| format!("failed to spawn `{program}`"))?;
                let pid = spawned.id();
                child = Some(spawned);
                info!("spawned `{}` (pid {pid})", argv.join(" "));
                RootInfo {
                    pid,
                    ppid: std::process::id(),
                }
            },
            Target::Attach(pid) => {
                info!("attaching to pid {pid}");
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
        let mut grace: Option<u32> = None;

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
                    } => {
                        debug!("spawned: {name} (pid {pid}, ppid {ppid})");
                        registry.on_spawned(pid, ppid, name, exe, t);
                        // Late spawn: the tree is alive again, cancel the grace window.
                        grace = None;
                    },
                    ProcessEvent::Exited { pid } => {
                        debug!("exited: pid {pid}");
                        registry.on_exited(pid, t);
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

            if registry.root_exited() && alive == 0 {
                grace = match grace {
                    None => Some(0),
                    Some(n) if n + 1 >= self.grace_ticks => break None,
                    Some(n) => Some(n + 1),
                };
            }
            next_tick += self.interval;
        };

        let duration_ms = millis(start.elapsed());
        let (outcome, exit_code) = if let Some(outcome) = killed {
            (outcome, EXIT_CODE_KILLED)
        } else {
            let code = match &mut child {
                Some(c) => c.wait().ok().and_then(|s| s.code()),
                None => self.backend.exit_code(root.pid),
            };
            let code_u8 = code.map_or(1, |c| u8::try_from(c.clamp(0, 255)).unwrap_or(255));
            (Outcome::Exited { code }, code_u8)
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
            },
        };
        Ok((report, exit_code))
    }
}

/// The limiter decision, isolated for testing.
fn should_kill(total_rss: u64, max_rss: Option<u64>) -> bool {
    max_rss.is_some_and(|max| total_rss > max)
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
        // Duplicate events (pid reuse within the same run) are ignored.
        if self.index.contains_key(&pid) {
            return;
        }
        self.index.insert(pid, self.processes.len());
        self.processes.push(ProcessSeries {
            pid,
            ppid,
            name,
            exe,
            spawn_ms: t_ms,
            exit_ms: None,
            samples: Vec::new(),
        });
    }

    fn on_exited(&mut self, pid: u32, t_ms: u64) {
        if let Some(p) = self.get_mut(pid) {
            p.exit_ms = Some(t_ms);
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
        reg.on_exited(3, 50);
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
}
