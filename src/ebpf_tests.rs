//! Live eBPF integration tests. Loading tracepoint programs requires root
//! (or CAP_BPF + CAP_PERFMON): build with `cargo test --features admin-tests
//! --no-run` and run the produced test binary as root.

use std::{
    fs,
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

use crate::{
    engine::{EXIT_CODE_KILLED, Engine, Target},
    model::{Outcome, Report},
    monitor::linux::LinuxBackend,
};

const MB: u64 = 1 << 20;

/// Monitor `argv` with the engine and return its report and exit code.
fn run_engine(argv: &[&str], max_memory: Option<u64>) -> (Report, u8) {
    let mut backend = LinuxBackend::new();
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
    Engine::new(
        &mut backend,
        Target::Spawn(argv),
        Duration::from_millis(50),
        max_memory,
    )
    .run()
    .expect("engine run failed")
}

/// Python one-liner allocating `mb` MiB and sleeping `secs` seconds.
fn alloc_snippet(mb: u64, secs: u32) -> String {
    format!("import time; x=bytearray({mb}*1024*1024); time.sleep({secs})")
}

/// Non-root processes that delivered at least one memory sample.
fn sampled_children(report: &Report) -> Vec<&crate::model::ProcessSeries> {
    report
        .processes
        .iter()
        .filter(|p| p.pid != report.root_pid && !p.samples.is_empty())
        .collect()
}

/// Dead or a zombie (the spawn-mode root is reaped only at backend drop).
fn pid_is_dead(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_none_or(|(_, rest)| rest.starts_with('Z')),
    }
}

fn assert_eventually_dead(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if pid_is_dead(pid) {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    panic!("pid {pid} is still alive 5 s after the tree was killed");
}

#[test]
fn enforces_limit_and_kills_tree() {
    // Two children at ~22 MB each: below the limit alone, above it
    // together, so the kill proves tree discovery. The kernel usually
    // trips memory.max before the sampler crosses the limit, so both kill
    // reasons are accepted.
    let child = alloc_snippet(10, 10);
    let script = format!("python3 -c '{child}' & python3 -c '{child}' & wait");
    let (report, exit_code) = run_engine(&["bash", "-c", &script], Some(35 * MB));

    assert!(
        matches!(report.outcome, Outcome::Killed { .. }),
        "unexpected outcome: {:?}",
        report.outcome
    );
    assert_eq!(exit_code, EXIT_CODE_KILLED);
    assert!(
        report.processes.len() >= 3,
        "children were not discovered before the kill: {report:#?}"
    );
    for p in &report.processes {
        assert_eventually_dead(p.pid);
    }
}

#[test]
fn cgroup_enforces_limit() {
    // One child allocates far beyond memory.max: the kernel OOM-kills it
    // between two samples; memory.peak then approximately equals the limit.
    let child = alloc_snippet(500, 30);
    // Two commands: a single-command `bash -c` would exec the child
    // directly, forking nothing.
    let script = format!("python3 -c '{child}'; true");
    let (report, exit_code) = run_engine(&["bash", "-c", &script], Some(50 * MB));

    assert!(
        matches!(report.outcome, Outcome::Killed { .. }),
        "unexpected outcome: {:?}",
        report.outcome
    );
    assert_eq!(exit_code, EXIT_CODE_KILLED);
    let peak = report
        .summary
        .job_peak_memory_bytes
        .expect("cgroup memory.peak missing from summary");
    assert!(
        peak >= 49 * MB,
        "cgroup peak {peak} bytes, expected near the 50 MB limit"
    );
    for p in &report.processes {
        assert_eventually_dead(p.pid);
    }
}

#[test]
fn discovers_spawned_children() {
    let child = alloc_snippet(100, 3);
    let script = format!("python3 -c '{child}' & python3 -c '{child}' & wait");
    let (report, exit_code) = run_engine(&["bash", "-c", &script], None);

    let children = sampled_children(&report);
    assert!(
        children.len() >= 2,
        "expected both children in the report, got {}: {report:#?}",
        children.len()
    );
    assert!(
        report.summary.peak_total_rss_bytes > 150 * MB,
        "peak total RSS {} bytes, expected > 150 MB",
        report.summary.peak_total_rss_bytes
    );
    assert_eq!(report.outcome, Outcome::Exited { code: Some(0) });
    assert_eq!(exit_code, 0);
}

#[test]
fn event_stats_counter_is_readable() {
    // The kernel-side attempted/dropped counters must be readable; forcing
    // an actual ring overflow is not attempted here.
    let mut backend = LinuxBackend::new();
    let argv = vec!["true".to_owned()];
    Engine::new(
        &mut backend,
        Target::Spawn(argv),
        Duration::from_millis(50),
        None,
    )
    .run()
    .expect("engine run failed");
    let (attempted, dropped) = backend.event_stats().expect("EVENT_STATS map unreadable");
    assert!(attempted > 0, "no fork/exit events were counted");
    assert!(dropped <= attempted);
}

#[test]
fn page_cache_at_limit_is_not_os_limit_trip() {
    // Writing a file larger than memory.max charges page cache to the
    // cgroup, pushing usage (and memory.peak) to the limit; the kernel
    // reclaims the cache, so no OOM kill happens and the clean exit must
    // classify as exited. memory.peak stays informational.
    let limit = 64 * MB;
    let dir = std::env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/target").to_owned());
    let file = format!("{dir}/ramline-cache-test.bin");
    // 300 MB on a real filesystem; tmpfs is unreclaimable and could trip a
    // real OOM kill.
    let script =
        format!("dd if=/dev/zero of={file} bs=1M count=300 status=none; rm -f {file}; true");
    let (report, exit_code) = run_engine(&["bash", "-c", &script], Some(limit));
    assert_eq!(report.outcome, Outcome::Exited { code: Some(0) });
    assert_eq!(exit_code, 0);
    let peak = report
        .summary
        .job_peak_memory_bytes
        .expect("cgroup memory.peak missing from summary");
    assert!(
        peak >= limit - limit / 50,
        "peak {peak} bytes should reach the {limit} limit without an OOM kill"
    );
}

#[test]
fn attach_mode_discovers_existing_children() {
    // Start the tree first, then attach: child 1 must come from the /proc
    // seed, child 2 (forked after the attach) from a live fork event.
    let child2 = alloc_snippet(30, 5);
    let script = format!("sleep 8 & sleep 2; python3 -c '{child2}' & wait");
    let mut root = Command::new("bash")
        .args(["-c", &script])
        .spawn()
        .expect("failed to spawn tree");
    sleep(Duration::from_millis(1500));

    let mut backend = LinuxBackend::new();
    let (report, _) = Engine::new(
        &mut backend,
        Target::Attach(root.id()),
        Duration::from_millis(50),
        None,
    )
    .run()
    .expect("engine run failed");
    let _ = root.kill();
    let _ = root.wait();

    let children: Vec<_> = report
        .processes
        .iter()
        .filter(|p| p.pid != report.root_pid)
        .collect();
    assert!(
        children.len() >= 2,
        "attach mode discovered {} children (seed + live fork), expected >= 2: {report:#?}",
        children.len()
    );
}

#[test]
fn shortlived_child_appears_in_report() {
    // The child allocates ~30 MB and exits immediately; zero samples are
    // acceptable (no commit-peak equivalent on Linux), presence and the exit
    // timestamp are what matters.
    let child = alloc_snippet(30, 0);
    // Two commands: a single-command `bash -c` would exec the child
    // directly, forking nothing.
    let script = format!("python3 -c '{child}'; true");
    let (report, exit_code) = run_engine(&["bash", "-c", &script], None);

    let child = report
        .processes
        .iter()
        .find(|p| p.pid != report.root_pid)
        .expect("short-lived child missing from the report");
    assert!(
        child.exit_ms.is_some(),
        "short-lived child has no exit_ms: {child:#?}"
    );
    assert_eq!(report.outcome, Outcome::Exited { code: Some(0) });
    assert_eq!(exit_code, 0);
}
