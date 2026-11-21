//! Live ETW integration tests. Creating an ETW trace session is admin-only:
//! build with `cargo test --features admin-tests --no-run` and run the
//! produced test binary as administrator (e.g. via sudo).

use std::{
    fmt::Write as _,
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

use windows::Win32::{
    Foundation::{CloseHandle, STILL_ACTIVE},
    System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
};

use crate::{
    engine::{EXIT_CODE_KILLED, Engine, Target},
    model::{Outcome, Report},
    monitor::windows::WindowsBackend,
};

const MB: u64 = 1 << 20;

/// Monitor `argv` with the engine and return its report and exit code.
fn run_engine(argv: &[&str], max_memory: Option<u64>) -> (Report, u8) {
    let mut backend = WindowsBackend::new();
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

/// Powershell argv whose process allocates `mb` megabytes and then sleeps.
fn alloc_script(mb: u64, secs: u32) -> String {
    format!("$x = New-Object byte[] {mb}MB; Start-Sleep -Seconds {secs}")
}

/// Powershell argv that spawns `n` children, each allocating `mb` megabytes
/// and living `secs` seconds, and waits for them.
fn spawn_children_argv(n: usize, mb: u64, secs: u32) -> [String; 4] {
    let inner = alloc_script(mb, secs);
    let mut script = String::from("$ids = @(); ");
    for _ in 0..n {
        let _ = write!(
            script,
            "$ids += (Start-Process powershell -ArgumentList '-NoProfile','-Command','{inner}' \
             -PassThru).Id; "
        );
    }
    script.push_str("Wait-Process -Id $ids");
    [
        "powershell".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ]
}

/// Powershell argv spawning a chain of `depth` nested child powershell
/// processes immediately at startup; the innermost allocates `mb` megabytes
/// and sleeps `secs`, and every level waits for its child.
fn spawn_chain_argv(depth: usize, mb: u64, secs: u32) -> [String; 4] {
    let mut script = alloc_script(mb, secs);
    for _ in 1..depth {
        // Single quotes are doubled for each extra nesting level.
        let escaped = script.replace('\'', "''");
        script = format!(
            "Start-Process powershell -ArgumentList '-NoProfile','-Command','{escaped}' -Wait"
        );
    }
    [
        "powershell".to_owned(),
        "-NoProfile".to_owned(),
        "-Command".to_owned(),
        script,
    ]
}

/// Non-root processes that delivered at least one memory sample.
fn sampled_children(report: &Report) -> Vec<&crate::model::ProcessSeries> {
    report
        .processes
        .iter()
        .filter(|p| p.pid != report.root_pid && !p.samples.is_empty())
        .collect()
}

fn pid_is_dead(pid: u32) -> bool {
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return true;
    };
    let mut code = 0u32;
    let exited = unsafe { GetExitCodeProcess(handle, &raw mut code) }.is_ok()
        && code != STILL_ACTIVE.0 as u32;
    let _ = unsafe { CloseHandle(handle) };
    exited
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
fn discovers_spawned_children() {
    let argv = spawn_children_argv(2, 100, 3);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (report, exit_code) = run_engine(&argv, None);

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

    // The session must be stopped when the backend is dropped.
    let out = Command::new("logman")
        .args(["query", "-ets"])
        .output()
        .expect("logman query failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("ramline-"),
        "leaked ETW session:\n{stdout}"
    );
}

#[test]
fn spawn_mode_discovers_immediately_spawned_chain() {
    // Regression: children spawned between process creation and ETW session
    // start used to be missed; the capture-state rundown must enumerate
    // them. A 3-deep chain spawns within milliseconds of the root.
    let argv = spawn_chain_argv(3, 10, 3);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (report, exit_code) = run_engine(&argv, None);

    let children = sampled_children(&report);
    assert!(
        children.len() >= 3,
        "expected the full 3-deep chain sampled, got {} descendants: {report:#?}",
        children.len()
    );
    assert_eq!(report.outcome, Outcome::Exited { code: Some(0) });
    assert_eq!(exit_code, 0);
}

#[test]
fn enforces_limit_and_kills_tree() {
    // Two idle children. The tree's baseline RSS (~210 MB) crosses the
    // limit only once both children are discovered and sampled, while its
    // commit (~175 MB) stays below the limit so the job backstop does not
    // trip first; the kill therefore proves tree discovery worked.
    let argv = spawn_children_argv(2, 0, 30);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (report, exit_code) = run_engine(&argv, Some(190 * MB));

    assert!(
        matches!(report.outcome, Outcome::Killed {
            reason: crate::model::KillReason::MemoryLimitExceeded,
            ..
        }),
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
fn job_enforces_limit_when_limit_set() {
    // The child allocates far beyond the limit in one shot; either the
    // engine limiter or the job-object commit limit kills the tree.
    let argv = spawn_children_argv(1, 500, 30);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (report, exit_code) = run_engine(&argv, Some(50 * MB));

    assert!(
        matches!(report.outcome, Outcome::Killed { .. }),
        "unexpected outcome: {:?}",
        report.outcome
    );
    assert_eq!(exit_code, EXIT_CODE_KILLED);
    assert!(
        report.summary.job_peak_memory_bytes.is_some(),
        "job peak missing from summary"
    );
    for p in &report.processes {
        assert_eventually_dead(p.pid);
    }
}

#[test]
fn captures_shortlived_commit_peak() {
    // The child allocates ~30 MB and exits immediately; it lives less than
    // the ETW notification latency, so its commit peak at exit may be its
    // only memory data point.
    let script = "Start-Process powershell -ArgumentList '-NoProfile','-Command','$x = New-Object \
                  byte[] 30MB' -Wait";
    let argv = ["powershell", "-NoProfile", "-Command", script];
    let (report, _) = run_engine(&argv, None);

    let child = report
        .processes
        .iter()
        .find(|p| p.pid != report.root_pid)
        .expect("short-lived child missing from the report");
    let peak = child
        .final_commit_peak_bytes
        .expect("commit peak missing for short-lived child");
    assert!(
        peak > 20 * MB,
        "commit peak {peak} bytes, expected > 20 MB (samples: {})",
        child.samples.len()
    );
}

#[test]
fn attach_mode_discovers_existing_children() {
    // Start the tree first, then attach: the child must be discovered via
    // the provider rundown (event 15).
    let child = alloc_script(50, 5);
    let script = format!(
        "Start-Process powershell -ArgumentList '-NoProfile','-Command','{child}'; Start-Sleep \
         -Seconds 4"
    );
    let mut root = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .spawn()
        .expect("failed to spawn tree");
    sleep(Duration::from_millis(1500));

    let mut backend = WindowsBackend::new();
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

    assert!(
        report.processes.iter().any(|p| p.pid != report.root_pid),
        "attach mode discovered no existing children: {report:#?}"
    );
}
