//! Serializable report model.
//!
//! Field names are part of the JSON schema; keep them stable and prefer adding
//! optional fields over changing existing ones (Linux backend planned).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The full monitoring report, serialized as the JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Report {
    /// Monitored command line (argv); empty in attach mode.
    pub command: Vec<String>,
    pub root_pid: u32,
    pub processes: Vec<ProcessSeries>,
    pub totals: Vec<TotalSample>,
    pub outcome: Outcome,
    pub summary: Summary,
}

/// Timeline of a single process in the monitored tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessSeries {
    pub pid: u32,
    /// Parent pid; 0 when unknown (attach mode).
    pub ppid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<PathBuf>,
    /// Milliseconds since monitoring start when the process was first seen.
    pub spawn_ms: u64,
    /// Milliseconds since monitoring start when the process exited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_ms: Option<u64>,
    /// Peak commit (private bytes) reported by the OS at process exit.
    /// Only memory data point for processes too short-lived to be sampled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_commit_peak_bytes: Option<u64>,
    pub samples: Vec<Sample>,
}

/// One memory snapshot of a process.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sample {
    pub t_ms: u64,
    pub rss_bytes: u64,
    pub private_bytes: u64,
    pub page_faults: u64,
}

/// Aggregated memory of all alive processes at one tick.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotalSample {
    pub t_ms: u64,
    pub rss_bytes: u64,
    pub private_bytes: u64,
    pub alive_processes: u32,
}

/// How the monitoring run ended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// The root process exited; `code` is its exit code if known.
    Exited { code: Option<i32> },
    /// The process tree was killed by ramline.
    Killed {
        reason: KillReason,
        t_ms: u64,
        total_rss_at_kill: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KillReason {
    MemoryLimitExceeded,
    /// The job object's OS-enforced commit limit killed the tree before the
    /// engine's limiter observed it (job peak commit reached the limit).
    OsJobLimit,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub peak_total_rss_bytes: u64,
    pub peak_total_private_bytes: u64,
    pub duration_ms: u64,
    /// Peak total commit of the job object, present when a job limit was
    /// active. Job accounting includes exited processes, so this peak can
    /// exceed `peak_total_rss_bytes`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_peak_memory_bytes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_serde_roundtrip() {
        let report = Report {
            command: vec!["cmd".to_owned(), "/c".to_owned(), "dir".to_owned()],
            root_pid: 42,
            processes: vec![
                ProcessSeries {
                    pid: 42,
                    ppid: 1,
                    name: "cmd".to_owned(),
                    exe: Some(PathBuf::from(r"C:\Windows\System32\cmd.exe")),
                    spawn_ms: 0,
                    exit_ms: Some(900),
                    final_commit_peak_bytes: Some(2048),
                    samples: vec![Sample {
                        t_ms: 100,
                        rss_bytes: 1024,
                        private_bytes: 512,
                        page_faults: 7,
                    }],
                },
                ProcessSeries {
                    pid: 43,
                    ppid: 42,
                    name: "child".to_owned(),
                    exe: None,
                    spawn_ms: 200,
                    exit_ms: None,
                    final_commit_peak_bytes: None,
                    samples: vec![],
                },
            ],
            totals: vec![TotalSample {
                t_ms: 100,
                rss_bytes: 1024,
                private_bytes: 512,
                alive_processes: 2,
            }],
            outcome: Outcome::Killed {
                reason: KillReason::MemoryLimitExceeded,
                t_ms: 950,
                total_rss_at_kill: 4096,
            },
            summary: Summary {
                peak_total_rss_bytes: 4096,
                peak_total_private_bytes: 2048,
                duration_ms: 1000,
                job_peak_memory_bytes: Some(8192),
            },
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);
    }
}
