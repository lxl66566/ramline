//! RAII wrapper over a Windows job object with a job-wide commit limit.

use std::mem::size_of;

use anyhow::{Context as _, Result};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        },
    },
    core::PWSTR,
};

/// A job object enforcing a total commit limit on every assigned process.
/// Created with `KILL_ON_JOB_CLOSE`: when the last handle to the job is
/// closed (including ramline exiting or crashing), Windows terminates every
/// process still in the job.
pub struct Job(HANDLE);

impl Job {
    /// Create a job whose total commit charge is limited to `limit_bytes`.
    ///
    /// # Errors
    /// Returns an error if the job cannot be created or configured.
    pub fn new(limit_bytes: u64) -> Result<Self> {
        // Safety: the returned handle is owned by Job and closed on drop.
        let handle =
            unsafe { CreateJobObjectW(None, PWSTR::null()) }.context("CreateJobObjectW failed")?;
        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation:
                windows::Win32::System::JobObjects::JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    ..Default::default()
                },
            JobMemoryLimit: usize::try_from(limit_bytes).unwrap_or(usize::MAX),
            ..Default::default()
        };
        let size =
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(u32::MAX);
        // Safety: info points to a JOBOBJECT_EXTENDED_LIMIT_INFORMATION of
        // the advertised size.
        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size,
            )
        }
        .context("SetInformationJobObject failed")?;
        Ok(Self(handle))
    }

    /// Add a process to the job; its future descendants inherit the job.
    ///
    /// # Errors
    /// Returns an error if the assignment fails.
    pub fn assign(&self, process: HANDLE) -> Result<()> {
        // Safety: both handles are valid and only borrowed by the call.
        unsafe { AssignProcessToJobObject(self.0, process) }
            .context("AssignProcessToJobObject failed")
    }

    /// Peak total commit charge of all processes ever assigned to the job,
    /// including exited ones.
    pub fn peak_memory_bytes(&self) -> Option<u64> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let size =
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(u32::MAX);
        // Safety: info is a valid out buffer of the advertised size.
        unsafe {
            QueryInformationJobObject(
                Some(self.0),
                JobObjectExtendedLimitInformation,
                (&raw mut info).cast(),
                size,
                None,
            )
        }
        .ok()?;
        u64::try_from(info.PeakJobMemoryUsed).ok()
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Safety: the job handle is owned and closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}
