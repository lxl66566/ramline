//! Windows backend: handle-based sampling and termination via Win32.
//!
//! The event source is a placeholder that registers only the root pid.
// TODO(etw): replaced by ferrisetw2 kernel trace in the next milestone; the
// ETW provider emits Spawned/Exited for every process in the monitored tree.

use std::{
    collections::HashMap, ffi::OsString, mem::size_of, os::windows::ffi::OsStringExt as _,
    path::PathBuf, time::Duration,
};

use anyhow::{Context as _, Result};
use crossfire::{MTx, Rx, mpsc::List};
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, STILL_ACTIVE},
        System::{
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX},
            Threading::{
                GetExitCodeProcess, OpenProcess, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW,
                TerminateProcess,
            },
        },
    },
    core::PWSTR,
};

use super::{EventSource, MemorySample, ProcessEvent, ProcessOps, RootInfo};

const BUF_LEN: u32 = 1024;

/// Windows backend. Process handles are opened lazily and cached per pid.
pub struct WindowsBackend {
    handles: HashMap<u32, HANDLE>,
    event_tx: MTx<List<ProcessEvent>>,
    event_rx: Rx<List<ProcessEvent>>,
}

impl WindowsBackend {
    pub fn new() -> Self {
        let (event_tx, event_rx) = crossfire::mpsc::unbounded_blocking::<ProcessEvent>();
        Self {
            handles: HashMap::new(),
            event_tx,
            event_rx,
        }
    }

    /// Open and cache a handle for `pid`; `None` if the process cannot be opened.
    fn handle(&mut self, pid: u32) -> Option<HANDLE> {
        if let Some(handle) = self.handles.get(&pid) {
            return Some(*handle);
        }
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE;
        let handle = unsafe { OpenProcess(access, false, pid) }.ok()?;
        self.handles.insert(pid, handle);
        Some(handle)
    }

    fn close(&mut self, pid: u32) {
        if let Some(handle) = self.handles.remove(&pid) {
            let _ = unsafe { CloseHandle(handle) };
        }
    }

    /// Resolve the image path of a process via its handle.
    fn query_image(handle: HANDLE) -> Option<(String, PathBuf)> {
        let mut buf = [0u16; BUF_LEN as usize];
        let mut len = BUF_LEN;
        unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &raw mut len,
            )
        }
        .ok()?;
        let exe = PathBuf::from(OsString::from_wide(&buf[..len as usize]));
        let name = exe.file_name()?.to_string_lossy().into_owned();
        Some((name, exe))
    }

    /// Raw exit code; `None` while the process is still running.
    fn raw_exit_code(handle: HANDLE) -> Option<u32> {
        let mut code = 0u32;
        unsafe { GetExitCodeProcess(handle, &raw mut code) }.ok()?;
        (code != STILL_ACTIVE.0 as u32).then_some(code)
    }
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WindowsBackend {
    fn drop(&mut self) {
        for (_, handle) in self.handles.drain() {
            let _ = unsafe { CloseHandle(handle) };
        }
    }
}

impl EventSource for WindowsBackend {
    fn start(&mut self, root: RootInfo) -> Result<()> {
        // TODO(etw): replaced by ferrisetw2 kernel trace in the next milestone;
        // only the root process is reported, no descendant discovery yet.
        let handle = self
            .handle(root.pid)
            .with_context(|| format!("cannot open root process (pid {})", root.pid))?;
        let (name, exe) = Self::query_image(handle)
            .map_or_else(|| (String::from("unknown"), None), |(n, e)| (n, Some(e)));
        self.event_tx
            .send(ProcessEvent::Spawned {
                pid: root.pid,
                ppid: root.ppid,
                name,
                exe,
            })
            .map_err(|e| anyhow::anyhow!("event channel closed: {e}"))?;
        Ok(())
    }

    fn recv_timeout(&mut self, timeout: Duration) -> Option<ProcessEvent> {
        self.event_rx.recv_timeout(timeout).ok()
    }
}

impl ProcessOps for WindowsBackend {
    fn sample(&mut self, pid: u32) -> Option<MemorySample> {
        let handle = self.handle(pid)?;
        // GetExitCodeProcess doubles as a liveness probe: a terminated process
        // stays openable while we hold a handle, so query failure alone cannot
        // detect exit.
        if Self::raw_exit_code(handle).is_some() {
            self.close(pid);
            return None;
        }
        let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS_EX>()).unwrap_or(u32::MAX);
        let mut counters = PROCESS_MEMORY_COUNTERS_EX {
            cb: size,
            ..Default::default()
        };
        unsafe { GetProcessMemoryInfo(handle, (&raw mut counters).cast(), size) }.ok()?;
        Some(MemorySample {
            rss_bytes: counters.WorkingSetSize as u64,
            private_bytes: counters.PrivateUsage as u64,
            page_faults: u64::from(counters.PageFaultCount),
        })
    }

    fn kill(&mut self, pid: u32) -> Result<()> {
        let Some(handle) = self.handle(pid) else {
            return Ok(()); // already gone
        };
        unsafe { TerminateProcess(handle, 1) }
            .with_context(|| format!("TerminateProcess failed for pid {pid}"))?;
        self.close(pid);
        Ok(())
    }

    fn exit_code(&mut self, pid: u32) -> Option<i32> {
        let handle = self.handle(pid)?;
        Self::raw_exit_code(handle).map(|code| i32::from_ne_bytes(code.to_ne_bytes()))
    }
}
