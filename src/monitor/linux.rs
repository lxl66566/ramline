//! Linux backend stub.
// TODO(ebpf): implement via aya eBPF process trace; every entry errors until then.

use std::time::Duration;

use anyhow::{Result, bail};

use super::{EventSource, MemorySample, ProcessEvent, ProcessOps, RootInfo};

const NOT_IMPLEMENTED: &str = "linux backend is not implemented yet (planned: aya eBPF)";

pub struct LinuxBackend;

impl EventSource for LinuxBackend {
    fn start(&mut self, _root: RootInfo) -> Result<()> {
        bail!("{NOT_IMPLEMENTED}")
    }

    fn recv_timeout(&mut self, _timeout: Duration) -> Option<ProcessEvent> {
        None
    }
}

impl ProcessOps for LinuxBackend {
    fn sample(&mut self, _pid: u32) -> Option<MemorySample> {
        None
    }

    fn kill(&mut self, _pid: u32) -> Result<()> {
        bail!("{NOT_IMPLEMENTED}")
    }

    fn exit_code(&mut self, _pid: u32) -> Option<i32> {
        None
    }
}
