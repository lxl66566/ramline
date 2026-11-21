#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ramline_ebpf_common::{EventKind, ExitEvent, ForkEvent, StatKind};

// Sized for fork bursts: the fork tracepoint fires for every clone
// system-wide, threads included (the record carries no child tgid, so
// thread filtering happens in userspace).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Per-CPU event counters, indexed by [`StatKind`]; userspace sums the
/// per-CPU slots.
#[map]
static EVENT_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    u32::from(try_fork(&ctx).is_err())
}

/// Field offsets follow the tracepoint record layout, see
/// `/sys/kernel/tracing/events/sched/sched_process_fork/format`.
fn try_fork(ctx: &TracePointContext) -> Result<(), i32> {
    let child_pid: i32 = unsafe { ctx.read_at(20)? };
    // The current task is the parent; report its thread-group id so a fork
    // from a non-leader thread still attaches to the tracked process.
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // child_comm is a `__data_loc` field: low 16 bits are the offset of the
    // string data from the record start.
    let comm_loc: u32 = unsafe { ctx.read_at(16)? };
    let comm_off = (comm_loc & 0xffff) as usize;
    let mut comm = [0u8; 16];
    let src = unsafe { ctx.as_ptr().add(comm_off) } as *const u8;
    unsafe { bpf_probe_read_kernel_str_bytes(src, &mut comm)? };
    emit(ForkEvent {
        kind: EventKind::Fork,
        pid: child_pid as u32,
        ppid: parent_tgid,
        comm,
    });
    Ok(())
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    u32::from(try_exit(&ctx).is_err())
}

/// Field offsets follow the tracepoint record layout, see
/// `/sys/kernel/tracing/events/sched/sched_process_exit/format`.
fn try_exit(ctx: &TracePointContext) -> Result<(), i32> {
    // The tracepoint fires per task; group_dead is set only when the
    // thread-group leader exits.
    let group_dead: u8 = unsafe { ctx.read_at(32)? };
    if group_dead == 0 {
        return Ok(());
    }
    // The pid comes from the helper instead of the record field: both
    // describe the exiting task.
    let pid = bpf_get_current_pid_tgid() as u32;
    emit(ExitEvent {
        kind: EventKind::Exit,
        pid,
    });
    Ok(())
}

/// Push one event to the ring buffer, counting attempts and drops.
fn emit<T: 'static>(event: T) {
    count(StatKind::Attempted);
    let Some(mut entry) = EVENTS.reserve::<T>(0) else {
        // Ring full: the event is lost; userspace warns from the counter.
        count(StatKind::Dropped);
        return;
    };
    entry.write(event);
    entry.submit(0);
}

/// Increment one per-CPU slot of EVENT_STATS; the per-CPU layout makes the
/// increment race-free.
fn count(stat: StatKind) {
    if let Some(ptr) = EVENT_STATS.get_ptr_mut(stat as u32) {
        unsafe { *ptr += 1 };
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
static LICENSE: [u8; 4] = *b"GPL\0";
