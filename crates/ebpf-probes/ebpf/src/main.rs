#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{PerCpuArray, RingBuf};
use aya_ebpf::programs::TracePointContext;


const MAX_RING_BYTES: u32 = 64 * 1024;


const WORD_BITS: u32 = 32;


const COMM_BYTES: usize = 16;


const COMM_WORD_BYTES: usize = 4;


const COMM_WORDS: usize = 4;


const RECORD_WORDS: usize = 10;


#[link_section = "license"]
#[used]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";


#[no_mangle]
static REAL_PARENT_OFFSET: u64 = 0;


#[no_mangle]
static TGID_OFFSET: u64 = 0;


#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_RING_BYTES, 0);


#[map]
static EXEC_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);


extern "C" {
    fn ebpf_panic_reached() -> !;
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: the symbol is never defined, so this call exists only in an object where a panic path survived; lab/ebpf-no-panic.sh refuses that object. libbpf also refuses it (failed to find BTF for extern) but that depends on the object layout and the production loader is aya, so the check is the line of defence.
    unsafe { ebpf_panic_reached() }
}


fn global_offset(global: &'static u64) -> usize {
    // SAFETY: the reference points at a live static; the volatile read stops the compiler folding the loader-set value to its initialiser.
    let offset = unsafe { core::ptr::read_volatile(global) };
    offset as usize
}


fn parent_tgid() -> u32 {
    // SAFETY: the helper takes no argument and only returns the current task pointer, which is used as an address and never dereferenced here.
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let parent_field = task.wrapping_add(global_offset(&REAL_PARENT_OFFSET)).cast::<u64>();
    // SAFETY: bpf_probe_read_kernel faults safely, so an address that is not readable gives Err and never a crash.
    let parent = unsafe { bpf_probe_read_kernel::<u64>(parent_field) }.unwrap_or(0) as *const u8;
    let tgid_field = parent.wrapping_add(global_offset(&TGID_OFFSET)).cast::<u32>();
    // SAFETY: same helper and same guarantee as above for the parent task.
    unsafe { bpf_probe_read_kernel::<u32>(tgid_field) }.unwrap_or(0)
}


fn comm_words() -> [u32; COMM_WORDS] {
    let comm = bpf_get_current_comm().unwrap_or([0; COMM_BYTES]);
    let chunks: [[u8; COMM_WORD_BYTES]; COMM_WORDS] = comm
        .as_chunks::<COMM_WORD_BYTES>()
        .0
        .try_into()
        .unwrap_or([[0; COMM_WORD_BYTES]; COMM_WORDS]);
    chunks.map(u32::from_le_bytes)
}


fn build_record() -> [u32; RECORD_WORDS] {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    // SAFETY: the helper takes no argument and returns the monotonic clock.
    let monotonic_ns = unsafe { bpf_ktime_get_ns() };
    let [comm_0, comm_1, comm_2, comm_3] = comm_words();
    [
        pid_tgid.wrapping_shr(WORD_BITS) as u32,
        parent_tgid(),
        uid_gid as u32,
        uid_gid.wrapping_shr(WORD_BITS) as u32,
        monotonic_ns as u32,
        monotonic_ns.wrapping_shr(WORD_BITS) as u32,
        comm_0,
        comm_1,
        comm_2,
        comm_3,
    ]
}


fn count_drop() {
    if let Some(slot) = EXEC_DROPS.get_ptr_mut(0) {
        // SAFETY: the pointer comes from the per-CPU array lookup and is valid for this program run; only this CPU writes its own slot.
        let dropped = unsafe { slot.read_volatile() };
        // SAFETY: same pointer and same guarantee; the plain add cannot race because the slot is per CPU and the program does not migrate.
        unsafe { slot.write_volatile(dropped.wrapping_add(1)) };
    }
}


fn emit_exec() {
    if let Some(mut entry) = EXEC_EVENTS.reserve::<[u32; RECORD_WORDS]>(0) {
        entry.write(build_record());
        entry.submit(0);
    } else {
        count_drop();
    }
}


#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(_context: TracePointContext) -> u32 {
    emit_exec();
    0
}
