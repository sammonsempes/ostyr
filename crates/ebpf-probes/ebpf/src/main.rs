#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
    bpf_probe_read_user_str_bytes,
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


const FILE_RING_BYTES: u32 = 256 * 1024;


const FILE_RECORD_KIND: u32 = 2;


const FILE_HEADER_WORDS: usize = 7;


const FILE_PATH_BYTES: usize = 256;


const FILE_RECORD_BYTES: usize = FILE_HEADER_WORDS * COMM_WORD_BYTES + FILE_PATH_BYTES;


const FILENAME_OFFSET: usize = 24;


const OPEN_FLAGS_OFFSET: usize = 32;


const OPEN_WRITE_MASK: u32 = 0o1 | 0o2 | 0o100 | 0o1000;


const STATUS_CUT: u32 = 1;


const STATUS_UNREADABLE: u32 = 2;


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


#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(FILE_RING_BYTES, 0);


#[map]
static FILE_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);


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


fn count_drop(drops: &PerCpuArray<u64>) {
    if let Some(slot) = drops.get_ptr_mut(0) {
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
        count_drop(&EXEC_DROPS);
    }
}


#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(_context: TracePointContext) -> u32 {
    emit_exec();
    0
}


fn file_header(flags: u32, status: u32) -> [u32; FILE_HEADER_WORDS] {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    // SAFETY: the helper takes no argument and returns the monotonic clock.
    let monotonic_ns = unsafe { bpf_ktime_get_ns() };
    [
        FILE_RECORD_KIND,
        pid_tgid.wrapping_shr(WORD_BITS) as u32,
        uid_gid as u32,
        flags,
        status,
        monotonic_ns as u32,
        monotonic_ns.wrapping_shr(WORD_BITS) as u32,
    ]
}


fn fill_file_record(bytes: &mut [u8], filename: *const u8, flags: u32) -> Option<()> {
    bytes.fill(0);
    let (header, path) = bytes.split_at_mut_checked(FILE_HEADER_WORDS * COMM_WORD_BYTES)?;
    // SAFETY: bpf_probe_read_user_str faults safely, so an unmapped or hostile user pointer gives Err and never a crash; it writes at most path.len() bytes into the reserved record.
    let read = unsafe { bpf_probe_read_user_str_bytes(filename, path) };
    let status = match read {
        Ok(text) if text.len().wrapping_add(1) >= FILE_PATH_BYTES => STATUS_CUT,
        Ok(_) => 0,
        Err(_) => STATUS_UNREADABLE,
    };
    let words = file_header(flags, status).map(u32::to_le_bytes);
    header.iter_mut().zip(words.as_flattened()).for_each(|(slot, byte)| *slot = *byte);
    Some(())
}


fn emit_file(context: &TracePointContext) {
    // SAFETY: read_at reads the tracepoint argument slot through bpf_probe_read_kernel, which faults safely.
    let filename = unsafe { context.read_at::<u64>(FILENAME_OFFSET) }.unwrap_or(0) as *const u8;
    // SAFETY: same helper and the same guarantee for the flags slot.
    let flags = unsafe { context.read_at::<u64>(OPEN_FLAGS_OFFSET) }.unwrap_or(0) as u32;
    if flags & OPEN_WRITE_MASK != 0 {
        match FILE_EVENTS.reserve_bytes(FILE_RECORD_BYTES, 0) {
            Some(mut entry) => {
                if fill_file_record(&mut entry, filename, flags).is_some() {
                    entry.submit(0);
                } else {
                    entry.discard(0);
                }
            }
            None => count_drop(&FILE_DROPS),
        }
    }
}


#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn sys_enter_openat(context: TracePointContext) -> u32 {
    emit_file(&context);
    0
}
