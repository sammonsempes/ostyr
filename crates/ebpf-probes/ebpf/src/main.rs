#![no_std]
#![no_main]

use aya_ebpf::bindings::path;
use aya_ebpf::helpers::{
    bpf_d_path, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
use aya_ebpf::macros::{fexit, map, tracepoint};
use aya_ebpf::maps::{PerCpuArray, RingBuf};
use aya_ebpf::programs::{FExitContext, TracePointContext};


const MAX_RING_BYTES: u32 = 64 * 1024;


const WORD_BITS: u32 = 32;


const COMM_BYTES: usize = 16;


const COMM_WORD_BYTES: usize = 4;


const COMM_WORDS: usize = 4;


const RECORD_WORDS: usize = 10;


const FILE_RING_BYTES: u32 = 256 * 1024;


const FILE_RECORD_KIND: u32 = 3;


const FILE_HEADER_WORDS: usize = 12;


const FILE_PATH_BYTES: usize = 256;


const FILE_RECORD_BYTES: usize = FILE_HEADER_WORDS * COMM_WORD_BYTES + FILE_PATH_BYTES;


const FMODE_WRITE: u32 = 0x2;


const FMODE_CREATED: u32 = 0x0010_0000;


const O_TRUNC: u32 = 0o1000;


const ENAMETOOLONG: i64 = 36;


const FILE_FIRST_ARGUMENT: usize = 0;


const FILE_RETURN_SLOT: usize = 1;


const STATUS_TOO_LONG: u32 = 1;


const STATUS_PATH_ERROR: u32 = 2;


const STATUS_UNLINKED: u32 = 4;


#[link_section = "license"]
#[used]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";


#[no_mangle]
static REAL_PARENT_OFFSET: u64 = 0;


#[no_mangle]
static TGID_OFFSET: u64 = 0;


#[no_mangle]
static FILE_MODE_OFFSET: u64 = 0;


#[no_mangle]
static FILE_FLAGS_OFFSET: u64 = 0;


#[no_mangle]
static FILE_PATH_OFFSET: u64 = 0;


#[no_mangle]
static FILE_INODE_OFFSET: u64 = 0;


#[no_mangle]
static PATH_DENTRY_OFFSET: u64 = 0;


#[no_mangle]
static INODE_SB_OFFSET: u64 = 0;


#[no_mangle]
static INODE_INO_OFFSET: u64 = 0;


#[no_mangle]
static SUPER_BLOCK_DEV_OFFSET: u64 = 0;


#[no_mangle]
static DENTRY_PARENT_OFFSET: u64 = 0;


#[no_mangle]
static DENTRY_HASH_PPREV_OFFSET: u64 = 0;


#[no_mangle]
static TASK_NSPROXY_OFFSET: u64 = 0;


#[no_mangle]
static NSPROXY_MNT_NS_OFFSET: u64 = 0;


#[no_mangle]
static MNT_NS_INUM_OFFSET: u64 = 0;


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


fn at(base: *const u8, global: &'static u64) -> *const u8 {
    base.wrapping_add(global_offset(global))
}


fn u64_at(base: *const u8, global: &'static u64) -> u64 {
    // SAFETY: bpf_probe_read_kernel faults safely, so an address that is not readable gives Err and never a crash.
    unsafe { bpf_probe_read_kernel::<u64>(at(base, global).cast::<u64>()) }.unwrap_or(0)
}


fn u32_at(base: *const u8, global: &'static u64) -> u32 {
    // SAFETY: same helper and same guarantee as u64_at.
    unsafe { bpf_probe_read_kernel::<u32>(at(base, global).cast::<u32>()) }.unwrap_or(0)
}


fn pointer_at(base: *const u8, global: &'static u64) -> *const u8 {
    u64_at(base, global) as *const u8
}


fn opener_mount_namespace() -> u32 {
    // SAFETY: the helper takes no argument and only returns the current task pointer, which is used as an address and never dereferenced here.
    let task = unsafe { bpf_get_current_task() } as *const u8;
    u32_at(
        pointer_at(pointer_at(task, &TASK_NSPROXY_OFFSET), &NSPROXY_MNT_NS_OFFSET),
        &MNT_NS_INUM_OFFSET,
    )
}


fn is_unlinked(dentry: *const u8) -> bool {
    let unhashed = u64_at(dentry, &DENTRY_HASH_PPREV_OFFSET) == 0;
    unhashed && pointer_at(dentry, &DENTRY_PARENT_OFFSET) != dentry
}


fn file_header(file: *const u8, flags: u32, mode: u32, status: u32) -> [u32; FILE_HEADER_WORDS] {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    // SAFETY: the helper takes no argument and returns the monotonic clock.
    let monotonic_ns = unsafe { bpf_ktime_get_ns() };
    let inode = pointer_at(file, &FILE_INODE_OFFSET);
    let inode_number = u64_at(inode, &INODE_INO_OFFSET);
    let device = u32_at(pointer_at(inode, &INODE_SB_OFFSET), &SUPER_BLOCK_DEV_OFFSET);
    let dentry = pointer_at(at(file, &FILE_PATH_OFFSET), &PATH_DENTRY_OFFSET);
    let unlinked = if is_unlinked(dentry) { STATUS_UNLINKED } else { 0 };
    [
        FILE_RECORD_KIND,
        pid_tgid.wrapping_shr(WORD_BITS) as u32,
        uid_gid as u32,
        flags,
        mode,
        status | unlinked,
        monotonic_ns as u32,
        monotonic_ns.wrapping_shr(WORD_BITS) as u32,
        device,
        inode_number as u32,
        inode_number.wrapping_shr(WORD_BITS) as u32,
        opener_mount_namespace(),
    ]
}


fn fill_file_record(bytes: &mut [u8], file: *const u8, flags: u32, mode: u32) -> Option<()> {
    bytes.fill(0);
    let (header, path_bytes) = bytes.split_at_mut_checked(FILE_HEADER_WORDS * COMM_WORD_BYTES)?;
    let location = at(file, &FILE_PATH_OFFSET).cast::<path>();
    // SAFETY: the pointer is the f_path member of the struct file the verifier proved is the first argument of security_file_open; bpf_d_path writes at most path_bytes.len() bytes into the reserved record.
    let written = unsafe { bpf_d_path(location, path_bytes.as_mut_ptr().cast(), FILE_PATH_BYTES as u32) };
    let status = if written > 0 {
        0
    } else if written == -ENAMETOOLONG {
        STATUS_TOO_LONG
    } else {
        STATUS_PATH_ERROR
    };
    if status != 0 {
        path_bytes.fill(0);
    }
    let words = file_header(file, flags, mode, status).map(u32::to_le_bytes);
    header.iter_mut().zip(words.as_flattened()).for_each(|(slot, byte)| *slot = *byte);
    Some(())
}


fn emit_file(file: *const u8) {
    let mode = u32_at(file, &FILE_MODE_OFFSET);
    let flags = u32_at(file, &FILE_FLAGS_OFFSET);
    if mode & (FMODE_WRITE | FMODE_CREATED) != 0 || flags & O_TRUNC != 0 {
        match FILE_EVENTS.reserve_bytes(FILE_RECORD_BYTES, 0) {
            Some(mut entry) => {
                if fill_file_record(&mut entry, file, flags, mode).is_some() {
                    entry.submit(0);
                } else {
                    entry.discard(0);
                }
            }
            None => count_drop(&FILE_DROPS),
        }
    }
}


#[fexit(function = "security_file_open")]
pub fn security_file_open(context: FExitContext) -> i32 {
    let returned: u64 = context.arg(FILE_RETURN_SLOT);
    if returned as u32 == 0 {
        emit_file(context.arg::<*const u8>(FILE_FIRST_ARGUMENT));
    }
    0
}
