#![cfg(feature = "ebpf-live-test")]

use ebpf_probes::drain::{KernelDropped, MAX_DRAIN_PER_POLL};
use ebpf_probes::loader::{attach_probes, drain_exec, drain_probes, prepare_exec_probe_from_bytes, Probe, ProbeDrained};
use ebpf_probes::object::{read_object, EXEC_OBJECT_PATH};
use ebpf_probes::record::{FileRecord, FILE_PATH_BYTES};
use ebpf_probes::shape::{EXEC_PROBE, FILE_PROBE};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};


const O_WRITE_BITS: u32 = 0o1 | 0o2 | 0o100 | 0o1000;


const STORM_OPENS: u32 = 3000;


const WRITES_EXPECTED: usize = 2;


const SCRATCH: &str = "/tmp/t919-live";


const TRUE_BINARY: &str = "/usr/bin/true";


const MAX_PATH_NAME: usize = 4094;


const HELPER: &str = r#"
import ctypes, mmap, os, sys
libc = ctypes.CDLL(None, use_errno=True)
mode = sys.argv[1]
flags = os.O_WRONLY | os.O_CREAT
if mode == "unmapped":
    libc.syscall(257, -100, ctypes.c_void_p(1), flags, 0o644)
elif mode == "nonul":
    page = mmap.mmap(-1, 8192)
    base = ctypes.addressof(ctypes.c_char.from_buffer(page))
    page.write(b"/" + b"a" * 4095)
    libc.mprotect(ctypes.c_void_p(base + 4096), 4096, 0)
    libc.syscall(257, -100, ctypes.c_void_p(base + 4096 - 100), flags, 0o644)
elif mode == "storm":
    for _ in range(int(sys.argv[2])):
        os.close(os.open(sys.argv[3], flags))
elif mode == "read":
    os.close(os.open(sys.argv[2], os.O_RDONLY))
elif mode == "long":
    try:
        os.open("/" + "a" * int(sys.argv[2]), flags)
    except OSError:
        pass
"#;


fn probe() -> Result<Probe, Box<dyn Error>> {
    let bytes = read_object(Path::new(EXEC_OBJECT_PATH))?;
    let mut loaded = prepare_exec_probe_from_bytes(&bytes)?;
    attach_probes(&mut loaded)?;
    Ok(loaded)
}


fn file_records(loaded: &mut Probe) -> Result<Vec<FileRecord>, Box<dyn Error>> {
    let drains = drain_probes(loaded, MAX_DRAIN_PER_POLL);
    let names: Vec<&str> = drains.iter().map(|entry| entry.name).collect();
    assert_eq!(names, [EXEC_PROBE.name, FILE_PROBE.name]);
    let records = drains.into_iter().find_map(|entry| match entry.drained {
        ProbeDrained::File(drained) => Some(drained.records),
        ProbeDrained::Exec(_) => None,
    });
    Ok(records.ok_or("no file drain")?)
}


fn scratch(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::fs::create_dir_all(SCRATCH)?;
    Ok(Path::new(SCRATCH).join(name))
}


fn helper(mode: &str, extra: &[&str]) -> Result<u32, Box<dyn Error>> {
    let mut child = Command::new("python3").arg("-I").arg("-c").arg(HELPER).arg(mode).args(extra).spawn()?;
    let pid = child.id();
    child.wait()?;
    Ok(pid)
}


#[test]
fn touch_and_a_redirect_make_two_write_records_and_a_cat_makes_none() -> Result<(), Box<dyn Error>> {
    let target = scratch("three-ops")?;
    let text = target.to_string_lossy().to_string();
    let mut loaded = probe()?;
    Command::new("touch").arg(&target).status()?;
    Command::new("tee").arg(&target).stdin(Stdio::null()).stdout(Stdio::null()).status()?;
    Command::new("cat").arg(&target).status()?;
    let ours: Vec<FileRecord> = file_records(&mut loaded)?.into_iter().filter(|record| record.path == text).collect();
    assert_eq!(ours.len(), WRITES_EXPECTED, "{ours:?}");
    assert!(ours
        .iter()
        .all(|record| record.flags & O_WRITE_BITS != 0 && !record.cut && !record.unreadable));
    Ok(())
}


#[test]
fn a_read_only_open_never_reaches_the_ring() -> Result<(), Box<dyn Error>> {
    let mut loaded = probe()?;
    let marker = "/etc/hostname";
    let pid = helper("read", &[marker])?;
    let records = file_records(&mut loaded)?;
    assert!(records.iter().all(|record| record.pid != pid), "a read-only helper produced {records:?}");
    assert!(records.iter().all(|record| record.path != marker), "{records:?}");
    Ok(())
}


#[test]
fn a_long_path_is_cut_and_flagged_without_a_fault() -> Result<(), Box<dyn Error>> {
    let mut loaded = probe()?;
    let pid = helper("long", &[&MAX_PATH_NAME.to_string()])?;
    let records = file_records(&mut loaded)?;
    let mine: Vec<&FileRecord> = records.iter().filter(|record| record.pid == pid).collect();
    assert_eq!(mine.len(), 1, "{mine:?}");
    assert!(mine
        .iter()
        .all(|record| record.cut && !record.unreadable && record.path.len() == FILE_PATH_BYTES - 1));
    Ok(())
}


#[test]
fn a_path_without_nul_in_the_page_and_an_unmapped_pointer_are_flagged() -> Result<(), Box<dyn Error>> {
    let mut loaded = probe()?;
    let faulting = helper("nonul", &[])?;
    let unmapped = helper("unmapped", &[])?;
    let records = file_records(&mut loaded)?;
    let first: Vec<&FileRecord> = records.iter().filter(|record| record.pid == faulting).collect();
    let second: Vec<&FileRecord> = records.iter().filter(|record| record.pid == unmapped).collect();
    assert_eq!((first.len(), second.len()), (1, 1), "{records:?}");
    assert!(first
        .iter()
        .chain(second.iter())
        .all(|record| record.unreadable && record.path.is_empty()));
    Ok(())
}


#[test]
fn a_write_storm_leaves_a_kernel_drop_count_and_exec_records_keep_flowing() -> Result<(), Box<dyn Error>> {
    let target = scratch("storm")?;
    let mut loaded = probe()?;
    helper("storm", &[&STORM_OPENS.to_string(), &target.to_string_lossy()])?;
    let child = Command::new(TRUE_BINARY)
        .spawn()
        .and_then(|mut process| process.wait().map(|_| process.id()))?;
    let exec = drain_exec(&mut loaded, MAX_DRAIN_PER_POLL);
    assert!(exec.records.iter().any(|record| record.pid == child), "no exec record for {child}");
    let drains = drain_probes(&mut loaded, MAX_DRAIN_PER_POLL);
    let found = drains.into_iter().find_map(|entry| match entry.drained {
        ProbeDrained::File(drained) => Some(drained),
        ProbeDrained::Exec(_) => None,
    });
    let file = found.ok_or("no file drain")?;
    assert!(
        matches!(file.report.kernel_dropped, KernelDropped::Counted(count) if count > 0),
        "{:?}",
        file.report
    );
    Ok(())
}
