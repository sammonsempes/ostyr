#![cfg(feature = "ebpf-live")]

use aya::maps::RingBuf;
use aya::programs::TracePoint;
use aya::EbpfLoader;
use ebpf_probes::btf::{read_task_offsets, require_64_bit, VMLINUX_BTF_PATH};
use ebpf_probes::record::{decode_exec, ExecRecord};
use std::error::Error;
use std::path::Path;
use std::process::Command;


const OBJECT_ENV: &str = "EBPF_PROBES_OBJECT";


const PROGRAM_NAME: &str = "sched_process_exec";


const RING_NAME: &str = "EXEC_EVENTS";


const UNPRIVILEGED_UID: u32 = 65534;


const TRUE_BINARY: &str = "/usr/bin/true";


fn object_path() -> Result<String, Box<dyn Error>> {
    Ok(std::env::var(OBJECT_ENV).map_err(|source| format!("{OBJECT_ENV} must name the built kernel object: {source}"))?)
}


fn exec_records(object: &str) -> Result<(u32, Vec<ExecRecord>), Box<dyn Error>> {
    require_64_bit(usize::BITS)?;
    let offsets = read_task_offsets(Path::new(VMLINUX_BTF_PATH))?;
    let real_parent = u64::from(offsets.real_parent);
    let tgid = u64::from(offsets.tgid);
    let mut ebpf = EbpfLoader::new()
        .override_global("REAL_PARENT_OFFSET", &real_parent, true)
        .override_global("TGID_OFFSET", &tgid, true)
        .load_file(object)?;
    let program: &mut TracePoint = ebpf
        .program_mut(PROGRAM_NAME)
        .ok_or("program sched_process_exec is missing")?
        .try_into()?;
    program.load()?;
    program.attach("sched", PROGRAM_NAME)?;
    let mut ring = RingBuf::try_from(ebpf.take_map(RING_NAME).ok_or("ring buffer EXEC_EVENTS is missing")?)?;
    let mut process = Command::new("setpriv")
        .arg("--reuid")
        .arg(UNPRIVILEGED_UID.to_string())
        .arg(TRUE_BINARY)
        .spawn()?;
    let child = process.id();
    process.wait()?;
    let records = std::iter::from_fn(|| ring.next().map(|item| decode_exec(&item))).collect::<Result<Vec<_>, _>>()?;
    Ok((child, records))
}


#[test]
fn an_unprivileged_exec_is_reported_with_pid_ppid_uid_and_comm() -> Result<(), Box<dyn Error>> {
    let object = object_path()?;
    let (child, records) = exec_records(&object)?;
    let found = records.iter().find(|record| record.pid == child && record.comm == "true");
    let record = found.ok_or_else(|| format!("no exec record for pid {child} among {} records", records.len()))?;
    assert_eq!(record.ppid, std::process::id());
    assert_eq!(record.uid, UNPRIVILEGED_UID);
    assert!(record.monotonic_ns > 0);
    Ok(())
}
