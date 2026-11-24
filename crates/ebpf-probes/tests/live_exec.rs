#![cfg(feature = "ebpf-live")]

use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};
use ebpf_probes::btf::{read_task_offsets, require_64_bit, VMLINUX_BTF_PATH};
use ebpf_probes::live::read_dropped;
use ebpf_probes::record::{decode_exec, ExecRecord};
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::process::Command;


const OBJECT_ENV: &str = "EBPF_PROBES_OBJECT";


const PROGRAM_NAME: &str = "sched_process_exec";


const RING_NAME: &str = "EXEC_EVENTS";


const DROPS_NAME: &str = "EXEC_DROPS";


const UNPRIVILEGED_UID: u32 = 65534;


const TRUE_BINARY: &str = "/usr/bin/true";


const STORM_EXECS: u32 = 3000;


struct Probe {
    _ebpf: Ebpf,
    ring: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
}


fn object_path() -> Result<String, Box<dyn Error>> {
    Ok(std::env::var(OBJECT_ENV).map_err(|source| format!("{OBJECT_ENV} must name the built kernel object: {source}"))?)
}


fn load_probe(object: &str) -> Result<Probe, Box<dyn Error>> {
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
    let ring = RingBuf::try_from(ebpf.take_map(RING_NAME).ok_or("ring buffer EXEC_EVENTS is missing")?)?;
    let drops = PerCpuArray::try_from(ebpf.take_map(DROPS_NAME).ok_or("map EXEC_DROPS is missing")?)?;
    Ok(Probe { _ebpf: ebpf, ring, drops })
}


fn run_true_as_nobody() -> Result<u32, Box<dyn Error>> {
    let mut process = Command::new("setpriv")
        .arg("--reuid")
        .arg(UNPRIVILEGED_UID.to_string())
        .arg(TRUE_BINARY)
        .spawn()?;
    let child = process.id();
    process.wait()?;
    Ok(child)
}


fn drain(ring: &mut RingBuf<MapData>) -> Result<Vec<ExecRecord>, Box<dyn Error>> {
    Ok(std::iter::from_fn(|| ring.next().map(|item| decode_exec(&item))).collect::<Result<Vec<_>, _>>()?)
}


#[test]
fn an_unprivileged_exec_is_reported_with_pid_ppid_uid_and_comm() -> Result<(), Box<dyn Error>> {
    let object = object_path()?;
    let mut probe = load_probe(&object)?;
    let child = run_true_as_nobody()?;
    let records = drain(&mut probe.ring)?;
    let dropped = read_dropped(&probe.drops)?;
    let found = records.iter().find(|record| record.pid == child && record.comm == "true");
    let record = found.ok_or_else(|| format!("no exec record for pid {child} among {} records", records.len()))?;
    assert_eq!(record.ppid, std::process::id());
    assert_eq!(record.uid, UNPRIVILEGED_UID);
    assert!(record.monotonic_ns > 0);
    assert_eq!(dropped, 0);
    Ok(())
}


#[test]
fn an_undrained_storm_is_counted_as_dropped() -> Result<(), Box<dyn Error>> {
    let object = object_path()?;
    let mut probe = load_probe(&object)?;
    (0..STORM_EXECS).try_for_each(|_| Command::new(TRUE_BINARY).status().map(drop))?;
    let dropped = read_dropped(&probe.drops)?;
    let kept = drain(&mut probe.ring)?.len() as u64;
    writeln!(
        std::io::stdout(),
        "storm of {STORM_EXECS} execs: {kept} records kept, {dropped} drops counted"
    )?;
    assert!(dropped > 0, "no drop counted after {STORM_EXECS} execs, {kept} kept");
    assert!(
        kept + dropped >= u64::from(STORM_EXECS),
        "kept {kept} plus dropped {dropped} is below {STORM_EXECS}"
    );
    Ok(())
}
