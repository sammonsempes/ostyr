#![cfg(feature = "ebpf-live-test")]

use aya::programs::loaded_programs;
use ebpf_probes::drain::{KernelDropped, MAX_DRAIN_PER_POLL};
use ebpf_probes::loader::{drain_exec, load_exec_probe, load_exec_probe_from_bytes, LoadError, Probe, PROGRAM_NAME};
use ebpf_probes::object::{read_object, EXEC_OBJECT_PATH};
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::process::Command;


const UNPRIVILEGED_UID: u32 = 65534;


const TRUE_BINARY: &str = "/usr/bin/true";


const STORM_EXECS: u32 = 3000;


const HALVES: usize = 2;


const MARKER: &str = "MARKER-7f3a9c";


fn load() -> Result<Probe, Box<dyn Error>> {
    Ok(load_exec_probe(Path::new(EXEC_OBJECT_PATH))?)
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


fn program_ids() -> Result<Vec<u32>, Box<dyn Error>> {
    let infos = loaded_programs().collect::<Result<Vec<_>, _>>()?;
    Ok(infos.iter().map(|info| info.id()).collect())
}


fn assert_no_marker(error: &LoadError) {
    let first: &(dyn std::error::Error + 'static) = error;
    let chain = std::iter::successors(Some(first), |inner| (*inner).source());
    let texts: Vec<String> = chain.flat_map(|inner| [inner.to_string(), format!("{inner:?}")]).collect();
    assert!(texts.iter().all(|text| !text.contains(MARKER)), "{texts:?}");
}


#[test]
fn an_unprivileged_exec_is_drained_with_pid_ppid_uid_and_comm() -> Result<(), Box<dyn Error>> {
    let mut probe = load()?;
    let child = run_true_as_nobody()?;
    let drained = drain_exec(&mut probe, MAX_DRAIN_PER_POLL);
    let record = drained
        .records
        .iter()
        .find(|record| record.pid == child && record.comm == "true")
        .ok_or_else(|| format!("no exec record for pid {child} among {}", drained.records.len()))?;
    assert_eq!(record.ppid, std::process::id());
    assert_eq!(record.uid, UNPRIVILEGED_UID);
    assert_eq!(drained.report.refused, 0);
    assert_eq!(drained.report.kernel_dropped, KernelDropped::Counted(0));
    Ok(())
}


#[test]
fn an_undrained_storm_is_a_loud_kernel_drop_count() -> Result<(), Box<dyn Error>> {
    let mut probe = load()?;
    (0..STORM_EXECS).try_for_each(|_| Command::new(TRUE_BINARY).status().map(drop))?;
    let drained = drain_exec(&mut probe, MAX_DRAIN_PER_POLL);
    writeln!(std::io::stdout(), "storm: {:?}", drained.report)?;
    assert!(
        matches!(drained.report.kernel_dropped, KernelDropped::Counted(count) if count > 0),
        "{:?}",
        drained.report
    );
    Ok(())
}


#[test]
fn dropping_the_probe_unloads_the_program() -> Result<(), Box<dyn Error>> {
    let probe = load()?;
    let held = probe.ebpf.program(PROGRAM_NAME).ok_or("program is missing")?.info()?.id();
    assert!(program_ids()?.contains(&held));
    drop(probe);
    assert!(!program_ids()?.contains(&held), "program {held} is still loaded after the drop");
    Ok(())
}


#[test]
fn a_forged_object_fails_by_name_and_keeps_no_aya_text() -> Result<(), Box<dyn Error>> {
    let forged = format!("{MARKER} this is not an ELF object").into_bytes();
    let refused = load_exec_probe_from_bytes(&forged).err().ok_or("a forged object loaded")?;
    assert_no_marker(&refused);
    assert_eq!(refused, LoadError::Parse);
    let mut truncated = read_object(Path::new(EXEC_OBJECT_PATH))?;
    truncated.truncate(truncated.len() / HALVES);
    let cut = load_exec_probe_from_bytes(&truncated).err().ok_or("a truncated object loaded")?;
    assert_no_marker(&cut);
    Ok(())
}
