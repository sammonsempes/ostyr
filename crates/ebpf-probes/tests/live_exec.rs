#![cfg(feature = "ebpf-live-test")]

use aya::programs::loaded_programs;
use ebpf_probes::drain::{KernelDropped, MAX_DRAIN_PER_POLL};
use ebpf_probes::error::LoadError;
use ebpf_probes::loader::{drain_exec, load_exec_probe, load_exec_probe_from_bytes, run_exec_probe, Probe};
use ebpf_probes::object::{read_object, EXEC_OBJECT_PATH};
use ebpf_probes::shape::{ShapeError, PROGRAM_NAME};
use std::error::Error;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;


const UNPRIVILEGED_UID: u32 = 65534;


const TRUE_BINARY: &str = "/usr/bin/true";


const STORM_EXECS: u32 = 3000;


const HALVES: usize = 2;


const MARKER: &str = "MARKER-7f3a9c";


const UNLOAD_POLL_ATTEMPTS: u32 = 200;


const UNLOAD_POLL_MILLIS: u64 = 50;


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


fn wait_until_unloaded(held: u32) -> Result<bool, Box<dyn Error>> {
    let gone = (0..UNLOAD_POLL_ATTEMPTS).find_map(|_| match program_ids() {
        Ok(ids) if !ids.contains(&held) => Some(Ok(())),
        Ok(_) => {
            std::thread::sleep(Duration::from_millis(UNLOAD_POLL_MILLIS));
            None
        }
        Err(error) => Some(Err(error)),
    });
    Ok(gone.transpose()?.is_some())
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
    assert!(wait_until_unloaded(held)?, "program {held} is still loaded after the drop");
    Ok(())
}


#[test]
fn a_forged_object_fails_by_name_and_keeps_no_aya_text() -> Result<(), Box<dyn Error>> {
    let forged = format!("{MARKER} this is not an ELF object").into_bytes();
    let refused = load_exec_probe_from_bytes(&forged).err().ok_or("a forged object loaded")?;
    assert_no_marker(&refused);
    assert_eq!(refused, LoadError::Shape(ShapeError::Parse));
    let mut truncated = read_object(Path::new(EXEC_OBJECT_PATH))?;
    truncated.truncate(truncated.len() / HALVES);
    let cut = load_exec_probe_from_bytes(&truncated).err().ok_or("a truncated object loaded")?;
    assert_no_marker(&cut);
    Ok(())
}


#[test]
fn a_stop_set_before_the_attach_attaches_nothing_and_leaves_no_program() -> Result<(), Box<dyn Error>> {
    let before = program_ids()?;
    let stop = AtomicBool::new(true);
    let attached = AtomicBool::new(false);
    let polls = run_exec_probe(&stop, 1, &mut || attached.store(true, Ordering::Relaxed), &mut |_| ())?;
    assert_eq!(polls, 0);
    assert!(!attached.load(Ordering::Relaxed), "the probe attached after the stop flag was set");
    let fresh: Vec<u32> = program_ids()?.into_iter().filter(|id| !before.contains(id)).collect();
    let gone = fresh.iter().map(|id| wait_until_unloaded(*id)).collect::<Result<Vec<_>, _>>()?;
    assert!(
        gone.iter().all(|unloaded| *unloaded),
        "a program loaded by the stopped run is still listed: {fresh:?}"
    );
    Ok(())
}
