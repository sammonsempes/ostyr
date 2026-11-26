use crate::types::TestResult;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::sync::mpsc::channel;
use std::time::Duration;
use sys_windows::job_spawn::{
    child_in_job, child_job_limits, child_process_id, child_process_ids, spawn_in_job, spawn_in_job_with, terminate, wait_for_exit, JobChild,
    JobOutput,
};
use sys_windows::session::ACTIVE_PROCESS_LIMIT;
use sys_windows::test_probes::process_is_running;
use sys_windows::types::ConsoleError;


const TREE_MIN_PROCESSES: usize = 2;


const WAIT_SECONDS: u64 = 60;


const WAIT_MILLIS: u32 = 60_000;


const POLL_MILLIS: u64 = 100;


const POLL_ATTEMPTS: u32 = 300;


const FAULT_CODE_BASE: u32 = 0x4000_0000;


const KILL_ON_JOB_CLOSE: u32 = 0x2000;


const DIE_ON_UNHANDLED_EXCEPTION: u32 = 0x400;


const ACTIVE_PROCESS: u32 = 0x8;


const BREAKAWAY_OK: u32 = 0x800;


const SILENT_BREAKAWAY_OK: u32 = 0x1000;


const EXIT_SEVEN: u32 = 7;


const ENVIRONMENT_MARKER: &str = "OSTYR_T893_MARKER";


const MARKER_VALUE: &str = "kept";


const CMD_OWN_VARIABLES: [&str; 3] = ["PROMPT", "COMSPEC", "PATHEXT"];


fn fault_with_the_process_id(process_id: u32) -> Result<(), u32> {
    Err(FAULT_CODE_BASE + process_id)
}


fn system_directory() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{}\\System32", std::env::var("SystemRoot")?))
}


fn cmd_path() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{}\\cmd.exe", system_directory()?))
}


fn start(arguments: &[&str], extra: &[(&str, &str)]) -> Result<JobOutput, Box<dyn std::error::Error>> {
    let root = std::env::var("SystemRoot")?;
    let system = system_directory()?;
    let mut environment = vec![("SystemRoot", root.as_str())];
    environment.extend_from_slice(extra);
    Ok(spawn_in_job(&cmd_path()?, arguments, &environment, &system)?)
}


fn read_to_end_guarded(mut stdout: File) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout.read_to_end(&mut bytes).map(|_| bytes);
        let delivered = sender.send(read).is_ok();
        std::hint::black_box(delivered);
    });
    let received = receiver
        .recv_timeout(Duration::from_secs(WAIT_SECONDS))
        .map_err(|_| "the output never reached its end")?;
    Ok(received?)
}


fn wait_for_tree(child: &JobChild) -> Result<BTreeSet<u32>, Box<dyn std::error::Error>> {
    let found = (0..POLL_ATTEMPTS).find_map(|_| {
        std::thread::sleep(Duration::from_millis(POLL_MILLIS));
        child_process_ids(child)
            .ok()
            .map(|ids| ids.into_iter().collect::<BTreeSet<u32>>())
            .filter(|ids| ids.len() >= TREE_MIN_PROCESSES)
    });
    Ok(found.ok_or("the program never started a descendant")?)
}


fn wait_until_gone(process_ids: &BTreeSet<u32>) -> bool {
    (0..POLL_ATTEMPTS)
        .find_map(|_| {
            std::thread::sleep(Duration::from_millis(POLL_MILLIS));
            process_ids.iter().all(|value| !process_is_running(*value)).then_some(())
        })
        .is_some()
}


#[test]
fn terminate_ends_the_whole_tree_and_the_output_reaches_its_end() -> TestResult {
    let JobOutput { child, stdout } = start(&["/D", "/C", "ping -t 127.0.0.1"], &[])?;
    assert!(child_in_job(&child)?);
    let tree = wait_for_tree(&child)?;
    assert!(tree.contains(&child_process_id(&child)));
    assert!(tree.iter().all(|value| process_is_running(*value)));
    terminate(&child)?;
    assert!(wait_until_gone(&tree), "{tree:?} still running");
    read_to_end_guarded(stdout)?;
    Ok(())
}


#[test]
fn dropping_the_handle_ends_the_whole_tree_and_the_output_reaches_its_end() -> TestResult {
    let JobOutput { child, stdout } = start(&["/D", "/C", "ping -t 127.0.0.1"], &[])?;
    let tree = wait_for_tree(&child)?;
    drop(child);
    assert!(wait_until_gone(&tree), "{tree:?} still running");
    read_to_end_guarded(stdout)?;
    Ok(())
}


#[test]
fn the_job_carries_the_kill_on_close_limit_and_no_breakaway() -> TestResult {
    let JobOutput { child, .. } = start(&["/D", "/C", "ping -t 127.0.0.1"], &[])?;
    let (flags, active) = child_job_limits(&child)?;
    assert_eq!(
        flags & (KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION | ACTIVE_PROCESS),
        KILL_ON_JOB_CLOSE | DIE_ON_UNHANDLED_EXCEPTION | ACTIVE_PROCESS
    );
    assert_eq!(flags & (BREAKAWAY_OK | SILENT_BREAKAWAY_OK), 0);
    assert_eq!(active, ACTIVE_PROCESS_LIMIT);
    Ok(())
}


#[test]
fn a_failing_assignment_leaves_no_process_and_no_handle() -> TestResult {
    let root = std::env::var("SystemRoot")?;
    let refused = spawn_in_job_with(
        &cmd_path()?,
        &["/D", "/C", "ping -t 127.0.0.1"],
        &[("SystemRoot", root.as_str())],
        &system_directory()?,
        fault_with_the_process_id,
    )
    .err()
    .ok_or("accepted")?;
    let child = Some(refused)
        .and_then(|error| match error {
            ConsoleError::Windows {
                operation: "AssignProcessToJobObject",
                code,
            } => Some(code - FAULT_CODE_BASE),
            _ => None,
        })
        .ok_or("the refusal is not an assignment error")?;
    assert!(child > 0);
    assert!(wait_until_gone(&BTreeSet::from([child])));
    Ok(())
}


#[test]
fn the_environment_is_exactly_the_given_list() -> TestResult {
    let JobOutput { child, stdout } = start(&["/D", "/C", "set"], &[(ENVIRONMENT_MARKER, MARKER_VALUE)])?;
    let text = String::from_utf8_lossy(&read_to_end_guarded(stdout)?).to_string();
    let names = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, _)| name.to_ascii_uppercase())
        .collect::<BTreeSet<String>>();
    let allowed = CMD_OWN_VARIABLES
        .iter()
        .map(|name| (*name).to_string())
        .chain(["SYSTEMROOT".to_string(), ENVIRONMENT_MARKER.to_ascii_uppercase()])
        .collect::<BTreeSet<String>>();
    assert!(text.contains(&format!("{ENVIRONMENT_MARKER}={MARKER_VALUE}")), "{text}");
    assert!(names.is_subset(&allowed), "{text}");
    let inherited = std::env::vars()
        .map(|(name, _)| name.to_ascii_uppercase())
        .filter(|name| !allowed.contains(name) && names.contains(name))
        .collect::<Vec<String>>();
    assert!(inherited.is_empty(), "{inherited:?}");
    drop(child);
    Ok(())
}


#[test]
fn stdin_and_stderr_are_the_null_device() -> TestResult {
    let JobOutput { child, stdout } = start(&["/D", "/C", "more & echo to-stderr 1>&2 & echo to-stdout"], &[])?;
    let text = String::from_utf8_lossy(&read_to_end_guarded(stdout)?).to_string();
    assert!(text.contains("to-stdout"), "{text}");
    assert!(!text.contains("to-stderr"), "{text}");
    assert_eq!(wait_for_exit(&child, WAIT_MILLIS)?, Some(0));
    Ok(())
}


#[test]
fn the_exit_code_is_read_and_a_running_program_is_none() -> TestResult {
    let JobOutput { child, .. } = start(&["/D", "/C", &format!("exit {EXIT_SEVEN}")], &[])?;
    assert_eq!(wait_for_exit(&child, WAIT_MILLIS)?, Some(EXIT_SEVEN));
    let JobOutput { child: running, .. } = start(&["/D", "/C", "ping -t 127.0.0.1"], &[])?;
    assert_eq!(wait_for_exit(&running, 0)?, None);
    terminate(&running)?;
    Ok(())
}


#[test]
fn a_program_outside_the_grammar_never_starts() -> TestResult {
    let refused = spawn_in_job("cmd.exe", &[], &[], &system_directory()?).err().ok_or("accepted")?;
    assert!(matches!(refused, ConsoleError::BadProgram(_)));
    Ok(())
}
