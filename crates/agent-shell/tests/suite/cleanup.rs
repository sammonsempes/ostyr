use crate::support::{owner_of, private_tempdir};
use crate::types::TestResult;
use agent_shell::account::ShellAccount;
use agent_shell::cleanup::{
    account_processes, account_processes_within, cleanup_fn, parse_status, production_plan, read_facts, signal_process, sweep, tolerate_gone,
    ProcessFacts, SweepPlan, MAX_SWEEP_ROUNDS,
};
use rustix::process::{Pid, Signal};
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use tempfile::TempDir;


const OTHER_UID: u32 = 4_000_000;


const UNUSED_UID: u32 = 3_999_999_999;


const HUP_IGNORING_PROGRAM: &str = "import signal, time\nsignal.signal(signal.SIGHUP, signal.SIG_IGN)\nprint('ready', flush=True)\ntime.sleep(1000)";


const TRAPPING_PROGRAM: &str = "import os, signal, sys, time\nsignal.signal(signal.SIGHUP, lambda number, frame: os.write(1, b'hup\\n'))\nsignal.signal(signal.SIGUSR1, lambda number, frame: (os.write(1, b'usr1\\n'), sys.exit(0)))\nos.write(1, b'ready\\n')\nfor i in range(20000): time.sleep(0.05)";


const TWO_ENTRIES: usize = 2;


const KEPT: usize = 7;


const GRACE_POLLS: u64 = 50;


const FIRST_PID: i32 = 11;


const SECOND_PID: i32 = 12;


const THIRD_PID: i32 = 13;


const FOURTH_PID: i32 = 14;


const GROUP_PLAN_ROUNDS: usize = 3;


const SIGNAL_KILL: i32 = 9;


fn status_text(uid: u32, state: &str) -> String {
    format!("Name:\tx\nState:\t{state}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t0\t0\t0\t0\n")
}


fn pid_of(raw: i32) -> Result<Pid, Box<dyn std::error::Error>> {
    Ok(Pid::from_raw(raw).ok_or("pid")?)
}


fn write_status(root: &Path, pid: i32, text: &str) -> TestResult {
    let directory = root.join(pid.to_string());
    std::fs::create_dir_all(&directory)?;
    std::fs::write(directory.join("status"), text)?;
    Ok(())
}


fn plan_for(root: &Path, uid: u32, grace_polls: u64, rounds: usize) -> SweepPlan {
    SweepPlan {
        proc_root: root.to_path_buf(),
        uid,
        grace_polls,
        rounds,
    }
}


fn own_uid() -> Result<u32, Box<dyn std::error::Error>> {
    let directory = private_tempdir()?;
    owner_of(directory.path())
}


fn linked_root(pids: &[u32]) -> Result<TempDir, Box<dyn std::error::Error>> {
    let root = private_tempdir()?;
    pids.iter()
        .try_for_each(|pid| std::os::unix::fs::symlink(format!("/proc/{pid}"), root.path().join(pid.to_string())))?;
    Ok(root)
}


fn sleeper() -> Result<Child, Box<dyn std::error::Error>> {
    Ok(Command::new("sleep").arg("1000").spawn()?)
}


fn hup_ignoring_sleeper() -> Result<Child, Box<dyn std::error::Error>> {
    let mut child = Command::new("python3")
        .args(["-I", "-c", HUP_IGNORING_PROGRAM])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut line = String::new();
    BufReader::new(child.stdout.take().ok_or("stdout")?).read_line(&mut line)?;
    Ok(child)
}


fn trapping_child() -> Result<(Child, BufReader<ChildStdout>), Box<dyn std::error::Error>> {
    let mut child = Command::new("python3")
        .args(["-I", "-c", TRAPPING_PROGRAM])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("stdout")?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok((child, reader))
}


fn signals_seen_by(mut child: Child, mut reader: BufReader<ChildStdout>, uid: u32, root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let pid = pid_of(i32::try_from(child.id())?)?;
    signal_process(&plan_for(root, uid, 0, 1), pid, Signal::HUP)?;
    rustix::process::kill_process(pid, Signal::USR1)?;
    let mut seen = String::new();
    reader.read_to_string(&mut seen)?;
    child.wait()?;
    Ok(seen)
}


#[test]
fn a_status_gives_the_real_uid_and_the_zombie_state() -> TestResult {
    assert_eq!(
        parse_status(&status_text(OTHER_UID, "S (sleeping)"))?,
        ProcessFacts {
            real_uid: OTHER_UID,
            zombie: false
        }
    );
    assert!(parse_status(&status_text(OTHER_UID, "Z (zombie)"))?.zombie);
    assert!(parse_status("State:\tS\n").is_err());
    assert!(parse_status("Uid:\t1\t1\t1\t1\n").is_err());
    assert!(parse_status("State:\tS\nUid:\tx\n").is_err());
    assert!(parse_status("State:\nUid:\t1\n").is_err());
    Ok(())
}


#[test]
fn a_process_that_is_gone_is_not_an_error_but_anything_else_is() -> TestResult {
    assert_eq!(tolerate_gone(Err::<usize, _>(std::io::Error::from(std::io::ErrorKind::NotFound)))?, 0);
    assert_eq!(tolerate_gone(Err::<usize, _>(std::io::Error::from_raw_os_error(libc::ESRCH)))?, 0);
    assert!(tolerate_gone(Err::<usize, _>(std::io::Error::from(std::io::ErrorKind::PermissionDenied))).is_err());
    assert_eq!(tolerate_gone(Ok(KEPT))?, KEPT);
    Ok(())
}


#[test]
fn the_process_table_gives_the_live_processes_of_the_account_only() -> TestResult {
    let root = private_tempdir()?;
    write_status(root.path(), FIRST_PID, &status_text(OTHER_UID, "S (sleeping)"))?;
    write_status(root.path(), SECOND_PID, &status_text(OTHER_UID + 1, "S (sleeping)"))?;
    write_status(root.path(), THIRD_PID, &status_text(OTHER_UID, "Z (zombie)"))?;
    std::fs::create_dir(root.path().join(FOURTH_PID.to_string()))?;
    std::fs::write(root.path().join("cpuinfo"), "x")?;
    assert_eq!(account_processes(root.path(), OTHER_UID)?, vec![pid_of(FIRST_PID)?]);
    assert!(account_processes(&root.path().join("missing"), OTHER_UID).is_err());
    assert_eq!(read_facts(root.path(), pid_of(FOURTH_PID)?)?, None);
    write_status(root.path(), FOURTH_PID, "garbage")?;
    assert!(read_facts(root.path(), pid_of(FOURTH_PID)?).is_err());
    assert!(account_processes(root.path(), OTHER_UID).is_err());
    Ok(())
}


#[test]
fn a_process_of_another_uid_is_never_signalled() -> TestResult {
    let mine = own_uid()?;
    let (foreign, foreign_reader) = trapping_child()?;
    let foreign_root = linked_root(&[foreign.id()])?;
    let foreign_seen = signals_seen_by(foreign, foreign_reader, mine + 1, foreign_root.path())?;
    assert_eq!(foreign_seen, "usr1\n");
    let (own, own_reader) = trapping_child()?;
    let own_root = linked_root(&[own.id()])?;
    let own_seen = signals_seen_by(own, own_reader, mine, own_root.path())?;
    assert_eq!(own_seen, "hup\nusr1\n");
    Ok(())
}


#[test]
fn a_sweep_of_another_uid_finds_nothing_and_signals_nothing() -> TestResult {
    let mut child = sleeper()?;
    let root = linked_root(&[child.id()])?;
    let pid = pid_of(i32::try_from(child.id())?)?;
    let mine = own_uid()?;
    assert!(account_processes(root.path(), mine + 1)?.is_empty());
    assert_eq!(sweep(&plan_for(root.path(), mine + 1, 0, 1))?, 0);
    assert_eq!(account_processes(root.path(), mine)?, vec![pid]);
    signal_process(&plan_for(root.path(), mine, 0, 1), pid, Signal::KILL)?;
    assert_eq!(child.wait()?.signal(), Some(SIGNAL_KILL));
    Ok(())
}


#[test]
fn a_process_table_longer_than_the_cap_is_an_error_not_a_clean_scan() -> TestResult {
    let root = private_tempdir()?;
    write_status(root.path(), FIRST_PID, &status_text(OTHER_UID, "S (sleeping)"))?;
    write_status(root.path(), SECOND_PID, &status_text(OTHER_UID, "S (sleeping)"))?;
    assert_eq!(account_processes_within(root.path(), OTHER_UID, TWO_ENTRIES)?.len(), TWO_ENTRIES);
    assert!(account_processes_within(root.path(), OTHER_UID, 1).is_err());
    assert!(account_processes_within(root.path(), OTHER_UID, 0).is_err());
    Ok(())
}


#[test]
fn a_process_that_has_exited_is_tolerated() -> TestResult {
    let mut child = Command::new("true").spawn()?;
    let pid = pid_of(i32::try_from(child.id())?)?;
    child.wait()?;
    let root = private_tempdir()?;
    signal_process(&plan_for(root.path(), own_uid()?, 0, 1), pid, Signal::HUP)?;
    let corrupt = private_tempdir()?;
    let mut live = sleeper()?;
    let live_pid = pid_of(i32::try_from(live.id())?)?;
    write_status(corrupt.path(), i32::try_from(live.id())?, "garbage")?;
    assert!(signal_process(&plan_for(corrupt.path(), own_uid()?, 0, 1), live_pid, Signal::HUP).is_err());
    live.kill()?;
    live.wait()?;
    Ok(())
}


#[test]
fn a_sweep_hangs_up_a_process_and_waits_for_it_to_go() -> TestResult {
    let mut child = sleeper()?;
    let root = linked_root(&[child.id()])?;
    assert_eq!(sweep(&plan_for(root.path(), own_uid()?, GRACE_POLLS, MAX_SWEEP_ROUNDS))?, 0);
    assert!(child.wait()?.signal().is_some());
    Ok(())
}


#[test]
fn a_sweep_kills_a_process_that_ignores_the_hangup_after_the_grace() -> TestResult {
    let mut child = hup_ignoring_sleeper()?;
    let root = linked_root(&[child.id()])?;
    assert_eq!(sweep(&plan_for(root.path(), own_uid()?, 0, GROUP_PLAN_ROUNDS))?, 0);
    assert_eq!(child.wait()?.signal(), Some(SIGNAL_KILL));
    Ok(())
}


#[test]
fn what_is_left_after_the_rounds_is_counted() -> TestResult {
    let mut child = sleeper()?;
    let root = linked_root(&[child.id()])?;
    assert_eq!(sweep(&plan_for(root.path(), own_uid()?, 0, 0))?, 1);
    assert!(sweep(&plan_for(&root.path().join("missing"), own_uid()?, 0, 1)).is_err());
    child.kill()?;
    child.wait()?;
    Ok(())
}


#[test]
fn the_production_plan_scans_the_real_table_for_the_account() -> TestResult {
    let account = ShellAccount {
        uid: UNUSED_UID,
        gid: UNUSED_UID,
        home: "/nonexistent".into(),
    };
    let plan = production_plan(&account);
    assert_eq!(plan.proc_root, Path::new("/proc"));
    assert_eq!((plan.uid, plan.grace_polls, plan.rounds), (UNUSED_UID, GRACE_POLLS, MAX_SWEEP_ROUNDS));
    Ok(())
}


#[tokio::test]
async fn the_production_cleanup_runs_on_the_blocking_pool() -> TestResult {
    let account = ShellAccount {
        uid: UNUSED_UID,
        gid: UNUSED_UID,
        home: "/nonexistent".into(),
    };
    let cleanup = cleanup_fn(&account);
    assert_eq!(cleanup().await?, 0);
    Ok(())
}
