use crate::common::types::Failure;
use crate::common::types::TestResult;
use crate::support::{kill_host, pause_briefly, RUN_UID};
use connector_manifest::error::ConnectorError;
use connector_manifest::kill::{
    group_of, is_populated, kill_group, kill_leaf, member_groups, parse_ids, read_list, status_field, system_kill_host, tolerate_gone,
    wait_unpopulated, KillHost, KILL_POLLS, KILL_ROUNDS, MAX_LIST_BYTES, MAX_MEMBERS, THREADS_FILE,
};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Child, Command};
use tempfile::TempDir;


const STATUS_ID: i32 = 777_777;


const OTHER_UID: u32 = 1_234;


const SECOND_ID: i32 = 4_242;


const LONG_SLEEP: &str = "30";


const ROUNDS: usize = 2;


const POLLS: u64 = 2;


const NO_SUCH_PID: i32 = 2_147_483_000;


const SIGKILL_CODE: i32 = 9;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const FIRST_ID: i32 = 1;


const SECOND_LISTED: i32 = 2;


const UID_NINE: u32 = 9;


pub struct Sleeper(pub Child);


impl Drop for Sleeper {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            log::debug!("sleeper already gone: {:?}", error.kind());
        }
        if let Err(error) = self.0.wait() {
            log::debug!("sleeper not reaped: {:?}", error.kind());
        }
    }
}


pub fn sleeper() -> Result<Sleeper, Failure> {
    Ok(Sleeper(Command::new("sleep").arg(LONG_SLEEP).spawn()?))
}


pub fn leaf(procs: &str, threads: &str, events: &str) -> Result<TempDir, Failure> {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("cgroup.procs"), procs)?;
    fs::write(directory.path().join(THREADS_FILE), threads)?;
    fs::write(directory.path().join("cgroup.events"), events)?;
    fs::write(directory.path().join("cgroup.kill"), "")?;
    Ok(directory)
}


pub fn status(proc_root: &Path, id: i32, group: u32, uid: u32) -> TestResult {
    fs::create_dir_all(proc_root.join(id.to_string()))?;
    fs::write(
        proc_root.join(id.to_string()).join("status"),
        format!("Name:\tx\nTgid:\t{group}\nPid:\t{id}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
    )?;
    Ok(())
}


pub fn host_with(proc_root: &Path) -> KillHost {
    KillHost {
        pause: pause_briefly,
        proc_root: proc_root.to_path_buf(),
        rounds: ROUNDS,
        polls: POLLS,
    }
}


#[test]
fn an_empty_cgroup_is_killed_once_and_reports_success() -> TestResult {
    let directory = leaf("", "", "populated 0\n")?;
    let handle = File::open(directory.path())?;
    kill_leaf(&kill_host(), handle.as_fd(), RUN_UID)?;
    assert_eq!(fs::read_to_string(directory.path().join("cgroup.kill"))?, "1");
    Ok(())
}


#[test]
fn a_cgroup_that_never_empties_is_a_named_failure_after_the_capped_rounds() -> TestResult {
    let directory = leaf("", "", "populated 1\n")?;
    let handle = File::open(directory.path())?;
    let proc_root = tempfile::tempdir()?;
    let verdict = kill_leaf(&host_with(proc_root.path()), handle.as_fd(), RUN_UID);
    assert!(matches!(verdict, Err(ConnectorError::KillFailed)), "{verdict:?}");
    Ok(())
}


#[test]
fn a_group_listed_only_by_one_of_its_threads_is_killed_by_pidfd() -> TestResult {
    let victim = sleeper()?;
    let proc_root = tempfile::tempdir()?;
    status(proc_root.path(), STATUS_ID, victim.0.id(), RUN_UID)?;
    status(proc_root.path(), i32::try_from(victim.0.id())?, victim.0.id(), RUN_UID)?;
    let directory = leaf("", &format!("{STATUS_ID}\n"), "populated 0\n")?;
    let handle = File::open(directory.path())?;
    kill_leaf(&host_with(proc_root.path()), handle.as_fd(), RUN_UID)?;
    let mut waited = victim;
    let exit = waited.0.wait()?;
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&exit), Some(SIGKILL_CODE));
    Ok(())
}


#[test]
fn a_group_listed_by_cgroup_procs_is_killed_too_and_listed_twice_is_killed_once() -> TestResult {
    let victim = sleeper()?;
    let proc_root = tempfile::tempdir()?;
    let pid = i32::try_from(victim.0.id())?;
    status(proc_root.path(), pid, victim.0.id(), RUN_UID)?;
    status(proc_root.path(), STATUS_ID, victim.0.id(), RUN_UID)?;
    let directory = leaf(&format!("{pid}\n"), &format!("{pid}\n{STATUS_ID}\n"), "populated 0\n")?;
    let handle = File::open(directory.path())?;
    let groups = member_groups(&host_with(proc_root.path()), handle.as_fd(), RUN_UID)?;
    assert_eq!(groups, vec![pid]);
    kill_leaf(&host_with(proc_root.path()), handle.as_fd(), RUN_UID)?;
    let mut waited = victim;
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&waited.0.wait()?), Some(SIGKILL_CODE));
    Ok(())
}


#[test]
fn a_member_of_another_user_or_one_that_vanished_is_left_alone() -> TestResult {
    let bystander = sleeper()?;
    let proc_root = tempfile::tempdir()?;
    status(proc_root.path(), STATUS_ID, bystander.0.id(), OTHER_UID)?;
    let directory = leaf("", &format!("{STATUS_ID}\n{SECOND_ID}\n"), "populated 0\n")?;
    let handle = File::open(directory.path())?;
    kill_leaf(&host_with(proc_root.path()), handle.as_fd(), RUN_UID)?;
    let mut still = bystander;
    assert!(still.0.try_wait()?.is_none());
    Ok(())
}


#[test]
fn a_group_whose_own_owner_is_another_user_is_never_signalled() -> TestResult {
    let bystander = sleeper()?;
    let proc_root = tempfile::tempdir()?;
    status(proc_root.path(), STATUS_ID, bystander.0.id(), RUN_UID)?;
    status(proc_root.path(), i32::try_from(bystander.0.id())?, bystander.0.id(), OTHER_UID)?;
    let directory = leaf("", &format!("{STATUS_ID}\n"), "populated 0\n")?;
    let handle = File::open(directory.path())?;
    kill_leaf(&host_with(proc_root.path()), handle.as_fd(), RUN_UID)?;
    let mut still = bystander;
    assert!(still.0.try_wait()?.is_none());
    Ok(())
}


#[test]
fn a_member_group_whose_owner_cannot_be_read_fails_the_round() -> TestResult {
    let proc_root = tempfile::tempdir()?;
    let own_pid = i32::try_from(std::process::id())?;
    status(proc_root.path(), STATUS_ID, std::process::id(), RUN_UID)?;
    fs::create_dir_all(proc_root.path().join(own_pid.to_string()).join("status"))?;
    let directory = leaf("", &format!("{STATUS_ID}\n"), "populated 0\n")?;
    let verdict = kill_leaf(&host_with(proc_root.path()), File::open(directory.path())?.as_fd(), RUN_UID);
    assert!(matches!(verdict, Err(ConnectorError::Pipe(_))), "{verdict:?}");
    Ok(())
}


#[test]
fn unreadable_or_malformed_lists_are_errors_not_silence() -> TestResult {
    let proc_root = tempfile::tempdir()?;
    let host = host_with(proc_root.path());
    let bad = leaf("not-a-pid\n", "", "populated 0\n")?;
    assert!(matches!(
        kill_leaf(&host, File::open(bad.path())?.as_fd(), RUN_UID),
        Err(ConnectorError::Pipe(_))
    ));
    let no_events = leaf("", "", "nothing here\n")?;
    assert!(matches!(
        kill_leaf(&host, File::open(no_events.path())?.as_fd(), RUN_UID),
        Err(ConnectorError::Pipe(_))
    ));
    let missing = tempfile::tempdir()?;
    assert!(read_list(File::open(missing.path())?.as_fd(), "cgroup.procs").is_err());
    assert!(is_populated(File::open(missing.path())?.as_fd()).is_err());
    let invalid_utf8 = leaf("", "", "populated 0\n")?;
    fs::write(invalid_utf8.path().join("cgroup.procs"), NOT_UTF8)?;
    assert!(read_list(File::open(invalid_utf8.path())?.as_fd(), "cgroup.procs").is_err());
    let oversized = leaf("", "", "populated 0\n")?;
    fs::write(oversized.path().join("cgroup.procs"), vec![b'1'; usize::try_from(MAX_LIST_BYTES)? + 1])?;
    assert!(read_list(File::open(oversized.path())?.as_fd(), "cgroup.procs").is_err());
    let unlistable = leaf("", "", "populated 0\n")?;
    fs::write(unlistable.path().join("cgroup.procs"), "1\n".repeat(MAX_MEMBERS + 1))?;
    assert!(member_groups(&host, File::open(unlistable.path())?.as_fd(), RUN_UID).is_err());
    Ok(())
}


#[test]
fn a_status_that_cannot_be_read_is_an_error_but_a_missing_one_is_a_gone_process() -> TestResult {
    let proc_root = tempfile::tempdir()?;
    let host = host_with(proc_root.path());
    assert_eq!(group_of(&host, STATUS_ID, RUN_UID)?, None);
    fs::create_dir_all(proc_root.path().join(STATUS_ID.to_string()).join("status"))?;
    assert!(group_of(&host, STATUS_ID, RUN_UID).is_err());
    status(proc_root.path(), SECOND_ID, 1, RUN_UID)?;
    assert_eq!(group_of(&host, SECOND_ID, RUN_UID)?, Some(1));
    Ok(())
}


#[test]
fn the_helpers_parse_numbers_and_tolerate_only_a_gone_process() -> TestResult {
    assert_eq!(parse_ids("1\n 2 \n")?, vec![FIRST_ID, SECOND_LISTED]);
    assert!(parse_ids("1\nx\n").is_err());
    assert_eq!(parse_ids("")?, Vec::<i32>::new());
    assert_eq!(status_field("Tgid:\t5\nUid:\t9 9\n", "Uid:"), Some(UID_NINE));
    assert_eq!(status_field("Tgid:\tx\n", "Tgid:"), None);
    assert_eq!(status_field("", "Tgid:"), None);
    assert_eq!(tolerate_gone::<u8>(Err(io::Error::from(io::ErrorKind::NotFound)))?, 0);
    assert_eq!(
        tolerate_gone::<u8>(Err(io::Error::from_raw_os_error(rustix::io::Errno::SRCH.raw_os_error())))?,
        0
    );
    assert!(tolerate_gone::<u8>(Err(io::Error::from(io::ErrorKind::PermissionDenied))).is_err());
    assert_eq!(tolerate_gone::<u8>(Ok(1))?, 1);
    Ok(())
}


#[test]
fn a_pid_that_is_not_one_and_a_pid_that_is_gone_are_handled() -> TestResult {
    let proc_root = tempfile::tempdir()?;
    let host = host_with(proc_root.path());
    assert!(kill_group(&host, 0, RUN_UID).is_err());
    kill_group(&host, NO_SUCH_PID, RUN_UID)?;
    fs::create_dir_all(proc_root.path().join(NO_SUCH_PID.to_string()).join("status"))?;
    kill_group(&host, NO_SUCH_PID, RUN_UID)?;
    let own_pid = i32::try_from(std::process::id())?;
    fs::create_dir_all(proc_root.path().join(own_pid.to_string()).join("status"))?;
    assert!(kill_group(&host, own_pid, RUN_UID).is_err());
    let directory = leaf("", "", "populated 1\n")?;
    let real_host = host_with(Path::new("/proc"));
    assert!(wait_unpopulated(&real_host, File::open(directory.path())?.as_fd())?);
    Ok(())
}


#[test]
fn the_production_host_polls_the_real_proc_with_the_capped_rounds() -> TestResult {
    let host = system_kill_host();
    assert_eq!(host.proc_root, Path::new("/proc"));
    assert_eq!((host.rounds, host.polls), (KILL_ROUNDS, KILL_POLLS));
    let proc_root = tempfile::tempdir()?;
    fs::create_dir_all(proc_root.path().join(STATUS_ID.to_string()).join("status"))?;
    let directory = leaf("", &format!("{STATUS_ID}\n"), "populated 0\n")?;
    assert!(member_groups(&host_with(proc_root.path()), File::open(directory.path())?.as_fd(), RUN_UID).is_err());
    Ok(())
}
