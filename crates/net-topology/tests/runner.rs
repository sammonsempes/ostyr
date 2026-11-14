#![cfg(unix)]
#[path = "common/fake.rs"]
mod fake;
#[path = "common/types.rs"]
mod types;


use fake::{install_script, is_gone, scratch};
use net_topology::model::RunFailure;
use net_topology::runner::{read_output, run_command, run_lldpcli, wait_polls, MAX_DEADLINE_SECONDS, WAIT_POLL_MILLIS};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use types::TestResult;


const LONG_DEADLINE_SECONDS: u64 = 120;


const LONG_DEADLINE_POLLS: usize = 12_001;


const TWO_POLLS: usize = 2;


const OLD_WAIT_CAP: usize = 6_200;


const MAX_DEADLINE_POLLS: usize = 360_001;


const PATIENT: Duration = Duration::from_secs(60);


const IMPATIENT: Duration = Duration::from_millis(300);


const CAP: u64 = 100;


const CAP_MINUS_ONE: u64 = 99;


const HUGE_CAP: u64 = 1_048_576;


const GONE_ATTEMPTS: usize = 100;


const GONE_POLL: Duration = Duration::from_millis(50);


const PARTIAL_BYTES: u64 = 8;


const EXIT_CODE: i32 = 3;


const CHILD_ENV: &str = "T420_CHILD";


const MEMORY_LIMIT: &str = "--as=419430400";


fn pid_in(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::fs::read_to_string(path)?.trim().parse::<u32>()?)
}


fn wait_gone(pid: u32) -> bool {
    (0..GONE_ATTEMPTS).any(|_| {
        let gone = is_gone(pid);
        if !gone {
            std::thread::sleep(GONE_POLL);
        }
        gone
    })
}


#[test]
fn the_argument_vector_is_exact() -> TestResult {
    let dir = scratch()?;
    let program = install_script(dir.path(), "lldpcli", r#"for a in "$@"; do echo "$a"; done"#)?;
    let output = run_lldpcli(&program, "vx0", HUGE_CAP, PATIENT).map_err(|failure| format!("{failure:?}"))?;
    assert_eq!(String::from_utf8(output)?, "-f\njson0\nshow\nneighbors\nports\nvx0\ndetails\n");
    Ok(())
}


#[test]
fn output_at_the_cap_is_accepted_and_one_more_is_too_large() -> TestResult {
    let dir = scratch()?;
    let program = install_script(dir.path(), "lldpcli", "head -c 100 /dev/zero")?;
    let exact = run_command(&program, &[], CAP, PATIENT);
    assert_eq!(exact.map(|bytes| bytes.len()), Ok(usize::try_from(CAP)?));
    assert_eq!(run_command(&program, &[], CAP_MINUS_ONE, PATIENT), Err(RunFailure::TooLarge));
    Ok(())
}


#[test]
fn a_sleeping_child_times_out_and_is_killed() -> TestResult {
    let dir = scratch()?;
    let pid_file = dir.path().join("pid");
    let program = install_script(dir.path(), "lldpcli", &format!("echo $$ > {}\nexec sleep 60", pid_file.display()))?;
    assert_eq!(run_command(&program, &[], CAP, IMPATIENT), Err(RunFailure::TimedOut));
    assert!(wait_gone(pid_in(&pid_file)?));
    Ok(())
}


#[test]
fn a_grandchild_holding_stdout_times_out_and_the_group_is_killed() -> TestResult {
    let dir = scratch()?;
    let pid_file = dir.path().join("pid");
    let program = install_script(dir.path(), "lldpcli", &format!("sleep 60 &\necho $! > {}\nexit 0", pid_file.display()))?;
    assert_eq!(run_command(&program, &[], CAP, IMPATIENT), Err(RunFailure::TimedOut));
    assert!(wait_gone(pid_in(&pid_file)?));
    Ok(())
}


#[test]
fn a_child_that_closes_stdout_and_keeps_running_times_out() -> TestResult {
    let dir = scratch()?;
    let pid_file = dir.path().join("pid");
    let body = format!("echo $$ > {}\necho hi\nexec >&-\nexec sleep 60", pid_file.display());
    let program = install_script(dir.path(), "lldpcli", &body)?;
    assert_eq!(run_command(&program, &[], CAP, IMPATIENT), Err(RunFailure::TimedOut));
    assert!(wait_gone(pid_in(&pid_file)?));
    Ok(())
}


#[test]
fn a_same_group_grandchild_does_not_survive_a_normal_exit() -> TestResult {
    let dir = scratch()?;
    let pid_file = dir.path().join("pid");
    let body = format!("sleep 4242 >/dev/null 2>&1 &\necho $! > {}\necho done", pid_file.display());
    let program = install_script(dir.path(), "lldpcli", &body)?;
    let output = run_command(&program, &[], CAP, PATIENT).map_err(|failure| format!("{failure:?}"))?;
    assert_eq!(output, b"done\n");
    assert!(wait_gone(pid_in(&pid_file)?));
    Ok(())
}


#[test]
fn the_wait_cap_follows_the_deadline() -> TestResult {
    assert_eq!(wait_polls(Duration::ZERO), 1);
    assert_eq!(wait_polls(Duration::from_millis(WAIT_POLL_MILLIS)), TWO_POLLS);
    assert_eq!(wait_polls(Duration::from_secs(LONG_DEADLINE_SECONDS)), LONG_DEADLINE_POLLS);
    assert!(wait_polls(Duration::from_secs(LONG_DEADLINE_SECONDS)) > OLD_WAIT_CAP);
    assert_eq!(wait_polls(Duration::from_secs(MAX_DEADLINE_SECONDS)), MAX_DEADLINE_POLLS);
    assert_eq!(
        wait_polls(Duration::from_secs(MAX_DEADLINE_SECONDS + MAX_DEADLINE_SECONDS)),
        MAX_DEADLINE_POLLS
    );
    Ok(())
}


#[test]
fn an_expired_deadline_stops_the_read_even_with_data_in_the_pipe() -> TestResult {
    let (mut reader, mut writer) = std::io::pipe()?;
    writer.write_all(b"data that is already there")?;
    assert_eq!(read_output(&mut reader, HUGE_CAP, Instant::now()), Err(RunFailure::TimedOut));
    drop(writer);
    let (mut open_reader, mut open_writer) = std::io::pipe()?;
    open_writer.write_all(b"fine")?;
    drop(open_writer);
    assert_eq!(read_output(&mut open_reader, HUGE_CAP, Instant::now() + PATIENT), Ok(b"fine".to_vec()));
    Ok(())
}


#[test]
fn a_non_zero_exit_is_failed_with_the_bytes_read() -> TestResult {
    let dir = scratch()?;
    let program = install_script(dir.path(), "lldpcli", "echo partial\nexit 3")?;
    assert_eq!(
        run_command(&program, &[], CAP, PATIENT),
        Err(RunFailure::Failed {
            code: Some(EXIT_CODE),
            read: PARTIAL_BYTES
        })
    );
    let killed = install_script(dir.path(), "killed", "kill -9 $$")?;
    assert_eq!(run_command(&killed, &[], CAP, PATIENT), Err(RunFailure::Failed { code: None, read: 0 }));
    Ok(())
}


#[test]
fn the_environment_is_cleared() -> TestResult {
    let dir = scratch()?;
    let program = install_script(dir.path(), "lldpcli", "/usr/bin/env")?;
    let output = String::from_utf8(run_command(&program, &[], HUGE_CAP, PATIENT).map_err(|failure| format!("{failure:?}"))?)?;
    assert!(std::env::var("HOME").is_ok());
    assert!(!output.contains("HOME="), "{output}");
    assert!(!output.contains("CARGO"), "{output}");
    Ok(())
}


#[test]
fn a_missing_or_non_executable_program_is_a_spawn_failure() -> TestResult {
    let dir = scratch()?;
    assert_eq!(run_command(&dir.path().join("absent"), &[], CAP, PATIENT), Err(RunFailure::Spawn));
    std::fs::write(dir.path().join("plain"), "x")?;
    assert_eq!(run_command(&dir.path().join("plain"), &[], CAP, PATIENT), Err(RunFailure::Spawn));
    Ok(())
}


#[test]
fn a_port_outside_the_grammar_is_never_spawned() -> TestResult {
    let dir = scratch()?;
    let marker = dir.path().join("spawned");
    let program = install_script(dir.path(), "lldpcli", &format!("echo x > {}", marker.display()))?;
    ["-help", "a,vx0", "", "--help", "a b", ".."]
        .iter()
        .for_each(|port| assert_eq!(run_lldpcli(&program, port, CAP, PATIENT), Err(RunFailure::Refused), "{port:?}"));
    assert!(!marker.exists());
    Ok(())
}


#[test]
fn an_io_error_is_the_io_category() -> TestResult {
    assert_eq!(RunFailure::from(std::io::Error::other("injected")), RunFailure::Io);
    Ok(())
}


fn rerun(test: &str, limit: Option<&str>) -> TestResult {
    let exe = std::env::current_exe()?;
    let mut command = match limit {
        Some(value) => {
            let mut wrapped = Command::new("prlimit");
            wrapped.arg(value).arg("--").arg(exe);
            wrapped
        }
        None => Command::new(exe),
    };
    let output = command.args(["--exact", test, "--test-threads=1"]).env(CHILD_ENV, "1").output()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{text}");
    assert!(text.contains("1 passed"), "the child test did not run: {text}");
    Ok(())
}


fn two_gibibytes_are_cut_at_the_cap() -> TestResult {
    let dir = scratch()?;
    let program = install_script(dir.path(), "lldpcli", "head -c 2147483648 /dev/zero")?;
    assert_eq!(run_command(&program, &[], HUGE_CAP, PATIENT), Err(RunFailure::TooLarge));
    Ok(())
}


#[test]
fn child_two_gibibytes() -> TestResult {
    std::env::var(CHILD_ENV).map_or(Ok(()), |_marker| two_gibibytes_are_cut_at_the_cap())
}


#[test]
fn two_gibibytes_of_output_stay_flat_under_an_address_space_limit() -> TestResult {
    rerun("child_two_gibibytes", Some(MEMORY_LIMIT))
}


fn thread_count() -> Result<usize, Box<dyn std::error::Error>> {
    Ok(std::fs::read_dir("/proc/self/task")?.count())
}


fn no_thread_survives_a_setsid_holder() -> TestResult {
    let dir = scratch()?;
    let program = install_script(dir.path(), "lldpcli", "setsid sleep 2 &\nexit 0")?;
    let before = thread_count()?;
    assert_eq!(run_command(&program, &[], CAP, IMPATIENT), Err(RunFailure::TimedOut));
    assert_eq!(thread_count()?, before);
    Ok(())
}


#[test]
fn child_threads() -> TestResult {
    std::env::var(CHILD_ENV).map_or(Ok(()), |_marker| no_thread_survives_a_setsid_holder())
}


#[test]
fn a_setsid_holder_of_the_pipe_leaves_no_helper_thread() -> TestResult {
    rerun("child_threads", None)
}
