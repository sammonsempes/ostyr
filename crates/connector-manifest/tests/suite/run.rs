use crate::common::types::Failure;
use crate::common::types::TestResult;
use crate::support::{
    checked, dropping_launcher, fixture, host, leftovers, long_deadline, own_cgroup_root, params, plain_launcher, processes_with, python_fixture,
    runner_uid, short_deadline, spec, system_programs, tiny_elf, RUN_GID, RUN_UID,
};
use connector_manifest::error::ConnectorError;
use connector_manifest::reply::Reply;
use connector_manifest::run::{run_connector, spawn_piped, RunHost, RunOutcome, MAX_REQUEST_BYTES};
use script_library::cgroup::{CgroupOps, SYSTEM_CGROUP};
use script_library::error::ScriptError;
use script_library::model::{Limits, RunAs};
use std::fs;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;


const ECHO: &str = r#"
import json, os, sys
request = json.loads(sys.stdin.readline())
here = os.path.dirname(os.path.abspath(__file__))
print(json.dumps({"status": "ok", "result": {"action": request["action"], "params": request["params"], "isolated": sys.flags.isolated, "path": sys.path, "here": here, "uid": os.getuid()}}, separators=(",", ":")))
"#;


const ERROR_REPLY: &str = r#"print('{"status": "error", "error": "not-found"}')"#;


const EXIT_THREE: &str = "import sys\nsys.exit(3)";


const KILL_SELF: &str = "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)";


const SLEEPER: &str = "import time\ntime.sleep(3600)";


const FLOOD: &str = "import sys\nchunk = b'x' * 65536\nwhile True:\n    sys.stdout.buffer.write(chunk)\n    sys.stdout.buffer.flush()";


const STDERR_ECHO: &str = r#"
import sys
sys.stderr.write("CREDENTIAL-MARKER-7731 " * 3000)
sys.stderr.flush()
print('{"status": "ok", "result": 1}')
"#;


const MANY_ELEMENTS: &str = r#"
print('{"status": "ok", "result": [' + '0,' * 400000 + '0]}')
"#;


const TOO_BIG_REPLY: &str = r#"
print('{"status": "ok", "result": "' + 'a' * 1100000 + '"}')
"#;


const DOUBLE_FORK: &str = r#"
import os, sys
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        os.execv("/bin/sleep", ["sleep", "MARKER"])
    os._exit(0)
os.wait()
sys.exit(0)
"#;


const ZOMBIE_LEADER: &str = r#"
import ctypes, threading, time
def keep():
    time.sleep(3600)
threading.Thread(target=keep, daemon=True).start()
ctypes.CDLL(None).pthread_exit(None)
"#;


const GRANDCHILD_HOLDS_STDOUT: &str = r#"
import os, sys
if os.fork() == 0:
    os.execv("/bin/sleep", ["sleep", "MARKER"])
print('{"status": "ok", "result": 1}')
sys.stdout.flush()
sys.exit(0)
"#;


const NEVER_READS_STDIN: &str = "import time\ntime.sleep(3600)";


const NO_ENVIRONMENT: &str = r#"
import json, os
print(json.dumps({"status": "ok", "result": {"env": dict(os.environ)}}, separators=(",", ":")))
"#;


const BIG_PARAMS_BYTES: usize = 300_000;


const EXIT_THREE_CODE: i32 = 3;


const LOOSE_MODE: u32 = 0o775;


const WORLD_WRITABLE: u32 = 0o777;


fn cgroup_children(path: &Path) -> Result<usize, Failure> {
    Ok(fs::read_dir(path)?.flatten().filter(|entry| entry.path().is_dir()).count())
}


fn run_python(code: &str, params_text: &str, deadline: Duration) -> Result<Result<RunOutcome, ConnectorError>, Failure> {
    let fixture = python_fixture(code)?;
    let parent = own_cgroup_root()?;
    let value = params(params_text)?;
    let result = run_connector(&spec(&fixture, &parent.path, deadline, &value), &host());
    assert_eq!(leftovers(fixture.code_root.path())?, 0, "the private copy must vanish");
    assert_eq!(cgroup_children(&parent.path)?, 0, "the run cgroup must vanish");
    Ok(result)
}


fn result_text(outcome: &RunOutcome) -> Result<String, Failure> {
    match &outcome.reply {
        Reply::Success { result: Some(value) } => Ok(value.get().to_owned()),
        other => Err(format!("not a success with a result: {other:?}").into()),
    }
}


#[test]
fn a_python_connector_answers_in_isolated_mode_as_the_run_user_from_the_private_copy() -> TestResult {
    let fixture = python_fixture(ECHO)?;
    let parent = own_cgroup_root()?;
    let value = params(r#"{"name":"nginx"}"#)?;
    let outcome = run_connector(&spec(&fixture, &parent.path, long_deadline(), &value), &host())?;
    let text = result_text(&outcome)?;
    assert!(text.contains(r#""action":"restart-service""#), "{text}");
    assert!(text.contains(r#""params":{"name":"nginx"}"#), "{text}");
    assert!(text.contains(r#""isolated":1"#), "{text}");
    assert!(text.contains(&format!(r#""uid":{RUN_UID}"#)), "{text}");
    let here = text
        .split(r#""here":""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("no here")?;
    assert!(
        here.starts_with(&fixture.code_root.path().display().to_string()),
        "the connector ran outside the private copy: {here}"
    );
    assert!(
        !here.starts_with(&fixture.package.path().display().to_string()),
        "the connector ran from the package: {here}"
    );
    assert_eq!(text.matches(here).count(), 1, "the code directory is on sys.path: {text}");
    assert_eq!(outcome.stderr.bytes, 0);
    Ok(())
}


#[test]
fn the_connector_gets_an_empty_environment() -> TestResult {
    let text = result_text(&run_python(NO_ENVIRONMENT, "null", long_deadline())??)?;
    assert!(text.contains(r#""env":{"#), "{text}");
    assert!(!text.contains("PATH"), "{text}");
    Ok(())
}


#[test]
fn a_native_static_connector_runs_by_path() -> TestResult {
    let reply = br#"{"status":"ok","result":"native"}"#;
    let fixture = fixture("connector", "native", &tiny_elf(reply))?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    let outcome = run_connector(&spec(&fixture, &parent.path, long_deadline(), &value), &host())?;
    assert_eq!(result_text(&outcome)?, r#""native""#);
    Ok(())
}


#[test]
fn an_error_reply_is_a_failure_with_its_code() -> TestResult {
    let outcome = run_python(ERROR_REPLY, "{}", long_deadline())??;
    assert!(matches!(&outcome.reply, Reply::Failure { code } if code == "not-found"));
    Ok(())
}


#[test]
fn a_non_zero_exit_and_a_death_by_signal_refuse_the_reply() -> TestResult {
    assert!(matches!(
        run_python(EXIT_THREE, "{}", long_deadline())?,
        Err(ConnectorError::RunFailed { code: Some(EXIT_THREE_CODE) })
    ));
    assert!(matches!(
        run_python(KILL_SELF, "{}", long_deadline())?,
        Err(ConnectorError::RunFailed { code: None })
    ));
    Ok(())
}


#[test]
fn a_connector_that_runs_past_the_deadline_is_killed() -> TestResult {
    assert!(matches!(run_python(SLEEPER, "{}", short_deadline())?, Err(ConnectorError::RunTimeout)));
    Ok(())
}


#[test]
fn a_connector_that_never_reads_a_large_request_cannot_stall_the_runner() -> TestResult {
    let big = format!(r#""{}""#, "a".repeat(BIG_PARAMS_BYTES));
    assert!(matches!(
        run_python(NEVER_READS_STDIN, &big, short_deadline())?,
        Err(ConnectorError::RunTimeout)
    ));
    Ok(())
}


#[test]
fn a_flood_on_stdout_is_cut_at_the_cap_and_killed_at_once() -> TestResult {
    assert!(matches!(
        run_python(FLOOD, "{}", long_deadline())?,
        Err(ConnectorError::ReplyTooLarge { .. })
    ));
    assert!(matches!(
        run_python(TOO_BIG_REPLY, "{}", long_deadline())?,
        Err(ConnectorError::ReplyTooLarge { .. })
    ));
    Ok(())
}


#[test]
fn a_reply_with_too_many_elements_under_the_byte_cap_is_refused_whole() -> TestResult {
    assert!(matches!(
        run_python(MANY_ELEMENTS, "{}", long_deadline())?,
        Err(ConnectorError::ReplyBound { bound: "elements" })
    ));
    Ok(())
}


#[test]
fn stderr_is_counted_and_dropped_and_never_reaches_a_value_or_an_error() -> TestResult {
    let outcome = run_python(STDERR_ECHO, "{}", long_deadline())??;
    assert!(outcome.stderr.bytes > 0 && outcome.stderr.cut);
    assert!(!format!("{outcome:?}").contains("CREDENTIAL-MARKER"));
    Ok(())
}


#[test]
fn a_setsid_double_fork_grandchild_is_killed_after_the_main_process_exits() -> TestResult {
    let marker = format!("{}.25", std::process::id());
    let outcome = run_python(&DOUBLE_FORK.replace("MARKER", &marker), "{}", short_deadline())?;
    assert!(
        matches!(
            outcome,
            Err(ConnectorError::RunFailed { .. } | ConnectorError::MalformedReply | ConnectorError::RunTimeout)
        ),
        "{outcome:?}"
    );
    assert_eq!(processes_with(&marker)?, 0, "the grandchild survived");
    Ok(())
}


#[test]
fn a_grandchild_holding_stdout_cannot_hold_the_run_past_the_deadline() -> TestResult {
    let marker = format!("{}.75", std::process::id());
    let outcome = run_python(&GRANDCHILD_HOLDS_STDOUT.replace("MARKER", &marker), "{}", short_deadline())?;
    assert!(matches!(outcome, Err(ConnectorError::RunTimeout)), "{outcome:?}");
    assert_eq!(processes_with(&marker)?, 0, "the grandchild survived");
    Ok(())
}


#[test]
fn a_zombie_leader_with_a_live_thread_is_killed_at_the_deadline() -> TestResult {
    assert!(matches!(
        run_python(ZOMBIE_LEADER, "{}", short_deadline())?,
        Err(ConnectorError::RunTimeout)
    ));
    Ok(())
}


fn fail_place(_leaf: BorrowedFd<'_>, _pid: u32) -> io::Result<()> {
    Err(io::Error::other("injected placement failure"))
}


fn fail_limit(_leaf: BorrowedFd<'_>, _limits: &Limits) -> io::Result<()> {
    Err(io::Error::other("injected limit failure"))
}


fn spawn_failure(_command: &mut Command) -> io::Result<Child> {
    Err(io::Error::from(io::ErrorKind::NotFound))
}


fn spawn_without_pipes(command: &mut Command) -> io::Result<Child> {
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
}


fn refused_with(changed: RunHost, code: &str) -> Result<ConnectorError, Failure> {
    let fixture = python_fixture(code)?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    let result = run_connector(&spec(&fixture, &parent.path, long_deadline(), &value), &changed);
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    assert_eq!(cgroup_children(&parent.path)?, 0);
    result.err().ok_or_else(|| "the run was not refused".into())
}


#[test]
fn a_failed_placement_never_releases_the_gate_and_nothing_is_left() -> TestResult {
    let marker = tempfile::tempdir()?;
    let code = format!("open({:?}, 'w').write('ran')", marker.path().join("ran"));
    let error = refused_with(
        RunHost {
            cgroup: CgroupOps {
                place: fail_place,
                ..SYSTEM_CGROUP
            },
            ..host()
        },
        &code,
    )?;
    assert!(matches!(error, ConnectorError::Pipe(_)), "{error:?}");
    assert!(!marker.path().join("ran").exists());
    Ok(())
}


#[test]
fn a_failed_limit_write_stops_the_run_before_it_starts() -> TestResult {
    let error = refused_with(
        RunHost {
            cgroup: CgroupOps {
                limit: fail_limit,
                ..SYSTEM_CGROUP
            },
            ..host()
        },
        ECHO,
    )?;
    assert!(matches!(error, ConnectorError::Pipe(_)), "{error:?}");
    Ok(())
}


#[test]
fn a_spawn_failure_and_a_child_without_pipes_are_named() -> TestResult {
    let refused = refused_with(
        RunHost {
            spawn: spawn_failure,
            ..host()
        },
        ECHO,
    )?;
    assert!(matches!(refused, ConnectorError::Launch(_)), "{refused:?}");
    let piped = refused_with(
        RunHost {
            spawn: spawn_without_pipes,
            ..host()
        },
        SLEEPER,
    )?;
    assert!(matches!(piped, ConnectorError::Pipe(_)), "{piped:?}");
    Ok(())
}


#[test]
fn a_cgroup_root_that_is_not_cgroup_v2_runs_nothing() -> TestResult {
    let fixture = python_fixture(ECHO)?;
    let plain = tempfile::tempdir()?;
    let value = params("{}")?;
    let verdict = run_connector(&spec(&fixture, plain.path(), long_deadline(), &value), &host());
    assert!(matches!(verdict, Err(ConnectorError::Script(ScriptError::NotCgroupV2))), "{verdict:?}");
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    Ok(())
}


#[test]
fn the_run_user_is_never_root_nor_the_callers_own_ids() -> TestResult {
    let fixture = python_fixture(ECHO)?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    let refused = [
        RunAs { uid: 0, gid: RUN_GID },
        RunAs { uid: RUN_UID, gid: 0 },
        RunAs {
            uid: runner_uid(),
            gid: RUN_GID,
        },
    ];
    refused.iter().try_for_each(|user| {
        let mut request = spec(&fixture, &parent.path, long_deadline(), &value);
        request.run_as = *user;
        match run_connector(&request, &host()) {
            Err(ConnectorError::Script(ScriptError::InvalidRunAs)) => Ok(()),
            other => Err(format!("{user:?}: {other:?}")),
        }
    })?;
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    Ok(())
}


#[test]
fn an_unknown_action_and_an_oversized_request_are_refused_before_anything_is_copied() -> TestResult {
    let fixture = python_fixture(ECHO)?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    let mut request = spec(&fixture, &parent.path, long_deadline(), &value);
    request.action = "nope";
    assert!(matches!(run_connector(&request, &host()), Err(ConnectorError::UnknownAction { action }) if action == "nope"));
    let big = params(&format!(r#""{}""#, "a".repeat(MAX_REQUEST_BYTES)))?;
    let oversized = spec(&fixture, &parent.path, long_deadline(), &big);
    assert!(matches!(run_connector(&oversized, &host()), Err(ConnectorError::RequestTooLarge { .. })));
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    Ok(())
}


#[test]
fn a_program_that_the_runner_does_not_trust_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let loose = directory.path().join("python3");
    fs::copy("/usr/bin/python3", &loose)?;
    fs::set_permissions(&loose, std::os::unix::fs::PermissionsExt::from_mode(LOOSE_MODE))?;
    assert!(matches!(checked(&loose), Err(ConnectorError::Invalid { field: "program" })));
    let device = Path::new("/dev/null");
    assert!(matches!(checked(device), Err(ConnectorError::Invalid { field: "program" })));
    assert!(matches!(checked(Path::new("/")), Err(ConnectorError::Invalid { field: "program" })));
    assert!(matches!(checked(&directory.path().join("absent")), Err(ConnectorError::Io { .. })));
    checked(Path::new("/bin/sh"))?;
    let fixture = python_fixture(ECHO)?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    let mut changed = host();
    changed.programs.python = PathBuf::from(&loose);
    let verdict = run_connector(&spec(&fixture, &parent.path, long_deadline(), &value), &changed);
    assert!(matches!(verdict, Err(ConnectorError::Invalid { field: "program" })), "{verdict:?}");
    assert_eq!(leftovers(fixture.code_root.path())?, 0);
    let mut native_host = host();
    native_host.programs.python = PathBuf::from(&loose);
    let native = fixture_native()?;
    run_connector(&spec(&native, &parent.path, long_deadline(), &value), &native_host)?;
    Ok(())
}


fn fixture_native() -> Result<crate::support::Fixture, Failure> {
    fixture("connector", "native", &tiny_elf(br#"{"status":"ok","result":1}"#))
}


#[test]
fn the_launcher_and_the_spawner_are_the_injected_ones() -> TestResult {
    let native = fixture_native()?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    let plain = RunHost {
        launch: plain_launcher,
        spawn: spawn_piped,
        ..host()
    };
    let outcome = run_connector(&spec(&native, &parent.path, long_deadline(), &value), &plain)?;
    assert_eq!(result_text(&outcome)?, "1");
    let again = run_connector(
        &spec(&native, &parent.path, long_deadline(), &value),
        &RunHost {
            launch: dropping_launcher,
            ..host()
        },
    )?;
    assert_eq!(result_text(&again)?, "1");
    assert!(system_programs().shell.ends_with("sh"));
    Ok(())
}


#[test]
fn a_package_changed_after_verification_never_runs_and_a_cgroup_that_cannot_be_emptied_is_named() -> TestResult {
    let fixture = python_fixture(ECHO)?;
    let parent = own_cgroup_root()?;
    let value = params("{}")?;
    fs::write(fixture.package.path().join("main.py"), "print('changed')")?;
    let changed = run_connector(&spec(&fixture, &parent.path, long_deadline(), &value), &host());
    assert!(matches!(changed, Err(ConnectorError::FileChanged { .. })), "{changed:?}");
    assert_eq!(cgroup_children(&parent.path)?, 0);
    let clean = python_fixture(ECHO)?;
    let mut stuck = host();
    stuck.kill.rounds = 0;
    let verdict = run_connector(&spec(&clean, &parent.path, long_deadline(), &value), &stuck);
    assert!(matches!(verdict, Err(ConnectorError::KillFailed)), "{verdict:?}");
    Ok(())
}


#[test]
fn a_program_in_a_directory_others_can_write_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), std::os::unix::fs::PermissionsExt::from_mode(WORLD_WRITABLE))?;
    let program = directory.path().join("tool");
    fs::write(&program, "x")?;
    assert!(matches!(checked(&program), Err(ConnectorError::WorkDir(_))));
    Ok(())
}


#[test]
fn a_program_owned_by_another_user_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let program = directory.path().join("tool");
    fs::write(&program, "x")?;
    std::os::unix::fs::chown(&program, Some(RUN_UID), None)?;
    assert!(matches!(checked(&program), Err(ConnectorError::Invalid { field: "program" })));
    Ok(())
}
