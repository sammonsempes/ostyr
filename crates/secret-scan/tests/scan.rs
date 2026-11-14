#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::error::ReportError;
use secret_scan::model::{Limits, ScanScope};
use secret_scan::scan::{
    check_path, kill_all, never_expired, run_settings, scan_arguments, scan_directory, scan_with_ticks, RunSettings, ScanError, ScanTarget,
    MAX_PATH_BYTES,
};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use types::TestResult;


const MEMORY_BYTES: u64 = 8 << 30;


const FILE_BYTES: u64 = 8 << 30;


const POLL_MILLIS: u64 = 10;


const SHORT_TICKS: u64 = 3;


const LONG_TICKS: u64 = 100_000;


const TIMEOUT_SECONDS: u64 = 5;


const TOO_LONG_TIMEOUT: u64 = 3601;


const SAMPLE_FINDINGS: usize = 3;


const GONE_POLLS: u32 = 500;


const TINY_BYTES: usize = 16;


const FAILURE_CODE: i32 = 3;


const PRLIMIT: &str = "/usr/bin/prlimit";


const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gitleaks-report.json");


const TENANT: &str = "acme";


const SCOPE_ID: &str = "scope-1";


struct Env {
    root: TempDir,
    work: PathBuf,
    tree: PathBuf,
}


fn setup() -> Result<Env, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let work = root.path().join("work");
    let tree = root.path().join("tree");
    fs::create_dir(&work)?;
    fs::create_dir(&tree)?;
    Ok(Env { root, work, tree })
}


fn settings(env: &Env) -> RunSettings {
    run_settings(PathBuf::from(PRLIMIT), env.work.clone(), MEMORY_BYTES, FILE_BYTES, POLL_MILLIS)
}


fn script(env: &Env, name: &str, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let source = env.root.path().join(format!("{name}.src"));
    let program = env.root.path().join(name);
    fs::write(&source, format!("#!/bin/sh\n{body}\n"))?;
    let status = Command::new("install").arg("-m").arg("755").arg(&source).arg(&program).status()?;
    fs::remove_file(&source)?;
    assert!(status.success());
    Ok(program)
}


fn scan(env: &Env, program: &Path, ticks: u64, run: &RunSettings) -> Result<secret_scan::model::Report, ScanError> {
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    scan_with_ticks(program, &env.tree, &target, &Limits::default(), ticks, run)
}


fn work_is_empty(env: &Env) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(fs::read_dir(&env.work)?.next().is_none())
}


fn ready_marker(dir: &Path) -> bool {
    dir.join("ready").exists()
}


fn process_gone(pid: &str) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| stat.contains(") Z"))
}


fn wait_gone(pid: &str) -> bool {
    (0..GONE_POLLS).any(|_| {
        let gone = process_gone(pid);
        if !gone {
            std::thread::sleep(std::time::Duration::from_millis(POLL_MILLIS));
        }
        gone
    })
}


#[test]
fn arguments_are_exact() -> TestResult {
    let arguments = scan_arguments(Path::new("/srv/tree"), Path::new("/tmp/r/report.json"));
    let expected = [
        "dir",
        "/srv/tree",
        "--report-format",
        "json",
        "--report-path",
        "/tmp/r/report.json",
        "--no-banner",
        "--redact=0",
        "--exit-code",
        "0",
    ];
    assert_eq!(arguments, expected.iter().map(OsString::from).collect::<Vec<_>>());
    Ok(())
}


#[test]
fn refused_paths_never_spawn() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    let plain_file = env.root.path().join("plain");
    fs::write(&plain_file, b"x")?;
    let evil = env.tree.join("--config=evil.toml");
    fs::create_dir(&evil)?;
    let long = format!("/{}", "a".repeat(MAX_PATH_BYTES + 1));
    let refused = [
        PathBuf::from("relative/dir"),
        env.tree.join("..").join("tree"),
        evil,
        PathBuf::from("/-x"),
        PathBuf::from(long),
        plain_file,
        env.root.path().join("missing"),
    ];
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let run = settings(&env);
    refused.iter().try_for_each(|path| {
        let result = scan_with_ticks(&program, path, &target, &Limits::default(), LONG_TICKS, &run);
        if matches!(result, Err(ScanError::BadPath(_))) {
            Ok(())
        } else {
            Err(format!("not refused: {path:?}"))
        }
    })?;
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    assert!(check_path(&env.tree).is_ok());
    Ok(())
}


#[test]
fn relative_program_and_bad_timeouts_are_refused() -> TestResult {
    let env = setup()?;
    let run = settings(&env);
    assert!(matches!(scan(&env, Path::new("gitleaks"), SHORT_TICKS, &run), Err(ScanError::BadProgram)));
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let program = script(&env, "fake", "exit 0")?;
    [0, TOO_LONG_TIMEOUT].iter().try_for_each(|seconds| {
        let result = scan_directory(&program, &env.tree, &target, &Limits::default(), *seconds, &run);
        if matches!(result, Err(ScanError::BadTimeout)) {
            Ok(())
        } else {
            Err("timeout accepted")
        }
    })?;
    Ok(())
}


#[test]
fn success_round_trip_removes_the_directory() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", &format!("cp {FIXTURE} \"$6\""))?;
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let report = scan_directory(&program, &env.tree, &target, &Limits::default(), TIMEOUT_SECONDS, &settings(&env))?;
    assert_eq!(report.findings.len(), SAMPLE_FINDINGS);
    assert_eq!(report.tenant, TENANT);
    assert_eq!(report.scope_id, SCOPE_ID);
    assert!(work_is_empty(&env)?);
    assert!(!never_expired(&env.tree));
    Ok(())
}


#[test]
fn timeout_is_typed_never_parsed_and_cleans_up() -> TestResult {
    let env = setup()?;
    let pid_file = env.root.path().join("pid");
    let program = script(&env, "fake", &format!("cp {FIXTURE} \"$6\"\necho $$ > {}\nsleep 300", pid_file.display()))?;
    let result = scan(&env, &program, SHORT_TICKS, &settings(&env));
    assert!(matches!(result, Err(ScanError::TimedOut)));
    assert!(work_is_empty(&env)?);
    let pid = fs::read_to_string(&pid_file)?;
    assert!(wait_gone(pid.trim()));
    Ok(())
}


#[test]
fn grandchild_is_killed_with_the_group() -> TestResult {
    let env = setup()?;
    let pid_file = env.root.path().join("grandchild");
    let body = format!("sleep 300 &\necho $! > {}\n: > \"$HOME/ready\"\nwait", pid_file.display());
    let program = script(&env, "fake", &body)?;
    let run = RunSettings {
        expired: ready_marker,
        ..settings(&env)
    };
    let result = scan(&env, &program, LONG_TICKS, &run);
    assert!(matches!(result, Err(ScanError::TimedOut)));
    let pid = fs::read_to_string(&pid_file)?;
    assert!(wait_gone(pid.trim()));
    Ok(())
}


#[test]
fn failures_are_typed_without_parsing() -> TestResult {
    let env = setup()?;
    let run = settings(&env);
    let failing = script(&env, "failing", &format!("cp {FIXTURE} \"$6\"\nexit 3"))?;
    assert!(matches!(
        scan(&env, &failing, LONG_TICKS, &run),
        Err(ScanError::Failed(Some(FAILURE_CODE)))
    ));
    let limited = script(&env, "limited", "kill -XFSZ $$")?;
    assert!(matches!(scan(&env, &limited, LONG_TICKS, &run), Err(ScanError::ResourceLimit)));
    let killed = script(&env, "killed", "kill -KILL $$")?;
    assert!(matches!(scan(&env, &killed, LONG_TICKS, &run), Err(ScanError::Failed(None))));
    let missing = env.root.path().join("no-such-program");
    assert!(matches!(scan(&env, &missing, LONG_TICKS, &run), Err(ScanError::Failed(Some(_)))));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn unspawnable_launcher_is_io() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", "exit 0")?;
    let run = RunSettings {
        prlimit: env.root.path().join("no-prlimit"),
        ..settings(&env)
    };
    assert!(matches!(scan(&env, &program, LONG_TICKS, &run), Err(ScanError::Io(_))));
    let gone_work = RunSettings {
        work_dir: env.root.path().join("no-work"),
        ..settings(&env)
    };
    assert!(matches!(scan(&env, &program, LONG_TICKS, &gone_work), Err(ScanError::Io(_))));
    Ok(())
}


#[test]
fn report_that_is_a_symlink_is_refused() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", "ln -s /etc/passwd \"$6\"")?;
    assert!(matches!(scan(&env, &program, LONG_TICKS, &settings(&env)), Err(ScanError::Io(_))));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn report_that_is_a_fifo_is_refused_without_blocking() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", "mkfifo \"$6\"")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::ReportNotRegular)
    ));
    Ok(())
}


#[test]
fn report_of_another_owner_is_refused() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", &format!("cp {FIXTURE} \"$6\""))?;
    let run = settings(&env);
    let foreign = RunSettings {
        expected_uid: run.expected_uid.wrapping_add(1),
        ..run
    };
    assert!(matches!(scan(&env, &program, LONG_TICKS, &foreign), Err(ScanError::ReportForeign)));
    Ok(())
}


#[test]
fn missing_report_is_io() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", "exit 0")?;
    assert!(matches!(scan(&env, &program, LONG_TICKS, &settings(&env)), Err(ScanError::Io(_))));
    Ok(())
}


#[test]
fn sparse_report_over_the_cap_is_refused() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", "truncate -s 2G \"$6\"")?;
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let limits = Limits {
        max_bytes: TINY_BYTES,
        ..Limits::default()
    };
    let result = scan_with_ticks(&program, &env.tree, &target, &limits, LONG_TICKS, &settings(&env));
    assert!(matches!(result, Err(ScanError::Report(ReportError::TooLarge { max: TINY_BYTES }))));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn child_environment_is_cleared() -> TestResult {
    let env = setup()?;
    let out = env.root.path().join("env.txt");
    let program = script(&env, "fake", &format!("/usr/bin/env > {}\necho '[]' > \"$6\"", out.display()))?;
    scan(&env, &program, LONG_TICKS, &settings(&env))?;
    let text = fs::read_to_string(&out)?;
    let names: Vec<&str> = text.lines().filter_map(|line| line.split_once('=').map(|pair| pair.0)).collect();
    assert!(names.contains(&"HOME"));
    assert!(names.contains(&"TMPDIR"));
    assert!(!names.contains(&"PATH"));
    assert!(text.contains(&format!("HOME={}", env.work.display())));
    Ok(())
}


#[test]
fn kill_all_tolerates_a_child_that_has_no_group_of_its_own() -> TestResult {
    let mut child = Command::new("/usr/bin/sleep").arg("300").spawn()?;
    kill_all(rustix::process::Pid::from_child(&child))?;
    let status = child.wait()?;
    assert!(!status.success());
    Ok(())
}
