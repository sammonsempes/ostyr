#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::error::ReportError;
use secret_scan::model::{Limits, ScanScope};
use secret_scan::scan::{
    check_no_ignore_file, check_path, check_rules, copy_git_config, find_git_configs, kill_all, never_expired, original_of, run_settings,
    scan_arguments, scan_directory, scan_with_ticks, stage_git_configs, RunSettings, ScanError, ScanTarget, MAX_GIT_CONFIG_BYTES, MAX_PATH_BYTES,
};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use types::TestResult;


const MEMORY_BYTES: u64 = 8 << 30;


const FILE_BYTES: u64 = 8 << 30;


const POLL_MILLIS: u64 = 10;


const LONG_TICKS: u64 = 100_000;


const TIMEOUT_SECONDS: u64 = 3600;


const TOO_LONG_TIMEOUT: u64 = 3601;


const SAMPLE_FINDINGS: usize = 3;


const BOTH_FINDINGS: usize = 6;


const STAGED_FINDINGS: usize = 4;


const GONE_POLLS: u32 = 6000;


const POLL_ABOVE_RANGE: u64 = 1001;


const TINY_BYTES: usize = 16;


const FAILURE_CODE: i32 = 3;


const PRIVATE_MODE: u32 = 0o644;


const GROUP_WRITABLE_MODE: u32 = 0o664;


const PRLIMIT: &str = "/usr/bin/prlimit";


const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gitleaks-report.json");


const TENANT: &str = "acme";


const SCOPE_ID: &str = "scope-1";


struct Env {
    root: TempDir,
    work: PathBuf,
    tree: PathBuf,
    rules: PathBuf,
}


fn setup() -> Result<Env, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let work = root.path().join("work");
    let tree = root.path().join("tree");
    let rules = root.path().join("rules.toml");
    fs::create_dir(&work)?;
    fs::create_dir(&tree)?;
    fs::write(&rules, b"title = \"rules\"\n")?;
    fs::set_permissions(&rules, fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(Env { root, work, tree, rules })
}


fn settings(env: &Env) -> RunSettings {
    run_settings(
        PathBuf::from(PRLIMIT),
        env.rules.clone(),
        env.work.clone(),
        MEMORY_BYTES,
        FILE_BYTES,
        POLL_MILLIS,
    )
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
    let arguments = scan_arguments(
        Path::new("/srv/tree"),
        Path::new("/tmp/r/report.json"),
        Path::new("/etc/ostyr/rules.toml"),
        Path::new("/tmp/r/ignore"),
    );
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
        "--config",
        "/etc/ostyr/rules.toml",
        "--gitleaks-ignore-path",
        "/tmp/r/ignore",
        "--ignore-gitleaks-allow",
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
    assert!(matches!(scan(&env, Path::new("gitleaks"), LONG_TICKS, &run), Err(ScanError::BadProgram)));
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
    let program = script(
        &env,
        "fake",
        &format!("cp {FIXTURE} \"$6\"\necho $$ > {}\n: > \"$HOME/ready\"\nsleep 300", pid_file.display()),
    )?;
    let run = RunSettings {
        expired: ready_marker,
        ..settings(&env)
    };
    let result = scan(&env, &program, LONG_TICKS, &run);
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


#[test]
fn child_gets_the_callers_rules_an_empty_ignore_file_and_its_own_directory() -> TestResult {
    let env = setup()?;
    let body = format!(
        "[ \"${{12}}\" = \"{}\" ] || exit 11\n[ \"${{13}}\" = --gitleaks-ignore-path ] || exit 12\n[ -f \"${{14}}\" ] && [ ! -s \"${{14}}\" ] || exit 13\n\
         [ \"${{15}}\" = --ignore-gitleaks-allow ] || exit 14\n[ \"$(pwd)\" = \"$HOME\" ] || exit 15\ncp {FIXTURE} \"$6\"",
        env.rules.display()
    );
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert_eq!(report.findings.len(), SAMPLE_FINDINGS);
    Ok(())
}


#[test]
fn bad_rules_files_are_refused_before_any_directory() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    let run = settings(&env);
    let writable = env.root.path().join("writable.toml");
    fs::write(&writable, b"x")?;
    fs::set_permissions(&writable, fs::Permissions::from_mode(GROUP_WRITABLE_MODE))?;
    let link = env.root.path().join("link.toml");
    symlink(&env.rules, &link)?;
    let cases = [
        (PathBuf::from("rules.toml"), "not absolute"),
        (env.tree.clone(), "not a regular file"),
        (writable, "writable by group or others"),
    ];
    cases.iter().try_for_each(|(rules, reason)| {
        let refused = RunSettings {
            rules: rules.clone(),
            ..settings(&env)
        };
        if matches!(scan(&env, &program, LONG_TICKS, &refused), Err(ScanError::BadRules(found)) if found == *reason) {
            Ok(())
        } else {
            Err(format!("not refused: {rules:?}"))
        }
    })?;
    [link, env.root.path().join("missing.toml")].iter().try_for_each(|rules| {
        let refused = RunSettings {
            rules: rules.clone(),
            ..settings(&env)
        };
        if matches!(scan(&env, &program, LONG_TICKS, &refused), Err(ScanError::Io(_))) {
            Ok(())
        } else {
            Err(format!("not refused: {rules:?}"))
        }
    })?;
    let run_foreign = RunSettings {
        rules_uid: run.rules_uid.wrapping_add(1),
        ..settings(&env)
    };
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &run_foreign),
        Err(ScanError::BadRules("not owned by the caller"))
    ));
    assert!(check_rules(&env.rules, run.rules_uid).is_ok());
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_tree_with_an_ignore_file_is_refused_before_spawning() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    fs::write(env.tree.join(".gitleaksignore"), b"x:y:1\n")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::IgnoreFileInTree)
    ));
    fs::remove_file(env.tree.join(".gitleaksignore"))?;
    symlink("/etc/passwd", env.tree.join(".gitleaksignore"))?;
    assert!(matches!(check_no_ignore_file(&env.tree), Err(ScanError::IgnoreFileInTree)));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn an_ignore_file_appearing_during_the_run_discards_the_report() -> TestResult {
    let env = setup()?;
    let body = format!("cp {FIXTURE} \"$6\"\n: > {}/.gitleaksignore", env.tree.display());
    let program = script(&env, "fake", &body)?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::IgnoreFileInTree)
    ));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn an_unreadable_tree_root_is_io() -> TestResult {
    assert!(matches!(check_no_ignore_file(Path::new("/dev/null")), Err(ScanError::Io(_))));
    Ok(())
}


#[test]
fn bad_run_settings_are_refused_before_any_directory() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    let relative_launcher = RunSettings {
        prlimit: PathBuf::from("prlimit"),
        ..settings(&env)
    };
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &relative_launcher),
        Err(ScanError::BadSettings("prlimit is not absolute"))
    ));
    [0, POLL_ABOVE_RANGE].iter().try_for_each(|poll_millis| {
        let refused = RunSettings {
            poll_millis: *poll_millis,
            ..settings(&env)
        };
        if matches!(
            scan(&env, &program, LONG_TICKS, &refused),
            Err(ScanError::BadSettings("poll_millis out of range"))
        ) {
            Ok(())
        } else {
            Err(format!("accepted: {poll_millis}"))
        }
    })?;
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let zero_poll = RunSettings {
        poll_millis: 0,
        ..settings(&env)
    };
    let result = scan_directory(&program, &env.tree, &target, &Limits::default(), TIMEOUT_SECONDS, &zero_poll);
    assert!(matches!(result, Err(ScanError::BadSettings(_))));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_fifo_at_the_rules_path_is_refused_without_blocking() -> TestResult {
    let env = setup()?;
    let fifo = env.root.path().join("rules.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let uid = settings(&env).rules_uid;
    assert!(matches!(check_rules(&fifo, uid), Err(ScanError::BadRules("not a regular file"))));
    Ok(())
}


#[test]
fn a_background_process_does_not_outlive_a_clean_exit() -> TestResult {
    let env = setup()?;
    let pid_file = env.root.path().join("background");
    let body = format!("sleep 4242 &\necho $! > {}\necho '[]' > \"$6\"", pid_file.display());
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert!(report.findings.is_empty());
    let pid = fs::read_to_string(&pid_file)?;
    assert!(wait_gone(pid.trim()));
    Ok(())
}


fn make_git_tree(env: &Env) -> TestResult {
    fs::create_dir_all(env.tree.join(".git/objects"))?;
    fs::create_dir_all(env.tree.join("deep/.git"))?;
    fs::write(env.tree.join(".git/config"), b"[remote]\nurl = root-marker\n")?;
    fs::write(env.tree.join(".git/HEAD"), b"ref: x\n")?;
    fs::write(env.tree.join(".git/objects/config"), b"not a repo config\n")?;
    fs::write(env.tree.join("deep/.git/config"), b"[remote]\nurl = deep-marker\n")?;
    Ok(())
}


#[test]
fn find_git_configs_lists_only_regular_git_config_files() -> TestResult {
    let env = setup()?;
    make_git_tree(&env)?;
    fs::create_dir_all(env.tree.join("linked/.git"))?;
    symlink("/etc/passwd", env.tree.join("linked/.git/config"))?;
    fs::create_dir_all(env.tree.join("plain"))?;
    fs::write(env.tree.join("plain/config"), b"x")?;
    fs::write(env.tree.join("plain/other.txt"), b"x")?;
    fs::create_dir_all(env.tree.join("dirconfig/.git/config"))?;
    let mut found = find_git_configs(&env.tree);
    found.sort();
    assert_eq!(found, vec![env.tree.join(".git/config"), env.tree.join("deep/.git/config")]);
    assert!(find_git_configs(&env.root.path().join("missing")).is_empty());
    Ok(())
}


#[test]
fn copy_git_config_refuses_links_and_fifos_and_truncates() -> TestResult {
    let env = setup()?;
    let link = env.root.path().join("link");
    symlink("/etc/passwd", &link)?;
    let fifo = env.root.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let big = env.root.path().join("big");
    fs::write(&big, vec![b'a'; usize::try_from(MAX_GIT_CONFIG_BYTES)? + TINY_BYTES])?;
    let copy = |source: &Path, name: &str| copy_git_config(source, &env.root.path().join(name));
    assert!(copy(&link, "from-link").is_err());
    assert!(copy(&fifo, "from-fifo").is_err());
    assert!(!env.root.path().join("from-link").exists());
    assert!(!env.root.path().join("from-fifo").exists());
    copy(&big, "from-big")?;
    assert_eq!(fs::metadata(env.root.path().join("from-big"))?.len(), MAX_GIT_CONFIG_BYTES);
    assert!(copy(&big, "from-big").is_err());
    Ok(())
}


#[test]
fn stage_skips_an_uncopyable_config_and_indexes_the_rest() -> TestResult {
    let env = setup()?;
    let stage = env.root.path().join("stage");
    fs::create_dir(&stage)?;
    let good = env.root.path().join("good");
    fs::write(&good, b"x")?;
    let link = env.root.path().join("link");
    symlink(&good, &link)?;
    let originals = stage_git_configs(&stage, &[link, good.clone()])?;
    assert_eq!(originals, vec![good]);
    assert!(stage.join("0/git-config").is_file());
    assert!(!stage.join("1").exists());
    assert!(stage_git_configs(&env.root.path().join("no-stage"), std::slice::from_ref(&env.rules)).is_err());
    Ok(())
}


#[test]
fn staged_paths_map_back_and_other_paths_stay() -> TestResult {
    let stage = Path::new("/w/stage");
    let originals = [PathBuf::from("/t/.git/config"), PathBuf::from("/t/deep/.git/config")];
    assert_eq!(original_of("/w/stage/1/git-config", stage, &originals), "/t/deep/.git/config");
    assert_eq!(original_of("/w/stage/0/git-config", stage, &originals), "/t/.git/config");
    assert_eq!(original_of("/w/stage/2/git-config", stage, &originals), "/w/stage/2/git-config");
    assert_eq!(original_of("/w/stage/x/git-config", stage, &originals), "/w/stage/x/git-config");
    assert_eq!(original_of("/elsewhere/0/git-config", stage, &originals), "/elsewhere/0/git-config");
    Ok(())
}


const REPORT_OF_STAGED: &str =
    "printf '[{\"File\":\"%s/0/git-config\",\"StartLine\":1,\"EndLine\":1,\"RuleID\":\"r\",\"Match\":\"abc\",\"Secret\":\"abc\"},\
     {\"File\":\"%s/1/git-config\",\"StartLine\":2,\"EndLine\":2,\"RuleID\":\"r\",\"Match\":\"abc\",\"Secret\":\"abc\"}]' \"$2\" \"$2\" > \"$6\"";


#[test]
fn git_configs_are_scanned_as_a_second_run_and_reported_at_their_origin() -> TestResult {
    let env = setup()?;
    make_git_tree(&env)?;
    let copies = env.root.path().join("copies");
    let body = format!(
        "[ \"$2\" = \"{tree}\" ] || cat \"$2\"/*/git-config >> {copies}\n[ \"$2\" = \"{tree}\" ] || ls \"$2\"/0 >> {copies}\n{REPORT_OF_STAGED}",
        tree = env.tree.display(),
        copies = copies.display()
    );
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    let mut origins: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.file.as_str())
        .filter(|file| file.ends_with("/.git/config"))
        .collect();
    origins.sort_unstable();
    let root_config = format!("{}/.git/config", env.tree.display());
    let deep_config = format!("{}/deep/.git/config", env.tree.display());
    assert_eq!(origins, vec![root_config.as_str(), deep_config.as_str()]);
    assert_eq!(report.findings.len(), STAGED_FINDINGS);
    let copied = fs::read_to_string(&copies)?;
    assert!(copied.contains("root-marker"));
    assert!(copied.contains("deep-marker"));
    assert!(!copied.contains("HEAD"));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_combined_findings_stay_within_the_limit() -> TestResult {
    let env = setup()?;
    make_git_tree(&env)?;
    let program = script(&env, "fake", &format!("cp {FIXTURE} \"$6\""))?;
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let limits = Limits {
        max_findings: SAMPLE_FINDINGS,
        ..Limits::default()
    };
    let result = scan_with_ticks(&program, &env.tree, &target, &limits, LONG_TICKS, &settings(&env));
    assert!(matches!(result, Err(ScanError::TooManyFindings(count)) if count == BOTH_FINDINGS));
    let both = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert_eq!(both.findings.len(), BOTH_FINDINGS);
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_failing_git_config_run_is_typed() -> TestResult {
    let env = setup()?;
    make_git_tree(&env)?;
    let body = format!("[ \"$2\" = \"{}\" ] || exit 3\necho '[]' > \"$6\"", env.tree.display());
    let program = script(&env, "fake", &body)?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::Failed(Some(FAILURE_CODE)))
    ));
    assert!(work_is_empty(&env)?);
    Ok(())
}
