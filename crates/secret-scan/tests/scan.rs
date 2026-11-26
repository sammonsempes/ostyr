#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::copy::{RENAMED_PREFIX, STAGED_NAME};
use secret_scan::error::ReportError;
use secret_scan::model::{Limits, ScanScope};
use secret_scan::scan::{
    bwrap_arguments, check_bwrap, check_no_ignore_file, check_path, check_program_outside, kill_all, library_dirs, never_expired, run_settings,
    sandbox_ancestors, scan_arguments, scan_directory, scan_with_ticks, stale_after, RunSettings, ScanError, ScanTarget, MAX_PATH_BYTES,
};
use secret_scan::scan::{check_fuse, check_fuse_sys_admin, check_hardlinks, FUSE_CONF_BYTES, FUSE_SYS_ADMIN_BYTES};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
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


const GONE_POLLS: u32 = 6000;


const POLL_ABOVE_RANGE: u64 = 1001;


const TINY_BYTES: usize = 16;


const NON_UTF8_BYTE: u8 = 0xff;


const FAILURE_CODE: i32 = 3;


const PRIVATE_MODE: u32 = 0o644;


const GROUP_WRITABLE_MODE: u32 = 0o664;


const PRLIMIT: &str = "/usr/bin/prlimit";


const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/gitleaks-report.json");


const FAKE_BWRAP: &str = "while [ \"$1\" != -- ]; do printf '%s\\n' \"$1\" >> \"$HOME/bwrap-args\"; shift; done\nshift\nexec \"$@\"";


const PAIR: usize = 2;


const STALE_MARGIN: u64 = 600;


const MAX_POLL: u64 = 1000;


const REAP_COUNT: u64 = 1000;


const FAILING_BWRAP: &str = "exit 1";


const COPY_OF_THE_TREE: &str = "COPY=\"$(awk -v tree=\"$2\" 'p2==\"--ro-bind\"&&$0==tree{print p1} {p2=p1;p1=$0}' \"$HOME/bwrap-args\")\"\n";


const FIXTURE_ENTRIES: &str = concat!(
    "tr -d '\\n' < ",
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/gitleaks-report.json | sed 's/^ *\\[//; s/\\] *$//' >> \"$6\""
);


fn report_of(own: &str) -> String {
    format!("printf '[' > \"$6\"\n{own}\nprintf ']' >> \"$6\"")
}


const TENANT: &str = "acme";


const SCOPE_ID: &str = "scope-1";


struct Env {
    root: TempDir,
    work: PathBuf,
    tree: PathBuf,
    rules: PathBuf,
    sysctl: PathBuf,
    bwrap: PathBuf,
}


fn install_script(root: &Path, name: &str, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let source = root.join(format!("{name}.src"));
    let program = root.join(name);
    fs::write(&source, format!("#!/bin/sh\n{body}\n"))?;
    let status = Command::new("install").arg("-m").arg("755").arg(&source).arg(&program).status()?;
    fs::remove_file(&source)?;
    assert!(status.success());
    Ok(program)
}


fn setup() -> Result<Env, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let work = root.path().join("work");
    let tree = root.path().join("tree");
    let rules = root.path().join("rules.toml");
    fs::create_dir(&work)?;
    fs::create_dir(&tree)?;
    let sysctl = root.path().join("protected_hardlinks");
    fs::write(&sysctl, b"1\n")?;
    fs::write(&rules, b"title = \"rules\"\n")?;
    fs::set_permissions(&rules, fs::Permissions::from_mode(PRIVATE_MODE))?;
    let bwrap = install_script(root.path(), "bwrap", FAKE_BWRAP)?;
    Ok(Env {
        root,
        work,
        tree,
        rules,
        sysctl,
        bwrap,
    })
}


fn settings(env: &Env) -> RunSettings {
    RunSettings {
        hardlink_sysctl: env.sysctl.clone(),
        fuse_conf: env.root.path().join("fuse.conf"),
        fuse_sys_admin: env.root.path().join("allow_sys_admin_access"),
        ..run_settings(
            PathBuf::from(PRLIMIT),
            env.bwrap.clone(),
            env.rules.clone(),
            env.work.clone(),
            MEMORY_BYTES,
            FILE_BYTES,
            POLL_MILLIS,
        )
    }
}


fn script(env: &Env, name: &str, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    install_script(env.root.path(), name, body)
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
    let program = script(&env, "fake", &report_of(FIXTURE_ENTRIES))?;
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
    assert!(matches!(result, Err(ScanError::Report(ReportError::TooLarge { max }) ) if max == TINY_BYTES));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn child_environment_is_cleared() -> TestResult {
    let env = setup()?;
    let out = env.root.path().join("env.txt");
    let program = script(&env, "fake", &report_of(&format!("/usr/bin/env > {}", out.display())))?;
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
        "[ \"${{12}}\" = \"$HOME/config.toml\" ] || exit 11\ncmp -s \"${{12}}\" {} || exit 16\n[ \"${{13}}\" = --gitleaks-ignore-path ] || exit 12\n[ -f \"${{14}}\" ] && [ ! -s \"${{14}}\" ] || exit 13\n\
         [ \"${{15}}\" = --ignore-gitleaks-allow ] || exit 14\n[ \"$(pwd)\" = \"$HOME\" ] || exit 15\n{}",
        env.rules.display(),
        report_of(FIXTURE_ENTRIES)
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
    let body = format!("{COPY_OF_THE_TREE}cp {FIXTURE} \"$6\"\n: > \"$COPY\"/.gitleaksignore");
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
fn a_work_directory_with_a_parent_component_is_a_settings_error_before_anything_else() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", &empty_report())?;
    let hostile = RunSettings {
        work_dir: env.work.join("missing/../elsewhere"),
        rules: env.root.path().join("absent-rules"),
        ..settings(&env)
    };
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &hostile),
        Err(ScanError::BadSettings("work directory has a component other than a name"))
    ));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_program_inside_the_scanned_tree_is_refused_before_anything_is_created() -> TestResult {
    let env = setup()?;
    let inside = script(&env, "outside", &empty_report())?;
    let moved = env.tree.join("gitleaks");
    fs::rename(&inside, &moved)?;
    assert!(matches!(scan(&env, &moved, LONG_TICKS, &settings(&env)), Err(ScanError::ProgramInTree)));
    assert!(matches!(check_program_outside(&moved, Path::new("/")), Err(ScanError::ProgramInTree)));
    assert!(check_program_outside(&moved, &env.work).is_ok());
    assert!(check_program_outside(&env.tree.join("gitleaks-sibling"), &env.tree.join("gitleaks")).is_ok());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_stale_age_covers_both_budgets_the_reap_polls_and_a_margin() -> TestResult {
    assert_eq!(stale_after(1).as_secs(), PAIR as u64 * TIMEOUT_SECONDS + 1 + STALE_MARGIN);
    assert_eq!(stale_after(MAX_POLL).as_secs(), PAIR as u64 * TIMEOUT_SECONDS + REAP_COUNT + STALE_MARGIN);
    assert!(stale_after(u64::MAX).as_secs() > stale_after(MAX_POLL).as_secs());
    Ok(())
}


#[test]
fn a_fifo_at_the_rules_path_is_refused_without_blocking() -> TestResult {
    let env = setup()?;
    let fifo = env.root.path().join("rules.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    let program = script(&env, "fake", "exit 0")?;
    let run = RunSettings {
        rules: fifo,
        ..settings(&env)
    };
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &run),
        Err(ScanError::BadRules("not a regular file"))
    ));
    Ok(())
}


#[test]
fn a_background_process_does_not_outlive_a_clean_exit() -> TestResult {
    let env = setup()?;
    let pid_file = env.root.path().join("background");
    let body = format!("sleep 4242 &\necho $! > {}\n{}", pid_file.display(), report_of(""));
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert!(report.findings.is_empty());
    let pid = fs::read_to_string(&pid_file)?;
    assert!(wait_gone(pid.trim()));
    Ok(())
}


const REPORT_OF_COPY: &str =
    "printf '{\"File\":\"%s/a.txt\",\"StartLine\":1,\"EndLine\":1,\"RuleID\":\"r\",\"Match\":\"abc\",\"Secret\":\"abc\"},\
     {\"File\":\"%s/secret-scan-reserved-git-config\",\"StartLine\":2,\"EndLine\":2,\"RuleID\":\"r\",\"Match\":\"abc\",\"Secret\":\"abc\"}' \"$2\" \"$2\" >> \"$6\"";


fn always_expired(_dir: &Path) -> bool {
    true
}


#[test]
fn gitleaks_scans_the_private_copy_seen_at_the_original_path_and_findings_map_back() -> TestResult {
    let env = setup()?;
    fs::create_dir(env.tree.join(".git"))?;
    fs::write(env.tree.join(".git/config"), b"git-marker")?;
    fs::write(env.tree.join("a.txt"), b"tree-marker")?;
    let seen = env.root.path().join("seen");
    let body = format!(
        "{COPY_OF_THE_TREE}cat \"$COPY/a.txt\" \"$COPY/secret-scan-reserved-git-config\" > {seen}\nls \"$COPY\" >> {seen}\n{}",
        report_of(REPORT_OF_COPY),
        seen = seen.display()
    );
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    let mut files: Vec<&str> = report.findings.iter().map(|finding| finding.file.as_str()).collect();
    files.sort_unstable();
    let git_config = format!("{}/.git/config", env.tree.display());
    let text_file = format!("{}/a.txt", env.tree.display());
    assert_eq!(files, vec![git_config.as_str(), text_file.as_str()]);
    let output = fs::read_to_string(&seen)?;
    assert!(output.contains("tree-markergit-marker"));
    assert!(output.ends_with("a.txt\nsecret-scan-reserved-git-config\n"));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_copy_has_the_scan_deadline_and_is_removed_after_a_timeout() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("a.txt"), b"x")?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    assert!(matches!(scan(&env, &program, 0, &settings(&env)), Err(ScanError::TimedOut)));
    let mut run = settings(&env);
    run.expired = always_expired;
    assert!(matches!(scan(&env, &program, LONG_TICKS, &run), Err(ScanError::TimedOut)));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_symlink_in_the_scan_path_and_a_foreign_work_root_are_refused_before_spawning() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    fs::create_dir(env.root.path().join("secret"))?;
    symlink(env.root.path().join("secret"), env.tree.join("via"))?;
    let scope = ScanScope::default();
    let target = ScanTarget {
        tenant: TENANT,
        scope_id: SCOPE_ID,
        scope: &scope,
    };
    let through = env.tree.join("via");
    let result = scan_with_ticks(&program, &through, &target, &Limits::default(), LONG_TICKS, &settings(&env));
    assert!(matches!(result, Err(ScanError::BadPath("symlink in path"))));
    let mut foreign = settings(&env);
    foreign.work_uid += 1;
    assert!(matches!(scan(&env, &program, LONG_TICKS, &foreign), Err(ScanError::BadSettings(_))));
    let mut huge = settings(&env);
    huge.copy.max_entries = usize::MAX;
    assert!(matches!(scan(&env, &program, LONG_TICKS, &huge), Err(ScanError::BadSettings(_))));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_path_that_is_not_utf8_is_refused() -> TestResult {
    let env = setup()?;
    let odd = env.root.path().join(OsString::from_vec(vec![b'o', NON_UTF8_BYTE]));
    fs::create_dir(&odd)?;
    assert!(matches!(check_path(&odd), Err(ScanError::BadPath("not UTF-8"))));
    Ok(())
}


#[test]
fn an_ignore_file_deep_in_the_tree_is_refused_before_spawning() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    fs::create_dir_all(env.tree.join("a/b"))?;
    fs::write(env.tree.join("a/b/.gitleaksignore"), b"x:y:1\n")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::IgnoreFileInTree)
    ));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


fn empty_report() -> String {
    report_of("")
}


const SMALL_FILE_LIMIT: u64 = 16;


const OTHER_OWNER: u32 = 4242;


const SEVEN_ENTRIES: usize = 7;


const EXPECTED_BYTES: u64 = 22;


const TWO_LINKS: usize = 2;


fn swap_and_remove(path: &Path) {
    let name = path.file_name();
    if name == Some(std::ffi::OsStr::new("victim")) {
        let moved = fs::rename(path, path.with_file_name("victim.moved")).and_then(|()| symlink("/", path));
        assert!(moved.is_ok());
    }
    if name == Some(std::ffi::OsStr::new("gone.txt")) {
        assert!(fs::remove_file(path).is_ok());
    }
}


#[test]
fn the_report_carries_every_count_of_the_copy() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("plain.txt"), b"x")?;
    fs::write(env.tree.join("big.txt"), vec![b'a'; TINY_BYTES + 1])?;
    fs::write(env.tree.join(".gitleaks.toml"), b"useDefault = false")?;
    fs::write(env.tree.join("gone.txt"), b"x")?;
    fs::create_dir(env.tree.join("victim"))?;
    symlink("/etc/passwd", env.tree.join("link"))?;
    fs::write(env.tree.join(OsString::from_vec(vec![b'o', NON_UTF8_BYTE])), b"odd")?;
    let program = script(&env, "fake", &empty_report())?;
    let mut run = settings(&env);
    run.copy.max_file_bytes = SMALL_FILE_LIMIT;
    run.before_open = swap_and_remove;
    let report = scan(&env, &program, LONG_TICKS, &run)?;
    let copy = &report.copy;
    assert_eq!(copy.entries, SEVEN_ENTRIES);
    assert_eq!(copy.truncated_files, 1);
    assert_eq!(copy.skipped_special, 1);
    assert_eq!(copy.skipped_swapped, 1);
    assert_eq!(copy.skipped_vanished, 1);
    assert_eq!(copy.config_files, 1);
    assert_eq!(copy.renamed_names, 1);
    assert_eq!(copy.foreign_owner_files, 0);
    assert_eq!(copy.other_device, 0);
    assert_eq!((copy.denied_entries, copy.leased_files), (0, 0));
    assert_eq!(copy.bytes, EXPECTED_BYTES);
    Ok(())
}


struct Restore {
    path: PathBuf,
}


impl Drop for Restore {
    fn drop(&mut self) {
        assert!(std::os::unix::fs::chown(&self.path, Some(rustix::process::geteuid().as_raw()), None).is_ok());
    }
}


#[test]
fn a_file_of_another_owner_is_counted_in_the_report() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("host-key"), b"root only")?;
    fs::hard_link(env.tree.join("host-key"), env.tree.join("planted"))?;
    let moved = std::os::unix::fs::chown(env.tree.join("host-key"), Some(OTHER_OWNER), None).is_ok();
    let restore = Restore {
        path: env.tree.join("host-key"),
    };
    let program = script(&env, "fake", &empty_report())?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert_eq!(report.copy.foreign_owner_files, if moved { TWO_LINKS } else { 0 });
    drop(restore);
    Ok(())
}


#[test]
fn a_git_config_under_a_name_that_is_not_utf8_is_scanned_and_shown_escaped() -> TestResult {
    let env = setup()?;
    let name = OsString::from_vec(vec![b'o', b'k', NON_UTF8_BYTE]);
    fs::create_dir_all(env.tree.join(&name).join(".git"))?;
    fs::write(env.tree.join(&name).join(".git/config"), b"pat-marker")?;
    let seen = env.root.path().join("seen");
    let body = format!(
        "{COPY_OF_THE_TREE}cat \"$COPY/{RENAMED_PREFIX}0/{STAGED_NAME}\" > {seen}\n{}",
        report_of(&format!(
            "printf '{{\"File\":\"%s/{RENAMED_PREFIX}0/{STAGED_NAME}\",\"StartLine\":1,\"EndLine\":1,\"RuleID\":\"r\",\"Match\":\"abc\",\"Secret\":\"abc\"}}' \"$2\" >> \"$6\""
        )),
        seen = seen.display()
    );
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert_eq!(fs::read_to_string(&seen)?, "pat-marker");
    let file = report.findings.first().map(|finding| finding.file.clone()).ok_or("no finding")?;
    assert_eq!(file, format!("{}/ok\\\\x{{ff}}/.git/config", env.tree.display()));
    assert!(!file.contains('\u{fffd}'));
    assert_eq!(report.copy.renamed_names, 1);
    Ok(())
}


#[test]
fn the_run_is_refused_unless_hard_links_are_protected() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    fs::write(env.tree.join("a"), b"x")?;
    fs::write(&env.sysctl, b"0\n")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::HardlinksUnprotected)
    ));
    fs::write(&env.sysctl, b"garbage that is longer than the read bound")?;
    assert!(matches!(check_hardlinks(&env.sysctl), Err(ScanError::HardlinksUnprotected)));
    fs::remove_file(&env.sysctl)?;
    assert!(matches!(check_hardlinks(&env.sysctl), Err(ScanError::Io(_))));
    assert!(matches!(scan(&env, &program, LONG_TICKS, &settings(&env)), Err(ScanError::Io(_))));
    fs::write(&env.sysctl, b"1\n")?;
    assert!(check_hardlinks(&env.sysctl).is_ok());
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_child_runs_the_operator_rules_bytes_unchanged() -> TestResult {
    let env = setup()?;
    let text = "[allowlist]\npaths = ['''vendor/''']\n[[rules]]\nid = \"op\"\nregex = '''x+'''\n";
    fs::write(&env.rules, text)?;
    let seen = env.root.path().join("config-seen");
    let program = script(&env, "fake", &report_of(&format!("cp \"${{12}}\" {}", seen.display())))?;
    scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert_eq!(fs::read_to_string(&seen)?, text);
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_lenient_key_in_the_rules_is_refused_before_any_directory() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    fs::write(&env.rules, "[extend]\nuseDefault = true\n")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::BadRulesKey(found)) if found == "extend"
    ));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_sandbox_arguments_are_exact() -> TestResult {
    let arguments = bwrap_arguments(
        Path::new("/opt/gitleaks"),
        &[PathBuf::from("/usr"), PathBuf::from("/lib")],
        Path::new("/w/secret-scan-x/data/tree"),
        Path::new("/srv/a/tree"),
        Path::new("/w/secret-scan-x/run"),
    );
    let expected = [
        "--tmpfs",
        "/",
        "--cap-drop",
        "ALL",
        "--dir",
        "/srv",
        "--dir",
        "/srv/a",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--ro-bind",
        "/opt/gitleaks",
        "/opt/gitleaks",
        "--ro-bind",
        "/w/secret-scan-x/data/tree",
        "/srv/a/tree",
        "--bind",
        "/w/secret-scan-x/run",
        "/w/secret-scan-x/run",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
        "--die-with-parent",
        "--",
    ];
    assert_eq!(arguments, expected.iter().map(OsString::from).collect::<Vec<_>>());
    assert!(!arguments
        .windows(PAIR)
        .any(|pair| pair == [OsString::from("--ro-bind"), OsString::from("/")]));
    Ok(())
}


#[test]
fn only_existing_system_directories_are_bound_and_a_top_level_tree_has_no_ancestors() -> TestResult {
    let env = setup()?;
    let missing = env.root.path().join("missing");
    let found = library_dirs(&["/usr", missing.to_str().ok_or("not UTF-8")?]);
    assert_eq!(found, vec![PathBuf::from("/usr")]);
    assert!(sandbox_ancestors(Path::new("/tree")).is_empty());
    assert_eq!(sandbox_ancestors(Path::new("/a/b/c")), [Path::new("/a"), Path::new("/a/b")]);
    Ok(())
}


const SANDBOX_CHECKS: &str = "[ \"$(sed -n 1p \"$HOME/bwrap-args\")\" = --tmpfs ] && [ \"$(sed -n 2p \"$HOME/bwrap-args\")\" = / ] || exit 21\n\
     awk 'p==\"--ro-bind\"&&$0==\"/\"{bad=1} {p=$0} END{exit bad}' \"$HOME/bwrap-args\" || exit 22\n\
     grep -qx -e ALL \"$HOME/bwrap-args\" || exit 23\n";


#[test]
fn gitleaks_sees_the_copy_at_the_original_path_and_never_the_work_directory() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("a.txt"), b"x")?;
    let tree = env.tree.display();
    let work = env.work.display();
    let body = format!(
        "{SANDBOX_CHECKS}[ \"$2\" = {tree} ] || exit 24\n{COPY_OF_THE_TREE}[ \"$COPY\" != {tree} ] || exit 25\n\
         case \"$COPY\" in {work}/secret-scan-*/data/tree) ;; *) exit 26;; esac\n\
         grep -qx -e \"$HOME\" \"$HOME/bwrap-args\" || exit 27\ngrep -qx -e --unshare-ipc \"$HOME/bwrap-args\" || exit 28\n{}",
        report_of(""),
    );
    let program = script(&env, "fake", &body)?;
    let report = scan(&env, &program, LONG_TICKS, &settings(&env))?;
    assert!(report.findings.is_empty());
    Ok(())
}


#[test]
fn a_missing_launcher_is_a_fixed_error_and_nothing_is_scanned() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    fs::write(env.tree.join("a.txt"), b"x")?;
    [env.root.path().join("no-bwrap"), env.root.path().to_path_buf()]
        .iter()
        .try_for_each(|bwrap| {
            let run = RunSettings {
                bwrap: bwrap.clone(),
                ..settings(&env)
            };
            if matches!(scan(&env, &program, LONG_TICKS, &run), Err(ScanError::NoSandbox)) {
                Ok(())
            } else {
                Err(format!("not refused: {bwrap:?}"))
            }
        })?;
    assert!(check_bwrap(&env.bwrap).is_ok());
    assert!(ScanError::NoSandbox.to_string().contains("nothing was scanned"));
    let relative = RunSettings {
        bwrap: PathBuf::from("bwrap"),
        ..settings(&env)
    };
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &relative),
        Err(ScanError::BadSettings("bwrap is not absolute"))
    ));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn a_launcher_that_fails_to_start_fails_the_scan_and_gitleaks_never_runs_unsandboxed() -> TestResult {
    let env = setup()?;
    let marker = env.root.path().join("spawned");
    let program = script(&env, "fake", &format!("touch {}", marker.display()))?;
    let failing = install_script(env.root.path(), "failing-bwrap", FAILING_BWRAP)?;
    let run = RunSettings {
        bwrap: failing,
        ..settings(&env)
    };
    fs::write(env.tree.join("a.txt"), b"x")?;
    assert!(matches!(scan(&env, &program, LONG_TICKS, &run), Err(ScanError::Failed(Some(1)))));
    assert!(!marker.exists());
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_run_is_refused_when_fuse_conf_lets_other_users_share_mounts() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", &empty_report())?;
    fs::write(env.tree.join("a"), b"x")?;
    let conf = env.root.path().join("fuse.conf");
    fs::write(&conf, b"# user_allow_other\n  \nmount_max = 1000\n")?;
    assert!(scan(&env, &program, LONG_TICKS, &settings(&env)).is_ok());
    fs::write(&conf, b"mount_max = 1000\n\tuser_allow_other  \n")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::FuseAllowOther)
    ));
    fs::write(&conf, b"user_allow_other")?;
    assert!(matches!(check_fuse(&conf), Err(ScanError::FuseAllowOther)));
    fs::write(&conf, vec![b'#'; FUSE_CONF_BYTES as usize + 1])?;
    assert!(matches!(check_fuse(&conf), Err(ScanError::BadSettings("fuse.conf is too large"))));
    fs::remove_file(&conf)?;
    assert!(check_fuse(&conf).is_ok());
    assert!(matches!(check_fuse(env.root.path()), Err(ScanError::Io(_))));
    assert!(matches!(check_fuse(&env.rules.join("below-a-file")), Err(ScanError::Io(_))));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_run_is_refused_unless_fuse_sys_admin_access_is_off() -> TestResult {
    let env = setup()?;
    let program = script(&env, "fake", &empty_report())?;
    fs::write(env.tree.join("a"), b"x")?;
    let parameter = env.root.path().join("allow_sys_admin_access");
    assert!(scan(&env, &program, LONG_TICKS, &settings(&env)).is_ok());
    fs::write(&parameter, b"N\n")?;
    assert!(scan(&env, &program, LONG_TICKS, &settings(&env)).is_ok());
    fs::write(&parameter, b"Y\n")?;
    assert!(matches!(
        scan(&env, &program, LONG_TICKS, &settings(&env)),
        Err(ScanError::FuseSysAdminAccess)
    ));
    assert!(work_is_empty(&env)?);
    ["", "y", "Y", "yes", "0", "NN"].iter().try_for_each(|value| {
        fs::write(&parameter, value).map_err(|error| error.to_string())?;
        if matches!(check_fuse_sys_admin(&parameter), Err(ScanError::FuseSysAdminAccess)) {
            Ok(())
        } else {
            Err(format!("not refused: {value:?}"))
        }
    })?;
    fs::write(
        &parameter,
        [b"N".as_slice(), vec![b' '; FUSE_SYS_ADMIN_BYTES as usize].as_slice()].concat(),
    )?;
    assert!(matches!(check_fuse_sys_admin(&parameter), Err(ScanError::FuseSysAdminAccess)));
    fs::write(
        &parameter,
        [b"N".as_slice(), vec![b' '; FUSE_SYS_ADMIN_BYTES as usize - 1].as_slice()].concat(),
    )?;
    assert!(check_fuse_sys_admin(&parameter).is_ok());
    fs::remove_file(&parameter)?;
    assert!(check_fuse_sys_admin(&parameter).is_ok());
    assert!(matches!(check_fuse_sys_admin(env.root.path()), Err(ScanError::Io(_))));
    assert!(matches!(check_fuse_sys_admin(&env.rules.join("below-a-file")), Err(ScanError::Io(_))));
    Ok(())
}


const ZOMBIE_STATE: &str = "Z";


const STATE_FIELD: usize = 3;


fn leader_state(pid: rustix::process::Pid) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_pid())).ok()?;
    let after_name = stat.rsplit_once(')')?.1;
    after_name.split_whitespace().next().map(str::to_owned)
}


fn kill_group_only_when_leader_is_a_zombie(pid: rustix::process::Pid) {
    if leader_state(pid).as_deref() == Some(ZOMBIE_STATE) {
        let killed = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        assert!(killed.is_ok(), "state field {STATE_FIELD}");
    }
}


#[test]
fn the_group_is_killed_while_the_exited_leader_is_still_a_zombie() -> TestResult {
    let env = setup()?;
    let pid_file = env.root.path().join("background");
    let body = format!("sleep 4243 &\necho $! > {}\n{}", pid_file.display(), report_of(""));
    let program = script(&env, "fake", &body)?;
    let run = RunSettings {
        group_kill: kill_group_only_when_leader_is_a_zombie,
        ..settings(&env)
    };
    let report = scan(&env, &program, LONG_TICKS, &run)?;
    assert!(report.findings.is_empty());
    let pid = fs::read_to_string(&pid_file)?;
    assert!(wait_gone(pid.trim()));
    Ok(())
}


#[test]
fn a_child_that_cannot_be_waited_on_is_an_error_not_a_pass() -> TestResult {
    let env = setup()?;
    let mut child = Command::new("true").spawn()?;
    child.wait()?;
    let result = secret_scan::scan::wait_child(&mut child, LONG_TICKS, never_expired, &settings(&env), &env.tree);
    assert!(result.is_err());
    Ok(())
}


#[test]
fn an_empty_group_after_the_exit_is_only_logged() -> TestResult {
    let mut child = Command::new("true").process_group(0).spawn()?;
    child.wait()?;
    secret_scan::scan::kill_group_after_exit(rustix::process::Pid::from_child(&child));
    Ok(())
}
