use crate::cgroup::{accept, fail};
use crate::common::{manifest_with, params_of, path_kind, refusal, text, text_kind, FailingReader};
use crate::types::TestResult;
use data_encoding::HEXLOWER;
use script_library::cgroup::{CgroupOps, SYSTEM_CGROUP};
use script_library::error::ScriptError;
use script_library::launch::{
    allowed_environment, capture, launch_script, reap, resolve_interpreter, resolve_paths, run_script, tolerate_empty_group, wait_deadline,
    DEFAULT_KILL_GRACE_SECONDS,
};
use script_library::model::{Interpreter, LaunchRequest, LimitHit, Limits, Manifest, Outcome, RunAs};
use script_library::pattern::compile_secret_pattern;
use script_library::types::Params;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::process::{Child, ExitStatus};
use std::time::Duration;


pub const SMALL_CAP: u64 = 16;


pub const OVERFLOW: usize = 5000;


pub const PARTIAL_PREFIX: usize = 4;


pub const EXIT_CODE: i32 = 3;


pub const INVALID_UTF8_BYTE: u8 = 0xff;


pub const MODE_LINE: usize = 1;


pub const DIRECTORY_LINE: usize = 2;


pub const LABEL_LINE: usize = 3;


pub const ALLOWED_VARIABLES: usize = 2;


pub const PARTIAL_DROPPED: u64 = 2;


const SYSTEM_PATH: &str = "/usr/bin:/bin";


fn no_place(_cgroup: BorrowedFd<'_>, _pid: u32) -> io::Result<()> {
    Ok(())
}


fn no_kill(_cgroup: BorrowedFd<'_>) -> io::Result<()> {
    Ok(())
}


fn no_limit(_cgroup: BorrowedFd<'_>, _limits: &Limits) -> io::Result<()> {
    Ok(())
}


fn no_events(_cgroup: BorrowedFd<'_>) -> io::Result<Option<LimitHit>> {
    Ok(None)
}


fn memory_events(_cgroup: BorrowedFd<'_>) -> io::Result<Option<LimitHit>> {
    Ok(Some(LimitHit::Memory))
}


fn failing_events(_cgroup: BorrowedFd<'_>) -> io::Result<Option<LimitHit>> {
    Err(io::Error::other("injected events failure"))
}


fn failing_limit(_cgroup: BorrowedFd<'_>, _limits: &Limits) -> io::Result<()> {
    Err(io::Error::other("injected limit failure"))
}


fn failing_kill(_cgroup: BorrowedFd<'_>) -> io::Result<()> {
    Err(io::Error::other("injected kill failure"))
}


fn failing_place(_cgroup: BorrowedFd<'_>, _pid: u32) -> io::Result<()> {
    Err(io::Error::other("injected placement failure"))
}


const FAKE_CGROUP: CgroupOps = CgroupOps {
    check: accept,
    place: no_place,
    kill: no_kill,
    limit: no_limit,
    events: no_events,
};


fn run(launch: &LaunchRequest) -> Result<Outcome, ScriptError> {
    run_script(launch, wait_deadline, &FAKE_CGROUP)
}


fn digest_of(bytes: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(bytes))
}


fn instant_timeout(_child: &mut Child, _deadline: Duration) -> io::Result<Option<ExitStatus>> {
    Ok(None)
}


fn failing_wait(_child: &mut Child, _deadline: Duration) -> io::Result<Option<ExitStatus>> {
    Err(io::Error::other("injected wait failure"))
}


fn request(root: &Path, interpreter: Interpreter, script: &str) -> LaunchRequest {
    let manifest = Manifest {
        sha256: digest_of(script.as_bytes()),
        ..manifest_with(interpreter, vec![])
    };
    LaunchRequest {
        manifest,
        params: Params::new(),
        script_bytes: script.as_bytes().to_vec(),
        work_root: root.to_path_buf(),
        cgroup_root: root.to_path_buf(),
        kill_grace: Duration::from_secs(DEFAULT_KILL_GRACE_SECONDS),
        environment: vec![("PATH".to_string(), SYSTEM_PATH.to_string())],
        run_as: None,
    }
}


fn output_text(outcome: &Outcome) -> String {
    String::from_utf8_lossy(&outcome.output).to_string()
}


fn utf8(path: &Path) -> Result<&str, &'static str> {
    path.to_str().ok_or("path is not UTF-8")
}


#[test]
fn bash_runs_the_digested_bytes_from_a_private_file() -> TestResult {
    let root = tempfile::tempdir()?;
    let script = "echo \"$0\"\nstat -c '%a' \"$0\"\nstat -c '%a' \"$(dirname \"$0\")\"\necho \"$1\"\n";
    let mut launch = request(root.path(), Interpreter::Bash, script);
    launch
        .manifest
        .parameters
        .insert("label".to_string(), text_kind(0, SMALL_CAP as usize, None));
    launch.params = params_of(vec![("label", text("x y"))]);
    let outcome = run(&launch)?;
    assert_eq!(outcome.exit_code, Some(0));
    assert!(!outcome.timed_out);
    let lines: Vec<String> = output_text(&outcome).lines().map(str::to_string).collect();
    let path = lines.first().ok_or("path")?;
    assert!(Path::new(path).is_absolute());
    assert!(path.starts_with(utf8(root.path())?));
    assert_eq!(lines.get(MODE_LINE).map(String::as_str), Some("600"));
    assert_eq!(lines.get(DIRECTORY_LINE).map(String::as_str), Some("700"));
    assert_eq!(lines.get(LABEL_LINE).map(String::as_str), Some("--label=x y"));
    assert!(!Path::new(path).exists());
    Ok(())
}


#[test]
fn swapping_the_library_file_after_the_digest_has_no_effect() -> TestResult {
    let root = tempfile::tempdir()?;
    let library = root.path().join("library.sh");
    std::fs::write(&library, "echo genuine\n")?;
    let original = request(root.path(), Interpreter::Bash, "echo genuine\n");
    let digested = std::fs::read(&library)?;
    std::fs::write(&library, "echo swapped\n")?;
    let launch = LaunchRequest {
        script_bytes: digested,
        ..original
    };
    assert_eq!(output_text(&run(&launch)?), "genuine\n");
    Ok(())
}


#[test]
fn bytes_that_do_not_match_the_digest_are_never_run() -> TestResult {
    let root = tempfile::tempdir()?;
    let launch = LaunchRequest {
        script_bytes: b"echo evil\n".to_vec(),
        ..request(root.path(), Interpreter::Bash, "echo genuine\n")
    };
    assert!(matches!(refusal(run(&launch))?, ScriptError::DigestMismatch));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}


#[test]
fn python_runs_isolated() -> TestResult {
    let root = tempfile::tempdir()?;
    let script = "import sys\nprint(sys.flags.isolated, sys.argv[0].endswith('script.py'))\n";
    let outcome = run(&request(root.path(), Interpreter::Python, script))?;
    assert_eq!(output_text(&outcome), "1 True\n");
    Ok(())
}


#[test]
fn only_allowlisted_variables_reach_the_script() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, "env | sort\n");
    launch.environment = vec![
        ("PATH".to_string(), SYSTEM_PATH.to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("SECRET_TOKEN".to_string(), "hunter2".to_string()),
        ("LD_PRELOAD".to_string(), "/evil.so".to_string()),
    ];
    let shown = output_text(&run(&launch)?);
    assert!(shown.contains("LANG=C"));
    assert!(shown.contains(&format!("PATH={SYSTEM_PATH}")));
    assert!(!shown.contains("SECRET_TOKEN"));
    assert!(!shown.contains("LD_PRELOAD"));
    assert_eq!(allowed_environment(&launch.environment).len(), ALLOWED_VARIABLES);
    Ok(())
}


#[test]
fn output_beyond_the_cap_is_dropped_and_counted() -> TestResult {
    let root = tempfile::tempdir()?;
    let script = format!("head -c {OVERFLOW} /dev/zero | tr '\\0' a\n");
    let mut launch = request(root.path(), Interpreter::Bash, &script);
    launch.manifest.max_output_bytes = SMALL_CAP;
    let outcome = run(&launch)?;
    assert_eq!(outcome.output, b"a".repeat(SMALL_CAP as usize));
    assert_eq!(outcome.dropped_bytes, OVERFLOW as u64 - SMALL_CAP);
    Ok(())
}


#[test]
fn stderr_shares_the_pipe_and_exit_code_is_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let script = format!("echo oops >&2\nexit {EXIT_CODE}\n");
    let outcome = run(&request(root.path(), Interpreter::Bash, &script))?;
    assert_eq!(outcome.exit_code, Some(EXIT_CODE));
    assert_eq!(output_text(&outcome), "oops\n");
    assert_eq!(outcome.dropped_bytes, 0);
    Ok(())
}


#[test]
fn deadline_kills_the_whole_process_group() -> TestResult {
    let root = tempfile::tempdir()?;
    let outcome = run_script(
        &request(root.path(), Interpreter::Bash, "sleep 300 &\nwait\n"),
        instant_timeout,
        &FAKE_CGROUP,
    )?;
    assert!(outcome.timed_out);
    assert_eq!(outcome.exit_code, None);
    Ok(())
}


#[test]
fn wait_failure_kills_and_is_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let error = refusal(run_script(
        &request(root.path(), Interpreter::Bash, "sleep 300\n"),
        failing_wait,
        &FAKE_CGROUP,
    ))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("wait")));
    Ok(())
}


#[test]
fn the_interpreter_comes_from_the_declared_list_not_the_path() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, "echo hi\n");
    launch.environment = vec![("PATH".to_string(), "/nonexistent".to_string())];
    assert_eq!(output_text(&run(&launch)?), "hi\n");
    assert_eq!(resolve_interpreter(&["/nonexistent/bash", "/bin/sh"])?, "/bin/sh");
    assert!(matches!(
        refusal(resolve_interpreter(&["/nonexistent/bash"]))?,
        ScriptError::NoInterpreter
    ));
    assert!(matches!(refusal(resolve_interpreter(&[]))?, ScriptError::NoInterpreter));
    Ok(())
}


#[test]
fn unusable_work_root_is_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let launch = request(&root.path().join("absent"), Interpreter::Bash, "echo hi\n");
    let error = refusal(run(&launch))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("work root")));
    Ok(())
}


#[test]
fn invalid_request_is_refused_before_anything_is_written() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, "echo hi\n");
    launch.manifest.script = "-c".to_string();
    assert!(matches!(refusal(run(&launch))?, ScriptError::InvalidManifest { .. }));
    let mut missing = request(root.path(), Interpreter::Bash, "echo hi\n");
    missing
        .manifest
        .parameters
        .insert("label".to_string(), text_kind(0, SMALL_CAP as usize, None));
    assert!(matches!(refusal(run(&missing))?, ScriptError::MissingParameter(_)));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}


#[test]
fn capture_counts_without_buffering() -> TestResult {
    let kept = capture(&b"abcdef"[..], PARTIAL_PREFIX as u64, &[])?;
    assert_eq!(kept.bytes, b"abcd");
    assert_eq!(kept.dropped, PARTIAL_DROPPED);
    assert!(capture(FailingReader, SMALL_CAP, &[]).is_err());
    Ok(())
}


fn path_manifest(prefix: &str) -> Manifest {
    manifest_with(
        Interpreter::Bash,
        vec![("target", path_kind(&[prefix])), ("label", text_kind(0, SMALL_CAP as usize, None))],
    )
}


#[test]
fn symlinks_are_resolved_before_the_prefix_check() -> TestResult {
    let root = tempfile::tempdir()?;
    let base = std::fs::canonicalize(root.path())?;
    let allowed = base.join("allowed");
    let outside = base.join("outside");
    std::fs::create_dir(&allowed)?;
    std::fs::create_dir(&outside)?;
    std::fs::write(allowed.join("ok.txt"), "x")?;
    std::fs::write(outside.join("secret.txt"), "x")?;
    symlink(outside.join("secret.txt"), allowed.join("escape.txt"))?;
    symlink(&allowed, base.join("alias"))?;
    let manifest = path_manifest(utf8(&allowed)?);
    let good = params_of(vec![("target", text(utf8(&allowed.join("ok.txt"))?)), ("label", text("a"))]);
    let resolved = resolve_paths(&manifest, &good)?;
    assert_eq!(resolved.get("target"), good.get("target"));
    assert_eq!(resolved.get("label"), good.get("label"));
    let aliased = params_of(vec![("target", text(utf8(&base.join("alias/ok.txt"))?))]);
    assert_eq!(resolve_paths(&manifest, &aliased)?.get("target"), good.get("target"));
    let escape = params_of(vec![("target", text(utf8(&allowed.join("escape.txt"))?))]);
    assert!(matches!(refusal(resolve_paths(&manifest, &escape))?, ScriptError::PathOutsidePrefixes(_)));
    let absent = params_of(vec![("target", text(utf8(&allowed.join("absent"))?))]);
    assert!(matches!(refusal(resolve_paths(&manifest, &absent))?, ScriptError::PathUnresolved { .. }));
    let unresolvable = path_manifest("/nonexistent-prefix");
    assert!(matches!(
        refusal(resolve_paths(&unresolvable, &good))?,
        ScriptError::PathOutsidePrefixes(_)
    ));
    Ok(())
}


#[test]
fn a_symlinked_parameter_reaches_the_script_resolved() -> TestResult {
    let root = tempfile::tempdir()?;
    let base = std::fs::canonicalize(root.path())?;
    let allowed = base.join("allowed");
    std::fs::create_dir(&allowed)?;
    std::fs::write(allowed.join("ok.txt"), "x")?;
    symlink(allowed.join("ok.txt"), allowed.join("link.txt"))?;
    let mut launch = request(&base, Interpreter::Bash, "echo \"$1\"\necho \"$2\"\n");
    launch.manifest.parameters = path_manifest(utf8(&allowed)?).parameters;
    launch.params = params_of(vec![("target", text(utf8(&allowed.join("link.txt"))?)), ("label", text("a"))]);
    let shown = output_text(&run(&launch)?);
    assert!(shown.contains("--label=a"));
    assert!(shown.contains(&format!("--target={}", allowed.join("ok.txt").display())));
    Ok(())
}


#[test]
fn powershell_names_its_file_with_the_script_extension() -> TestResult {
    let root = tempfile::tempdir()?;
    let launch = request(root.path(), Interpreter::Powershell, "Write-Output hi\n");
    match run(&launch) {
        Ok(_) | Err(ScriptError::NoInterpreter) => Ok(()),
        Err(error) => Err(error.into()),
    }
}


#[test]
fn kill_and_reader_failures_keep_their_cause() -> TestResult {
    let killed = ScriptError::from(rustix::io::Errno::PERM);
    assert!(matches!(&killed, ScriptError::Io { context, .. } if context.contains("kill")));
    assert!(std::error::Error::source(&killed).is_some());
    let stopped = ScriptError::from(std::sync::mpsc::RecvTimeoutError::Disconnected);
    assert!(matches!(&stopped, ScriptError::Io { context, .. } if context.contains("reader")));
    assert!(std::error::Error::source(&stopped).is_some());
    let held = ScriptError::from(std::sync::mpsc::RecvTimeoutError::Timeout);
    assert!(matches!(&held, ScriptError::Io { context, .. } if context.contains("held open")));
    assert!(matches!(tolerate_empty_group(Err(rustix::io::Errno::SRCH)), Ok(())));
    assert!(matches!(tolerate_empty_group(Ok(())), Ok(())));
    assert!(matches!(
        tolerate_empty_group(Err(rustix::io::Errno::PERM)),
        Err(ScriptError::Io { context, .. }) if context.contains("kill")
    ));
    Ok(())
}


fn non_utf8_name() -> OsString {
    OsString::from_vec(vec![b'o', INVALID_UTF8_BYTE, b'x'])
}


#[test]
fn non_utf8_paths_are_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    let base = std::fs::canonicalize(root.path())?;
    let allowed = base.join("allowed");
    std::fs::create_dir(&allowed)?;
    std::fs::write(allowed.join(non_utf8_name()), "x")?;
    symlink(allowed.join(non_utf8_name()), allowed.join("link.txt"))?;
    let manifest = path_manifest(utf8(&allowed)?);
    let params = params_of(vec![("target", text(utf8(&allowed.join("link.txt"))?))]);
    assert!(matches!(refusal(resolve_paths(&manifest, &params))?, ScriptError::MalformedPath(_)));
    let odd_root = base.join(non_utf8_name());
    std::fs::create_dir(&odd_root)?;
    let launch = request(&odd_root, Interpreter::Bash, "echo hi\n");
    assert!(matches!(refusal(run(&launch))?, ScriptError::MalformedPath(_)));
    Ok(())
}


#[test]
fn a_background_job_does_not_outlive_a_normal_exit() -> TestResult {
    let root = tempfile::tempdir()?;
    let script = "(sleep 20; echo late) &\necho early\nexit 0\n";
    let parent = own_cgroup_root()?;
    let mut launch = request(root.path(), Interpreter::Bash, script);
    launch.cgroup_root = parent.path.clone();
    let outcome = launch_script(&launch)?;
    assert!(!outcome.timed_out);
    assert_eq!(outcome.exit_code, Some(0));
    assert_eq!(output_text(&outcome), "early\n");
    Ok(())
}


#[test]
fn an_output_held_open_past_the_deadline_is_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("escaped");
    let script = format!(
        "setsid bash -c 'touch {0}; sleep 3' &\nfor i in $(seq 1 1000); do [ -e {0} ] || sleep 0.01; done\necho hi\n",
        marker.display()
    );
    let mut launch = request(root.path(), Interpreter::Bash, &script);
    launch.manifest.timeout_seconds = 1;
    launch.kill_grace = Duration::from_secs(1);
    let error = refusal(run(&launch))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("held open")));
    Ok(())
}


#[test]
fn a_script_that_cannot_be_placed_in_its_cgroup_is_killed_and_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let launch = request(root.path(), Interpreter::Bash, "sleep 300\n");
    let error = refusal(run_script(
        &launch,
        failing_wait,
        &CgroupOps {
            place: failing_place,
            ..FAKE_CGROUP
        },
    ))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("place")));
    Ok(())
}


#[test]
fn a_failing_cgroup_kill_is_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let launch = request(root.path(), Interpreter::Bash, "echo hi\n");
    let ops = CgroupOps {
        kill: failing_kill,
        ..FAKE_CGROUP
    };
    let error = refusal(run_script(&launch, wait_deadline, &ops))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("kill the script cgroup")));
    Ok(())
}


#[test]
fn an_unusable_cgroup_root_is_reported_and_nothing_is_left() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, "echo hi\n");
    launch.cgroup_root = root.path().join("absent");
    let error = refusal(run(&launch))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("create the script cgroup")));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    let failing = CgroupOps { check: fail, ..FAKE_CGROUP };
    assert!(matches!(
        refusal(run_script(&request(root.path(), Interpreter::Bash, "echo hi\n"), wait_deadline, &failing))?,
        ScriptError::Io { .. }
    ));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}


#[test]
fn a_plain_directory_as_cgroup_root_fails_closed_and_nothing_runs() -> TestResult {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("ran");
    let script = format!("touch {}\n", marker.display());
    let launch = request(root.path(), Interpreter::Bash, &script);
    assert!(matches!(refusal(launch_script(&launch))?, ScriptError::NotCgroupV2));
    assert!(!marker.exists());
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}


#[test]
fn the_wait_after_the_kill_has_a_deadline() -> TestResult {
    let mut stuck = Command::new("sleep").arg("300").spawn()?;
    let error = refusal(reap(&mut stuck, Duration::from_millis(SHORT_GRACE_MILLISECONDS), wait_deadline))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("still running")));
    let failed = refusal(reap(&mut stuck, Duration::from_secs(1), failing_wait))?;
    assert!(matches!(failed, ScriptError::Io { context, .. } if context.contains("reap")));
    stuck.kill()?;
    let status = reap(&mut stuck, Duration::from_secs(DEFAULT_KILL_GRACE_SECONDS), wait_deadline)?;
    assert_eq!(status.code(), None);
    Ok(())
}


pub const SHORT_GRACE_MILLISECONDS: u64 = 10;


pub const POLL_ATTEMPTS: u32 = 1000;


pub const POLL_MILLISECONDS: u64 = 10;


pub const SET_M_MARKER: &str = "31337";


pub const SETSID_MARKER: &str = "31338";


fn job_alive(marker: &str) -> bool {
    let needle = format!("sleep\0{marker}\0");
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|entry| std::fs::read(entry.path().join("cmdline")))
        .any(|cmdline| String::from_utf8_lossy(&cmdline).contains(&needle))
}


fn poll_until(condition: impl Fn() -> bool) -> bool {
    (0..POLL_ATTEMPTS).any(|_attempt| {
        let done = condition();
        if !done {
            std::thread::sleep(Duration::from_millis(POLL_MILLISECONDS));
        }
        done
    })
}


fn wait_for_set_m_job(_child: &mut Child, _deadline: Duration) -> io::Result<Option<ExitStatus>> {
    poll_until(|| job_alive(SET_M_MARKER));
    Ok(None)
}


fn wait_for_setsid_job(_child: &mut Child, _deadline: Duration) -> io::Result<Option<ExitStatus>> {
    poll_until(|| job_alive(SETSID_MARKER));
    Ok(None)
}


pub const CONTROLLERS: &str = "+cpu +memory +pids";


/// An empty cgroup below the test process's own, with the controllers enabled for its children; removed when dropped.
struct ParentCgroup {
    path: std::path::PathBuf,
}


impl Drop for ParentCgroup {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir(&self.path) {
            tracing::warn!(%error, "cannot remove the test cgroup");
        }
    }
}


fn own_cgroup_root() -> Result<ParentCgroup, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    let probe = script_library::fsdir::random_name()?;
    let own = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|relative| Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
        .ok_or("this host has no cgroup v2 hierarchy: the confinement tests cannot run")?;
    let found = own.ancestors().take(ANCESTOR_LEVELS).try_fold(String::new(), |failures, base| {
        enable_controllers(&base.join(&probe)).map_or_else(|error| Ok(format!("{failures} {}: {error};", base.display())), Err)
    });
    match found {
        Err(parent) => Ok(parent),
        Ok(failures) => Err(format!("no writable cgroup v2 with {CONTROLLERS} for the confinement tests:{failures}").into()),
    }
}


pub const ANCESTOR_LEVELS: usize = 3;


/// A cgroup with no process can enable controllers for its children, the test process's own cannot: the first ancestor that allows it wins.
fn enable_controllers(path: &Path) -> io::Result<ParentCgroup> {
    let parent = ParentCgroup { path: path.to_path_buf() };
    std::fs::create_dir(&parent.path)?;
    std::fs::write(parent.path.join("cgroup.subtree_control"), CONTROLLERS)?;
    Ok(parent)
}


fn escaping_job_is_killed(script: &str, marker: &str, wait: script_library::types::WaitFn) -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, script);
    let parent = own_cgroup_root()?;
    launch.cgroup_root = parent.path.clone();
    let outcome = run_script(&launch, wait, &SYSTEM_CGROUP)?;
    assert!(outcome.timed_out);
    assert!(poll_until(|| !job_alive(marker)), "the job survived the deadline");
    Ok(())
}


#[test]
fn a_set_m_job_is_killed_at_the_deadline() -> TestResult {
    escaping_job_is_killed("set -m\nsleep 31337 &\nwait\n", SET_M_MARKER, wait_for_set_m_job)
}


#[test]
fn the_script_runs_in_its_cgroup_from_its_first_instruction() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, "cat /proc/self/cgroup\n");
    let parent = own_cgroup_root()?;
    launch.cgroup_root = parent.path.clone();
    let shown = output_text(&launch_script(&launch)?);
    assert!(shown.contains("/cg-script-"), "{shown}");
    Ok(())
}


#[test]
fn a_setsid_job_is_killed_at_the_deadline() -> TestResult {
    escaping_job_is_killed("setsid sleep 31338 &\nwait\n", SETSID_MARKER, wait_for_setsid_job)
}


pub const SECRET: &str = "tok-4242";


pub const SECRET_LINES: usize = 2;


pub const REDACTED: &str = "[REDACTED]";


pub const GENEROUS_CAP: u64 = 4096;


pub const NOBODY: u32 = 65534;


pub const SEARCHABLE: u32 = 0o711;


pub const MEMORY_LIMIT: u64 = 33_554_432;


pub const PIDS_LIMIT: u64 = 8;


pub const CPU_PERCENT: u64 = 50;


pub const FORK_BOMB: &str = "import os, time\nfor i in range(64):\n    try:\n        pid = os.fork()\n    except OSError:\n        print('refused')\n        break\n    if pid == 0:\n        time.sleep(30)\n        os._exit(0)\n";


struct OneByteAtATime {
    data: Vec<u8>,
    position: usize,
}


impl Read for OneByteAtATime {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let next = self.data.get(self.position).copied();
        self.position += 1;
        next.zip(buffer.first_mut()).map_or(Ok(0), |(byte, slot)| {
            *slot = byte;
            Ok(1)
        })
    }
}


#[test]
fn a_secret_split_across_read_chunks_is_redacted() -> TestResult {
    let pattern = compile_secret_pattern("tok-[0-9]+")?;
    let source = OneByteAtATime {
        data: format!("a {SECRET} b").into_bytes(),
        position: 0,
    };
    let captured = capture(source, GENEROUS_CAP, &[pattern])?;
    assert_eq!(String::from_utf8(captured.bytes)?, format!("a {REDACTED} b"));
    assert_eq!(captured.dropped, 0);
    Ok(())
}


#[test]
fn a_secret_straddling_the_cap_leaves_no_prefix_of_itself() -> TestResult {
    let pattern = compile_secret_pattern("tok-[0-9]+")?;
    let text = format!("{}{SECRET}", "a".repeat(SMALL_CAP as usize - SECRET_PREFIX));
    let captured = capture(text.as_bytes(), SMALL_CAP, &[pattern])?;
    assert!(!String::from_utf8(captured.bytes.clone())?.contains("tok"));
    assert_eq!(captured.bytes.len(), SMALL_CAP as usize);
    assert_eq!(captured.dropped, (SMALL_CAP as usize - SECRET_PREFIX + REDACTED.len()) as u64 - SMALL_CAP);
    Ok(())
}


pub const SECRET_PREFIX: usize = 3;


#[test]
fn declared_secrets_never_leave_the_launcher() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, &format!("echo key {SECRET}\necho again {SECRET} >&2\n"));
    launch.manifest.secret_patterns = vec!["tok-[0-9]+".to_string()];
    let shown = output_text(&run(&launch)?);
    assert!(!shown.contains(SECRET));
    assert_eq!(shown.matches(REDACTED).count(), SECRET_LINES);
    launch.manifest.secret_patterns = vec!["(".to_string()];
    assert!(matches!(refusal(run(&launch))?, ScriptError::Pattern(_)));
    Ok(())
}


#[test]
fn a_limit_that_cannot_be_applied_stops_the_run_and_a_hit_is_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let launch = request(root.path(), Interpreter::Bash, "echo hi\n");
    let failing = CgroupOps {
        limit: failing_limit,
        ..FAKE_CGROUP
    };
    let error = refusal(run_script(&launch, wait_deadline, &failing))?;
    assert!(matches!(error, ScriptError::Io { context, .. } if context.contains("limits")));
    let hit = CgroupOps {
        events: memory_events,
        ..FAKE_CGROUP
    };
    assert_eq!(run_script(&launch, wait_deadline, &hit)?.limit_hit, Some(LimitHit::Memory));
    assert_eq!(run(&launch)?.limit_hit, None);
    let unreadable = CgroupOps {
        events: failing_events,
        ..FAKE_CGROUP
    };
    let unread = refusal(run_script(&launch, wait_deadline, &unreadable))?;
    assert!(matches!(unread, ScriptError::Io { context, .. } if context.contains("events")));
    Ok(())
}


fn sibling_cgroup(parent: &ParentCgroup) -> io::Result<ParentCgroup> {
    let sibling = ParentCgroup {
        path: parent.path.join("sibling"),
    };
    std::fs::create_dir(&sibling.path)?;
    Ok(sibling)
}


fn cgroup_leaves(parent: &ParentCgroup) -> io::Result<usize> {
    Ok(std::fs::read_dir(&parent.path)?
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("cg-"))
        .count())
}


fn limited_launch(root: &Path, parent: &ParentCgroup, interpreter: Interpreter, script: &str) -> LaunchRequest {
    let mut launch = request(root, interpreter, script);
    launch.cgroup_root = parent.path.clone();
    launch.manifest.limits = Limits {
        memory_bytes: MEMORY_LIMIT,
        pids: PIDS_LIMIT,
        cpu_percent: Some(CPU_PERCENT),
    };
    launch.manifest.timeout_seconds = LIMITED_TIMEOUT_SECONDS;
    launch
}


pub const LIMITED_TIMEOUT_SECONDS: u64 = 30;


#[test]
fn the_limits_are_written_to_the_run_cgroup() -> TestResult {
    let root = tempfile::tempdir()?;
    let parent = own_cgroup_root()?;
    let script = "d=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)\ncat $d/memory.max $d/pids.max $d/cpu.max $d/memory.swap.max\n";
    let launch = limited_launch(root.path(), &parent, Interpreter::Bash, script);
    let outcome = launch_script(&launch)?;
    assert_eq!(outcome.limit_hit, None);
    assert_eq!(output_text(&outcome), format!("{MEMORY_LIMIT}\n{PIDS_LIMIT}\n50000 100000\n0\n"));
    assert_eq!(cgroup_leaves(&parent)?, 0);
    Ok(())
}


#[test]
fn a_run_that_outgrows_its_memory_limit_is_killed_and_reported() -> TestResult {
    let root = tempfile::tempdir()?;
    let parent = own_cgroup_root()?;
    let launch = limited_launch(root.path(), &parent, Interpreter::Bash, "head -c 1073741824 /dev/zero | tail -n 1\n");
    let outcome = launch_script(&launch)?;
    assert_eq!(outcome.limit_hit, Some(LimitHit::Memory));
    assert!(!outcome.timed_out);
    Ok(())
}


#[test]
fn a_fork_bomb_is_stopped_by_the_pids_limit_and_nothing_survives() -> TestResult {
    let root = tempfile::tempdir()?;
    let parent = own_cgroup_root()?;
    let launch = limited_launch(root.path(), &parent, Interpreter::Python, FORK_BOMB);
    let outcome = launch_script(&launch)?;
    assert_eq!(output_text(&outcome), "refused\n");
    assert_eq!(outcome.limit_hit, Some(LimitHit::Pids));
    assert_eq!(cgroup_leaves(&parent)?, 0);
    Ok(())
}


#[test]
fn a_script_run_as_another_user_cannot_leave_its_cgroup() -> TestResult {
    let root = tempfile::tempdir()?;
    std::fs::set_permissions(root.path(), std::os::unix::fs::PermissionsExt::from_mode(SEARCHABLE))?;
    let parent = own_cgroup_root()?;
    let sibling = sibling_cgroup(&parent)?;
    let script = format!(
        "id -u\necho $$ > {0}/cgroup.procs && echo escaped || echo denied\necho kill > {0}/cgroup.kill && echo killed || echo kept\n",
        sibling.path.display()
    );
    let mut launch = limited_launch(root.path(), &parent, Interpreter::Bash, &script);
    launch.run_as = Some(RunAs { uid: NOBODY, gid: NOBODY });
    let outcome = launch_script(&launch)?;
    assert!(output_text(&outcome).starts_with(&format!("{NOBODY}\n")), "{}", output_text(&outcome));
    assert!(output_text(&outcome).contains("denied"));
    assert!(output_text(&outcome).contains("kept"));
    assert!(!output_text(&outcome).contains("escaped"));
    assert_eq!(cgroup_leaves(&parent)?, 0);
    Ok(())
}


#[test]
fn a_script_run_as_the_agent_user_can_still_move_itself_out() -> TestResult {
    let root = tempfile::tempdir()?;
    let parent = own_cgroup_root()?;
    let sibling = sibling_cgroup(&parent)?;
    let script = format!("echo $$ > {}/cgroup.procs && echo escaped || echo denied\n", sibling.path.display());
    let launch = limited_launch(root.path(), &parent, Interpreter::Bash, &script);
    assert!(output_text(&launch_script(&launch)?).contains("escaped"));
    Ok(())
}


#[test]
fn files_are_handed_to_the_script_user_before_the_bytes_are_written() -> TestResult {
    let root = tempfile::tempdir()?;
    let mut launch = request(root.path(), Interpreter::Bash, "echo hi\n");
    launch.run_as = Some(RunAs {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
    });
    assert_eq!(output_text(&run(&launch)?), "hi\n");
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    Ok(())
}
