#![cfg(unix)]

#[path = "common/types.rs"]
mod types;


use sbom::error::{RunError, SbomError, SettingsError, TargetError};
use sbom::model::Stderr;
use sbom::run::{child_environment, drain_stderr, generate, stderr_excerpt};
use sbom::settings::{SyftSettings, Target};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/syft-debian.cdx.json");


const FIXTURE_COMPONENTS: usize = 7;


const SCRIPT_MODE: u32 = 0o755;


const DEADLINE_MILLIS: u64 = 200;


const LONG_DEADLINE_MILLIS: u64 = 60_000;


const MAX_STDOUT: usize = 1_048_576;


const SMALL_STDOUT: usize = 100;


const MAX_COMPONENTS: usize = 5;


const STDERR_CAP: usize = 1000;


const FLOOD_BYTES: &str = "5000000";


const EXIT_CODE: i32 = 3;


const LONG_STDERR: usize = 1000;


const DOUBLE_STDERR: usize = 2000;


const DOUBLE_EXCERPT: usize = 512;


fn fake_syft(dir: &TempDir, body: &str) -> io::Result<PathBuf> {
    let path = dir.path().join("syft");
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(SCRIPT_MODE))?;
    Ok(path)
}


fn settings(dir: &TempDir, binary: PathBuf, deadline_millis: u64) -> SyftSettings {
    SyftSettings {
        binary,
        work_dir: dir.path().to_path_buf(),
        deadline_millis,
        max_stdout_bytes: MAX_STDOUT,
        max_components: MAX_COMPONENTS * MAX_COMPONENTS,
        max_stderr_bytes: STDERR_CAP,
    }
}


fn target() -> Target {
    Target::Directory(PathBuf::from("/srv/tree"))
}


const TEXT_FILE_BUSY: i32 = 26;


const BUSY_RETRIES: usize = 20;


fn run_once(settings: &SyftSettings) -> Result<sbom::model::Sbom, RunError> {
    generate(settings, &target(), "tenant-a", "web:1.0")
}


fn run(settings: &SyftSettings) -> Result<sbom::model::Sbom, RunError> {
    (0..BUSY_RETRIES).fold(run_once(settings), |result, _| match result {
        Err(RunError::Io(error)) if error.raw_os_error() == Some(TEXT_FILE_BUSY) => run_once(settings),
        other => other,
    })
}


#[test]
fn good_run_parses_fixture_and_carries_scope() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'"))?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    assert_eq!(sbom.components.len(), FIXTURE_COMPONENTS);
    assert_eq!(sbom.tenant, "tenant-a");
    assert_eq!(sbom.artefact, "web:1.0");
    Ok(())
}


#[test]
fn arguments_are_separate_and_typed() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$*\"")?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let name = sbom.components.first().map(|component| component.name.as_str());
    assert_eq!(name, Some("scan -o cyclonedx-json dir:/srv/tree"));
    Ok(())
}


#[test]
fn environment_is_cleared_and_explicit() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":[{\"name\":\"%s\"}]}' \"$(env | sort | tr '\\n' ' ')\"")?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    let seen = sbom
        .components
        .first()
        .map(|component| component.name.to_lowercase())
        .ok_or("no component")?;
    assert!(seen.contains("syft_check_for_app_update=false"));
    assert!(seen.contains("home="));
    assert!(!seen.contains("proxy"));
    assert!(!seen.contains("cargo"));
    Ok(())
}


#[test]
fn environment_names_are_fixed() -> TestResult {
    let names: Vec<String> = child_environment(Path::new("/w/h")).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names, ["HOME", "XDG_CACHE_HOME", "SYFT_CACHE_DIR", "TMPDIR", "SYFT_CHECK_FOR_APP_UPDATE"]);
    Ok(())
}


#[test]
fn oversized_output_is_too_large() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'"))?;
    let mut limited = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    limited.max_stdout_bytes = SMALL_STDOUT;
    let result = run(&limited);
    assert!(matches!(result, Err(RunError::Sbom(SbomError::TooLarge { .. }))));
    Ok(())
}


#[test]
fn endless_output_stops_at_the_component_cap() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "printf '{\"components\":['\nexec yes '{\"name\":\"a\"},'")?;
    let mut limited = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    limited.max_components = MAX_COMPONENTS;
    let result = run(&limited);
    assert!(matches!(result, Err(RunError::Sbom(SbomError::TooMany { .. }))));
    Ok(())
}


#[test]
fn silent_hang_is_killed_at_the_deadline() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "exec sleep 3600")?;
    let result = run(&settings(&dir, binary, DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::TimedOut)));
    Ok(())
}


#[test]
fn background_holder_of_the_pipe_dies_with_the_group() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "sleep 3600 &\nwait")?;
    let result = run(&settings(&dir, binary, DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::TimedOut)));
    Ok(())
}


#[test]
fn non_zero_exit_is_typed() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("cat '{FIXTURE}'\nexit {EXIT_CODE}"))?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Failed { code: Some(EXIT_CODE) })));
    Ok(())
}


#[test]
fn garbage_output_is_a_parse_error() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "echo nonsense")?;
    let result = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Sbom(_))));
    Ok(())
}


#[test]
fn stderr_flood_is_drained_and_capped() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, &format!("yes noise | head -c {FLOOD_BYTES} >&2\ncat '{FIXTURE}'"))?;
    let sbom = run(&settings(&dir, binary, LONG_DEADLINE_MILLIS))?;
    assert_eq!(sbom.components.len(), FIXTURE_COMPONENTS);
    Ok(())
}


#[test]
fn drain_keeps_the_cap_and_counts_the_rest() -> TestResult {
    let data = vec![b'x'; DOUBLE_STDERR];
    let drained = drain_stderr(data.as_slice(), STDERR_CAP)?;
    assert_eq!(drained.kept.len(), STDERR_CAP);
    assert_eq!(drained.total, u64::try_from(DOUBLE_STDERR)?);
    Ok(())
}


#[test]
fn excerpt_is_bounded_and_escaped() -> TestResult {
    let mut kept = b"line\nnext\x1b[31m".to_vec();
    kept.extend(vec![b'y'; LONG_STDERR]);
    let excerpt = stderr_excerpt(&Stderr { kept, total: 0 });
    assert!(excerpt.starts_with("line\\nnext\\u{1b}[31m"));
    assert!(excerpt.len() <= DOUBLE_EXCERPT);
    Ok(())
}


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}


#[test]
fn drain_reports_a_read_failure() -> TestResult {
    assert!(drain_stderr(Failing, STDERR_CAP).is_err());
    Ok(())
}


#[test]
fn refused_targets_never_spawn() -> TestResult {
    let dir = TempDir::new()?;
    let absent = dir.path().join("absent");
    let configured = settings(&dir, absent, LONG_DEADLINE_MILLIS);
    let relative = generate(&configured, &Target::Directory(PathBuf::from("tree")), "t", "a");
    assert!(matches!(relative, Err(RunError::Target(TargetError::Relative))));
    let dash = generate(&configured, &Target::OciArchive(PathBuf::from("-x")), "t", "a");
    assert!(matches!(dash, Err(RunError::Target(TargetError::LeadingDash))));
    let control = generate(&configured, &Target::DockerArchive(PathBuf::from("/a\nb")), "t", "a");
    assert!(matches!(control, Err(RunError::Target(TargetError::Control))));
    Ok(())
}


#[test]
fn invalid_settings_are_refused() -> TestResult {
    let dir = TempDir::new()?;
    let mut bad = settings(&dir, PathBuf::from("syft"), LONG_DEADLINE_MILLIS);
    bad.binary = PathBuf::from("relative-syft");
    assert!(matches!(run(&bad), Err(RunError::Settings(SettingsError::Invalid("binary")))));
    Ok(())
}


#[test]
fn binary_must_exist_and_be_a_regular_file() -> TestResult {
    let dir = TempDir::new()?;
    let missing = run(&settings(&dir, dir.path().join("absent"), LONG_DEADLINE_MILLIS));
    assert!(matches!(missing, Err(RunError::Io(_))));
    let directory = run(&settings(&dir, dir.path().to_path_buf(), LONG_DEADLINE_MILLIS));
    assert!(matches!(directory, Err(RunError::NotRegular)));
    Ok(())
}


#[test]
fn non_executable_binary_fails_to_spawn() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("plain");
    fs::write(&path, "x")?;
    let result = run(&settings(&dir, path, LONG_DEADLINE_MILLIS));
    assert!(matches!(result, Err(RunError::Io(_))));
    Ok(())
}


#[test]
fn missing_work_directory_is_an_io_error() -> TestResult {
    let dir = TempDir::new()?;
    let binary = fake_syft(&dir, "exit 0")?;
    let mut configured = settings(&dir, binary, LONG_DEADLINE_MILLIS);
    configured.work_dir = dir.path().join("no-such-dir");
    assert!(matches!(run(&configured), Err(RunError::Io(_))));
    Ok(())
}
