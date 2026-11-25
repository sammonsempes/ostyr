#![cfg(unix)]
use backup_monitor::check::{previous_borg, previous_restic, run_round, CheckError, RepositoryCheck, RoundContext, RoundOutcome};
use backup_monitor::declarations::load_declarations;
use backup_monitor::model::{CoverageStatus, Declarations, FindingKind, Limits};
use backup_monitor::report::report_directory;
use backup_monitor::restic::{run_raw, ResticError};
use backup_monitor::secrets::{open_secrets_dir, SecretsDir};
use std::error::Error;
use std::fs::{create_dir, set_permissions, Permissions};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use time::macros::datetime;
use time::OffsetDateTime;
use tracing::Dispatch;


const RESTIC_SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-restic.sh");


const BORG_SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-borg.sh");


const CURRENT: &str = include_str!("fixtures/restic-current.json");


const CONFIG_ID: &str = "8ff9e8256a6089f1357840c0fc88b498c541e8948af3317219d4117ce4243ab5";


const OTHER_ID: &str = "66ebcb4aeb0ca5efc7d8211023adf4e91c6d815eed0da5d39a1385a9f725805a";


const BORG_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";


const ARCHIVE_ID: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";


const NOW: OffsetDateTime = datetime!(2026-11-20 00:00 UTC);


const PRIVATE_MODE: u32 = 0o700;


const SECRET_MODE: u32 = 0o600;


const SCRIPT_MODE: &str = "755";


const PATIENT: Duration = Duration::from_secs(120);


const REPOSITORY_COUNT: usize = 3;


const FIRST: usize = 0;


const SECOND: usize = 1;


const THIRD: usize = 2;


const MARKER_BYTES: usize = 3000;


const TEXT_MARKERS: [&str; 4] = ["LOCMARKER", "PWFILEMARKER", "PASSMARKER", "LISTMARKER"];


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


const DECLARATIONS: &str = "tenant: acme\ncritical:\n  - host: web1\n    max_age_hours: 8760\nrepositories:\n  - repository: alpha\n    expected_min_snapshots: 1\n    \
                            restic:\n      location: /srv/alpha\n      password_file: password\n  - repository: beta\n    expected_min_snapshots: 1\n    restic:\n      \
                            location: /srv/beta\n      password_file: password\n  - repository: gamma\n    expected_min_snapshots: 1\n    borg:\n      \
                            location: ssh://bk@localhost/srv/gamma\n      passphrase_file: passphrase\n";


struct CaptureWriter(Arc<Mutex<Vec<u8>>>);


impl io::Write for CaptureWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_poisoned| io::Error::other("poisoned"))?.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct Setup {
    dir: TempDir,
    restic: PathBuf,
    borg: PathBuf,
    state: PathBuf,
    secrets: SecretsDir,
    reports: OwnedFd,
    declarations: Declarations,
}


fn clock() -> OffsetDateTime {
    NOW
}


fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn install(script: &str, directory: &Path, name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let program = directory.join(name);
    let installed = Command::new("install").arg("-m").arg(SCRIPT_MODE).arg(script).arg(&program).status()?;
    assert!(installed.success());
    Ok(program)
}


fn secret(directory: &Path, name: &str, text: &str) -> Result<(), Box<dyn Error>> {
    let path = directory.join(name);
    std::fs::write(&path, text)?;
    set_permissions(&path, Permissions::from_mode(SECRET_MODE))?;
    Ok(())
}


fn setup(text: &str) -> Result<Setup, Box<dyn Error>> {
    LazyLock::force(&ANCHOR);
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    set_permissions(dir.path(), Permissions::from_mode(PRIVATE_MODE))?;
    let restic_dir = dir.path().join("restic");
    let borg_dir = dir.path().join("borg");
    let secrets_dir = dir.path().join("secrets");
    let state = dir.path().join("state");
    [&restic_dir, &borg_dir, &secrets_dir, &state].iter().try_for_each(create_dir)?;
    set_permissions(&secrets_dir, Permissions::from_mode(PRIVATE_MODE))?;
    let restic = install(RESTIC_SCRIPT, &restic_dir, "restic")?;
    let borg = install(BORG_SCRIPT, &borg_dir, "borg")?;
    std::fs::write(restic_dir.join("mode"), "ok")?;
    std::fs::write(restic_dir.join("config.json"), format!("{{\"version\":2,\"id\":\"{CONFIG_ID}\"}}"))?;
    std::fs::write(restic_dir.join("snapshots.json"), CURRENT)?;
    std::fs::write(borg_dir.join("mode"), "ok")?;
    std::fs::write(
        borg_dir.join("list.json"),
        format!("{{\"repository\":{{\"id\":\"{BORG_ID}\"}},\"archives\":[{{\"name\":\"srv1-1\",\"id\":\"{ARCHIVE_ID}\",\"time\":\"2026-11-12T13:30:39.000000\"}}]}}"),
    )?;
    secret(&secrets_dir, "password", "hunter2\n")?;
    secret(&secrets_dir, "passphrase", "correct horse\n")?;
    let declarations = load_declarations(text, "d.yaml")?;
    let secrets = open_secrets_dir(&secrets_dir, euid())?;
    let reports = report_directory(&state, &declarations.tenant, euid())?;
    Ok(Setup {
        dir,
        restic,
        borg,
        state,
        secrets,
        reports,
        declarations,
    })
}


fn round(setup: &Setup) -> RoundOutcome {
    let limits = Limits::default();
    let context = RoundContext {
        restic_program: &setup.restic,
        borg_program: &setup.borg,
        secrets: &setup.secrets,
        state: Some(&setup.state),
        reports: Some(&setup.reports),
        limits: &limits,
        deadline: PATIENT,
        euid: euid(),
        clock,
    };
    run_round(&context, &setup.declarations)
}


fn report_path(setup: &Setup, name: &str) -> PathBuf {
    setup.state.join("reports").join("acme").join(name)
}


fn check(outcome: &RoundOutcome, index: usize) -> Result<&RepositoryCheck, Box<dyn Error>> {
    let (_, result) = outcome.repositories.get(index).ok_or("no repository")?;
    Ok(result.as_ref().map_err(|error| error.to_string())?)
}


fn failure(outcome: &RoundOutcome, index: usize) -> Result<&CheckError, Box<dyn Error>> {
    let (_, result) = outcome.repositories.get(index).ok_or("no repository")?;
    result.as_ref().err().ok_or_else(|| "the repository succeeded".into())
}


fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |link: &&(dyn Error + 'static)| (**link).source())
        .map(|link| format!("{link} {link:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}


#[test]
fn a_round_checks_every_repository_and_keeps_the_reports() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    let first = round(&setup);
    assert_eq!(first.repositories.len(), REPOSITORY_COUNT);
    let names: Vec<&str> = first.repositories.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    [FIRST, SECOND, THIRD].iter().try_for_each(|index| -> Result<(), Box<dyn Error>> {
        let found = check(&first, *index)?;
        assert!(!found.previous_unreadable && found.findings.is_empty());
        Ok(())
    })?;
    assert_eq!(check(&first, FIRST)?.listing.repository, CONFIG_ID);
    assert_eq!(check(&first, THIRD)?.listing.repository, BORG_ID);
    assert!(first.refused_restic.is_empty() && first.refused_borg.is_empty());
    assert!(matches!(first.coverage.first().map(|entry| &entry.status), Some(CoverageStatus::Ok)));
    ["alpha.restic.id", "alpha.restic.snapshots", "beta.restic.id", "gamma.borg.snapshots"]
        .iter()
        .for_each(|name| assert!(report_path(&setup, name).is_file(), "{name}"));
    let second = round(&setup);
    assert!(!check(&second, FIRST)?.previous_unreadable && !check(&second, THIRD)?.previous_unreadable);
    assert!(second
        .repositories
        .iter()
        .all(|(_, result)| result.as_ref().is_ok_and(|found| found.findings.is_empty())));
    Ok(())
}


#[test]
fn a_replaced_repository_is_a_finding_against_the_previous_report() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    round(&setup);
    std::fs::write(
        setup.dir.path().join("restic").join("config.json"),
        format!("{{\"version\":2,\"id\":\"{OTHER_ID}\"}}"),
    )?;
    let second = round(&setup);
    assert!(check(&second, FIRST)?
        .findings
        .iter()
        .any(|finding| matches!(&finding.kind, FindingKind::RepositoryChanged { .. })));
    Ok(())
}


#[test]
fn a_planted_symlink_report_fails_only_that_repository() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    round(&setup);
    let planted = report_path(&setup, "beta.restic.snapshots");
    std::fs::remove_file(&planted)?;
    symlink("/etc/hostname", &planted)?;
    let second = round(&setup);
    assert!(check(&second, FIRST).is_ok() && check(&second, THIRD).is_ok());
    let error = failure(&second, SECOND)?;
    assert!(matches!(error, CheckError::Report(_)), "{error:?}");
    assert!(!chain(error).contains("/etc/hostname"));
    Ok(())
}


#[test]
fn a_report_that_cannot_be_written_fails_only_that_repository() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    create_dir(report_path(&setup, ".alpha.restic.snapshots.tmp"))?;
    create_dir(report_path(&setup, ".gamma.borg.snapshots.tmp"))?;
    let outcome = round(&setup);
    assert!(matches!(failure(&outcome, FIRST)?, CheckError::Report(_)));
    assert!(check(&outcome, SECOND).is_ok());
    assert!(matches!(failure(&outcome, THIRD)?, CheckError::Report(_)));
    Ok(())
}


#[test]
fn a_corrupt_or_half_written_previous_report_is_previous_unreadable_and_replaced() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    round(&setup);
    std::fs::write(report_path(&setup, "alpha.restic.snapshots"), "not json")?;
    std::fs::remove_file(report_path(&setup, "beta.restic.id"))?;
    std::fs::write(report_path(&setup, "gamma.borg.snapshots"), "{\"archives\":3}")?;
    let second = round(&setup);
    [FIRST, SECOND, THIRD].iter().try_for_each(|index| -> Result<(), Box<dyn Error>> {
        let found = check(&second, *index)?;
        assert!(found.previous_unreadable && found.findings.is_empty());
        Ok(())
    })?;
    let third = round(&setup);
    assert!(third
        .repositories
        .iter()
        .all(|(_, result)| result.as_ref().is_ok_and(|found| !found.previous_unreadable)));
    Ok(())
}


#[test]
fn a_bad_password_file_name_fails_only_its_repository() -> Result<(), Box<dyn Error>> {
    let text = DECLARATIONS.replacen("password_file: password", "password_file: absent", 1);
    let setup = setup(&text)?;
    let outcome = round(&setup);
    assert!(matches!(failure(&outcome, FIRST)?, CheckError::Restic(ResticError::PasswordFile)));
    assert!(check(&outcome, SECOND).is_ok() && check(&outcome, THIRD).is_ok());
    assert!(!report_path(&setup, "alpha.restic.id").exists());
    Ok(())
}


#[test]
fn names_with_a_separator_or_dots_are_refused_by_name_before_any_spawn() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    std::fs::create_dir(setup.dir.path().join("secrets").join("sub"))?;
    secret(&setup.dir.path().join("secrets").join("sub"), "password", "hunter2\n")?;
    secret(setup.dir.path(), "outside", "hunter2\n")?;
    let source = |name: &str| backup_monitor::model::ResticSource {
        location: "/srv/alpha".to_owned(),
        password_file: name.to_owned(),
    };
    ["sub/password", "../outside", "..", ".", "", "password/", "/etc/passwd", "pass word", "a."]
        .iter()
        .for_each(|name| {
            let outcome = run_raw(
                &setup.restic,
                &setup.secrets,
                &source(name),
                &Limits::default(),
                PATIENT,
                rustix::process::geteuid().as_raw(),
            );
            assert!(matches!(outcome, Err(ResticError::Refused)), "{name}");
        });
    assert!(!setup.dir.path().join("restic").join("args").exists());
    let text = DECLARATIONS
        .replace("password_file: password", "password_file: ../outside")
        .replace("passphrase_file: passphrase", "passphrase_file: sub/passphrase");
    let hostile = Setup {
        declarations: load_declarations(&text, "d.yaml")?,
        ..setup
    };
    let outcome = round(&hostile);
    assert_eq!(outcome.refused_restic, vec![FIRST, SECOND]);
    assert_eq!(outcome.refused_borg, vec![THIRD]);
    assert!(outcome.repositories.is_empty());
    Ok(())
}


#[test]
fn without_a_state_directory_borg_is_a_named_failure_and_restic_still_runs() -> Result<(), Box<dyn Error>> {
    let setup = setup(DECLARATIONS)?;
    let limits = Limits::default();
    let context = RoundContext {
        restic_program: &setup.restic,
        borg_program: &setup.borg,
        secrets: &setup.secrets,
        state: None,
        reports: None,
        limits: &limits,
        deadline: PATIENT,
        euid: euid(),
        clock,
    };
    let outcome = run_round(&context, &setup.declarations);
    assert!(check(&outcome, FIRST)?.findings.is_empty() && check(&outcome, SECOND).is_ok());
    assert!(matches!(failure(&outcome, THIRD)?, CheckError::NoStateDirectory));
    assert!(!report_path(&setup, "alpha.restic.id").exists());
    assert_eq!(previous_restic(None, "alpha", euid(), &limits)?.listing, None);
    assert_eq!(previous_borg(None, "alpha", &borg_source(), euid(), &limits)?.listing, None);
    Ok(())
}


fn borg_source() -> backup_monitor::model::BorgSource {
    backup_monitor::model::BorgSource {
        location: "ssh://bk@localhost/srv/x".to_owned(),
        passphrase_file: "passphrase".to_owned(),
        hostname_from_name: false,
    }
}


#[test]
fn a_hostile_repository_leaves_no_marker_in_the_log_or_any_error() -> Result<(), Box<dyn Error>> {
    let text = "tenant: acme\nrepositories:\n  - repository: absent\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/LOCMARKER\n      \
                password_file: PWFILEMARKER\n  - repository: hostile\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/LOCMARKER\n      \
                password_file: password\n  - repository: borgless\n    expected_min_snapshots: 1\n    borg:\n      location: ssh://bk@localhost/srv/LOCMARKER\n      \
                passphrase_file: PASSMARKER\n";
    let setup = setup(text)?;
    let marker = "LISTMARKER".repeat(MARKER_BYTES);
    std::fs::write(setup.dir.path().join("restic").join("snapshots.json"), format!("{{\"x\":\"{marker}\"}}"))?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || CaptureWriter(Arc::clone(&sink)))
            .finish(),
    );
    let outcome = tracing::dispatcher::with_default(&dispatch, || round(&setup));
    let log = String::from_utf8(captured.lock().map_err(|_poisoned| "poisoned")?.clone())?;
    assert!(log.contains("repository check failed") && log.contains("secret file refused"), "{log}");
    assert!(log.contains("absent") && log.contains("hostile"));
    let errors: String = outcome
        .repositories
        .iter()
        .filter_map(|(_, result)| result.as_ref().err())
        .map(|error| chain(error))
        .collect();
    assert_eq!(
        outcome.repositories.iter().filter(|(_, result)| result.is_err()).count(),
        REPOSITORY_COUNT
    );
    TEXT_MARKERS
        .iter()
        .for_each(|text_marker| assert!(!log.contains(text_marker) && !errors.contains(text_marker), "{text_marker}"));
    Ok(())
}
