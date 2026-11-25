#![cfg(target_os = "linux")]

use core_audit::tenant::AUDIT_TENANT;
use signal_hook::consts::SIGHUP;
use signal_hook::low_level::raise;
use std::error::Error;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::Duration;
use waf::apply::{check_settings, check_start_only, render_applied};
use waf::error::ServeError;
use waf::model::{ApplySettings, CommandStatus};
use waf::serve::{check_audit_path, error_line, exit_code, open_sink, parse_args, serve_with_program, service_context};


const ONE_ROUTE: &str = "routes:\n  - hosts: [a.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const MARKER_ROUTE: &str = "routes:\n  - hosts: [marker-host.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const BAD_TLS_ROUTE: &str = "tls:\n  issuer: nothing\nroutes:\n  - hosts: [a.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const OPEN_DIRECTORY: u32 = 0o755;


const POLL_ATTEMPTS: usize = 3_000;


const POLL_STEP: Duration = Duration::from_millis(10);


const TWO_CALLS: usize = 2;


const FOUR_CALLS: usize = 4;


struct Fixture {
    dir: tempfile::TempDir,
    settings_file: PathBuf,
    program: PathBuf,
    routes: PathBuf,
}


fn settings_text(dir: &Path, audit: &str) -> String {
    format!(
        "routes_file: {0}/routes.yaml\nout_dir: {0}/out\nadmin_socket: {0}/admin/sock\naudit_file: {1}\n",
        dir.display(),
        audit
    )
}


fn fixture_with(settings_for: &dyn Fn(&Path) -> String) -> Result<Fixture, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let routes = dir.path().join("routes.yaml");
    fs::write(&routes, ONE_ROUTE)?;
    ["out", "admin"].iter().try_for_each(|name| -> io::Result<()> {
        fs::create_dir(dir.path().join(name))?;
        fs::set_permissions(dir.path().join(name), fs::Permissions::from_mode(OPEN_DIRECTORY))
    })?;
    let program = dir.path().join("fake");
    fs::write(&program, "")?;
    fs::set_permissions(&program, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    fs::write(dir.path().join("fake.mode"), "ok")?;
    let settings_file = dir.path().join("settings.yaml");
    fs::write(&settings_file, settings_for(dir.path()))?;
    Ok(Fixture {
        dir,
        settings_file,
        program,
        routes,
    })
}


fn fixture() -> Result<Fixture, Box<dyn Error>> {
    fixture_with(&|dir| settings_text(dir, &format!("{}/audit.log", dir.display())))
}


fn fake(_handle: &OwnedFd, path: &Path, arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    let calls = format!("{}.calls", path.display());
    let before = fs::read_to_string(&calls).unwrap_or_else(|_| String::new());
    fs::write(&calls, format!("{before}{}\n", arguments.join(" ")))?;
    Ok(CommandStatus::Success)
}


fn replace(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


fn wait_until(condition: &dyn Fn() -> bool) -> io::Result<()> {
    (0..POLL_ATTEMPTS)
        .find_map(|_| {
            let done = condition();
            if !done {
                sleep(POLL_STEP);
            }
            done.then_some(())
        })
        .ok_or_else(|| io::Error::other("condition never held"))
}


fn audit_lines(fixture: &Fixture) -> Vec<String> {
    fs::read_to_string(fixture.dir.path().join("audit.log")).map_or_else(|_| Vec::new(), |text| text.lines().map(str::to_owned).collect())
}


fn call_count(fixture: &Fixture) -> usize {
    fs::read_to_string(format!("{}.calls", fixture.program.display())).map_or(0, |text| text.lines().count())
}


#[test]
fn the_service_applies_follows_edits_refuses_a_bad_one_and_audits_under_all() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let before_edit = fixture.dir.path().join("out/caddy.json");
    let wait = || -> io::Result<()> {
        assert_eq!(call_count(&fixture), TWO_CALLS);
        replace(&fixture.routes, MARKER_ROUTE)?;
        wait_until(&|| call_count(&fixture) >= FOUR_CALLS)?;
        let applied = fs::read_to_string(&before_edit)?;
        assert!(applied.contains("marker-host.example.test"));
        let refused_before = audit_lines(&fixture).iter().filter(|line| line.contains("refused")).count();
        replace(&fixture.routes, BAD_TLS_ROUTE)?;
        raise(SIGHUP).map_err(|failure| io::Error::other(failure.to_string()))?;
        wait_until(&|| audit_lines(&fixture).iter().filter(|line| line.contains("refused")).count() > refused_before)?;
        assert_eq!(fs::read_to_string(&before_edit)?, applied);
        Ok(())
    };
    serve_with_program(&fixture.settings_file, &fixture.program, fake, &wait)?;
    let lines = audit_lines(&fixture);
    assert!(lines.len() > TWO_CALLS);
    assert!(lines.iter().all(|line| line.contains(&format!("\"tenant\":\"{AUDIT_TENANT}\""))));
    Ok(())
}


#[test]
fn a_settings_file_without_an_audit_path_is_refused_before_anything_runs() -> Result<(), Box<dyn Error>> {
    let fixture = fixture_with(&|dir| {
        format!(
            "routes_file: {0}/routes.yaml\nout_dir: {0}/out\nadmin_socket: {0}/admin/sock\n",
            dir.display()
        )
    })?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &|| Ok(()))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::NoAuditFile));
    assert_eq!(call_count(&fixture), 0);
    Ok(())
}


#[test]
fn an_unusable_audit_file_stops_the_start() -> Result<(), Box<dyn Error>> {
    let fixture = fixture_with(&|dir| settings_text(dir, &format!("{}/out", dir.display())))?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &|| Ok(()))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::Open(_)));
    assert_eq!(call_count(&fixture), 0);
    Ok(())
}


#[test]
fn an_unreadable_settings_file_is_a_settings_refusal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let missing = fixture.dir.path().join("missing.yaml");
    let failure = serve_with_program(&missing, &fixture.program, fake, &|| Ok(())).err().ok_or("started")?;
    assert!(matches!(failure, ServeError::Settings(_)));
    Ok(())
}


#[test]
fn a_failed_wait_is_reported() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &|| Err(io::Error::other("no signals")))
        .err()
        .ok_or("stopped cleanly")?;
    assert!(matches!(failure, ServeError::Signal(_)));
    Ok(())
}


#[test]
fn a_refused_first_configuration_is_audited_and_stops() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    fs::write(&fixture.routes, BAD_TLS_ROUTE)?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &|| Ok(()))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::Open(_)));
    assert!(audit_lines(&fixture).iter().any(|line| line.contains("denied")));
    assert_eq!(call_count(&fixture), 0);
    Ok(())
}


#[test]
fn the_audit_path_of_the_running_settings_must_be_the_opened_one() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let audit = format!("{}/audit.log", fixture.dir.path().display());
    let settings = ApplySettings {
        routes_file: format!("{}/routes.yaml", fixture.dir.path().display()),
        out_dir: format!("{}/out", fixture.dir.path().display()),
        retired_caddy_program: false,
        admin_socket: format!("{}/admin/sock", fixture.dir.path().display()),
        deadline_seconds: 1,
        audit_file: Some(audit.clone()),
    };
    let applied = render_applied(&settings, &fixture.program, 0)?;
    check_audit_path(&applied, &audit)?;
    assert!(matches!(check_audit_path(&applied, "/other.log"), Err(ServeError::AuditPathChanged)));
    let without = ApplySettings {
        audit_file: None,
        ..settings.clone()
    };
    assert!(matches!(
        check_audit_path(&render_applied(&without, &fixture.program, 0)?, &audit),
        Err(ServeError::AuditPathChanged)
    ));
    assert!(check_start_only(&settings, &settings).is_ok());
    let moved = ApplySettings {
        audit_file: Some("/other.log".to_owned()),
        ..settings.clone()
    };
    assert!(check_start_only(&settings, &moved).is_err());
    assert!(check_settings(moved).is_ok());
    let relative = ApplySettings {
        audit_file: Some("audit.log".to_owned()),
        ..settings
    };
    assert!(check_settings(relative).is_err());
    Ok(())
}


#[test]
fn arguments_context_sink_and_error_line() -> Result<(), Box<dyn Error>> {
    assert_eq!(parse_args(&["s.yaml".to_owned()])?, PathBuf::from("s.yaml"));
    assert!(matches!(parse_args(&[]), Err(ServeError::Usage)));
    assert!(matches!(parse_args(&["a".to_owned(), "b".to_owned()]), Err(ServeError::Usage)));
    assert_eq!(service_context(Path::new("/s.yaml")).tenant, AUDIT_TENANT);
    assert!(open_sink("/nonexistent-directory/audit.log").is_err());
    let nested = ServeError::Signal(io::Error::other("inner cause"));
    assert_eq!(error_line(&nested), "cannot wait for signals: inner cause");
    Ok(())
}


struct BrokenPipe;


impl io::Write for BrokenPipe {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn the_exit_code_is_zero_after_a_stop_and_one_with_a_line_otherwise() -> Result<(), Box<dyn Error>> {
    let mut report = Vec::new();
    assert_eq!(exit_code(Ok(()), &mut report), ExitCode::SUCCESS);
    assert!(report.is_empty());
    assert_eq!(exit_code(Err(ServeError::Usage), &mut report), ExitCode::FAILURE);
    assert_eq!(String::from_utf8(report)?, "ostyr-waf: usage: ostyr-waf <settings.yaml>\n");
    assert_eq!(exit_code(Err(ServeError::NoAuditFile), &mut BrokenPipe), ExitCode::FAILURE);
    Ok(())
}
