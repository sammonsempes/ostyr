#![cfg(target_os = "linux")]

use core_audit::tenant::AUDIT_TENANT;
use signal_hook::consts::{SIGHUP, SIGTERM};
use std::error::Error;
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, PoisonError};
use std::thread::{scope, sleep};
use std::time::Duration;
use waf::apply::{check_settings, check_start_only, render_applied};
use waf::error::{DeliverError, OpenError, ServeError};
use waf::model::{ApplySettings, CommandStatus};
use waf::serve::{
    check_audit_distinct, check_audit_path, error_line, exit_code, open_sink, parse_args, same_file, serve_with_program, service_context,
};
use waf::types::RunnerFn;


const ONE_ROUTE: &str = "routes:\n  - hosts: [a.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const MARKER_ROUTE: &str = "routes:\n  - hosts: [marker-host.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const BAD_TLS_ROUTE: &str = "tls:\n  issuer: nothing\nroutes:\n  - hosts: [a.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const OPEN_DIRECTORY: u32 = 0o755;


const POLL_ATTEMPTS: usize = 3_000;


const POLL_STEP: Duration = Duration::from_millis(10);


const RELEASE_DELAY: Duration = Duration::from_millis(300);


const RETRY_POLLS: usize = 100;


const RETRY_ATTEMPTS: usize = 60;


const HANG_GUARD: Duration = Duration::from_secs(180);


const TWO_CALLS: usize = 2;


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


fn polled(condition: &dyn Fn() -> bool) -> bool {
    (0..RETRY_POLLS).any(|_| {
        let done = condition();
        if !done {
            sleep(POLL_STEP);
        }
        done
    })
}


fn replace_until(path: &Path, text: &str, condition: &dyn Fn() -> bool) -> io::Result<()> {
    let rewritten = (0..RETRY_ATTEMPTS).find_map(|_| {
        let written = replace(path, text);
        let seen = written.is_ok() && polled(condition);
        (written.is_err() || seen).then_some(written)
    });
    rewritten.ok_or_else(|| io::Error::other("condition never held"))?
}


fn queue(events: &[c_int]) -> impl Fn() -> io::Result<Receiver<c_int>> + '_ {
    move || {
        let (sender, receiver) = channel();
        events.iter().try_for_each(|event| sender.send(*event)).map_err(io::Error::other)?;
        Ok(receiver)
    }
}


fn feed(receiver: Receiver<c_int>, registered: Option<String>) -> impl Fn() -> io::Result<Receiver<c_int>> {
    let slot = Mutex::new(Some(receiver));
    move || {
        registered.iter().try_for_each(|marker| fs::write(marker, ""))?;
        slot.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| io::Error::other("source used twice"))
    }
}


fn finish(sender: &Sender<c_int>, body: io::Result<()>) -> io::Result<()> {
    let delivered = sender.send(SIGTERM).is_ok();
    tracing::debug!(delivered, "extra stop for a service whose driver failed");
    body
}


fn check(condition: bool, name: &str) -> io::Result<()> {
    condition.then_some(()).ok_or_else(|| io::Error::other(format!("check failed: {name}")))
}


fn serve_driven(
    fixture: &Fixture,
    runner: RunnerFn,
    source: &dyn Fn() -> io::Result<Receiver<c_int>>,
    sender: &Sender<c_int>,
    body: &(dyn Fn() -> io::Result<()> + Sync),
) -> Result<(), Box<dyn Error>> {
    let (done, finished) = channel::<()>();
    let (served, driven, expired) = scope(|scope| {
        let driver = scope.spawn(|| finish(sender, body()));
        let stopper = sender;
        let watchdog = scope.spawn(move || {
            let expired = finished.recv_timeout(HANG_GUARD).is_err();
            let stopped = expired && stopper.send(SIGTERM).is_ok();
            tracing::debug!(stopped, "hang guard");
            expired
        });
        let served = serve_with_program(&fixture.settings_file, &fixture.program, runner, source);
        let notified = done.send(()).is_ok();
        tracing::debug!(notified, "serve returned");
        let driven = driver.join().map_err(|_| io::Error::other("driver panicked")).and_then(|result| result);
        let expired = watchdog.join().map_err(|_| io::Error::other("watchdog panicked"));
        (served, driven, expired)
    });
    check(!expired?, "the service outlived the hang guard")?;
    served?;
    Ok(driven?)
}


fn send(sender: &Sender<c_int>, event: c_int) -> io::Result<()> {
    sender.send(event).map_err(io::Error::other)
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
    let (sender, receiver) = channel();
    let source = feed(receiver, None);
    serve_driven(&fixture, fake, &source, &sender, &|| {
        wait_until(&|| applied_count(&fixture) >= 1)?;
        wait_until(&|| call_count(&fixture) >= TWO_CALLS)?;
        replace_until(&fixture.routes, MARKER_ROUTE, &|| applied_count(&fixture) >= TWO_CALLS)?;
        let applied = fs::read_to_string(&before_edit)?;
        check(applied.contains("marker-host.example.test"), "the edited route is published")?;
        let refused_before = audit_lines(&fixture).iter().filter(|line| line.contains("refused")).count();
        replace(&fixture.routes, BAD_TLS_ROUTE)?;
        send(&sender, SIGHUP)?;
        wait_until(&|| audit_lines(&fixture).iter().filter(|line| line.contains("refused")).count() > refused_before)?;
        check(fs::read_to_string(&before_edit)? == applied, "a refused edit keeps the old configuration")?;
        send(&sender, SIGTERM)
    })?;
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
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &queue(&[]))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::NoAuditFile));
    assert_eq!(call_count(&fixture), 0);
    Ok(())
}


#[test]
fn an_unusable_audit_file_stops_the_start() -> Result<(), Box<dyn Error>> {
    let fixture = fixture_with(&|dir| settings_text(dir, &format!("{}/out", dir.display())))?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &queue(&[]))
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
    let failure = serve_with_program(&missing, &fixture.program, fake, &queue(&[])).err().ok_or("started")?;
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
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &queue(&[]))
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


fn slow_fake(handle: &OwnedFd, path: &Path, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    let hold = format!("{}.hold", path.display());
    if fs::remove_file(&hold).is_ok() {
        let registered = Path::new(&format!("{}.registered", path.display())).exists();
        fs::write(format!("{}.entered", path.display()), if registered { "registered" } else { "late" })?;
        wait_until(&|| Path::new(&format!("{}.release", path.display())).exists())?;
    }
    fake(handle, path, arguments, deadline)
}


fn applied_count(fixture: &Fixture) -> usize {
    audit_lines(fixture).iter().filter(|line| line.contains("applied")).count()
}


#[test]
fn a_reload_in_flight_when_the_wait_returns_is_audited_and_published_before_serve_returns() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let program = fixture.program.display().to_string();
    let (sender, receiver) = channel();
    let source = feed(receiver, Some(format!("{program}.registered")));
    serve_driven(&fixture, slow_fake, &source, &sender, &|| {
        wait_until(&|| applied_count(&fixture) >= 1)?;
        fs::write(format!("{program}.hold"), "")?;
        replace_until(&fixture.routes, MARKER_ROUTE, &|| Path::new(&format!("{program}.entered")).exists())?;
        send(&sender, SIGTERM)?;
        sleep(RELEASE_DELAY);
        fs::write(format!("{program}.release"), "")
    })?;
    assert_eq!(applied_count(&fixture), TWO_CALLS);
    assert!(fs::read_to_string(fixture.dir.path().join("out/caddy.json"))?.contains("marker-host.example.test"));
    Ok(())
}


#[test]
fn the_audit_file_is_never_the_settings_routes_or_published_file() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let dir = fixture.dir.path().display().to_string();
    let settings = ApplySettings {
        routes_file: format!("{dir}/routes.yaml"),
        out_dir: format!("{dir}/out"),
        retired_caddy_program: false,
        admin_socket: format!("{dir}/admin/sock"),
        deadline_seconds: 1,
        audit_file: None,
    };
    fs::write(format!("{dir}/out/caddy.json"), "{}")?;
    fs::hard_link(&fixture.routes, format!("{dir}/linked.log"))?;
    [
        fixture.settings_file.display().to_string(),
        format!("{dir}/routes.yaml"),
        format!("{dir}/out/caddy.json"),
        format!("{dir}/linked.log"),
    ]
    .iter()
    .try_for_each(|audit| -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            check_audit_distinct(&fixture.settings_file, &settings, audit),
            Err(ServeError::AuditPathClash)
        ));
        Ok(())
    })?;
    check_audit_distinct(&fixture.settings_file, &settings, &format!("{dir}/audit.log"))?;
    assert!(!same_file("/nonexistent-a", "/nonexistent-b"));
    Ok(())
}


#[test]
fn a_service_whose_audit_file_is_the_published_file_is_refused_before_anything_runs() -> Result<(), Box<dyn Error>> {
    let fixture = fixture_with(&|dir| settings_text(dir, &format!("{}/out/caddy.json", dir.display())))?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &queue(&[]))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::AuditPathClash));
    assert_eq!(call_count(&fixture), 0);
    Ok(())
}


fn failing_reload(_handle: &OwnedFd, _path: &Path, arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Ok(if arguments.first().is_some_and(|step| step == "reload") {
        CommandStatus::Failed(Some(1))
    } else {
        CommandStatus::Success
    })
}


fn leftover_stages(fixture: &Fixture) -> io::Result<usize> {
    Ok(fixture
        .dir
        .path()
        .join("out")
        .read_dir()?
        .filter(|entry| {
            entry
                .as_ref()
                .is_ok_and(|found| found.file_name().to_string_lossy().starts_with(".apply-"))
        })
        .count())
}


#[test]
fn a_stop_and_a_hangup_during_the_first_delivery_wait_for_its_audit_and_publish() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let program = fixture.program.display().to_string();
    fs::write(format!("{program}.hold"), "")?;
    let (sender, receiver) = channel();
    let source = feed(receiver, Some(format!("{program}.registered")));
    serve_driven(&fixture, slow_fake, &source, &sender, &|| {
        wait_until(&|| Path::new(&format!("{program}.entered")).exists())?;
        check(
            fs::read_to_string(format!("{program}.entered"))? == "registered",
            "the signal source is registered before the first delivery",
        )?;
        send(&sender, SIGHUP)?;
        send(&sender, SIGTERM)?;
        fs::write(format!("{program}.release"), "")
    })?;
    assert_eq!(applied_count(&fixture), 1);
    assert!(fs::read_to_string(fixture.dir.path().join("out/caddy.json"))?.contains("a.example.test"));
    assert_eq!(leftover_stages(&fixture)?, 0);
    Ok(())
}


#[test]
fn an_unknown_first_outcome_is_audited_before_the_start_stops() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, failing_reload, &queue(&[SIGTERM]))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::Open(_)));
    let lines = audit_lines(&fixture);
    assert!(lines.iter().any(|line| line.contains("denied") && line.contains("unknown")));
    assert!(lines.iter().all(|line| line.contains(&format!("\"tenant\":\"{AUDIT_TENANT}\""))));
    Ok(())
}


#[test]
fn an_audit_file_reached_through_a_symlinked_directory_of_out_dir_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture_with(&|dir| settings_text(dir, &format!("{}/alias/caddy.json", dir.display())))?;
    std::os::unix::fs::symlink(fixture.dir.path().join("out"), fixture.dir.path().join("alias"))?;
    let failure = serve_with_program(&fixture.settings_file, &fixture.program, fake, &queue(&[SIGTERM]))
        .err()
        .ok_or("started")?;
    assert!(matches!(failure, ServeError::Open(OpenError::Deliver(DeliverError::AuditSinkClash))));
    assert_eq!(call_count(&fixture), 0);
    Ok(())
}


fn refused_after_start(fixture: &Fixture, damage: &(dyn Fn(&Path) -> io::Result<()> + Sync)) -> Result<(), Box<dyn Error>> {
    let (sender, receiver) = channel();
    let source = feed(receiver, None);
    serve_driven(fixture, fake, &source, &sender, &|| {
        wait_until(&|| applied_count(fixture) >= 1)?;
        replace_until(&fixture.routes, MARKER_ROUTE, &|| applied_count(fixture) >= TWO_CALLS)?;
        let calls_before = call_count(fixture);
        damage(fixture.dir.path())?;
        replace(&fixture.routes, ONE_ROUTE)?;
        send(&sender, SIGHUP)?;
        wait_until(&|| audit_lines(fixture).iter().any(|line| line.contains("denied")))?;
        check(call_count(fixture) == calls_before, "a refused delivery runs nothing")?;
        check(leftover_stages(fixture)? == 0, "a refused delivery leaves no stage file")?;
        send(&sender, SIGTERM)
    })
}


#[test]
fn a_hard_link_made_after_the_start_refuses_the_next_delivery_and_keeps_the_old_configuration() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    refused_after_start(&fixture, &|dir| fs::hard_link(dir.join("audit.log"), dir.join("out/second-name")))
}


#[test]
fn an_audit_file_made_the_published_file_after_the_start_refuses_the_next_delivery() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    refused_after_start(&fixture, &|dir| {
        fs::remove_file(dir.join("out/caddy.json"))?;
        fs::hard_link(dir.join("audit.log"), dir.join("out/caddy.json"))
    })
}
