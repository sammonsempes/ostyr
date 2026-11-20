#![cfg(target_os = "linux")]

use core_audit::error::AuditError;
use core_audit::log::{append, open_file_log};
use core_audit::model::{NewEntry, Outcome};
use core_config::reload::{current_config, reload, reload_entry, ReloadContext, ReloadEngine, ReloadOutcome};
use core_config::trusted_program::open_trusted_program;
use data_encoding::HEXLOWER;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::error::Error as StdError;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use waf::admin::open_admin_directory;
use waf::apply::{
    applied_state, check_settings, check_start_only, config_error, config_id, deliver, discard, file_trusted, judge_program, late_audit,
    load_trusted_routes, load_trusted_settings, load_trusted_settings_file, open_apply, open_apply_audited, open_apply_audited_with_program,
    open_apply_with_program, path_text_ok, production_program, refused_text, render_applied, render_applied_capped, start_refusal,
};
use waf::error::{DeliverError, OpenError, WafError};
use waf::limits::CADDY_PROGRAM;
use waf::model::{Applied, ApplySettings, CommandStatus, Refusal};
use waf::runner::{leave_alone, logged, run_child, run_child_with_hook, run_with_deadline, stop, wait_child};


const TWO_ROUTES: &str = "tests/fixtures/two_routes.yaml";


const TWO_ROUTES_ADMIN: &str = "tests/fixtures/two_routes_admin.json";


const CA_PEM: &str = "tests/fixtures/ca.pem";


const ONE_ROUTE: &str = "routes:\n  - hosts: [a.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const MARKER_ROUTE: &str = "routes:\n  - hosts: [marker-host.example.test]\n    backends: [\"127.0.0.1:9001\"]\n";


const TWO_WITH_BAD: &str =
    "routes:\n  - hosts: [a.example.test]\n    backends: [\"127.0.0.1:9001\"]\n  - hosts: [\"bad host\"]\n    backends: [\"127.0.0.1:9002\"]\n";


const SOCKET: &str = "/run/ostyr-waf/caddy-admin.sock";


const SHORT_DEADLINE_MILLISECONDS: u64 = 100;


const LONG_SLEEP: &str = "60";


const SETTINGS_DEADLINE: u64 = 30;


const OTHER_DEADLINE: u64 = 31;


const TOO_LONG_DEADLINE: u64 = 121;


const FAILED_STATUS: i32 = 3;


const OWNER_ONLY: u32 = 0o600;


const MODE_BITS: u32 = 0o777;


const GROUP_WRITABLE: u32 = 0o775;


const OPEN_DIRECTORY: u32 = 0o755;


const REFUSED_COUNT: usize = 40;


const LISTED: usize = 32;


const STAGED_ARGUMENT: usize = 2;


const TWO_CALLS: usize = 2;


const THREE_CALLS: usize = 3;


const FOUR_CALLS: usize = 4;


const TINY_CAP: usize = 10;


const ANSWER_OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";


const ANSWER_MISSING: &str = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";


const ANSWER_GARBAGE: &str = "garbage garbage garbage\r\n\r\n";


const ID_HEX_CHARS: usize = 32;


const STDERR_MARKER: &str = "CADDY-STDERR-MARKER";


const CHILD_TEST: &str = "child_runs_the_fake_caddy";


const PROGRAM_VARIABLE: &str = "WAF_FAKE_CADDY";


struct Fixture {
    dir: tempfile::TempDir,
    routes: PathBuf,
    out: PathBuf,
    admin: PathBuf,
    settings_file: PathBuf,
    program: String,
}


fn fixture(routes_text: &str) -> Result<Fixture, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let routes = dir.path().join("routes.yaml");
    fs::write(&routes, routes_text)?;
    let out = dir.path().join("out");
    fs::create_dir(&out)?;
    fs::set_permissions(&out, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let admin = dir.path().join("admin");
    fs::create_dir(&admin)?;
    fs::set_permissions(&admin, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let program = dir.path().join("fake").to_string_lossy().into_owned();
    fs::write(format!("{program}.mode"), "ok")?;
    fs::write(&program, "")?;
    fs::set_permissions(&program, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let settings_file = dir.path().join("settings.yaml");
    let made = Fixture {
        dir,
        routes,
        out,
        admin,
        settings_file,
        program,
    };
    write_settings(&made, &settings_of(&made))?;
    Ok(made)
}


fn settings_of(fixture: &Fixture) -> ApplySettings {
    ApplySettings {
        routes_file: fixture.routes.to_string_lossy().into_owned(),
        out_dir: fixture.out.to_string_lossy().into_owned(),
        retired_caddy_program: false,
        admin_socket: fixture.admin.join("sock").to_string_lossy().into_owned(),
        deadline_seconds: SETTINGS_DEADLINE,
    }
}


fn write_settings(fixture: &Fixture, settings: &ApplySettings) -> Result<(), Box<dyn Error>> {
    let text = format!(
        "routes_file: {}\nout_dir: {}\nadmin_socket: {}\ndeadline_seconds: {}\n",
        settings.routes_file, settings.out_dir, settings.admin_socket, settings.deadline_seconds
    );
    Ok(fs::write(&fixture.settings_file, text)?)
}


fn prog(fixture: &Fixture) -> &Path {
    Path::new(&fixture.program)
}


fn set_mode(fixture: &Fixture, mode: &str) -> Result<(), Box<dyn Error>> {
    Ok(fs::write(format!("{}.mode", fixture.program), mode)?)
}


fn calls(fixture: &Fixture) -> Vec<String> {
    fs::read_to_string(format!("{}.calls", fixture.program)).map_or_else(|_| Vec::new(), |text| text.lines().map(str::to_owned).collect())
}


fn fake(_handle: &OwnedFd, path: &Path, arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    let program = path.display();
    let mode = fs::read_to_string(format!("{program}.mode"))?;
    let step = arguments.first().map_or("", String::as_str);
    let staged = arguments.get(STAGED_ARGUMENT).map(fs::read).transpose()?.unwrap_or_else(Vec::new);
    let line = format!("{}|{}\n", arguments.join(" "), HEXLOWER.encode(&Sha256::digest(&staged)));
    let calls = format!("{program}.calls");
    let before = fs::read_to_string(&calls).unwrap_or_else(|_| String::new());
    fs::write(&calls, format!("{before}{line}"))?;
    match (mode.as_str(), step) {
        ("validate-fail", "validate") | ("reload-fail", "reload") => Ok(CommandStatus::Failed(Some(FAILED_STATUS))),
        ("reload-timeout", "reload") => Ok(CommandStatus::TimedOut),
        ("refused", _) | ("refuse-reload", "reload") => Ok(CommandStatus::Refused),
        ("vanish", "reload") => {
            fs::remove_file(arguments.get(STAGED_ARGUMENT).ok_or_else(|| io::Error::other("no path"))?).map(|()| CommandStatus::Success)
        }
        ("spawn-fail", _) => Err(io::Error::other("cannot start")),
        _ => Ok(CommandStatus::Success),
    }
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "platform".to_owned(),
        module: "waf".to_owned(),
        target: "routes".to_owned(),
        request_id: "r".to_owned(),
    }
}


fn try_open(fixture: &Fixture) -> Result<Result<ReloadEngine<Applied>, OpenError>, Box<dyn Error>> {
    let audit_path = fixture.dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit_path)?);
    Ok(open_apply_with_program(
        &fixture.settings_file,
        prog(fixture),
        fake,
        Box::new(move |entry| append(&log, entry)),
        context(),
    ))
}


fn engine_of(fixture: &Fixture) -> Result<(ReloadEngine<Applied>, PathBuf), Box<dyn Error>> {
    let engine = try_open(fixture)??;
    Ok((engine, fixture.dir.path().join("audit.log")))
}


fn final_text(fixture: &Fixture) -> io::Result<String> {
    fs::read_to_string(fixture.out.join("caddy.json"))
}


fn hash_of(text: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(text.as_bytes()))
}


fn id_of(fixture: &Fixture) -> Result<String, Box<dyn Error>> {
    Ok(render_applied(&settings_of(fixture), prog(fixture), 0)?.id)
}


fn serve_once(directory: &Path, answer: &'static str) -> Result<JoinHandle<io::Result<String>>, Box<dyn Error>> {
    let held = fs::File::open(directory)?;
    let path = directory.join("sock");
    fs::remove_file(&path).or_else(|failure| (failure.kind() == io::ErrorKind::NotFound).then_some(()).ok_or(failure))?;
    let listener = UnixListener::bind(format!("/proc/self/fd/{}/sock", held.as_raw_fd()))?;
    Ok(std::thread::spawn(move || {
        let (stream, _) = listener.accept()?;
        let mut reader = BufReader::new(stream);
        let head = reader
            .by_ref()
            .lines()
            .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
            .collect::<io::Result<Vec<String>>>()?;
        let first = format!("{}\r\n", head.first().map_or("", String::as_str));
        reader.get_mut().write_all(answer.as_bytes())?;
        Ok(first)
    }))
}


fn joined(handle: JoinHandle<io::Result<String>>, directory: &Path) -> Result<String, Box<dyn Error>> {
    let held = fs::File::open(directory)?;
    let release = UnixStream::connect(format!("/proc/self/fd/{}/sock", held.as_raw_fd()));
    drop(release);
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


#[test]
fn the_render_with_admin_listen_and_id_matches_the_golden_file() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(&fs::read_to_string(TWO_ROUTES)?)?;
    let settings = ApplySettings {
        admin_socket: SOCKET.to_owned(),
        ..settings_of(&fixture)
    };
    let applied = render_applied(&settings, prog(&fixture), 0)?;
    assert_eq!(applied.json, fs::read_to_string(TWO_ROUTES_ADMIN)?.trim_end());
    let value: Value = serde_json::from_str(&applied.json)?;
    assert_eq!(
        value.pointer("/admin/listen").and_then(Value::as_str),
        Some("unix//run/ostyr-waf/caddy-admin.sock")
    );
    assert_eq!(value.pointer("/admin/@id").and_then(Value::as_str), Some(applied.id.as_str()));
    let without = applied.json.replace(&format!(",\n    \"@id\": \"{}\"", applied.id), "");
    assert!(!without.contains("@id"));
    assert_eq!(applied.id, config_id(&without));
    assert!(applied.id.starts_with("ostyr-"));
    assert_eq!(applied.id.len(), "ostyr-".len() + ID_HEX_CHARS);
    Ok(())
}


#[test]
fn the_id_follows_the_content() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let first = id_of(&fixture)?;
    assert_eq!(first, id_of(&fixture)?);
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    assert_ne!(first, id_of(&fixture)?);
    Ok(())
}


#[test]
fn a_first_load_validates_then_reloads_the_same_bytes_publishes_and_is_audited() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (_engine, audit) = engine_of(&fixture)?;
    let recorded = calls(&fixture);
    assert_eq!(recorded.len(), TWO_CALLS);
    let published = final_text(&fixture)?;
    let staged = format!("{}/.apply-", fixture.out.to_string_lossy());
    let first = recorded.first().ok_or("no validate")?;
    let second = recorded.get(1).ok_or("no reload")?;
    assert!(first.starts_with(&format!("validate --config {staged}")));
    assert!(second.starts_with(&format!("reload --config {staged}")));
    assert!(second.contains(&format!(" --address unix/{}|", settings_of(&fixture).admin_socket)));
    assert!(first.ends_with(&hash_of(&published)));
    assert!(second.ends_with(&hash_of(&published)));
    assert_eq!(fs::metadata(fixture.out.join("caddy.json"))?.permissions().mode() & MODE_BITS, OWNER_ONLY);
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 1);
    let log = fs::read_to_string(audit)?;
    assert!(log.contains("applied"));
    assert!(log.contains("initial configuration"));
    assert!(!log.contains("late"));
    Ok(())
}


#[test]
fn a_failed_validate_on_the_first_load_stops_the_start_without_a_reload() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    set_mode(&fixture, "validate-fail")?;
    let failure = try_open(&fixture)?.err().ok_or("started")?;
    assert!(failure.to_string().contains("first configuration was refused"));
    assert_eq!(calls(&fixture).len(), 1);
    assert!(final_text(&fixture).is_err());
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 0);
    Ok(())
}


#[test]
fn a_refused_reload_keeps_the_old_file_and_is_audited() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = final_text(&fixture)?;
    set_mode(&fixture, "validate-fail")?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    let outcome = reload(&engine);
    assert!(matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("validate failed")));
    assert_eq!(calls(&fixture).len(), THREE_CALLS);
    assert_eq!(final_text(&fixture)?, before);
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 1);
    let log = fs::read_to_string(audit)?;
    assert!(log.contains("refused"));
    assert!(!log.contains("marker-host"));
    set_mode(&fixture, "ok")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if !keys.contains(&"waf.epoch".to_owned())));
    Ok(())
}


#[test]
fn a_failed_reload_with_no_answer_is_unknown_and_the_next_reload_pushes_again() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = final_text(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "reload-fail")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("running configuration is unknown")));
    set_mode(&fixture, "reload-timeout")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("reload did not finish")));
    set_mode(&fixture, "spawn-fail")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("cannot run caddy validate")));
    assert_eq!(final_text(&fixture)?, before);
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 1);
    assert!(fs::read_to_string(audit)?.matches("refused").count() >= THREE_CALLS);
    let delivered = calls(&fixture).len();
    set_mode(&fixture, "ok")?;
    let outcome = reload(&engine);
    assert!(matches!(&outcome, ReloadOutcome::Applied { keys } if keys.contains(&"waf.epoch".to_owned())));
    assert_eq!(calls(&fixture).len(), delivered + TWO_CALLS);
    assert!(final_text(&fixture)?.contains("marker-host.example.test"));
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn a_reload_killed_at_the_deadline_that_caddy_still_applied_is_a_late_apply() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "reload-timeout")?;
    let id = id_of(&fixture)?;
    let server = serve_once(&fixture.admin, ANSWER_OK)?;
    let outcome = reload(&engine);
    assert!(matches!(outcome, ReloadOutcome::Applied { .. }));
    assert_eq!(joined(server, &fixture.admin)?, format!("GET /id/{id} HTTP/1.1\r\n"));
    assert!(final_text(&fixture)?.contains("marker-host.example.test"));
    assert!(current_config(&engine).json.contains("marker-host.example.test"));
    let log = fs::read_to_string(audit)?;
    assert!(log.contains("late"));
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn a_failed_reload_that_caddy_applied_anyway_is_a_late_apply_and_a_normal_one_is_not_late() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "reload-fail")?;
    let server = serve_once(&fixture.admin, ANSWER_OK)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    joined(server, &fixture.admin)?;
    fs::write(&fixture.routes, ONE_ROUTE)?;
    set_mode(&fixture, "ok")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    let log = fs::read_to_string(audit)?;
    assert_eq!(log.matches("\"late\"").count(), 1);
    Ok(())
}


#[test]
fn a_first_delivery_that_caddy_applied_after_its_client_failed_starts_and_is_audited_late() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    set_mode(&fixture, "reload-timeout")?;
    let server = serve_once(&fixture.admin, ANSWER_OK)?;
    let (_engine, audit) = engine_of(&fixture)?;
    joined(server, &fixture.admin)?;
    assert!(final_text(&fixture)?.contains("a.example.test"));
    let log = fs::read_to_string(audit)?;
    assert!(log.contains("late"));
    assert!(log.contains("initial configuration"));
    Ok(())
}


#[test]
fn a_daemon_that_does_not_hold_the_id_or_answers_garbage_leaves_the_state_unknown() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, _audit) = engine_of(&fixture)?;
    let before = final_text(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "reload-timeout")?;
    let missing = serve_once(&fixture.admin, ANSWER_MISSING)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("unknown")));
    joined(missing, &fixture.admin)?;
    let garbage = serve_once(&fixture.admin, ANSWER_GARBAGE)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("unknown")));
    joined(garbage, &fixture.admin)?;
    assert_eq!(final_text(&fixture)?, before);
    Ok(())
}


#[test]
fn an_unknown_first_delivery_stops_the_start() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    set_mode(&fixture, "reload-fail")?;
    let failure = try_open(&fixture)?.err();
    assert!(matches!(failure, Some(OpenError::Deliver(DeliverError::Unknown { .. }))));
    assert!(final_text(&fixture).is_err());
    Ok(())
}


#[test]
fn a_failing_audit_stops_the_start() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let failure = open_apply_with_program(
        &fixture.settings_file,
        prog(&fixture),
        fake,
        Box::new(|_entry| Err(AuditError::LogPoisoned)),
        context(),
    )
    .err();
    assert!(matches!(failure, Some(OpenError::Audit(_))));
    Ok(())
}


#[test]
fn a_good_change_is_applied_and_an_unchanged_file_calls_nothing() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, _audit) = engine_of(&fixture)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    assert_eq!(calls(&fixture).len(), TWO_CALLS);
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(calls(&fixture).len(), FOUR_CALLS);
    assert!(final_text(&fixture)?.contains("marker-host.example.test"));
    Ok(())
}


#[test]
fn a_route_refused_alone_applies_the_rest_and_is_listed() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(TWO_WITH_BAD)?;
    let (engine, audit) = engine_of(&fixture)?;
    let current = current_config(&engine);
    assert_eq!(current.refused.len(), 1);
    assert_eq!(refused_text(&current), "1 refused: 1");
    assert!(final_text(&fixture)?.contains("a.example.test"));
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys.contains(&"waf.refused".to_owned())));
    assert!(fs::read_to_string(audit)?.contains("waf.refused"));
    Ok(())
}


#[test]
fn the_refused_list_is_cut_with_a_visible_marker() -> Result<(), Box<dyn Error>> {
    let refused = (0..REFUSED_COUNT)
        .map(|index| Refusal {
            index,
            reason: "x",
            shadowed_by: None,
        })
        .collect();
    let applied = Applied {
        id: "ostyr-x".to_owned(),
        epoch: 0,
        program: PathBuf::from("/c"),
        settings: ApplySettings {
            routes_file: "/r".to_owned(),
            out_dir: "/o".to_owned(),
            retired_caddy_program: false,
            admin_socket: "/s".to_owned(),
            deadline_seconds: SETTINGS_DEADLINE,
        },
        json: "{}".to_owned(),
        ca_root: None,
        refused,
    };
    let text = refused_text(&applied);
    assert!(text.starts_with("40 refused: 0,1,2"));
    assert!(text.ends_with(&format!(",{} [{} more omitted]", LISTED - 1, REFUSED_COUNT - LISTED)));
    assert_eq!(applied_state(&applied).len(), FOUR_KEYS);
    assert!(!applied_state(&applied).contains_key("waf.caddy_program"));
    Ok(())
}


const FOUR_KEYS: usize = 4;


#[test]
fn a_fifo_symlink_or_directory_at_the_final_name_is_refused_before_any_write() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let target = fixture.out.join("caddy.json");
    let elsewhere = fixture.dir.path().join("elsewhere");
    fs::write(&elsewhere, "untouched")?;
    symlink(&elsewhere, &target)?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::BadTarget))));
    fs::remove_file(&target)?;
    fs::create_dir(&target)?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::BadTarget))));
    fs::remove_dir(&target)?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &target,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(OWNER_ONLY),
        0,
    )?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::BadTarget))));
    assert!(calls(&fixture).is_empty());
    assert_eq!(fs::read_to_string(&elsewhere)?, "untouched");
    Ok(())
}


#[test]
fn a_fifo_or_symlink_at_the_staged_name_is_never_followed_or_opened() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let staged = fixture.out.join(format!(".apply-{}.json", std::process::id()));
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &staged,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(OWNER_ONLY),
        0,
    )?;
    let failure = try_open(&fixture)?.err();
    assert!(matches!(failure, Some(OpenError::Deliver(DeliverError::Write(_)))));
    let elsewhere = fixture.dir.path().join("elsewhere");
    fs::write(&elsewhere, "untouched")?;
    symlink(&elsewhere, &staged)?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::Write(_)))));
    assert_eq!(fs::read_to_string(&elsewhere)?, "untouched");
    assert!(calls(&fixture).is_empty());
    Ok(())
}


#[test]
fn an_untrusted_out_dir_is_refused_before_any_write() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    fs::set_permissions(&fixture.out, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::OutDir(_)))));
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 0);
    assert!(calls(&fixture).is_empty());
    Ok(())
}


#[test]
fn an_admin_socket_in_a_sticky_or_open_directory_is_refused_before_any_call() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let in_tmp = ApplySettings {
        admin_socket: "/tmp/waf-admin.sock".to_owned(),
        ..settings_of(&fixture)
    };
    write_settings(&fixture, &in_tmp)?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::AdminDir(_)))));
    let at_root = ApplySettings {
        admin_socket: "/sock".to_owned(),
        ..settings_of(&fixture)
    };
    write_settings(&fixture, &at_root)?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::AdminDir(_)))));
    write_settings(&fixture, &settings_of(&fixture))?;
    fs::set_permissions(&fixture.admin, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::AdminDir(_)))));
    let link = fixture.dir.path().join("link");
    fs::set_permissions(&fixture.admin, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    symlink(&fixture.admin, &link)?;
    let through_link = ApplySettings {
        admin_socket: link.join("sock").to_string_lossy().into_owned(),
        ..settings_of(&fixture)
    };
    write_settings(&fixture, &through_link)?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Deliver(DeliverError::AdminDir(_)))));
    assert!(calls(&fixture).is_empty());
    assert!(final_text(&fixture).is_err());
    Ok(())
}


#[test]
fn an_admin_directory_opened_up_after_the_start_refuses_every_later_delivery() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = calls(&fixture).len();
    fs::set_permissions(&fixture.admin, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("untrusted admin socket directory")));
    assert_eq!(calls(&fixture).len(), before);
    assert!(fs::read_to_string(audit)?.contains("refused"));
    Ok(())
}


#[test]
fn deadline_and_program_follow_the_settings_file_and_the_rest_is_start_only() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    let base = settings_of(&fixture);
    write_settings(
        &fixture,
        &ApplySettings {
            deadline_seconds: OTHER_DEADLINE,
            ..base.clone()
        },
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys.contains(&"waf.deadline_seconds".to_owned())));
    assert_eq!(current_config(&engine).settings.deadline_seconds, OTHER_DEADLINE);
    let changed = [
        ApplySettings {
            out_dir: "/elsewhere".to_owned(),
            ..base.clone()
        },
        ApplySettings {
            routes_file: "/elsewhere.yaml".to_owned(),
            ..base.clone()
        },
        ApplySettings {
            admin_socket: "/elsewhere/sock".to_owned(),
            ..base.clone()
        },
    ];
    let reasons: Vec<String> = changed
        .iter()
        .map(|settings| {
            write_settings(&fixture, settings)?;
            Ok(format!("{:?}", reload(&engine)))
        })
        .collect::<Result<_, Box<dyn Error>>>()?;
    assert!(reasons
        .iter()
        .all(|reason| reason.contains("Refused") && reason.contains("cannot change while running")));
    assert!(reasons
        .iter()
        .zip(["out_dir", "routes_file", "admin_socket"])
        .all(|(reason, name)| reason.contains(name)));
    fs::write(&fixture.settings_file, "deadline_seconds: 0\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert!(fs::read_to_string(audit)?.contains("cannot change while running"));
    assert!(check_start_only(&base, &base).is_ok());
    Ok(())
}


#[test]
fn an_acme_ca_root_is_written_beside_the_rendered_file() -> Result<(), Box<dyn Error>> {
    let fixture = fixture("")?;
    let root = fixture.dir.path().join("root.pem");
    fs::copy(CA_PEM, &root)?;
    let text = format!(
        "tls:\n  issuer: acme\n  directory: https://acme.example.test/directory\n  email: ops@example.test\n  ca_root_file: {}\nroutes:\n  - hosts: [a.test]\n    backends: [\"127.0.0.1:9001\"]\n",
        root.to_string_lossy()
    );
    fs::write(&fixture.routes, text)?;
    let (_engine, _audit) = engine_of(&fixture)?;
    let name = format!("ca-root-{}.pem", HEXLOWER.encode(&Sha256::digest(fs::read(CA_PEM)?)));
    assert_eq!(fs::read(fixture.out.join(&name))?, fs::read(CA_PEM)?);
    assert!(final_text(&fixture)?.contains(&name));
    Ok(())
}


#[test]
fn render_failures_become_fixed_refusals() -> Result<(), Box<dyn Error>> {
    let fixture = fixture("routes: [")?;
    let settings = settings_of(&fixture);
    assert!(render_applied(&settings, prog(&fixture), 0).is_err());
    fs::write(&fixture.routes, "tls:\n  issuer: internal\n  email: x\nroutes: []\n")?;
    assert!(render_applied(&settings, prog(&fixture), 0).is_err());
    fs::write(&fixture.routes, ONE_ROUTE)?;
    let too_large = render_applied_capped(&settings, prog(&fixture), 0, TINY_CAP)
        .err()
        .ok_or("rendered")?
        .to_string();
    assert!(too_large.contains("exceeds the limit"));
    let missing = ApplySettings {
        routes_file: "/nonexistent/routes.yaml".to_owned(),
        ..settings.clone()
    };
    assert!(render_applied(&missing, prog(&fixture), 0).is_err());
    let root = fixture.dir.path().join("root.pem");
    fs::copy(CA_PEM, &root)?;
    fs::write(
        &fixture.routes,
        format!(
            "tls:\n  issuer: acme\n  directory: https://acme.example.test/d\n  email: ops@example.test\n  ca_root_file: {}\nroutes: []\n",
            root.to_string_lossy()
        ),
    )?;
    let relative = ApplySettings {
        out_dir: "relative".to_owned(),
        ..settings
    };
    assert!(render_applied(&relative, prog(&fixture), 0).is_err());
    let other = config_error(WafError::BadTls("fixed"));
    assert!(other.to_string().contains("fixed"));
    Ok(())
}


#[test]
fn settings_are_strict_and_bounded() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let good = settings_of(&fixture);
    assert!(check_settings(good.clone()).is_ok());
    let bad_paths = [
        ApplySettings {
            routes_file: "relative".to_owned(),
            ..good.clone()
        },
        ApplySettings {
            out_dir: "/a b".to_owned(),
            ..good.clone()
        },
        ApplySettings {
            retired_caddy_program: true,
            ..good.clone()
        },
        ApplySettings {
            admin_socket: "/run/x|0777".to_owned(),
            ..good.clone()
        },
    ];
    assert!(bad_paths.into_iter().all(|settings| check_settings(settings).is_err()));
    assert!(check_settings(ApplySettings {
        deadline_seconds: 0,
        ..good.clone()
    })
    .is_err());
    assert!(check_settings(ApplySettings {
        deadline_seconds: TOO_LONG_DEADLINE,
        ..good.clone()
    })
    .is_err());
    assert!(!path_text_ok("/a/../b"));
    let file = fixture.dir.path().join("minimal.yaml");
    fs::write(&file, format!("routes_file: {}\nout_dir: {}\n", good.routes_file, good.out_dir))?;
    let loaded = load_trusted_settings_file(&file)?;
    assert!(!loaded.retired_caddy_program);
    assert_eq!(loaded.admin_socket, SOCKET);
    assert_eq!(loaded.deadline_seconds, SETTINGS_DEADLINE);
    fs::write(&file, format!("routes_file: {}\nout_dir: {}\nextra: 1\n", good.routes_file, good.out_dir))?;
    assert!(load_trusted_settings_file(&file).is_err());
    Ok(())
}


#[test]
fn caddy_output_and_the_config_never_reach_an_error_or_the_audit() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "reload-fail")?;
    let outcome = reload(&engine);
    let refused = format!("{outcome:?}");
    assert!(!refused.contains("marker-host"));
    let failure = DeliverError::Spawn {
        step: "validate",
        source: io::Error::other("cannot start"),
    };
    let rendered = format!("{failure} {failure:?} {:?}", StdError::source(&failure).map(ToString::to_string));
    assert!(!rendered.contains("marker-host"));
    assert!(!fs::read_to_string(audit)?.contains("marker-host"));
    Ok(())
}


#[test]
fn discarding_a_missing_staged_file_is_logged_not_fatal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let directory = core_config::trusted_dir::open_trusted_dir(&fixture.out, rustix::process::geteuid().as_raw())?;
    discard(&directory, "missing");
    Ok(())
}


fn script(fixture: &Fixture, name: &str, body: &str) -> Result<(PathBuf, OwnedFd), Box<dyn Error>> {
    let path = fixture.dir.path().join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let handle = open_trusted_program(&path, rustix::process::geteuid().as_raw())?;
    Ok((path, handle))
}


#[test]
fn the_real_runner_reports_success_failure_spawn_error_and_deadline() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let second = Duration::from_secs(1);
    let short = Duration::from_millis(SHORT_DEADLINE_MILLISECONDS);
    let (yes, yes_handle) = script(&fixture, "yes", "exit 0")?;
    assert_eq!(run_with_deadline(&yes_handle, &yes, &[], second)?, CommandStatus::Success);
    let (no, no_handle) = script(&fixture, "no", "exit 1")?;
    assert_eq!(run_with_deadline(&no_handle, &no, &[], second)?, CommandStatus::Failed(Some(1)));
    let empty = open_trusted_program(prog(&fixture), rustix::process::geteuid().as_raw())?;
    assert!(run_with_deadline(&empty, prog(&fixture), &[], second).is_err());
    let (slow, slow_handle) = script(&fixture, "slow", &format!("exec sleep {LONG_SLEEP}"))?;
    assert_eq!(run_with_deadline(&slow_handle, &slow, &[], short)?, CommandStatus::TimedOut);
    Ok(())
}


#[test]
fn the_runner_passes_a_path_with_shell_characters_as_one_argument() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let odd = fixture.dir.path().join("marker file; touch x");
    fs::write(&odd, "")?;
    let arguments = ["-e".to_owned(), odd.to_string_lossy().into_owned()];
    let (checker, handle) = script(&fixture, "checker", "test \"$@\"")?;
    assert_eq!(
        run_with_deadline(&handle, &checker, &arguments, Duration::from_secs(1))?,
        CommandStatus::Success
    );
    assert!(!Path::new("x").exists());
    assert!(!fixture.dir.path().join("x").exists());
    Ok(())
}


#[test]
fn child_runs_the_fake_caddy() -> Result<(), Box<dyn Error>> {
    match std::env::var(PROGRAM_VARIABLE) {
        Ok(program) => {
            let handle = open_trusted_program(Path::new(&program), rustix::process::geteuid().as_raw())?;
            let status = run_with_deadline(
                &handle,
                Path::new(&program),
                &["validate".to_owned()],
                Duration::from_secs(SETTINGS_DEADLINE),
            )?;
            assert_eq!(status, CommandStatus::Success);
            Ok(())
        }
        Err(_) => Ok(()),
    }
}


#[test]
fn the_runner_never_lets_caddy_text_reach_the_standard_streams() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let script = fixture.dir.path().join("caddy-script");
    fs::write(&script, format!("#!/bin/sh\necho {STDERR_MARKER} >&2\necho {STDERR_MARKER}\nexit 0\n"))?;
    fs::set_permissions(&script, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([CHILD_TEST, "--exact", "--test-threads", "1", "--nocapture"])
        .env(PROGRAM_VARIABLE, &script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut standard_out = String::new();
    let mut standard_err = String::new();
    child.stdout.take().ok_or("no stdout")?.read_to_string(&mut standard_out)?;
    child.stderr.take().ok_or("no stderr")?.read_to_string(&mut standard_err)?;
    assert!(child.wait()?.success());
    assert!(standard_out.contains("test result: ok. 1 passed"));
    assert!(!standard_out.contains(STDERR_MARKER));
    assert!(!standard_err.contains(STDERR_MARKER));
    Ok(())
}


#[test]
fn a_staged_file_that_vanishes_before_publish_is_a_refusal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    set_mode(&fixture, "vanish")?;
    let failure = try_open(&fixture)?.err();
    assert!(matches!(failure, Some(OpenError::Deliver(DeliverError::Publish(_)))));
    assert!(final_text(&fixture).is_err());
    Ok(())
}


#[test]
fn a_routes_file_that_cannot_render_stops_the_start() -> Result<(), Box<dyn Error>> {
    let fixture = fixture("routes: [")?;
    let failure = try_open(&fixture)?.err();
    assert!(matches!(failure, Some(OpenError::Config(_))));
    assert!(calls(&fixture).is_empty());
    Ok(())
}


const PID_FILE: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/t555-wait.pid");


fn failing_wait(child: &mut Child, _deadline: Duration) -> io::Result<Option<ExitStatus>> {
    fs::write(PID_FILE, child.id().to_string())?;
    Err(io::Error::other("wait failed"))
}


fn audit_entry(result: &str) -> NewEntry {
    reload_entry(&context(), Outcome::Success, [("result", result.to_owned()), ("diff", "x".to_owned())])
}


fn engine_with_switch(fixture: &Fixture, fail: Arc<AtomicBool>) -> Result<ReloadEngine<Applied>, Box<dyn Error>> {
    let log = Arc::new(open_file_log(&fixture.dir.path().join("audit.log"))?);
    let engine = open_apply_with_program(
        &fixture.settings_file,
        prog(fixture),
        fake,
        Box::new(move |entry| {
            if fail.load(Ordering::SeqCst) {
                Err(AuditError::LogPoisoned)
            } else {
                append(&log, entry)
            }
        }),
        context(),
    )?;
    Ok(engine)
}


fn program_in(fixture: &Fixture, directory_mode: u32, file_mode: u32) -> Result<String, Box<dyn Error>> {
    let directory = fixture.dir.path().join("bin");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(directory_mode))?;
    let program = directory.join("caddy");
    fs::write(&program, "")?;
    fs::set_permissions(&program, fs::Permissions::from_mode(file_mode))?;
    Ok(program.to_string_lossy().into_owned())
}


#[test]
fn a_publish_failure_after_a_confirmed_reload_moves_the_epoch_so_a_revert_pushes_again() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "vanish")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("cannot publish")));
    set_mode(&fixture, "ok")?;
    fs::write(&fixture.routes, ONE_ROUTE)?;
    let before = calls(&fixture).len();
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys.contains(&"waf.epoch".to_owned())));
    assert_eq!(calls(&fixture).len(), before + TWO_CALLS);
    assert!(fs::read_to_string(audit)?.contains("applied"));
    Ok(())
}


#[test]
fn a_failed_audit_after_a_confirmed_reload_moves_the_epoch_so_a_revert_pushes_again() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let fail = Arc::new(AtomicBool::new(false));
    let engine = engine_with_switch(&fixture, Arc::clone(&fail))?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    fail.store(true, Ordering::SeqCst);
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert!(final_text(&fixture)?.contains("marker-host.example.test"));
    fail.store(false, Ordering::SeqCst);
    fs::write(&fixture.routes, ONE_ROUTE)?;
    let before = calls(&fixture).len();
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys.contains(&"waf.epoch".to_owned())));
    assert_eq!(calls(&fixture).len(), before + TWO_CALLS);
    assert!(final_text(&fixture)?.contains("a.example.test"));
    Ok(())
}


#[test]
fn the_late_flag_is_cleared_on_every_entry_and_the_epoch_moves_only_for_a_lost_applied_entry() -> Result<(), Box<dyn Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let late = Arc::new(AtomicBool::new(true));
    let epoch = Arc::new(AtomicU64::new(0));
    let audit = late_audit(
        Box::new(move |entry| {
            sink.lock()
                .map_err(|_| AuditError::LogPoisoned)?
                .push(entry.parameters.contains_key("late"));
            Err(AuditError::LogPoisoned)
        }),
        Arc::clone(&late),
        Arc::clone(&epoch),
    );
    assert!(audit(audit_entry("refused")).is_err());
    assert!(!late.load(Ordering::SeqCst));
    assert_eq!(epoch.load(Ordering::SeqCst), 0);
    assert!(audit(audit_entry("applied")).is_err());
    assert_eq!(epoch.load(Ordering::SeqCst), 1);
    late.store(true, Ordering::SeqCst);
    assert!(audit(audit_entry("applied")).is_err());
    assert_eq!(epoch.load(Ordering::SeqCst), TWO_CALLS as u64);
    assert_eq!(*seen.lock().map_err(|_| "poisoned")?, vec![false, false, true]);
    Ok(())
}


#[test]
fn a_wait_that_fails_kills_and_reaps_the_child_and_reads_back_like_a_failed_reload() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (slow, handle) = script(&fixture, "slow", &format!("exec sleep {LONG_SLEEP}"))?;
    let status = run_child(&handle, &slow, &[], Duration::from_secs(1), failing_wait)?;
    assert_eq!(status, CommandStatus::Failed(None));
    let pid = fs::read_to_string(PID_FILE)?;
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    Ok(())
}


#[test]
fn a_failure_while_stopping_a_child_is_logged_and_stopping_a_reaped_child_is_harmless() -> Result<(), Box<dyn Error>> {
    logged("test", Err(io::Error::other("refused")));
    logged("test", Ok(()));
    let mut child = Command::new("/usr/bin/true").spawn()?;
    child.wait()?;
    stop(&mut child);
    Ok(())
}


#[test]
fn a_program_in_an_open_directory_or_an_open_file_or_a_link_or_nothing_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    assert!(judge_program(prog(&fixture)).is_ok());
    let open_directory = program_in(&fixture, GROUP_WRITABLE, OPEN_DIRECTORY)?;
    assert!(judge_program(Path::new(&open_directory)).is_err_and(|failure| failure.to_string().contains("the Caddy program /usr/bin/caddy")));
    let open_file = program_in(&fixture, OPEN_DIRECTORY, GROUP_WRITABLE)?;
    assert!(judge_program(Path::new(&open_file)).is_err());
    let good = program_in(&fixture, OPEN_DIRECTORY, OPEN_DIRECTORY)?;
    assert!(judge_program(Path::new(&good)).is_ok());
    let link = fixture.dir.path().join("link");
    symlink(&good, &link)?;
    assert!(judge_program(&link).is_err());
    assert!(judge_program(Path::new(&format!("{good}x"))).is_err());
    assert!(judge_program(&fixture.dir.path().join("bin")).is_err());
    assert!(judge_program(Path::new("/")).is_err());
    assert!(judge_program(Path::new("/a/..")).is_err());
    assert!(judge_program(Path::new("/caddy")).is_err());
    Ok(())
}


#[test]
fn a_settings_directory_open_to_group_or_others_or_not_absolute_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    assert!(load_trusted_settings(&fixture.settings_file, prog(&fixture)).is_ok());
    fs::set_permissions(fixture.dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(
        load_trusted_settings(&fixture.settings_file, prog(&fixture)).is_err_and(|failure| failure.to_string().contains("settings file directory"))
    );
    assert!(load_trusted_settings_file(&fixture.settings_file).is_err());
    assert!(load_trusted_settings_file(Path::new("/")).is_err());
    assert!(load_trusted_settings_file(Path::new("settings.yaml")).is_err());
    Ok(())
}


#[test]
fn an_untrusted_program_refuses_the_start() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    fs::set_permissions(prog(&fixture), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Config(_))));
    assert!(calls(&fixture).is_empty());
    Ok(())
}


#[test]
fn a_program_owned_by_another_user_is_refused_at_load_at_delivery_and_in_the_runner() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let applied = render_applied(&settings_of(&fixture), prog(&fixture), 0)?;
    let (marker, handle) = script(&fixture, "marker", &format!("touch {}/spawned", fixture.dir.path().display()))?;
    std::os::unix::fs::chown(&marker, Some(FOREIGN_PROGRAM_OWNER), None)?;
    assert_eq!(
        run_child(&handle, &marker, &[], Duration::from_secs(1), wait_child)?,
        CommandStatus::Refused
    );
    assert!(!fixture.dir.path().join("spawned").exists());
    std::os::unix::fs::chown(prog(&fixture), Some(FOREIGN_PROGRAM_OWNER), None)?;
    assert!(judge_program(prog(&fixture)).is_err());
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Config(_))));
    let failure = deliver(&applied, fake).err().ok_or("delivered")?;
    assert!(matches!(failure, DeliverError::Program(_)));
    let text = format!("{failure} {failure:?}");
    assert!(!text.contains(&fixture.program));
    assert!(calls(&fixture).is_empty());
    Ok(())
}


const FOREIGN_PROGRAM_OWNER: u32 = 65_534;


fn swap_in_the_other_program(program: &Path) {
    let other = format!("{}.other", program.display());
    fs::rename(other, program).unwrap_or_else(|failure| tracing::error!(%failure, "test swap failed"));
}


fn remove_the_program(program: &Path) {
    fs::remove_file(program).unwrap_or_else(|failure| tracing::error!(%failure, "test removal failed"));
}


fn spawned_marker(fixture: &Fixture) -> PathBuf {
    fixture.dir.path().join("spawned")
}


#[test]
fn a_program_renamed_or_removed_between_the_check_and_the_spawn_is_refused_and_nothing_starts() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let body = format!("touch {}", spawned_marker(&fixture).display());
    let (path, handle) = script(&fixture, "swapped", &body)?;
    let other = format!("{}.other", path.display());
    fs::write(&other, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&other, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let euid = rustix::process::geteuid().as_raw();
    let second = Duration::from_secs(1);
    let status = run_child_with_hook((&handle, &path), &[], second, wait_child, (euid, swap_in_the_other_program))?;
    assert_eq!(status, CommandStatus::Refused);
    assert!(!spawned_marker(&fixture).exists());
    let removed = run_child_with_hook((&handle, &path), &[], second, wait_child, (euid, remove_the_program))?;
    assert_eq!(removed, CommandStatus::Refused);
    assert!(!spawned_marker(&fixture).exists());
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let fresh = open_trusted_program(&path, euid)?;
    let same = run_child_with_hook((&fresh, &path), &[], second, wait_child, (euid, leave_alone))?;
    assert_eq!(same, CommandStatus::Success);
    assert!(spawned_marker(&fixture).exists());
    Ok(())
}


#[test]
fn a_refused_run_is_neither_failed_nor_unknown_and_moves_no_epoch() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    set_mode(&fixture, "refused")?;
    let failure = try_open(&fixture)?.err();
    assert!(matches!(
        failure,
        Some(OpenError::Deliver(DeliverError::ProgramChanged { step: "validate" }))
    ));
    set_mode(&fixture, "ok")?;
    let (engine, _audit) = engine_of(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "refuse-reload")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("not started") && !reason.contains("unknown")));
    set_mode(&fixture, "ok")?;
    fs::write(&fixture.routes, ONE_ROUTE)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn no_setting_selects_the_caddy_program_and_the_const_is_the_package_path() -> Result<(), Box<dyn Error>> {
    assert_eq!(CADDY_PROGRAM, "/usr/bin/caddy");
    assert_eq!(production_program(), Path::new("/usr/bin/caddy"));
    let fixture = fixture(ONE_ROUTE)?;
    let sink: Box<core_config::types::SharedAuditFn> = Box::new(|_entry| Err(AuditError::LogPoisoned));
    let engine = open_apply(&fixture.settings_file, refusing_runner, sink, context());
    assert!(engine.is_err());
    let audited = open_apply_audited(&fixture.settings_file, refusing_runner, Err(AuditError::LogPoisoned), context());
    assert!(audited.is_err());
    Ok(())
}


fn refusing_runner(_handle: &OwnedFd, _program: &Path, _arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
    Err(io::Error::other("no program is run here"))
}


const RETIRED_TEXT: &str = "caddy_program is no longer a setting";


#[test]
fn the_retired_caddy_program_key_is_refused_at_start_and_on_reload_with_the_old_configuration_kept() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let base = fs::read_to_string(&fixture.settings_file)?;
    let marker = "/tmp/marker-caddy-value";
    let forms = [
        format!("caddy_program: {marker}\n"),
        "caddy_program:\n".to_owned(),
        "caddy_program: [1, 2]\n".to_owned(),
    ];
    forms.iter().try_for_each(|line| -> Result<(), Box<dyn Error>> {
        fs::write(&fixture.settings_file, format!("{base}{line}"))?;
        let failure = try_open(&fixture)?.err().ok_or("opened")?;
        let text = format!("{failure} {failure:?}");
        assert!(text.contains(RETIRED_TEXT) && !text.contains(marker));
        assert!(calls(&fixture).is_empty());
        Ok(())
    })?;
    fs::write(&fixture.settings_file, &base)?;
    let (engine, audit) = engine_of(&fixture)?;
    let running = current_config(&engine).json.clone();
    fs::write(&fixture.settings_file, format!("{base}caddy_program: {marker}\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(RETIRED_TEXT) && !reason.contains(marker)));
    assert_eq!(current_config(&engine).json, running);
    let log = fs::read_to_string(audit)?;
    assert!(log.contains(RETIRED_TEXT) && log.contains("denied") && !log.contains(marker));
    Ok(())
}


#[test]
fn an_untrusted_program_or_settings_directory_on_reload_keeps_the_old_settings_and_is_audited() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = calls(&fixture).len();
    let base = settings_of(&fixture);
    fs::set_permissions(prog(&fixture), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("the Caddy program")));
    assert_eq!(current_config(&engine).settings.admin_socket, base.admin_socket);
    fs::set_permissions(prog(&fixture), fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    fs::set_permissions(fixture.dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("settings file directory")));
    assert_eq!(calls(&fixture).len(), before);
    let log = fs::read_to_string(audit)?;
    assert!(log.contains("the Caddy program") && log.contains("settings file directory"));
    Ok(())
}


#[test]
fn the_admin_directory_refusal_names_the_admin_socket() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    fs::set_permissions(&fixture.admin, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    let failure = open_admin_directory(&settings_of(&fixture).admin_socket).err().ok_or("accepted")?;
    let cause = failure.source().ok_or("no cause")?.to_string();
    assert!(cause.contains("admin socket directory"));
    assert!(!cause.contains("output directory"));
    fs::set_permissions(&fixture.admin, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let missing = open_admin_directory(&fixture.admin.join("gone").join("sock").to_string_lossy())
        .err()
        .ok_or("accepted")?;
    assert!(matches!(missing, DeliverError::AdminDir(WafError::CaWrite(_))));
    Ok(())
}


const WORLD_WRITABLE_FILE: u32 = 0o666;


const REGULAR_FILE_MODE: u32 = 0o100_644;


const DIRECTORY_FILE_MODE: u32 = 0o040_755;


const FOREIGN_OWNER: u32 = 1_234;


const RUNNING_USER: u32 = 1_000;


const SETTINGS_FILE_TEXT: &str = "settings file must be a regular file";


#[test]
fn a_settings_file_open_to_others_or_foreign_or_linked_or_not_regular_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    assert!(load_trusted_settings(&fixture.settings_file, prog(&fixture)).is_ok());
    assert!(file_trusted(REGULAR_FILE_MODE, RUNNING_USER, RUNNING_USER));
    assert!(file_trusted(REGULAR_FILE_MODE, 0, RUNNING_USER));
    assert!(!file_trusted(REGULAR_FILE_MODE, FOREIGN_OWNER, RUNNING_USER));
    assert!(!file_trusted(REGULAR_FILE_MODE | WORLD_WRITABLE_FILE, RUNNING_USER, RUNNING_USER));
    assert!(!file_trusted(DIRECTORY_FILE_MODE, RUNNING_USER, RUNNING_USER));
    fs::set_permissions(&fixture.settings_file, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(load_trusted_settings(&fixture.settings_file, prog(&fixture)).is_err_and(|failure| failure.to_string().contains(SETTINGS_FILE_TEXT)));
    fs::set_permissions(&fixture.settings_file, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let target = fixture.dir.path().join("target.yaml");
    fs::copy(&fixture.settings_file, &target)?;
    let link = fixture.dir.path().join("link.yaml");
    symlink(&target, &link)?;
    assert!(load_trusted_settings(&link, prog(&fixture)).is_err_and(|failure| failure.to_string().contains(SETTINGS_FILE_TEXT)));
    assert!(load_trusted_settings(&fixture.dir.path().join("none.yaml"), prog(&fixture)).is_err());
    assert!(load_trusted_settings(&fixture.dir.path().join("bin"), prog(&fixture)).is_err());
    Ok(())
}


#[test]
fn an_open_or_linked_settings_file_refuses_the_start_and_a_reload_and_keeps_the_old_settings() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let base = settings_of(&fixture);
    fs::set_permissions(&fixture.settings_file, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Config(_))));
    assert!(calls(&fixture).is_empty());
    fs::set_permissions(&fixture.settings_file, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = calls(&fixture).len();
    fs::set_permissions(&fixture.settings_file, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(SETTINGS_FILE_TEXT)));
    assert_eq!(current_config(&engine).settings.admin_socket, base.admin_socket);
    fs::set_permissions(&fixture.settings_file, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let real = fixture.dir.path().join("real.yaml");
    fs::rename(&fixture.settings_file, &real)?;
    symlink(&real, &fixture.settings_file)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(SETTINGS_FILE_TEXT)));
    assert_eq!(current_config(&engine).settings.admin_socket, base.admin_socket);
    assert_eq!(calls(&fixture).len(), before);
    assert!(fs::read_to_string(audit)?.contains(SETTINGS_FILE_TEXT));
    Ok(())
}


#[test]
fn a_device_node_as_program_is_refused_without_opening_it() -> Result<(), Box<dyn Error>> {
    assert!(judge_program(Path::new("/dev/null")).is_err());
    Ok(())
}


const ROUTES_FILE_TEXT: &str = "routes file must be a regular file";


const ROUTES_DIRECTORY_TEXT: &str = "routes file directory must be absolute";


const GROUP_WRITABLE_DIRECTORY: u32 = 0o775;


const SECOND_ROUTE: &str = "routes:\n  - hosts: [b.example.test]\n    backends: [\"127.0.0.1:9002\"]\n";


#[test]
fn a_routes_file_open_to_others_or_linked_or_in_an_open_directory_or_missing_is_refused() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    assert!(load_trusted_routes(&fixture.routes).is_ok());
    fs::set_permissions(&fixture.routes, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(load_trusted_routes(&fixture.routes).is_err_and(|failure| failure.to_string().contains(ROUTES_FILE_TEXT)));
    fs::set_permissions(&fixture.routes, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let link = fixture.dir.path().join("link.yaml");
    symlink(&fixture.routes, &link)?;
    assert!(load_trusted_routes(&link).is_err_and(|failure| failure.to_string().contains(ROUTES_FILE_TEXT)));
    assert!(load_trusted_routes(&fixture.dir.path().join("none.yaml")).is_err());
    assert!(load_trusted_routes(&fixture.out).is_err());
    assert!(load_trusted_routes(Path::new("/")).is_err_and(|failure| failure.to_string().contains(ROUTES_DIRECTORY_TEXT)));
    assert!(load_trusted_routes(Path::new("relative.yaml")).is_err());
    fs::set_permissions(fixture.dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE_DIRECTORY))?;
    assert!(load_trusted_routes(&fixture.routes).is_err_and(|failure| failure.to_string().contains(ROUTES_DIRECTORY_TEXT)));
    Ok(())
}


#[test]
fn an_untrusted_routes_file_refuses_the_start_and_a_reload_keeps_the_old_routes_and_is_audited() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    fs::set_permissions(&fixture.routes, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(matches!(try_open(&fixture)?.err(), Some(OpenError::Config(_))));
    assert!(calls(&fixture).is_empty());
    fs::set_permissions(&fixture.routes, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = calls(&fixture).len();
    let old = current_config(&engine).json.clone();
    fs::write(&fixture.routes, SECOND_ROUTE)?;
    fs::set_permissions(&fixture.routes, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(ROUTES_FILE_TEXT)));
    assert_eq!(current_config(&engine).json, old);
    let real = fixture.dir.path().join("real.yaml");
    fs::rename(&fixture.routes, &real)?;
    fs::set_permissions(&real, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    symlink(&real, &fixture.routes)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(ROUTES_FILE_TEXT)));
    assert_eq!(current_config(&engine).json, old);
    assert_eq!(calls(&fixture).len(), before);
    assert!(fs::read_to_string(audit)?.contains(ROUTES_FILE_TEXT));
    Ok(())
}


const CA_ROOT_FILE_TEXT: &str = "ca_root_file must be a regular file";


const CA_ROOT_DIRECTORY_TEXT: &str = "ca_root_file directory must be absolute";


const CA_ROUTES_PREFIX: &str = "tls:\n  issuer: acme\n  directory: https://acme.example.test/d\n  email: ops@example.test\n  ca_root_file: ";


const CA_ROUTES_SUFFIX: &str = "\nroutes:\n  - hosts: [a.test]\n    backends: [\"127.0.0.1:9001\"]\n";


fn ca_fixture() -> Result<(Fixture, PathBuf), Box<dyn Error>> {
    let fixture = fixture("")?;
    let directory = fixture.dir.path().join("ca");
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let root = directory.join("root.pem");
    fs::copy(CA_PEM, &root)?;
    fs::write(&fixture.routes, format!("{CA_ROUTES_PREFIX}{}{CA_ROUTES_SUFFIX}", root.to_string_lossy()))?;
    Ok((fixture, root))
}


fn audit_lines(fixture: &Fixture) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(fs::read_to_string(fixture.dir.path().join("audit.log"))?
        .lines()
        .map(str::to_owned)
        .collect())
}


#[test]
fn a_ca_root_file_is_judged_like_the_routes_file() -> Result<(), Box<dyn Error>> {
    let (fixture, root) = ca_fixture()?;
    let settings = settings_of(&fixture);
    assert!(render_applied(&settings, prog(&fixture), 0).is_ok());
    fs::set_permissions(&root, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(render_applied(&settings, prog(&fixture), 0).is_err_and(|failure| failure.to_string().contains(CA_ROOT_FILE_TEXT)));
    fs::set_permissions(&root, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let real = root.with_file_name("real.pem");
    fs::rename(&root, &real)?;
    symlink(&real, &root)?;
    assert!(render_applied(&settings, prog(&fixture), 0).is_err_and(|failure| failure.to_string().contains(CA_ROOT_FILE_TEXT)));
    fs::remove_file(&root)?;
    fs::rename(&real, &root)?;
    assert!(render_applied(&settings, prog(&fixture), 0).is_ok());
    let directory = root.parent().ok_or("no parent")?;
    fs::set_permissions(directory, fs::Permissions::from_mode(GROUP_WRITABLE_DIRECTORY))?;
    assert!(render_applied(&settings, prog(&fixture), 0).is_err_and(|failure| failure.to_string().contains(CA_ROOT_DIRECTORY_TEXT)));
    assert!(!file_trusted(REGULAR_FILE_MODE, FOREIGN_OWNER, RUNNING_USER));
    assert!(file_trusted(REGULAR_FILE_MODE, 0, RUNNING_USER));
    Ok(())
}


#[test]
fn the_owner_predicate_takes_the_euid_it_is_given() -> Result<(), Box<dyn Error>> {
    assert!(file_trusted(REGULAR_FILE_MODE, FOREIGN_OWNER, FOREIGN_OWNER));
    assert!(!file_trusted(REGULAR_FILE_MODE, FOREIGN_OWNER, RUNNING_USER));
    assert!(!file_trusted(REGULAR_FILE_MODE, RUNNING_USER, FOREIGN_OWNER));
    assert!(file_trusted(REGULAR_FILE_MODE, 0, FOREIGN_OWNER));
    Ok(())
}


#[test]
fn a_reload_with_an_untrusted_ca_root_keeps_the_old_configuration_and_is_audited() -> Result<(), Box<dyn Error>> {
    let (fixture, root) = ca_fixture()?;
    let (engine, _audit) = engine_of(&fixture)?;
    let before = calls(&fixture).len();
    let old = current_config(&engine).json.clone();
    fs::set_permissions(&root, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    fs::write(&root, "")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains(CA_ROOT_FILE_TEXT)));
    assert_eq!(current_config(&engine).json, old);
    assert_eq!(calls(&fixture).len(), before);
    assert!(audit_lines(&fixture)?.last().is_some_and(|line| line.contains("denied")));
    Ok(())
}


#[test]
fn a_start_refused_for_a_bad_file_writes_one_denied_entry_and_never_reaches_caddy() -> Result<(), Box<dyn Error>> {
    let routes = fixture(ONE_ROUTE)?;
    fs::set_permissions(&routes.routes, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    let (settings, _root) = ca_fixture()?;
    fs::set_permissions(&settings.settings_file, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    let (ca, root) = ca_fixture()?;
    fs::set_permissions(&root, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    let texts = [(&routes, ROUTES_FILE_TEXT), (&settings, SETTINGS_FILE_TEXT), (&ca, CA_ROOT_FILE_TEXT)];
    texts.iter().try_for_each(|(fixture, text)| -> Result<(), Box<dyn Error>> {
        assert!(matches!(try_open(fixture)?.err(), Some(OpenError::Config(_))));
        let lines = audit_lines(fixture)?;
        assert_eq!(lines.len(), 1);
        assert!(lines
            .iter()
            .all(|line| line.contains("denied") && line.contains("refused") && line.contains(text)));
        assert!(calls(fixture).is_empty());
        Ok(())
    })
}


#[test]
fn a_refusal_at_start_is_returned_even_when_its_audit_fails() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    fs::set_permissions(&fixture.routes, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    let failure = open_apply_with_program(
        &fixture.settings_file,
        prog(&fixture),
        fake,
        Box::new(|_entry| Err(AuditError::LogPoisoned)),
        context(),
    )
    .err();
    assert!(matches!(failure, Some(OpenError::Config(_))));
    Ok(())
}


#[test]
fn a_sink_that_cannot_open_is_named_with_the_refusal_when_there_is_one() -> Result<(), Box<dyn Error>> {
    let good = fixture(ONE_ROUTE)?;
    let bad = fixture(ONE_ROUTE)?;
    fs::set_permissions(&bad.routes, fs::Permissions::from_mode(WORLD_WRITABLE_FILE))?;
    assert!(start_refusal(&good.settings_file, prog(&good)).is_none());
    assert!(start_refusal(&bad.settings_file, prog(&bad)).is_some());
    let only_sink = open_apply_audited_with_program(&good.settings_file, prog(&good), fake, Err(AuditError::LogPoisoned), context()).err();
    assert!(matches!(only_sink, Some(OpenError::NoSink(_))));
    let both = open_apply_audited_with_program(&bad.settings_file, prog(&bad), fake, Err(AuditError::LogPoisoned), context())
        .err()
        .ok_or("opened")?;
    assert!(matches!(both, OpenError::NoSinkAndRefused { .. }));
    let text = both.to_string();
    assert!(text.contains("audit sink") && text.contains(ROUTES_FILE_TEXT));
    let log = Arc::new(open_file_log(&good.dir.path().join("audit.log"))?);
    let sink: Box<core_config::types::SharedAuditFn> = Box::new(move |entry| append(&log, entry));
    assert!(open_apply_audited_with_program(&good.settings_file, prog(&good), fake, Ok(sink), context()).is_ok());
    Ok(())
}
