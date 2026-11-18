#![cfg(unix)]

use core_audit::log::{append, open_file_log};
use core_config::reload::{reload, ReloadContext, ReloadEngine, ReloadOutcome};
use data_encoding::HEXLOWER;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::error::Error as StdError;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use waf::apply::{
    applied_state, check_settings, config_error, discard, load_settings, open_apply, path_text_ok, refused_text, render_applied,
    render_applied_capped,
};
use waf::error::{DeliverError, OpenError, WafError};
use waf::model::{Applied, ApplySettings, CommandStatus, Refusal};
use waf::runner::run_with_deadline;


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


struct Fixture {
    dir: tempfile::TempDir,
    routes: PathBuf,
    out: PathBuf,
    program: String,
}


fn fixture(routes_text: &str) -> Result<Fixture, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let routes = dir.path().join("routes.yaml");
    fs::write(&routes, routes_text)?;
    let out = dir.path().join("out");
    fs::create_dir(&out)?;
    fs::set_permissions(&out, fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let program = dir.path().join("fake").to_string_lossy().into_owned();
    fs::write(format!("{program}.mode"), "ok")?;
    Ok(Fixture { dir, routes, out, program })
}


fn settings_of(fixture: &Fixture) -> ApplySettings {
    ApplySettings {
        routes_file: fixture.routes.to_string_lossy().into_owned(),
        out_dir: fixture.out.to_string_lossy().into_owned(),
        caddy_program: fixture.program.clone(),
        admin_socket: SOCKET.to_owned(),
        deadline_seconds: SETTINGS_DEADLINE,
    }
}


fn set_mode(fixture: &Fixture, mode: &str) -> Result<(), Box<dyn Error>> {
    Ok(fs::write(format!("{}.mode", fixture.program), mode)?)
}


fn calls(fixture: &Fixture) -> Vec<String> {
    fs::read_to_string(format!("{}.calls", fixture.program)).map_or_else(|_| Vec::new(), |text| text.lines().map(str::to_owned).collect())
}


fn fake(program: &str, arguments: &[String], _deadline: Duration) -> io::Result<CommandStatus> {
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
        ("vanish", "reload") => {
            fs::remove_file(arguments.get(STAGED_ARGUMENT).ok_or_else(|| io::Error::other("no path"))?).map(|()| CommandStatus::Success)
        }
        ("spawn-fail", _) => Err(io::Error::other("cannot start")),
        _ => Ok(CommandStatus::Success),
    }
}


fn try_open(fixture: &Fixture) -> Result<Result<ReloadEngine<Applied>, OpenError>, Box<dyn Error>> {
    let audit_path = fixture.dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit_path)?);
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "platform".to_owned(),
        module: "waf".to_owned(),
        target: "routes".to_owned(),
        request_id: "r".to_owned(),
    };
    Ok(open_apply(
        settings_of(fixture),
        fake,
        Box::new(move |entry| append(&log, entry)),
        context,
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


#[test]
fn the_render_with_admin_listen_matches_the_golden_file() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(&fs::read_to_string(TWO_ROUTES)?)?;
    let applied = render_applied(&settings_of(&fixture))?;
    assert_eq!(applied.json, fs::read_to_string(TWO_ROUTES_ADMIN)?.trim_end());
    let value: Value = serde_json::from_str(&applied.json)?;
    assert_eq!(
        value.pointer("/admin/listen").and_then(Value::as_str),
        Some("unix//run/ostyr-waf/caddy-admin.sock")
    );
    Ok(())
}


#[test]
fn a_first_load_validates_then_reloads_the_same_bytes_and_publishes() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (_engine, _audit) = engine_of(&fixture)?;
    let recorded = calls(&fixture);
    assert_eq!(recorded.len(), TWO_CALLS);
    let published = final_text(&fixture)?;
    let staged = format!("{}/.apply-", fixture.out.to_string_lossy());
    let first = recorded.first().ok_or("no validate")?;
    let second = recorded.get(1).ok_or("no reload")?;
    assert!(first.starts_with(&format!("validate --config {staged}")));
    assert!(second.starts_with(&format!("reload --config {staged}")));
    assert!(second.contains(" --address unix//run/ostyr-waf/caddy-admin.sock|"));
    assert!(first.ends_with(&hash_of(&published)));
    assert!(second.ends_with(&hash_of(&published)));
    assert_eq!(fs::metadata(fixture.out.join("caddy.json"))?.permissions().mode() & MODE_BITS, OWNER_ONLY);
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 1);
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
    Ok(())
}


#[test]
fn a_failed_reload_and_a_deadline_each_keep_the_old_file() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let (engine, audit) = engine_of(&fixture)?;
    let before = final_text(&fixture)?;
    fs::write(&fixture.routes, MARKER_ROUTE)?;
    set_mode(&fixture, "reload-fail")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("reload failed with exit status Some(3)")));
    set_mode(&fixture, "reload-timeout")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("reload exceeded 30 seconds")));
    set_mode(&fixture, "spawn-fail")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("cannot run caddy validate")));
    assert_eq!(final_text(&fixture)?, before);
    assert_eq!(fs::read_dir(&fixture.out)?.count(), 1);
    assert!(fs::read_to_string(audit)?.matches("refused").count() >= THREE_CALLS);
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
    let current = core_config::reload::current_config(&engine);
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
        json: "{}".to_owned(),
        ca_root: None,
        refused,
    };
    let text = refused_text(&applied);
    assert!(text.starts_with("40 refused: 0,1,2"));
    assert!(text.ends_with(&format!(",{} [{} more omitted]", LISTED - 1, REFUSED_COUNT - LISTED)));
    assert_eq!(applied_state(&applied).len(), TWO_CALLS);
    Ok(())
}


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
    assert!(render_applied(&settings).is_err());
    fs::write(&fixture.routes, "tls:\n  issuer: internal\n  email: x\nroutes: []\n")?;
    assert!(render_applied(&settings).is_err());
    fs::write(&fixture.routes, ONE_ROUTE)?;
    let too_large = render_applied_capped(&settings, TINY_CAP).err().ok_or("rendered")?.to_string();
    assert!(too_large.contains("exceeds the limit"));
    let missing = ApplySettings {
        routes_file: "/nonexistent/routes.yaml".to_owned(),
        ..settings.clone()
    };
    assert!(render_applied(&missing).is_err());
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
    assert!(render_applied(&relative).is_err());
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
            caddy_program: "-x".to_owned(),
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
    let file = fixture.dir.path().join("settings.yaml");
    fs::write(&file, format!("routes_file: {}\nout_dir: {}\n", good.routes_file, good.out_dir))?;
    let loaded = load_settings(&file)?;
    assert_eq!(loaded.caddy_program, "/usr/bin/caddy");
    assert_eq!(loaded.admin_socket, SOCKET);
    assert_eq!(loaded.deadline_seconds, SETTINGS_DEADLINE);
    fs::write(&file, format!("routes_file: {}\nout_dir: {}\nextra: 1\n", good.routes_file, good.out_dir))?;
    assert!(load_settings(&file).is_err());
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


#[test]
fn the_real_runner_reports_success_failure_spawn_error_and_deadline() -> Result<(), Box<dyn Error>> {
    let second = Duration::from_secs(1);
    let short = Duration::from_millis(SHORT_DEADLINE_MILLISECONDS);
    assert_eq!(run_with_deadline("/usr/bin/true", &[], second)?, CommandStatus::Success);
    assert_eq!(run_with_deadline("/usr/bin/false", &[], second)?, CommandStatus::Failed(Some(1)));
    assert!(run_with_deadline("/nonexistent/caddy", &[], second).is_err());
    assert_eq!(
        run_with_deadline("/usr/bin/sleep", &[LONG_SLEEP.to_owned()], short)?,
        CommandStatus::TimedOut
    );
    Ok(())
}


#[test]
fn the_runner_passes_arguments_separately() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    let marker = fixture.dir.path().join("marker file; touch x");
    let arguments = [marker.to_string_lossy().into_owned()];
    let status = run_with_deadline("/usr/bin/test", &["-e".to_owned(), arguments[0].clone()], Duration::from_secs(1))?;
    assert_eq!(status, CommandStatus::Failed(Some(1)));
    assert!(!Path::new("x").exists());
    Ok(())
}


#[test]
fn a_staged_file_that_vanishes_before_publish_is_a_refusal() -> Result<(), Box<dyn Error>> {
    let fixture = fixture(ONE_ROUTE)?;
    set_mode(&fixture, "vanish")?;
    let failure = try_open(&fixture)?.err();
    assert!(matches!(failure, Some(OpenError::Deliver(DeliverError::Write(_)))));
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
