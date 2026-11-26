#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use core_audit::log::open_file_log;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, reload, ReloadOutcome};
use core_config::types::{LoaderFn, SharedAuditFn};
use intel_feeds::config::{ClickhouseConfig, FeedConfig, FeedsFile};
use intel_feeds::error::TaxiiError;
use intel_feeds::limits::ROUND_CAP_EXIT_CODE;
use intel_feeds::load::{LoadError, LoadOutcome};
use intel_feeds::model::Ioc;
use intel_feeds::round::RoundHooks;
use intel_feeds::serve::{
    check_start_only, exit_code, left_of, open_service, parse_args, production_load, production_poll, serve_rounds, service_engine, signal_waiter,
    validate_settings, LoopEnd, ServeHooks, ServiceError, ServiceSettings,
};
use intel_feeds::taxii::PollOutcome;
use signal_hook::consts::SIGUSR1;
use signal_hook::low_level::raise;
use std::cell::{Cell, RefCell};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Cursor, ErrorKind, Write};
use std::net::TcpListener;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::scope;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const HANG_GUARD: Duration = Duration::from_secs(120);


const SETTLE: Duration = Duration::from_millis(300);


const INTERVAL: Duration = Duration::from_secs(60);


const ROUNDS: usize = 3;


const CAP: usize = 2;


const PASSWORD_MODE: u32 = 0o600;


const INTERVAL_SECONDS: u64 = 60;


const BELOW_MIN: u64 = 59;


const ABOVE_MAX: u64 = 86_401;


const AT_MAX: u64 = 86_400;


const DEFAULT_PORT: u16 = 9;


const FEEDS_AFTER: usize = 2;


const AUDIT_LINES: usize = 4;


const ROUND_SECONDS: i64 = 10;


const LEFT_SECONDS: u64 = 50;


const LONG_ROUND_SECONDS: i64 = 500;


const FEEDS_HEAD: &str = "feeds:\n  - name: good\n    format: crowdsec\n    path: good.txt\n";


const FEEDS_MORE: &str =
    "feeds:\n  - name: good\n    format: crowdsec\n    path: good.txt\n  - name: more\n    format: crowdsec\n    path: good.txt\n";


fn clickhouse_block(tenant: &str, port: u16) -> String {
    format!(
        "clickhouse:\n  url: http://127.0.0.1:{port}\n  user: u\n  password_file: /x\n  database: d\n  table: t\n  dictionary: dd\n  tenant: {tenant}\n"
    )
}


struct Rig {
    dir: TempDir,
}


fn make_rig(feeds: &str) -> Result<Rig, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    fs::write(dir.path().join("feeds.yaml"), feeds)?;
    Ok(Rig { dir })
}


fn standard() -> String {
    format!("{FEEDS_HEAD}{}", clickhouse_block("tenant-a", DEFAULT_PORT))
}


fn settings_text(rig: &Rig, interval: u64) -> String {
    format!(
        "feeds_file: {0}/feeds.yaml\naudit_file: {0}/audit.jsonl\ninterval_seconds: {interval}\n",
        rig.dir.path().display()
    )
}


fn write_settings(rig: &Rig, text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = rig.dir.path().join("settings.yaml");
    fs::write(&path, text)?;
    Ok(path.display().to_string())
}


fn open_ok(rig: &Rig) -> Result<intel_feeds::serve::Service, Box<dyn std::error::Error>> {
    let path = write_settings(rig, &settings_text(rig, INTERVAL_SECONDS))?;
    Ok(open_service(&[path])?)
}


fn audit_text(rig: &Rig) -> Result<String, io::Error> {
    fs::read_to_string(rig.dir.path().join("audit.jsonl"))
}


fn open(path: &Path) -> io::Result<Box<dyn BufRead>> {
    if path == Path::new("good.txt") {
        Ok(Box::new(Cursor::new("192.0.2.1\n")))
    } else {
        Err(io::Error::from(ErrorKind::NotFound))
    }
}


fn stored(_config: &ClickhouseConfig, iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    Ok(LoadOutcome {
        rows_per_batch: vec![iocs.len()],
        batches_planned: 1,
        ..LoadOutcome::default()
    })
}


fn no_poll(_feed: &FeedConfig, _cursor: Option<OffsetDateTime>, _now: OffsetDateTime) -> Result<PollOutcome, TaxiiError> {
    Err(TaxiiError::Unavailable)
}


fn is_refused<Value>(result: Result<Value, ServiceError>, wanted: &str) -> bool {
    result.err().is_some_and(|error| error.to_string().contains(wanted))
}


#[test]
fn the_arguments_are_one_settings_path() -> TestResult {
    assert_eq!(parse_args(&["settings.yaml".to_owned()])?, PathBuf::from("settings.yaml"));
    assert!(matches!(parse_args(&[]), Err(ServiceError::Usage)));
    assert!(matches!(parse_args(&["a".to_owned(), "b".to_owned()]), Err(ServiceError::Usage)));
    Ok(())
}


#[test]
fn settings_bounds_are_checked() -> TestResult {
    let good = ServiceSettings {
        feeds_file: PathBuf::from("/feeds.yaml"),
        audit_file: PathBuf::from("/audit.jsonl"),
        interval_seconds: INTERVAL_SECONDS,
    };
    assert!(validate_settings(&good).is_ok());
    let relative_feeds = ServiceSettings {
        feeds_file: PathBuf::from("feeds.yaml"),
        ..good.clone()
    };
    assert!(matches!(validate_settings(&relative_feeds), Err(ServiceError::Paths)));
    let relative_audit = ServiceSettings {
        audit_file: PathBuf::from("audit.jsonl"),
        ..good.clone()
    };
    assert!(matches!(validate_settings(&relative_audit), Err(ServiceError::Paths)));
    [BELOW_MIN, ABOVE_MAX, 0].into_iter().try_for_each(|interval| {
        let settings = ServiceSettings {
            interval_seconds: interval,
            ..good.clone()
        };
        assert!(matches!(validate_settings(&settings), Err(ServiceError::Interval)));
        Ok::<(), io::Error>(())
    })?;
    [INTERVAL_SECONDS, AT_MAX].into_iter().for_each(|interval| {
        let settings = ServiceSettings {
            interval_seconds: interval,
            ..good.clone()
        };
        assert!(validate_settings(&settings).is_ok());
    });
    Ok(())
}


#[test]
fn start_refuses_each_bad_input_by_name() -> TestResult {
    let rig = make_rig(&standard())?;
    assert!(is_refused(open_service(&[]), "usage"));
    assert!(is_refused(open_service(&["/nonexistent/settings.yaml".to_owned()]), ""));
    let unknown = write_settings(&rig, &format!("{}extra: 1\n", settings_text(&rig, INTERVAL_SECONDS)))?;
    assert!(open_service(&[unknown]).is_err());
    let relative = write_settings(&rig, "feeds_file: feeds.yaml\naudit_file: /tmp/a\ninterval_seconds: 60\n")?;
    assert!(is_refused(open_service(&[relative]), "absolute"));
    let slow = write_settings(&rig, &settings_text(&rig, BELOW_MIN))?;
    assert!(is_refused(open_service(&[slow]), "interval_seconds"));
    let no_audit_dir = write_settings(
        &rig,
        &format!(
            "feeds_file: {}/feeds.yaml\naudit_file: /nonexistent/dir/audit.jsonl\ninterval_seconds: 60\n",
            rig.dir.path().display()
        ),
    )?;
    assert!(is_refused(open_service(&[no_audit_dir]), "audit"));
    fs::write(rig.dir.path().join("feeds.yaml"), FEEDS_HEAD)?;
    let path = write_settings(&rig, &settings_text(&rig, INTERVAL_SECONDS))?;
    assert!(is_refused(open_service(std::slice::from_ref(&path)), "clickhouse"));
    fs::write(rig.dir.path().join("feeds.yaml"), format!("{FEEDS_HEAD}{FEEDS_HEAD}"))?;
    assert!(open_service(&[path]).is_err());
    Ok(())
}


#[test]
fn a_reload_is_audited_under_the_all_tenant_and_a_tenant_change_is_refused() -> TestResult {
    let rig = make_rig(&standard())?;
    let service = open_ok(&rig)?;
    assert_eq!(service.settings.interval_seconds, INTERVAL_SECONDS);
    fs::write(
        rig.dir.path().join("feeds.yaml"),
        format!("{FEEDS_MORE}{}", clickhouse_block("tenant-a", DEFAULT_PORT)),
    )?;
    assert!(matches!(reload(&service.engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&service.engine).feeds.len(), FEEDS_AFTER);
    fs::write(
        rig.dir.path().join("feeds.yaml"),
        format!("{FEEDS_HEAD}{}", clickhouse_block("tenant-b", DEFAULT_PORT)),
    )?;
    assert!(matches!(reload(&service.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(
        current_config(&service.engine).clickhouse.as_ref().map(|config| config.tenant.as_str()),
        Some("tenant-a")
    );
    fs::write(rig.dir.path().join("feeds.yaml"), FEEDS_HEAD)?;
    assert!(matches!(reload(&service.engine), ReloadOutcome::Refused { .. }));
    fs::write(rig.dir.path().join("feeds.yaml"), "not: [valid")?;
    assert!(matches!(reload(&service.engine), ReloadOutcome::Refused { .. }));
    let audit = audit_text(&rig)?;
    assert_eq!(audit.lines().count(), AUDIT_LINES);
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")));
    assert!(audit.contains("clickhouse.tenant"));
    assert!(audit.contains("\"result\":\"applied\""));
    assert!(!audit.contains("tenant-a\""));
    Ok(())
}


#[test]
fn the_tenant_baseline_tracks_absent_and_present() -> TestResult {
    let rig = make_rig(&standard())?;
    let with: FeedsFile = load_file(&rig.dir.path().join("feeds.yaml"))?;
    let without = FeedsFile {
        clickhouse: None,
        ..with.clone()
    };
    let baseline = OnceLock::new();
    assert!(check_start_only(&baseline, &with).is_ok());
    assert!(check_start_only(&baseline, &with).is_ok());
    assert!(matches!(check_start_only(&baseline, &without), Err(ConfigError::WatchedFile { .. })));
    let absent = OnceLock::new();
    assert!(check_start_only(&absent, &without).is_ok());
    assert!(matches!(check_start_only(&absent, &with), Err(ConfigError::WatchedFile { .. })));
    Ok(())
}


#[test]
fn the_wait_left_is_the_interval_less_the_round() -> TestResult {
    let later = NOW + time::Duration::seconds(ROUND_SECONDS);
    assert_eq!(left_of(INTERVAL, NOW, later), Duration::from_secs(LEFT_SECONDS));
    assert_eq!(left_of(INTERVAL, NOW, NOW + time::Duration::seconds(LONG_ROUND_SECONDS)), Duration::ZERO);
    assert_eq!(left_of(INTERVAL, later, NOW), INTERVAL);
    Ok(())
}


#[test]
fn rounds_run_one_after_the_other_until_a_stop_or_the_cap() -> TestResult {
    let rig = make_rig(&standard())?;
    let service = open_ok(&rig)?;
    let loads = Cell::<usize>::default();
    let waits = RefCell::new(Vec::new());
    let load = |config: &ClickhouseConfig, iocs: &[Ioc], feeds: &[FeedConfig], now| {
        loads.set(loads.get() + 1);
        stored(config, iocs, feeds, now)
    };
    let stopper = |left: Duration| {
        waits.borrow_mut().push(left);
        waits.borrow().len() >= ROUNDS
    };
    let hooks = ServeHooks {
        round: RoundHooks {
            clock: &|| NOW,
            open: &open,
            poll: &no_poll,
            load: &load,
        },
        wait: &stopper,
    };
    assert_eq!(serve_rounds(&service.engine, INTERVAL, &hooks, u64::MAX), LoopEnd::Stopped);
    assert_eq!(loads.get(), ROUNDS);
    assert_eq!(*waits.borrow(), vec![INTERVAL; ROUNDS]);
    loads.set(0);
    let never = |_left: Duration| false;
    let capped = ServeHooks { wait: &never, ..hooks };
    assert_eq!(serve_rounds(&service.engine, INTERVAL, &capped, CAP as u64), LoopEnd::RoundCap);
    assert_eq!(loads.get(), CAP);
    Ok(())
}


#[test]
fn a_reload_during_a_round_never_changes_that_rounds_settings() -> TestResult {
    let rig = make_rig(&standard())?;
    let service = open_ok(&rig)?;
    let counts = RefCell::new(Vec::new());
    fs::write(
        rig.dir.path().join("feeds.yaml"),
        format!("{FEEDS_MORE}{}", clickhouse_block("tenant-a", DEFAULT_PORT)),
    )?;
    let load = |config: &ClickhouseConfig, iocs: &[Ioc], feeds: &[FeedConfig], now| {
        counts.borrow_mut().push(feeds.len());
        reload(&service.engine);
        stored(config, iocs, feeds, now)
    };
    let stop = |_left: Duration| true;
    let hooks = ServeHooks {
        round: RoundHooks {
            clock: &|| NOW,
            open: &open,
            poll: &no_poll,
            load: &load,
        },
        wait: &stop,
    };
    serve_rounds(&service.engine, INTERVAL, &hooks, 1);
    assert_eq!(*counts.borrow(), vec![1]);
    assert_eq!(current_config(&service.engine).feeds.len(), FEEDS_AFTER);
    Ok(())
}


#[test]
fn a_stop_waits_for_the_reload_in_flight_and_its_audit_record() -> TestResult {
    let rig = make_rig(&standard())?;
    let path = rig.dir.path().join("feeds.yaml");
    let log = Arc::new(open_file_log(&rig.dir.path().join("audit.jsonl"))?);
    let audit: Box<SharedAuditFn> = {
        let owned = Arc::clone(&log);
        Box::new(move |entry| core_audit::log::append_declared(&owned, entry, &core_config::reload::RELOAD_DECLARED_KEYS))
    };
    let (entered_sender, entered_receiver) = channel();
    let (release_sender, release_receiver) = channel::<()>();
    let gate = Mutex::new((entered_sender, release_receiver));
    let calls = Mutex::<usize>::default();
    let loader_path = path.clone();
    let inner: Box<LoaderFn<FeedsFile>> = Box::new(move || {
        let call = {
            let mut count = calls.lock().map_err(|_| ConfigError::WatchedFile {
                file: "calls".to_owned(),
                reason: "poisoned".to_owned(),
            })?;
            *count += 1;
            *count
        };
        if call > 1 {
            let held = gate.lock().map_err(|_| ConfigError::WatchedFile {
                file: "gate".to_owned(),
                reason: "poisoned".to_owned(),
            })?;
            held.0.send(()).map_err(|_| ConfigError::WatchedFile {
                file: "entered".to_owned(),
                reason: "closed".to_owned(),
            })?;
            held.1.recv().map_err(|_| ConfigError::WatchedFile {
                file: "release".to_owned(),
                reason: "closed".to_owned(),
            })?;
        }
        load_file(&loader_path)
    });
    let engine = service_engine(inner, audit, "feeds.yaml")?;
    fs::write(&path, format!("{FEEDS_MORE}{}", clickhouse_block("tenant-a", DEFAULT_PORT)))?;
    let (done_sender, done_receiver) = channel();
    scope(|threads| -> TestResult {
        let reloading = threads.spawn(|| reload(&engine));
        entered_receiver.recv_timeout(HANG_GUARD)?;
        threads.spawn(|| {
            let stop = |_left: Duration| true;
            let hooks = ServeHooks {
                round: RoundHooks {
                    clock: &|| NOW,
                    open: &open,
                    poll: &no_poll,
                    load: &stored,
                },
                wait: &stop,
            };
            serve_rounds(&engine, INTERVAL, &hooks, 1);
            done_sender.send(audit_text(&rig))
        });
        let early = done_receiver.recv_timeout(SETTLE);
        release_sender.send(())?;
        assert!(matches!(
            reloading.join().map_err(|_| "reload thread panicked")?,
            ReloadOutcome::Applied { .. }
        ));
        let still_draining = early.as_ref().err() == Some(&RecvTimeoutError::Timeout);
        let written = early.or_else(|_| done_receiver.recv_timeout(HANG_GUARD))??;
        assert!(written.contains("\"result\":\"applied\""));
        assert!(still_draining);
        Ok(())
    })
}


#[test]
fn the_stop_wait_ends_on_its_signal() -> TestResult {
    let (wait, guard) = signal_waiter(&[SIGUSR1])?;
    assert!(!wait(Duration::ZERO));
    raise(SIGUSR1)?;
    assert!(wait(HANG_GUARD));
    drop(guard);
    Ok(())
}


#[test]
fn exit_codes_name_the_end_of_the_service() -> TestResult {
    assert_eq!(format!("{:?}", exit_code(Ok(LoopEnd::Stopped))), format!("{:?}", ExitCode::SUCCESS));
    assert_eq!(
        format!("{:?}", exit_code(Ok(LoopEnd::RoundCap))),
        format!("{:?}", ExitCode::from(ROUND_CAP_EXIT_CODE))
    );
    assert_eq!(format!("{:?}", exit_code(Err(ServiceError::Usage))), format!("{:?}", ExitCode::FAILURE));
    Ok(())
}


#[test]
fn the_production_edges_refuse_a_missing_section_and_a_bad_tenant() -> TestResult {
    let rig = make_rig(&standard())?;
    let config: FeedsFile = load_file(&rig.dir.path().join("feeds.yaml"))?;
    let feed = config.feeds.first().ok_or("no feed")?;
    assert!(matches!(production_poll(feed, None, NOW), Err(TaxiiError::NoSection)));
    let clickhouse = config.clickhouse.as_ref().ok_or("no clickhouse")?;
    let bad = ClickhouseConfig {
        tenant: "-x".to_owned(),
        ..clickhouse.clone()
    };
    assert!(production_load(&bad, &[], &config.feeds, NOW).is_err());
    Ok(())
}


#[test]
fn a_production_poll_reaches_the_server_and_reads_an_empty_collection() -> TestResult {
    let rig = make_rig(&standard())?;
    let password = rig.dir.path().join("taxii.pw");
    let mut file = OpenOptions::new().write(true).create_new(true).mode(PASSWORD_MODE).open(&password)?;
    writeln!(file, "secret")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let feeds = format!(
        "feeds:\n  - name: tx\n    format: taxii21\n    taxii:\n      api_root: http://127.0.0.1:{port}\n      collection: c1\n      user: u\n      password_file: {}\n{}",
        password.display(),
        clickhouse_block("tenant-a", DEFAULT_PORT)
    );
    fs::write(rig.dir.path().join("feeds.yaml"), feeds)?;
    let config: FeedsFile = load_file(&rig.dir.path().join("feeds.yaml"))?;
    let feed = config.feeds.first().ok_or("no feed")?;
    let outcome = scope(|threads| -> Result<PollOutcome, Box<dyn std::error::Error>> {
        threads.spawn(|| -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let head = BufReader::new(stream.try_clone()?);
            head.lines().map_while(Result::ok).take_while(|line| !line.is_empty()).for_each(drop);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/taxii+json;version=2.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        });
        Ok(production_poll(feed, None, NOW)?)
    })?;
    assert!(outcome.iocs.is_empty());
    Ok(())
}


fn changed(feeds: &FeedsFile, edit: fn(&mut ClickhouseConfig)) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let baseline = OnceLock::new();
    check_start_only(&baseline, feeds)?;
    let mut copy = feeds.clone();
    copy.clickhouse.iter_mut().for_each(edit);
    Ok(check_start_only(&baseline, &copy).err().map(|failure| failure.to_string()))
}


#[test]
fn the_url_the_password_file_and_the_ca_file_are_start_only_like_the_tenant() -> TestResult {
    let rig = make_rig(&standard())?;
    let feeds: FeedsFile = load_file(&rig.dir.path().join("feeds.yaml"))?;
    assert!(changed(&feeds, |section| section.url = "http://127.0.0.1:10".to_owned())?.is_some_and(|text| text.contains("clickhouse.url")));
    assert!(changed(&feeds, |section| section.password_file = PathBuf::from("/y"))?.is_some_and(|text| text.contains("clickhouse.password_file")));
    assert!(changed(&feeds, |section| section.ca_file = Some(PathBuf::from("/ca.pem")))?.is_some_and(|text| text.contains("clickhouse.ca_file")));
    assert!(changed(&feeds, |section| section.tenant = "tenant-b".to_owned())?.is_some_and(|text| text.contains("clickhouse.tenant")));
    assert!(changed(&feeds, |section| section.user = "other".to_owned())?.is_none());
    Ok(())
}
