#![cfg(unix)]
#[path = "../../siem-ingest/tests/nats_stub/mod.rs"]
mod nats_stub;
mod serve_support;


use core_audit::log::continue_log;
use core_audit::model::Outcome;
use core_config::error::WatchError;
use core_config::reload::{reload_entry, ReloadContext};
use metrics_ingest::consumer_settings::context_for;
use metrics_ingest::consumer_settings::{ConsumerSettingsError, OpenError};
use metrics_ingest::serve::{audit_to_file, exit_status, install_logging, run, Exit, ServeError, EXIT_CYCLE_CAP, EXIT_STOPPED, USAGE};
use nats_stub::{kill_connections, lock, start_stub, wait_until, Queued, Stub};
use serve_support::types::{TestError, TestResult};
use serve_support::{settings_text, write_settings, EVENT};
use siem_ingest::error::NatsError;
use std::fs::{self, File};
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread::spawn;
use tempfile::tempdir;


static SUBSCRIBER: LazyLock<bool> = LazyLock::new(|| {
    let subscriber = tracing_subscriber::fmt().with_writer(io::sink).finish();
    tracing::subscriber::set_global_default(subscriber).is_ok()
});


const TWO: usize = 2;


const LONG_DIFF: usize = 10_000;


fn arguments(path: &Path) -> Vec<String> {
    vec![path.display().to_string()]
}


fn failure_of(path: &Path) -> Result<ServeError, TestError> {
    let stop = Arc::new(AtomicBool::new(true));
    run(&arguments(path), &stop, 1).err().ok_or_else(|| "the service started".into())
}


#[test]
fn the_exit_status_names_the_cycle_cap() -> TestResult {
    assert_eq!(exit_status(Exit::Stopped), EXIT_STOPPED);
    assert_eq!(exit_status(Exit::CycleCap), EXIT_CYCLE_CAP);
    assert_ne!(EXIT_CYCLE_CAP, EXIT_STOPPED);
    assert_eq!(format!("{:?} {:?}", Exit::Stopped, ServeError::Usage), "Stopped Usage");
    Ok(())
}


#[test]
fn a_wrong_argument_count_is_the_usage() -> TestResult {
    let stop = Arc::new(AtomicBool::new(true));
    assert!(matches!(run(&[], &stop, 1), Err(ServeError::Usage)));
    assert!(matches!(run(&["a".to_owned(), "b".to_owned()], &stop, 1), Err(ServeError::Usage)));
    assert_eq!(ServeError::Usage.to_string(), USAGE);
    Ok(())
}


#[test]
fn a_missing_or_invalid_settings_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let missing = failure_of(&dir.path().join("absent.yaml"))?;
    assert!(matches!(missing, ServeError::Config(_)), "{missing}");
    assert!(missing.to_string().contains("absent.yaml"), "{missing}");
    let invalid = write_settings(dir.path(), "audit_file: [\n")?;
    assert!(matches!(failure_of(&invalid)?, ServeError::Config(_)));
    Ok(())
}


#[test]
fn a_settings_file_without_an_absolute_audit_file_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let none = write_settings(dir.path(), "ingest:\n  nats_consumer: metrics-ingest\n")?;
    let refused = failure_of(&none)?;
    assert!(matches!(refused, ServeError::AuditPath(_)), "{refused}");
    assert!(refused.to_string().contains("audit_file"), "{refused}");
    let relative = write_settings(dir.path(), "audit_file: audit.log\n")?;
    assert!(matches!(failure_of(&relative)?, ServeError::AuditPath(_)));
    Ok(())
}


#[test]
fn an_audit_file_that_cannot_be_opened_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("absent-directory").join("audit.log");
    let path = write_settings(dir.path(), &settings_text(1, &audit, ""))?;
    let refused = failure_of(&path)?;
    assert!(matches!(refused, ServeError::Audit(_)), "{refused}");
    assert!(refused.to_string().contains("audit file"), "{refused}");
    Ok(())
}


#[test]
fn an_invalid_ingest_section_is_refused_at_start() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let path = write_settings(dir.path(), &settings_text(1, &audit, "").replace("metric_samples", "bad`table"))?;
    let refused = failure_of(&path)?;
    assert!(matches!(refused, ServeError::Open(_)), "{refused}");
    Ok(())
}


#[test]
fn a_stop_that_is_already_raised_runs_no_cycle_and_the_audit_file_exists() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let path = write_settings(dir.path(), &settings_text(1, &audit, ""))?;
    let stop = Arc::new(AtomicBool::new(true));
    assert_eq!(run(&arguments(&path), &stop, 1)?, Exit::Stopped);
    assert!(audit.exists());
    Ok(())
}


#[test]
fn a_loop_that_reaches_its_cycle_cap_is_reported_as_such() -> TestResult {
    assert!(*SUBSCRIBER);
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let held = TcpListener::bind("127.0.0.1:0")?;
    let path = write_settings(dir.path(), &settings_text(held.local_addr()?.port(), &audit, ""))?;
    let stop = Arc::new(AtomicBool::new(false));
    assert_eq!(run(&arguments(&path), &stop, 1)?, Exit::CycleCap);
    assert!(!stop.load(Ordering::SeqCst));
    Ok(())
}


#[test]
fn one_served_round_stores_nothing_old_dead_letters_a_bad_identity_then_the_stop_ends_the_loop() -> TestResult {
    let dir = tempdir()?;
    let audit = dir.path().join("audit.log");
    let stub = start_stub(None, |state| {
        state.queue.push_back(Queued {
            subject: "events.a".to_owned(),
            payload: EVENT.as_bytes().to_vec(),
            extra_headers: 0,
            repeated_values: 0,
            message_ids: vec!["a:agent1:1:0".to_owned()],
        });
        state.queue.push_back(Queued {
            subject: "events.a".to_owned(),
            payload: EVENT.as_bytes().to_vec(),
            extra_headers: 0,
            repeated_values: 0,
            message_ids: Vec::new(),
        });
    })?;
    let path = write_settings(dir.path(), &settings_text(stub.port, &audit, ""))?;
    let stop = Arc::new(AtomicBool::new(false));
    let raise = Arc::clone(&stop);
    let observed = Stub {
        port: stub.port,
        hub: Arc::clone(&stub.hub),
    };
    let watcher = spawn(move || {
        let outcome = wait_until(&observed, |state| state.acks.len() >= TWO && !state.published.is_empty()).map_err(|error| error.to_string());
        raise.store(true, Ordering::SeqCst);
        outcome
    });
    assert_eq!(run(&arguments(&path), &stop, u64::MAX)?, Exit::Stopped);
    watcher.join().map_err(|_| "the watcher panicked")??;
    {
        let state = lock(&stub.hub);
        assert_eq!(state.acks.len(), TWO);
        let letter = state.published.first().ok_or("no dead letter")?;
        assert_eq!(letter.subject, "dead.events.a");
        assert_eq!(letter.payload, EVENT.as_bytes());
        assert!(letter.headers.contains("identity_unusable"), "{}", letter.headers);
    }
    kill_connections(&stub);
    Ok(())
}


#[test]
fn a_failed_audit_append_is_an_error_for_the_engine() -> TestResult {
    assert!(*SUBSCRIBER);
    let dir = tempdir()?;
    let file = dir.path().join("audit.log");
    fs::write(&file, "")?;
    let audit = audit_to_file(&Arc::new(continue_log(File::open(&file)?)?));
    let context: ReloadContext = context_for(&file, "ingest");
    let entry = reload_entry(
        &context,
        Outcome::Success,
        [("result", "applied".to_owned()), ("diff", "x".repeat(LONG_DIFF))],
    );
    assert!(audit(entry).is_err());
    Ok(())
}


#[test]
fn an_invalid_log_directive_is_refused_before_any_subscriber_is_installed() -> TestResult {
    let refused = install_logging(Some("target=notalevel"));
    assert!(matches!(refused, Err(ServeError::Directives(_))));
    Ok(())
}


#[test]
fn every_failure_kind_has_a_fixed_one_line_text() -> TestResult {
    let watch = ServeError::from(WatchError::FileName(PathBuf::from("bad name")));
    assert!(watch.to_string().starts_with("cannot watch the settings file"), "{watch}");
    let nats = ServeError::from(NatsError::CaEmpty);
    assert!(!nats.to_string().is_empty());
    let signals = ServeError::from(io::Error::other("no handler"));
    assert!(signals.to_string().starts_with("cannot register the signal handlers"), "{signals}");
    let open = ServeError::from(OpenError::Ingest(ConsumerSettingsError::Refused { field: "x", reason: "y" }));
    assert_eq!(open.to_string(), "x y");
    let audit_path = ServeError::from(ConsumerSettingsError::Refused {
        field: "audit_file",
        reason: "z",
    });
    assert_eq!(audit_path.to_string(), "audit_file z");
    Ok(())
}
