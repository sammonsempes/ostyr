#![cfg(unix)]


#[path = "common/gate.rs"]
mod gate;
#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;
#[path = "common/wait.rs"]
mod wait;


use core_config::model::ModuleConfig;
use core_config::reload::Subscriber;
use core_config::signal::{early_signals, reload_in_flight, reload_on_signals, reload_on_stream, stop_signals, DROP_JOIN_POLLS};
use gate::{gated_audit, Gate, HANG_GUARD};
use signal_hook::consts::{SIGURG, SIGUSR1, SIGUSR2, SIGWINCH};
use signal_hook::low_level::raise;
use std::io::{self, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use tracing::dispatcher::with_default;
use tracing::Dispatch;
use types::TestResult;
use wait::wait_until;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);


impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_| io::Error::other("poisoned")).map(|mut buffer| {
            buffer.extend_from_slice(bytes);
            bytes.len()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn capture() -> (Dispatch, Arc<Mutex<Vec<u8>>>) {
    LazyLock::force(&ANCHOR);
    let captured = Arc::<Mutex<Vec<u8>>>::default();
    let sink = Arc::clone(&captured);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || CaptureWriter(Arc::clone(&sink)))
            .finish(),
    );
    (dispatch, captured)
}


fn captured_text(captured: &Arc<Mutex<Vec<u8>>>) -> io::Result<String> {
    captured
        .lock()
        .map(|buffer| String::from_utf8_lossy(&buffer).into_owned())
        .map_err(|_| io::Error::other("poisoned"))
}


#[test]
fn an_idle_stop_logs_no_reload_in_flight() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let guard = reload_on_signals(engine, &[SIGUSR1])?;
    let (dispatch, captured) = capture();
    let joined = with_default(&dispatch, || stop_signals(guard));
    assert!(joined);
    assert!(entries(&recorded)?.is_empty());
    let text = captured_text(&captured)?;
    assert!(text.contains("in_flight=false"), "{text}");
    Ok(())
}


#[test]
fn a_stop_during_a_reload_logs_a_reload_in_flight() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let Gate {
        audit,
        entered,
        release: release_sender,
        audited,
    } = gated_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let guard = reload_on_signals(Arc::clone(&engine), &[SIGUSR2])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGUSR2)?;
    entered.recv_timeout(HANG_GUARD)?;
    let (dispatch, captured) = capture();
    let watched = Arc::clone(&captured);
    let releaser = thread::spawn(move || {
        wait_until(|| captured_text(&watched).is_ok_and(|text| text.contains("stopping the reload thread"))) && release_sender.send(()).is_ok()
    });
    let joined = with_default(&dispatch, || stop_signals(guard));
    assert!(joined);
    assert!(releaser.join().map_err(|_| io::Error::other("releaser panicked"))?);
    assert!(audited.load(Ordering::SeqCst));
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    let text = captured_text(&captured)?;
    assert!(text.contains("in_flight=true"), "{text}");
    Ok(())
}


#[test]
fn every_constructor_keeps_the_production_drop_bound() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, _recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let from_signals = reload_on_signals(Arc::clone(&engine), &[SIGURG])?;
    assert_eq!(from_signals.drop_join_polls, DROP_JOIN_POLLS);
    let early = early_signals()?;
    let from_stream = reload_on_stream(early.reload, engine);
    assert_eq!(from_stream.drop_join_polls, DROP_JOIN_POLLS);
    assert!(stop_signals(from_signals));
    assert!(stop_signals(from_stream));
    Ok(())
}


#[test]
fn a_panicking_apply_never_leaves_the_flag_set() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, _recorded) = recording_audit();
    let panicking: Subscriber<ModuleConfig> = Subscriber {
        section: "settings.retention".to_owned(),
        validate: Box::new(|_config| Ok(())),
        apply: Box::new(|_config| std::panic::resume_unwind(Box::new("apply panicked"))),
    };
    let engine = Arc::new(engine_for(&path, audit, vec![panicking])?);
    let guard = reload_on_signals(engine, &[SIGWINCH])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGWINCH)?;
    assert!(wait_until(|| guard.thread.as_ref().is_some_and(|thread| thread.is_finished())));
    assert!(!reload_in_flight(&guard));
    assert!(!stop_signals(guard));
    Ok(())
}
