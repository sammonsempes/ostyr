#![cfg(unix)]


#[path = "common/gate.rs"]
mod gate;
#[path = "common/reload.rs"]
mod support;
#[path = "common/types.rs"]
mod types;
#[path = "common/wait.rs"]
mod wait;


use core_config::signal::{close_and_join, join_bounded, reload_in_flight, reload_on_signals, stop_signals, SignalGuard};
use gate::{gated_audit, Gate, HANG_GUARD};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use signal_hook::low_level::raise;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use support::{engine_for, entries, module_text, recording_audit, replace_file, retention};
use tempfile::tempdir;
use types::TestResult;
use wait::wait_until;


const SETTLE: Duration = Duration::from_millis(500);


const INTERVAL: Duration = Duration::from_millis(1);


const FEW_POLLS: usize = 3;


const MANY_POLLS: usize = 1000;


const HANG_POLLS: usize = 6000;


const HANG_INTERVAL: Duration = Duration::from_millis(5);


#[test]
fn stop_waits_for_a_reload_in_flight_to_finish_its_audit() -> TestResult {
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
    let guard = reload_on_signals(Arc::clone(&engine), &[SIGHUP])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGHUP)?;
    entered.recv_timeout(HANG_GUARD)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let stopped_flag = Arc::clone(&stopped);
    let stopper = thread::spawn(move || {
        let joined = stop_signals(guard);
        stopped_flag.store(true, Ordering::SeqCst);
        joined
    });
    thread::sleep(SETTLE);
    assert!(!stopped.load(Ordering::SeqCst));
    release_sender.send(())?;
    assert!(wait_until(|| stopped.load(Ordering::SeqCst)));
    assert!(audited.load(Ordering::SeqCst));
    assert_eq!(retention(&engine).as_deref(), Some("90d"));
    assert!(stopper.join().map_err(|_| io::Error::other("stopper panicked"))?);
    Ok(())
}


#[test]
fn join_bounded_gives_up_on_a_running_thread_and_joins_finished_ones() -> TestResult {
    let (release_sender, release) = channel::<()>();
    let blocked = thread::spawn(move || {
        let received = release.recv_timeout(HANG_GUARD).is_ok();
        assert!(received);
    });
    assert!(!join_bounded(blocked, FEW_POLLS, INTERVAL));
    release_sender.send(())?;
    let quick = thread::spawn(|| ());
    assert!(join_bounded(quick, MANY_POLLS, INTERVAL));
    let panicking = thread::spawn(|| std::panic::resume_unwind(Box::new("test")));
    assert!(!join_bounded(panicking, MANY_POLLS, INTERVAL));
    Ok(())
}


#[test]
fn dropping_the_guard_joins_the_thread() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let (audit, recorded) = recording_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let guard = reload_on_signals(engine, &[SIGHUP])?;
    drop(guard);
    assert!(entries(&recorded)?.is_empty());
    Ok(())
}


#[test]
fn dropping_the_guard_gives_up_on_a_reload_that_never_ends() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let Gate {
        audit,
        entered,
        release: release_sender,
        ..
    } = gated_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let guard = reload_on_signals(engine, &[SIGHUP])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGHUP)?;
    entered.recv_timeout(HANG_GUARD)?;
    drop(guard);
    release_sender.send(())?;
    Ok(())
}


#[test]
fn a_guard_without_a_thread_stops_and_drops() -> TestResult {
    let stream = Signals::new([SIGHUP])?;
    let handle = stream.handle();
    let guard = SignalGuard {
        handle,
        thread: None,
        in_flight: Arc::default(),
    };
    assert!(stop_signals(guard));
    let other = Signals::new([SIGHUP])?.handle();
    drop(SignalGuard {
        handle: other,
        thread: None,
        in_flight: Arc::default(),
    });
    Ok(())
}


fn release_once_closed(handle: signal_hook::iterator::Handle, release: std::sync::mpsc::Sender<()>) -> thread::JoinHandle<bool> {
    thread::spawn(move || wait_until(|| handle.is_closed()) && release.send(()).is_ok())
}


#[test]
fn dropping_the_guard_waits_for_a_reload_released_once_the_stream_is_closed() -> TestResult {
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
    let guard = reload_on_signals(engine, &[SIGHUP])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGHUP)?;
    entered.recv_timeout(HANG_GUARD)?;
    let releaser = release_once_closed(guard.handle.clone(), release_sender);
    drop(guard);
    assert!(audited.load(Ordering::SeqCst));
    assert!(releaser.join().map_err(|_| io::Error::other("releaser panicked"))?);
    Ok(())
}


#[test]
fn close_and_join_with_a_hang_guard_bound_waits_for_the_reload() -> TestResult {
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
    let mut guard = reload_on_signals(engine, &[SIGHUP])?;
    replace_file(&path, &module_text("90d"))?;
    raise(SIGHUP)?;
    entered.recv_timeout(HANG_GUARD)?;
    let releaser = release_once_closed(guard.handle.clone(), release_sender);
    assert!(close_and_join(&mut guard, HANG_POLLS, HANG_INTERVAL));
    assert!(audited.load(Ordering::SeqCst));
    assert!(releaser.join().map_err(|_| io::Error::other("releaser panicked"))?);
    Ok(())
}


#[test]
fn the_in_flight_flag_is_set_only_while_a_reload_runs() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("module.yaml");
    replace_file(&path, &module_text("30d"))?;
    let Gate {
        audit,
        entered,
        release: release_sender,
        ..
    } = gated_audit();
    let engine = Arc::new(engine_for(&path, audit, Vec::new())?);
    let guard = reload_on_signals(engine, &[SIGHUP])?;
    assert!(!reload_in_flight(&guard));
    replace_file(&path, &module_text("90d"))?;
    raise(SIGHUP)?;
    entered.recv_timeout(HANG_GUARD)?;
    assert!(reload_in_flight(&guard));
    release_sender.send(())?;
    assert!(wait_until(|| !reload_in_flight(&guard)));
    assert!(stop_signals(guard));
    Ok(())
}
