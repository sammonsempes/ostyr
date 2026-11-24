use crate::support::scoped_logging;
use crate::types::TestResult;
use agent_channel::app::{reload_context, shared_log_audit};
use agent_channel::types::PauseFuture;
use agent_linux::exec_probe::{
    finish, not_built, observe, probe_entry, record, run_exec_controller, spawn_thread, start, start_if_due, tick, Controller, ProbeEnv, ACTION_LOAD,
    ACTION_UNLOAD, EXEC_PROBE_LOAD_DEADLINE_SECONDS, EXEC_PROBE_RETRY_SECONDS, PRODUCTION_PROBE, RESULT_FAILED, RESULT_LOADED, RESULT_UNLOADED,
};
use agent_linux::model::ExecProbeSettings;
use agent_linux::settings::{open_settings_engine, settings_state};
use agent_linux::types::{ProbeFn, ProbeJob, ProbeResult};
use arc_swap::ArcSwap;
use core_audit::log::open_file_log;
use core_audit::model::Outcome;
use core_config::load::load_file;
use core_config::reload::{reload, ReloadOutcome};
use core_config::types::SharedAuditFn;
use ebpf_probes::drain::{DrainReport, Drained, KernelDropped};
use ebpf_probes::error::LoadError;
use ebpf_probes::record::{decode_exec, EXEC_RECORD_BYTES};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::tempdir;


const SPIN_CAP: u32 = 60_000;


const FIRST_DELIVERY: usize = 2;


const SECOND_DELIVERY: usize = 3;


const EPERM: i32 = 1;


const TICKS: u64 = 2;


const HUNG_TICK_SECONDS: u64 = 10;


const SETTINGS_HEAD: &str = "agent_file: /a\nexport_path: /e\ncursor_file: /c\naudit_file: /l\n";


fn drained(count: usize) -> Result<Drained, Box<dyn std::error::Error>> {
    let record = decode_exec(&[0; EXEC_RECORD_BYTES])?;
    Ok(Drained {
        records: vec![record; count],
        report: DrainReport {
            delivered: count,
            refused: 0,
            first_refused_len: None,
            limited: 0,
            kernel_dropped: KernelDropped::Counted(0),
            more_pending: false,
        },
    })
}


fn spin_until_stop(stop: &AtomicBool) {
    (0..SPIN_CAP)
        .take_while(|_| !stop.load(Ordering::Relaxed))
        .for_each(|_| std::thread::sleep(Duration::from_millis(1)));
}


fn probe_loaded(stop: &AtomicBool, _max_polls: u32, deliver: &mut dyn FnMut(Drained)) -> ProbeResult {
    [FIRST_DELIVERY, SECOND_DELIVERY]
        .into_iter()
        .filter_map(|count| drained(count).ok())
        .for_each(&mut *deliver);
    spin_until_stop(stop);
    Ok(1)
}


fn probe_slow(stop: &AtomicBool, _max_polls: u32, _deliver: &mut dyn FnMut(Drained)) -> ProbeResult {
    spin_until_stop(stop);
    Ok(0)
}


fn probe_failing(_stop: &AtomicBool, _max_polls: u32, _deliver: &mut dyn FnMut(Drained)) -> ProbeResult {
    Err(LoadError::ProgramLoad { errno: Some(EPERM) })
}


fn probe_panicking(_stop: &AtomicBool, _max_polls: u32, _deliver: &mut dyn FnMut(Drained)) -> ProbeResult {
    std::panic::resume_unwind(Box::new(EPERM))
}


fn refuse_spawn(_job: ProbeJob) -> io::Result<JoinHandle<ProbeResult>> {
    Err(io::Error::other("no threads"))
}


fn environment(probe: ProbeFn) -> ProbeEnv {
    ProbeEnv {
        tenant: "tenant".to_owned(),
        probe,
        spawn: spawn_thread,
    }
}


struct Audit {
    dir: tempfile::TempDir,
    audit: Box<SharedAuditFn>,
}


fn audit() -> Result<Audit, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let log = Arc::new(open_file_log(&dir.path().join("audit"))?);
    let audit = shared_log_audit(&log);
    Ok(Audit { dir, audit })
}


fn audited(audit: &Audit) -> Result<String, io::Error> {
    fs::read_to_string(audit.dir.path().join("audit"))
}


fn wait_until(mut ready: impl FnMut() -> bool) -> TestResult {
    (0..SPIN_CAP)
        .find(|_| {
            let done = ready();
            if !done {
                std::thread::sleep(Duration::from_millis(1));
            }
            done
        })
        .map(|_| ())
        .ok_or_else(|| "the event never happened".into())
}


fn finished(controller: &Controller) -> bool {
    controller.run.as_ref().is_some_and(|run| run.handle.is_finished())
}


fn loaded(controller: &Controller) -> bool {
    controller.run.as_ref().is_some_and(|run| run.loaded.load(Ordering::Relaxed))
}


#[test]
fn a_disabled_setting_starts_no_probe_and_audits_nothing() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_loaded);
    let idle = (0..EXEC_PROBE_RETRY_SECONDS * TICKS).fold(Controller::default(), |controller, now| {
        tick(controller, false, now, &env, sink.audit.as_ref())
    });
    assert!(idle.run.is_none() && idle.last_start.is_none());
    assert_eq!(audited(&sink)?, "");
    Ok(())
}


#[test]
fn an_enabled_probe_is_loaded_once_counts_records_and_is_unloaded_by_a_disable() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_loaded);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    assert!(started.run.is_some() && started.last_start == Some(0));
    wait_until(|| loaded(&started))?;
    let first = tick(started, true, 1, &env, sink.audit.as_ref());
    let second = tick(first, true, TICKS, &env, sink.audit.as_ref());
    assert_eq!(audited(&sink)?.matches("\"result\":\"loaded\"").count(), 1);
    let stopping = tick(second, false, TICKS + 1, &env, sink.audit.as_ref());
    wait_until(|| finished(&stopping))?;
    let unloaded = tick(stopping, false, TICKS + TICKS, &env, sink.audit.as_ref());
    assert!(unloaded.run.is_none());
    let text = audited(&sink)?;
    assert_eq!(text.matches(ACTION_UNLOAD).count(), 1);
    assert!(text.contains(RESULT_UNLOADED) && text.contains(&format!("records={}", FIRST_DELIVERY + SECOND_DELIVERY)));
    Ok(())
}


#[test]
fn a_failed_load_is_audited_once_and_retries_are_spaced() -> TestResult {
    let _log = scoped_logging();
    let sink = audit()?;
    let env = environment(probe_failing);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    wait_until(|| finished(&started))?;
    let failed = tick(started, true, 1, &env, sink.audit.as_ref());
    assert!(failed.run.is_none());
    let waiting = tick(failed, true, EXEC_PROBE_RETRY_SECONDS - 1, &env, sink.audit.as_ref());
    assert!(waiting.run.is_none() && waiting.last_start == Some(0));
    let again = tick(waiting, true, EXEC_PROBE_RETRY_SECONDS, &env, sink.audit.as_ref());
    assert!(again.run.is_some() && again.last_start == Some(EXEC_PROBE_RETRY_SECONDS));
    wait_until(|| finished(&again))?;
    let repeated = tick(again, true, EXEC_PROBE_RETRY_SECONDS + 1, &env, sink.audit.as_ref());
    assert!(repeated.run.is_none());
    let text = audited(&sink)?;
    assert_eq!(text.matches(ACTION_LOAD).count(), 1);
    assert!(text.contains(RESULT_FAILED) && text.contains("ProgramLoad"));
    assert!(!text.contains("errno"));
    Ok(())
}


#[test]
fn a_panicking_probe_is_audited_once_as_panicked() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_panicking);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    wait_until(|| finished(&started))?;
    let joined = tick(started, true, 1, &env, sink.audit.as_ref());
    assert!(joined.run.is_none());
    let text = audited(&sink)?;
    assert_eq!(text.matches(ACTION_LOAD).count(), 1);
    assert!(text.contains("panicked") && text.contains("Panic"));
    Ok(())
}


#[test]
fn a_refused_thread_start_is_audited_once_and_spaced_like_a_failed_load() -> TestResult {
    let sink = audit()?;
    let env = ProbeEnv {
        spawn: refuse_spawn,
        ..environment(probe_loaded)
    };
    let refused = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    assert!(refused.run.is_none() && refused.last_start == Some(0));
    let waiting = tick(refused, true, 1, &env, sink.audit.as_ref());
    assert_eq!(waiting.last_start, Some(0));
    let again = tick(waiting, true, EXEC_PROBE_RETRY_SECONDS, &env, sink.audit.as_ref());
    assert_eq!(again.last_start, Some(EXEC_PROBE_RETRY_SECONDS));
    let text = audited(&sink)?;
    assert_eq!(text.matches(ACTION_LOAD).count(), 1);
    assert!(text.contains("Spawn"));
    Ok(())
}


#[test]
fn a_slow_load_is_audited_once_as_timed_out_and_never_gets_a_second_thread() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_slow);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    let at_deadline = tick(started, true, EXEC_PROBE_LOAD_DEADLINE_SECONDS, &env, sink.audit.as_ref());
    assert_eq!(audited(&sink)?, "");
    let late = tick(at_deadline, true, EXEC_PROBE_LOAD_DEADLINE_SECONDS + 1, &env, sink.audit.as_ref());
    let later = tick(late, true, EXEC_PROBE_RETRY_SECONDS * TICKS, &env, sink.audit.as_ref());
    assert_eq!(later.last_start, Some(0));
    assert_eq!(audited(&sink)?.matches("\"result\":\"timed_out\"").count(), 1);
    let stopping = tick(later, false, EXEC_PROBE_RETRY_SECONDS * TICKS + 1, &env, sink.audit.as_ref());
    wait_until(|| finished(&stopping))?;
    let ended = tick(stopping, false, EXEC_PROBE_RETRY_SECONDS * TICKS + TICKS, &env, sink.audit.as_ref());
    assert!(ended.run.is_none());
    Ok(())
}


#[test]
fn a_disable_inside_the_load_window_leaves_no_probe_and_the_next_start_is_spaced() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_slow);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    let disabled = tick(started, false, 1, &env, sink.audit.as_ref());
    wait_until(|| finished(&disabled))?;
    let ended = tick(disabled, false, TICKS, &env, sink.audit.as_ref());
    assert!(ended.run.is_none());
    let early = tick(ended, true, TICKS + 1, &env, sink.audit.as_ref());
    assert!(early.run.is_none());
    let spaced = tick(early, true, EXEC_PROBE_RETRY_SECONDS, &env, sink.audit.as_ref());
    assert!(spaced.run.is_some());
    Ok(())
}


#[test]
fn a_running_thread_is_never_joined_by_a_tick() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_slow);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    let stop = started.run.as_ref().map(|run| Arc::clone(&run.guard.stop)).ok_or("no run")?;
    let (sender, receiver) = channel();
    let audit_for_tick = sink.audit;
    let worker = std::thread::spawn(move || {
        let after = tick(started, true, 1, &env, audit_for_tick.as_ref());
        sender
            .send(after.run.is_some())
            .inspect_err(|error| tracing::warn!(%error, "receiver gone"))
            .ok();
        after
    });
    let answer = receiver.recv_timeout(Duration::from_secs(HUNG_TICK_SECONDS));
    stop.store(true, Ordering::Relaxed);
    worker.join().map_err(|_| "worker panicked")?;
    assert_eq!(answer, Ok(true));
    Ok(())
}


#[test]
fn dropping_the_controller_stops_its_probe() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_slow);
    let started = tick(Controller::default(), true, 0, &env, sink.audit.as_ref());
    let stop = started.run.as_ref().map(|run| Arc::clone(&run.guard.stop)).ok_or("no run")?;
    assert!(!stop.load(Ordering::Relaxed));
    drop(started);
    assert!(stop.load(Ordering::Relaxed));
    Ok(())
}


#[test]
fn the_pieces_are_usable_on_their_own() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_slow);
    let run = start(&env, 0)?;
    let stop = Arc::clone(&run.guard.stop);
    let observed = observe(Controller::default(), run, true, 0, &env, sink.audit.as_ref());
    assert!(observed.run.is_some());
    stop.store(true, Ordering::Relaxed);
    wait_until(|| finished(&observed))?;
    let run_again = observed.run.ok_or("no run")?;
    let ended = finish(Controller::default(), run_again, &env, sink.audit.as_ref());
    assert!(ended.run.is_none() && ended.last_cause.is_none());
    let idle = start_if_due(Controller::default(), false, 0, &env, sink.audit.as_ref());
    assert!(idle.run.is_none() && idle.last_start.is_none());
    Ok(())
}


#[test]
fn an_audit_record_holds_fixed_words_only_and_a_failing_audit_is_logged() -> TestResult {
    let _log = scoped_logging();
    let loaded_entry = probe_entry("t", ACTION_LOAD, RESULT_LOADED, None, None);
    assert_eq!(loaded_entry.outcome, Outcome::Success);
    assert_eq!(loaded_entry.parameters.len(), 1);
    let failed_entry = probe_entry("t", ACTION_LOAD, RESULT_FAILED, Some("Attach"), Some(1));
    assert_eq!(failed_entry.outcome, Outcome::Failure);
    assert_eq!(failed_entry.parameters.len(), TICKS as usize);
    assert_eq!(failed_entry.justification.as_deref(), Some("records=1"));
    let refusing: Box<SharedAuditFn> = Box::new(|_| Err(io::Error::other("refused").into()));
    record(refusing.as_ref(), failed_entry);
    Ok(())
}


#[test]
fn an_agent_built_without_the_loader_names_the_failure() -> TestResult {
    let stop = AtomicBool::new(false);
    let mut sink = |_: Drained| {};
    assert_eq!(not_built(&stop, 1, &mut sink), Err(LoadError::NotBuilt));
    let production: ProbeFn = PRODUCTION_PROBE;
    assert_eq!(production(&stop, 1, &mut sink), Err(LoadError::NotBuilt));
    Ok(())
}


#[tokio::test]
async fn the_controller_applies_the_setting_one_snapshot_per_tick() -> TestResult {
    let sink = audit()?;
    let env = environment(probe_slow);
    let shared = Arc::new(ArcSwap::from_pointee(ExecProbeSettings { enabled: true }));
    let calls = Arc::new(AtomicU64::new(0));
    let (switch, counted) = (Arc::clone(&shared), Arc::clone(&calls));
    let pause = move |_: Duration| -> PauseFuture {
        counted.fetch_add(1, Ordering::SeqCst);
        switch.store(Arc::new(ExecProbeSettings { enabled: false }));
        Box::pin(async {})
    };
    let clock = || 0;
    let controller = run_exec_controller(&shared, &env, sink.audit.as_ref(), TICKS, &pause, &clock).await;
    assert_eq!(calls.load(Ordering::SeqCst), TICKS);
    let run = controller.run.as_ref().ok_or("the probe should still be winding down")?;
    assert!(run.guard.stop.load(Ordering::Relaxed));
    Ok(())
}


#[test]
fn the_setting_is_part_of_the_state_and_a_toggle_is_applied() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("agent-linux.yaml");
    fs::write(&path, SETTINGS_HEAD)?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    let (engine, _shared, _sensor, _updates, _osquery, _metrics, exec_probe) = open_settings_engine(path.clone(), shared_log_audit(&log), context)?;
    assert!(!exec_probe.load().enabled);
    assert_eq!(state_value(&path)?, "false");
    fs::write(&path, format!("{SETTINGS_HEAD}exec_probe:\n  enabled: true\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert!(exec_probe.load().enabled);
    assert_eq!(state_value(&path)?, "true");
    fs::write(&path, format!("{SETTINGS_HEAD}exec_probe:\n  enabled: false\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert!(!exec_probe.load().enabled);
    fs::write(&path, format!("{SETTINGS_HEAD}exec_probe:\n  enabled: true\n  path: /tmp/evil.o\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert!(!exec_probe.load().enabled);
    fs::write(&path, format!("{SETTINGS_HEAD}exec_probe:\n  enabled: yes please\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    Ok(())
}


fn state_value(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let file = load_file::<agent_linux::model::LinuxFile>(path)?;
    let state = settings_state(&file);
    state
        .get("agent_linux.exec_probe_enabled")
        .cloned()
        .ok_or_else(|| "the state has no exec_probe_enabled".into())
}


#[test]
fn no_profile_turns_a_panic_into_an_abort() -> TestResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifests = [
        root.join("Cargo.toml"),
        root.join("../ebpf-probes/Cargo.toml"),
        root.join("../../Cargo.toml"),
    ];
    manifests.iter().try_for_each(|manifest| -> TestResult {
        let text = fs::read_to_string(manifest)?;
        assert!(!text.contains("abort"), "{} sets panic = abort", manifest.display());
        Ok(())
    })?;
    Ok(())
}
