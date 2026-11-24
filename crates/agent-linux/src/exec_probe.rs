use crate::error::SourceError;
use crate::exec_events::{deliver_or_stop, Delivery, ExecSink};
use crate::types::{ProbeFn, ProbeJob, ProbeResult, SharedExecProbe, SpawnFn};
use agent_channel::types::PauseFn;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::types::SharedAuditFn;
use ebpf_probes::drain::Drained;
use ebpf_probes::error::{load_error_name, LoadError};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use time::OffsetDateTime;


pub const EXEC_PROBE_LOAD_DEADLINE_SECONDS: u64 = 30;


pub const EXEC_PROBE_RETRY_SECONDS: u64 = 60;


pub const EXEC_PROBE_TICK_SECONDS: u64 = 1;


pub const EXEC_PROBE_MAX_POLLS: u32 = u32::MAX;


pub const EXEC_PROBE_MAX_TICKS: u64 = 1 << 40;


pub const AUDIT_MODULE: &str = "agent_linux_exec_probe";


pub const ACTION_LOAD: &str = "exec_probe.load";


pub const ACTION_UNLOAD: &str = "exec_probe.unload";


pub const AUDIT_TARGET: &str = "sched_process_exec";


pub const RESULT_LOADED: &str = "loaded";


pub const RESULT_FAILED: &str = "failed";


pub const RESULT_PANICKED: &str = "panicked";


pub const RESULT_TIMED_OUT: &str = "timed_out";


pub const RESULT_UNLOADED: &str = "unloaded";


pub const RESULT_ABANDONED: &str = "abandoned";


pub const CAUSE_PANIC: &str = "Panic";


pub const CAUSE_SPAWN: &str = "Spawn";


pub const CAUSE_DEADLINE: &str = "LoadDeadline";


pub const THREAD_NAME: &str = "exec-probe";


/// Sets the stop flag of its probe thread when dropped, so an agent that ends or a controller that is dropped never leaves a probe loaded.
#[derive(Debug)]
pub struct ProbeGuard {
    pub stop: Arc<AtomicBool>,
}


impl Drop for ProbeGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}


/// The one probe thread in flight and what the controller knows of it.
#[derive(Debug)]
pub struct ProbeRun {
    pub handle: JoinHandle<ProbeResult>,
    pub guard: ProbeGuard,
    pub loaded: Arc<AtomicBool>,
    pub records: Arc<AtomicUsize>,
    pub failures: Receiver<io::Error>,
    pub started: u64,
    pub loaded_reported: bool,
    pub timeout_reported: bool,
}


/// What the controller remembers between two ticks: the thread in flight, the monotonic second of the last start, the last audited cause.
#[derive(Debug, Default)]
pub struct Controller {
    pub run: Option<ProbeRun>,
    pub last_start: Option<u64>,
    pub last_cause: Option<String>,
    pub spool_error: Option<io::Error>,
}


/// The tenant of the audit records and the two injected steps: the probe and the thread start.
#[derive(Clone, Debug)]
pub struct ProbeEnv {
    pub tenant: String,
    pub probe: ProbeFn,
    pub spawn: SpawnFn,
    pub sink: ExecSink,
}


/// The probe of an agent built without the `ebpf` feature: a named failure, never a crash.
pub fn not_built(_stop: &AtomicBool, _max_polls: u32, _attached: &mut dyn FnMut(), _deliver: &mut dyn FnMut(Drained)) -> ProbeResult {
    Err(LoadError::NotBuilt)
}


#[cfg(feature = "ebpf")]
pub const PRODUCTION_PROBE: ProbeFn = ebpf_probes::loader::run_exec_probe;


#[cfg(not(feature = "ebpf"))]
pub const PRODUCTION_PROBE: ProbeFn = not_built;


pub fn spawn_thread(job: ProbeJob) -> io::Result<JoinHandle<ProbeResult>> {
    std::thread::Builder::new().name(THREAD_NAME.to_owned()).spawn(job)
}


/// One audit record: `result` and `reason` are fixed words (a `LoadError` variant name, never an errno or a path), the `records` count rides in the justification of an unload; the shared audit function keeps only the declared keys `result` and `reason`.
pub fn probe_entry(tenant: &str, action: &str, result: &str, cause: Option<&str>, records: Option<usize>) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: AUDIT_MODULE.to_owned(),
        },
        tenant: tenant.to_owned(),
        module: AUDIT_MODULE.to_owned(),
        action: action.to_owned(),
        target: AUDIT_TARGET.to_owned(),
        outcome: if matches!(result, RESULT_LOADED | RESULT_UNLOADED) {
            Outcome::Success
        } else {
            Outcome::Failure
        },
        request_id: format!("exec-probe-{result}"),
        justification: records.map(|count| format!("records={count}")),
        parameters: [("result", Some(result.to_owned())), ("reason", cause.map(str::to_owned))]
            .into_iter()
            .filter_map(|(key, text)| text.map(|present| (key.to_owned(), present)))
            .collect(),
    }
}


/// Appends one record; a failing audit is logged and never stops the controller.
pub fn record(audit: &SharedAuditFn, entry: NewEntry) {
    audit(entry).inspect_err(|error| tracing::error!(%error, "exec probe audit failed")).ok();
}


/// Starts the probe thread: it loads, then drains until its stop flag is set; the first delivery marks the probe loaded and every delivery adds its records.
pub fn start(env: &ProbeEnv, now: u64) -> io::Result<ProbeRun> {
    let stop = Arc::new(AtomicBool::new(false));
    let loaded = Arc::new(AtomicBool::new(false));
    let records = Arc::new(AtomicUsize::new(0));
    let (failure_sender, failures) = channel();
    let (job_stop, job_loaded, attached_loaded, job_records) = (Arc::clone(&stop), Arc::clone(&loaded), Arc::clone(&loaded), Arc::clone(&records));
    let (probe, sink) = (env.probe, env.sink.clone());
    let job: ProbeJob = Box::new(move || {
        let mut state = Delivery::default();
        probe(
            &job_stop,
            EXEC_PROBE_MAX_POLLS,
            &mut || attached_loaded.store(true, Ordering::Relaxed),
            &mut |drained| {
                job_loaded.store(true, Ordering::Relaxed);
                job_records.fetch_add(drained.records.len(), Ordering::Relaxed);
                state = deliver_or_stop(&sink, std::mem::take(&mut state), &drained, &job_stop, &failure_sender);
            },
        )
    });
    let handle = (env.spawn)(job)?;
    Ok(ProbeRun {
        handle,
        guard: ProbeGuard { stop },
        loaded,
        records,
        failures,
        started: now,
        loaded_reported: false,
        timeout_reported: false,
    })
}


/// A failed, panicked or timed out probe: one audit record per distinct cause, however many retries repeat it.
pub fn failure(controller: Controller, env: &ProbeEnv, audit: &SharedAuditFn, result: &str, cause: &str) -> Controller {
    let key = format!("{result}:{cause}");
    if controller.last_cause.as_deref() != Some(key.as_str()) {
        tracing::warn!(result, cause, "exec probe is not running");
        record(audit, probe_entry(&env.tenant, ACTION_LOAD, result, Some(cause), None));
    }
    Controller {
        last_cause: Some(key),
        ..controller
    }
}


/// A probe that ended cleanly: one `unload` closes a `loaded` record (written first when the tick never saw the load), and a load stopped before its first poll is one `abandoned` record, so the pairs balance.
pub fn settle_ended(tenant: &str, audit: &SharedAuditFn, was_loaded: bool, load_reported: bool, records: usize) {
    if !was_loaded {
        record(audit, probe_entry(tenant, ACTION_LOAD, RESULT_ABANDONED, None, None));
    } else {
        if !load_reported {
            record(audit, probe_entry(tenant, ACTION_LOAD, RESULT_LOADED, None, None));
        }
        record(audit, probe_entry(tenant, ACTION_UNLOAD, RESULT_UNLOADED, None, Some(records)));
    }
}


/// Joins a finished thread (it is finished, so the join never waits): the one place a panic becomes `panicked`.
pub fn finish(controller: Controller, run: ProbeRun, env: &ProbeEnv, audit: &SharedAuditFn) -> Controller {
    let records = run.records.load(Ordering::Relaxed);
    match run.handle.join() {
        Ok(Ok(_polls)) => {
            settle_ended(&env.tenant, audit, run.loaded.load(Ordering::Relaxed), run.loaded_reported, records);
            Controller {
                last_cause: None,
                ..controller
            }
        }
        Ok(Err(error)) => failure(controller, env, audit, RESULT_FAILED, load_error_name(&error)),
        Err(_payload) => failure(controller, env, audit, RESULT_PANICKED, CAUSE_PANIC),
    }
}


/// A thread still running: audit its load once, audit once a load past the deadline, and pass a disable on through its stop flag.
pub fn observe(controller: Controller, run: ProbeRun, enabled: bool, now: u64, env: &ProbeEnv, audit: &SharedAuditFn) -> Controller {
    let is_loaded = run.loaded.load(Ordering::Relaxed);
    let announce = is_loaded && !run.loaded_reported;
    let late = !is_loaded && !run.timeout_reported && now.saturating_sub(run.started) > EXEC_PROBE_LOAD_DEADLINE_SECONDS;
    if !enabled {
        run.guard.stop.store(true, Ordering::Relaxed);
    }
    let (loaded_reported, timeout_reported, last_cause) = match (announce, late) {
        (true, _) => {
            record(audit, probe_entry(&env.tenant, ACTION_LOAD, RESULT_LOADED, None, None));
            (true, run.timeout_reported, None)
        }
        (false, true) => {
            record(audit, probe_entry(&env.tenant, ACTION_LOAD, RESULT_TIMED_OUT, Some(CAUSE_DEADLINE), None));
            (run.loaded_reported, true, Some(format!("{RESULT_TIMED_OUT}:{CAUSE_DEADLINE}")))
        }
        (false, false) => (run.loaded_reported, run.timeout_reported, controller.last_cause),
    };
    Controller {
        run: Some(ProbeRun {
            loaded_reported,
            timeout_reported,
            ..run
        }),
        last_cause,
        ..controller
    }
}


/// Starts a probe when enabled, none is in flight and the last start is at least `EXEC_PROBE_RETRY_SECONDS` back, whatever the setting did meanwhile.
pub fn start_if_due(controller: Controller, enabled: bool, now: u64, env: &ProbeEnv, audit: &SharedAuditFn) -> Controller {
    let spaced = controller
        .last_start
        .is_none_or(|last| now.saturating_sub(last) >= EXEC_PROBE_RETRY_SECONDS);
    let due = enabled && controller.run.is_none() && spaced;
    if due {
        match start(env, now) {
            Ok(run) => Controller {
                run: Some(run),
                last_start: Some(now),
                ..controller
            },
            Err(_refused) => failure(
                Controller {
                    last_start: Some(now),
                    ..controller
                },
                env,
                audit,
                RESULT_FAILED,
                CAUSE_SPAWN,
            ),
        }
    } else {
        controller
    }
}


/// One controller tick on the monotonic second `now`, from one snapshot of the setting.
pub fn tick(controller: Controller, enabled: bool, now: u64, env: &ProbeEnv, audit: &SharedAuditFn) -> Controller {
    let spool_error = controller.run.as_ref().and_then(|run| run.failures.try_iter().next());
    let settled = match controller.run {
        Some(run) if run.handle.is_finished() => finish(Controller { run: None, ..controller }, run, env, audit),
        Some(run) => observe(Controller { run: None, ..controller }, run, enabled, now, env, audit),
        None => controller,
    };
    let remembered = Controller {
        last_cause: settled.last_cause.filter(|_| enabled),
        spool_error: spool_error.or(settled.spool_error),
        ..settled
    };
    start_if_due(remembered, enabled, now, env, audit)
}


/// Runs `max_ticks` ticks one `EXEC_PROBE_TICK_SECONDS` apart, reading the setting snapshot once per tick; the reload only stores the setting, this loop applies it. A failing spool write of the probe thread ends the loop with that error. Dropping the returned controller stops the probe.
pub async fn run_exec_controller(
    shared: &SharedExecProbe,
    env: &ProbeEnv,
    audit: &SharedAuditFn,
    max_ticks: u64,
    pause: &PauseFn,
    monotonic: &(dyn Fn() -> u64 + Sync),
) -> io::Result<Controller> {
    let mut controller = Controller::default();
    let mut ticks = 0;
    while controller.spool_error.is_none() && ticks < max_ticks.min(EXEC_PROBE_MAX_TICKS) {
        let enabled = shared.load().enabled;
        controller = tick(controller, enabled, monotonic(), env, audit);
        pause(Duration::from_secs(EXEC_PROBE_TICK_SECONDS)).await;
        ticks += 1;
    }
    match controller.spool_error.take() {
        Some(error) => Err(error),
        None => Ok(controller),
    }
}


/// The agent's view of the controller's end: a failing spool write of the probe thread is logged and ends the agent, a normal end is fine.
pub fn end_on_spool_error(ended: io::Result<Controller>) -> Result<(), SourceError> {
    ended
        .map(|_| ())
        .inspect_err(|error| tracing::error!(%error, "exec probe spool failed, the agent stops"))
        .map_err(SourceError::from)
}
