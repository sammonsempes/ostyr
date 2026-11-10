use crate::error::{SensorError, SourceError};
use crate::model::SensorSettings;
use crate::types::{RunFn, RunFuture, SharedSensor};
use agent_channel::spool::append_back;
use agent_channel::types::{ClockFn, PauseFn};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::types::SharedAuditFn;
use serde_json::json;
use std::collections::BTreeMap;
use std::iter::once;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::process::Command;


pub const SENSOR_NAME: &str = "tetragon";


pub const UNIT_NAME: &str = "tetragon.service";


pub const AUDIT_MODULE: &str = "agent_linux_sensor";


pub const AUDIT_ACTION: &str = "sensor.restart";


pub const MAX_OUTPUT_BYTES: u64 = 4_096;


pub const COMMAND_DEADLINE_SECONDS: u64 = 10;


pub const MIN_RESTART_INTERVAL_SECONDS: u64 = 30;


pub const HOUR_SECONDS: u64 = 3_600;


pub const MAX_EVENTS_PER_HOUR: usize = 60;


pub const MAX_SUB_STATE_BYTES: usize = 32;


pub const SHOW_KEYS: [&str; 3] = ["ActiveState", "SubState", "ExecMainPID"];


#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SensorState {
    #[default]
    Unknown,
    Running,
    Stopped,
    Stalled,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveState {
    Active,
    Down,
    Transitional,
}


/// The strictly parsed answer of `systemctl show`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub active: ActiveState,
    pub sub_state: String,
    pub pid: u32,
}


/// What identifies a state of the export file: a rotation changes the inode, an append the size and the time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub ino: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Unknown,
    Down,
    Up(Option<Progress>),
}


/// What the supervisor remembers between two ticks; `known` is the last state that was not `Unknown`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Supervisor {
    pub state: SensorState,
    pub known: SensorState,
    pub since: u64,
    pub progress: Option<Progress>,
    pub progress_at: Option<u64>,
    pub restarts: Vec<u64>,
    pub events: Vec<u64>,
    pub suppressed: u64,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensorEvent {
    pub state: SensorState,
    pub previous: SensorState,
    pub since: u64,
    pub suppressed: u64,
}


/// What a tick decides: at most one event, one restart attempt, and whether an event was cut by the hourly cap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Action {
    pub event: Option<SensorEvent>,
    pub restart: bool,
    pub suppressed: bool,
}


/// Where the supervisor reads and writes; `run` is injected.
#[derive(Clone, Debug)]
pub struct SensorEnv {
    pub systemctl: PathBuf,
    pub export: PathBuf,
    pub spool: PathBuf,
    pub tenant: String,
    pub run: RunFn,
}


pub fn state_name(state: SensorState) -> &'static str {
    match state {
        SensorState::Unknown => "unknown",
        SensorState::Running => "running",
        SensorState::Stopped => "stopped",
        SensorState::Stalled => "stalled",
    }
}


pub fn is_bad(state: SensorState) -> bool {
    matches!(state, SensorState::Stopped | SensorState::Stalled)
}


pub fn active_state(value: &str) -> Result<ActiveState, SensorError> {
    match value {
        "active" => Ok(ActiveState::Active),
        "inactive" | "failed" | "deactivating" => Ok(ActiveState::Down),
        "activating" | "reloading" | "maintenance" | "refreshing" => Ok(ActiveState::Transitional),
        _ => Err(SensorError::Parse),
    }
}


pub fn valid_sub_state(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SUB_STATE_BYTES && value.chars().all(|character| character.is_ascii_alphanumeric() || character == '-')
}


/// Exactly the three requested keys, each once, each value checked; nothing from the output is copied into an error.
pub fn parse_show(text: &str) -> Result<Unit, SensorError> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    text.lines().try_for_each(|line| {
        let (key, value) = line
            .split_once('=')
            .filter(|(key, _)| SHOW_KEYS.contains(key))
            .ok_or(SensorError::Parse)?;
        match seen.insert(key, value) {
            Some(_) => Err(SensorError::Parse),
            None => Ok(()),
        }
    })?;
    let active = active_state(seen.get("ActiveState").ok_or(SensorError::Parse)?)?;
    let sub_state = seen.get("SubState").filter(|value| valid_sub_state(value)).ok_or(SensorError::Parse)?;
    let pid = seen
        .get("ExecMainPID")
        .ok_or(SensorError::Parse)?
        .parse::<u32>()
        .map_err(|_| SensorError::Parse)?;
    Ok(Unit {
        active,
        sub_state: (*sub_state).to_owned(),
        pid,
    })
}


/// An active unit without a main process counts as down.
pub fn classify(unit: &Unit, progress: Option<Progress>) -> Observation {
    match unit.active {
        ActiveState::Transitional => Observation::Unknown,
        ActiveState::Down => Observation::Down,
        ActiveState::Active if unit.pid == 0 => Observation::Down,
        ActiveState::Active => Observation::Up(progress),
    }
}


/// The export file's identity, size and time; a file that cannot be read counts as no progress and is logged.
pub fn export_progress(path: &Path) -> Option<Progress> {
    std::fs::symlink_metadata(path)
        .inspect_err(|error| tracing::warn!(%error, "export file not readable for the sensor check"))
        .ok()
        .map(|metadata| Progress {
            ino: metadata.ino(),
            size: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        })
}


pub fn show_arguments() -> Vec<String> {
    ["show", "-p", "ActiveState,SubState,ExecMainPID", UNIT_NAME].map(str::to_owned).to_vec()
}


pub fn start_arguments() -> Vec<String> {
    ["start", UNIT_NAME].map(str::to_owned).to_vec()
}


/// Runs the command with at most `MAX_OUTPUT_BYTES` of standard output read, a deadline, and the child killed when dropped.
pub async fn run_bounded(program: PathBuf, arguments: Vec<String>) -> Result<String, SensorError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = Vec::new();
    for pipe in child.stdout.take().into_iter() {
        pipe.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut output).await?;
    }
    if output.len() as u64 > MAX_OUTPUT_BYTES {
        Err(SensorError::TooLarge(MAX_OUTPUT_BYTES))
    } else {
        let status = child.wait().await?;
        if status.success() {
            Ok(String::from_utf8(output)?)
        } else {
            Err(SensorError::Exit(status.code()))
        }
    }
}


pub async fn run_with_deadline(program: PathBuf, arguments: Vec<String>, deadline: Duration) -> Result<String, SensorError> {
    tokio::time::timeout(deadline, run_bounded(program, arguments))
        .await
        .map_err(|_| SensorError::Timeout)?
}


/// The production runner.
pub fn run_command(program: PathBuf, arguments: Vec<String>) -> RunFuture {
    Box::pin(run_with_deadline(program, arguments, Duration::from_secs(COMMAND_DEADLINE_SECONDS)))
}


/// One look at the unit and, when it is active, at the export file; a failed command is logged and the answer is `Unknown`.
pub async fn observe(env: &SensorEnv) -> Observation {
    let answer = (env.run)(env.systemctl.clone(), show_arguments())
        .await
        .and_then(|text| parse_show(&text));
    match answer {
        Ok(unit) => {
            let progress = (unit.active == ActiveState::Active).then(|| export_progress(&env.export)).flatten();
            let sub_state = unit.sub_state.clone();
            tracing::debug!(sub_state = %sub_state, pid = unit.pid, "sensor unit read");
            classify(&unit, progress)
        }
        Err(error) => {
            tracing::warn!(%error, "sensor state unknown, the unit could not be read");
            Observation::Unknown
        }
    }
}


/// The pure core of a tick: the next memory and what to do. Events and restarts happen on a transition only and are capped per hour.
pub fn step(supervisor: &Supervisor, observation: &Observation, now: u64, settings: &SensorSettings) -> (Supervisor, Action) {
    let (state, progress, progress_at) = match observation {
        Observation::Unknown => (SensorState::Unknown, supervisor.progress, supervisor.progress_at),
        Observation::Down => (SensorState::Stopped, None, None),
        Observation::Up(current) => {
            let moved = supervisor.progress != *current;
            let at = if moved { now } else { supervisor.progress_at.unwrap_or(now) };
            let stalled = now.saturating_sub(at) >= settings.window_seconds;
            (if stalled { SensorState::Stalled } else { SensorState::Running }, *current, Some(at))
        }
    };
    let known = if state == SensorState::Unknown { supervisor.known } else { state };
    let changed = known != supervisor.known;
    let notable = changed && (is_bad(known) || is_bad(supervisor.known));
    let recent = |times: &[u64]| {
        times
            .iter()
            .copied()
            .filter(|time| now.saturating_sub(*time) < HOUR_SECONDS)
            .collect::<Vec<u64>>()
    };
    let events = recent(&supervisor.events);
    let restarts = recent(&supervisor.restarts);
    let emit = notable && events.len() < MAX_EVENTS_PER_HOUR;
    let spaced = restarts
        .last()
        .is_none_or(|last| now.saturating_sub(*last) >= MIN_RESTART_INTERVAL_SECONDS);
    let restart = changed && is_bad(known) && spaced && (restarts.len() as u64) < settings.max_restarts_per_hour;
    let since = if state == supervisor.state { supervisor.since } else { now };
    let event = emit.then_some(SensorEvent {
        state: known,
        previous: supervisor.known,
        since,
        suppressed: supervisor.suppressed,
    });
    let next = Supervisor {
        state,
        known,
        since,
        progress,
        progress_at,
        restarts: restarts.into_iter().chain(restart.then_some(now)).collect(),
        events: events.into_iter().chain(emit.then_some(now)).collect(),
        suppressed: if emit { 0 } else { supervisor.suppressed + u64::from(notable) },
    };
    (
        next,
        Action {
            event,
            restart,
            suppressed: notable && !emit,
        },
    )
}


/// The ECS event of a transition (kind `agent.sensor`); the tenant is the channel identity's.
pub fn sensor_event_line(event: &SensorEvent) -> String {
    json!({
        "event": {"kind": "agent.sensor"},
        "agent": {"sensor": {
            "name": SENSOR_NAME,
            "state": state_name(event.state),
            "previous": state_name(event.previous),
            "since": event.since,
            "suppressed": event.suppressed,
        }},
    })
    .to_string()
}


pub fn restart_entry(tenant: &str, reason: SensorState, result: &str) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: AUDIT_MODULE.to_owned(),
        },
        tenant: tenant.to_owned(),
        module: AUDIT_MODULE.to_owned(),
        action: AUDIT_ACTION.to_owned(),
        target: UNIT_NAME.to_owned(),
        outcome: if result == "started" { Outcome::Success } else { Outcome::Failure },
        request_id: format!("sensor-restart-{}", state_name(reason)),
        justification: None,
        parameters: [("result", result), ("reason", state_name(reason))]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
    }
}


/// One restart attempt, audited; a failure of the command or of the audit is logged and never stops the supervisor.
pub async fn restart(env: &SensorEnv, audit: &SharedAuditFn, reason: SensorState) {
    let started = (env.run)(env.systemctl.clone(), start_arguments())
        .await
        .inspect_err(|error| tracing::warn!(%error, "sensor restart failed"));
    let result = if started.is_ok() { "started" } else { "failed" };
    tracing::warn!(reason = state_name(reason), result, "sensor restart attempted");
    audit(restart_entry(&env.tenant, reason, result))
        .inspect_err(|error| tracing::error!(%error, "sensor restart audit failed"))
        .ok();
}


/// One tick: observe, decide, spool the event of a transition, restart on a transition into a bad state.
pub async fn tick(
    env: &SensorEnv,
    audit: &SharedAuditFn,
    settings: &SensorSettings,
    supervisor: Supervisor,
    now: u64,
) -> Result<Supervisor, SourceError> {
    let observation = observe(env).await;
    let (next, action) = step(&supervisor, &observation, now, settings);
    if next.state != supervisor.state {
        let (state, previous) = (state_name(next.state), state_name(supervisor.state));
        tracing::info!(state, previous, "sensor state changed");
    }
    if let Some(event) = &action.event {
        append_back(once(Ok(sensor_event_line(event))), &env.spool)
            .inspect_err(|error| tracing::error!(%error, "sensor event not spooled, the agent stops"))?;
    }
    if action.suppressed {
        tracing::warn!(cap = MAX_EVENTS_PER_HOUR, "sensor event cut by the hourly cap and counted");
    }
    if action.restart {
        restart(env, audit, next.known).await;
    }
    Ok(next)
}


/// Ticks `max_ticks` times, reading the settings afresh each time; the clock and the pause are injected. Returns the final memory.
pub async fn run_sensor(
    shared: &SharedSensor,
    env: &SensorEnv,
    audit: &SharedAuditFn,
    max_ticks: u64,
    pause: &PauseFn,
    clock: &ClockFn,
) -> Result<Supervisor, SourceError> {
    let mut supervisor = Supervisor::default();
    for _ in 0..max_ticks {
        let settings = shared.load_full();
        supervisor = tick(env, audit, &settings, supervisor, clock()).await?;
        pause(Duration::from_secs(settings.interval_seconds)).await;
    }
    Ok(supervisor)
}
