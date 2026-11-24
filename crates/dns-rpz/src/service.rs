use crate::cli::{run_round, Session};
use crate::error::{ReloadError, ServiceError};
use crate::limits::{
    AUDIT_DECLARED_KEYS, CLICKHOUSE_PREFIX, DEFAULT_UNBOUND_COMMAND, MAX_INTERVAL_SECONDS, MAX_SERVICE_SETTINGS_BYTES, MIN_INTERVAL_SECONDS,
    ROUND_CAP_EXIT_CODE, ROUND_FAILED_AUDIT_ACTION, SERVICE_ACTOR, SERVICE_ALLOWED_PUNCTUATION, SERVICE_FILE_CLASS, SERVICE_MODULE, SERVICE_SECTION,
    SERVICE_TENANT, SERVICE_UNBOUND_COMMAND, STAGE_GENERATION, STAGE_ZONE_FILE,
};
use crate::model::{CommandStatus, LoopEnd, RoundLoop, RoundOutcome, ServiceSettings};
use crate::types::WaitFn;
use crate::unbound::run_with_deadline;
use core_audit::error::AuditError;
use core_audit::log::{append_declared, AuditLog};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome, Record};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_bytes_capped};
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use std::fs::File;
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{error, info};


/// The position of the first byte off the ASCII allowlist: no tag, anchor, alias, merge key, escape, comment, quote, block scalar or carriage return.
pub fn check_allowlist(bytes: &[u8], file: &str) -> Result<(), ConfigError> {
    match bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || SERVICE_ALLOWED_PUNCTUATION.contains(byte)))
    {
        Some(offset) => Err(ConfigError::WatchedFile {
            file: file.to_owned(),
            reason: format!("a byte at offset {offset} is outside the {SERVICE_FILE_CLASS} ASCII allowlist"),
        }),
        None => Ok(()),
    }
}


/// Reads the file once, checks those bytes against the allowlist, then parses the same bytes.
pub fn read_service_settings(path: &Path) -> Result<ServiceSettings, ConfigError> {
    let file = path.display().to_string();
    let bytes = read_bytes_capped(path, MAX_SERVICE_SETTINGS_BYTES)?;
    check_allowlist(&bytes, &file)?;
    let text: String = bytes.iter().map(|byte| char::from(*byte)).collect();
    parse_document(&text, &file)
}


pub fn is_absolute_file(text: &str) -> bool {
    let path = Path::new(text);
    path.is_absolute() && path.file_name().is_some()
}


/// Names of the settings that are out of bounds.
pub fn invalid_settings(settings: &ServiceSettings) -> Vec<&'static str> {
    let ioc_path = settings.ioc_source.strip_prefix(CLICKHOUSE_PREFIX).unwrap_or(&settings.ioc_source);
    [
        ("policy_file", !is_absolute_file(&settings.policy_file)),
        ("audit_file", !is_absolute_file(&settings.audit_file)),
        ("ioc_source", !is_absolute_file(ioc_path)),
        ("counter_file", !is_absolute_file(&settings.counter_file)),
        ("zone_file", !is_absolute_file(&settings.zone_file)),
        (
            "interval_seconds",
            !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&settings.interval_seconds),
        ),
    ]
    .into_iter()
    .filter_map(|(name, invalid)| invalid.then_some(name))
    .collect()
}


pub fn validate_settings(settings: &ServiceSettings) -> Result<(), ServiceError> {
    let invalid = invalid_settings(settings);
    if invalid.is_empty() {
        Ok(())
    } else {
        Err(ServiceError::Invalid(invalid.join(", ")))
    }
}


/// The name of the first start-only setting that differs, if any.
pub fn changed_pinned(started: &ServiceSettings, candidate: &ServiceSettings) -> Option<&'static str> {
    [
        ("policy_file", started.policy_file != candidate.policy_file),
        ("audit_file", started.audit_file != candidate.audit_file),
        ("ioc_source", started.ioc_source != candidate.ioc_source),
        ("counter_file", started.counter_file != candidate.counter_file),
        ("zone_file", started.zone_file != candidate.zone_file),
    ]
    .into_iter()
    .find_map(|(name, changed)| changed.then_some(name))
}


/// A reload may change `interval_seconds` only, and the value must be in range.
pub fn validate_reload(started: &ServiceSettings, candidate: &ServiceSettings) -> Result<(), ServiceError> {
    match changed_pinned(started, candidate) {
        Some(name) => Err(ServiceError::Pinned(name)),
        None => validate_settings(candidate),
    }
}


/// One key holding the whole file: the diff is for audit.
pub fn settings_state(settings: &ServiceSettings) -> ConfigState {
    ConfigState::from([(format!("{SERVICE_SECTION}.settings"), format!("{settings:#?}"))])
}


pub fn settings_loader(path: PathBuf) -> Box<LoaderFn<ServiceSettings>> {
    Box::new(move || read_service_settings(&path))
}


/// The first load must be valid and equal to `first` (the file the audit path came from); reloads are pinned to it.
pub fn open_settings_engine(
    path: PathBuf,
    first: &ServiceSettings,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<ServiceSettings>, ServiceError> {
    let engine = open_engine(settings_loader(path), settings_state, Vec::new(), audit, context)?;
    let loaded = current_config(&engine);
    if *loaded == *first {
        let started = first.clone();
        Ok(ReloadEngine {
            subscribers: vec![Subscriber {
                section: SERVICE_SECTION.to_owned(),
                validate: Box::new(move |candidate| validate_reload(&started, candidate).map_err(BoxError::from)),
                apply: Box::new(|_applied| ()),
            }],
            ..engine
        })
    } else {
        Err(ServiceError::Changed)
    }
}


/// The service runs only the crate's own control program: a policy that names another one fails the reload, named.
pub fn service_runner(program: &str, arguments: &[String], deadline: Duration) -> io::Result<CommandStatus> {
    if program == DEFAULT_UNBOUND_COMMAND {
        run_with_deadline(SERVICE_UNBOUND_COMMAND, arguments, deadline)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, ReloadError::Refused))
    }
}


pub fn round_failed_entry(context: &ReloadContext, zone_file: &Path, stage: &str) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: context.actor_id.clone(),
        },
        tenant: context.tenant.clone(),
        module: context.module.clone(),
        action: ROUND_FAILED_AUDIT_ACTION.to_owned(),
        target: zone_file.display().to_string(),
        outcome: Outcome::Failure,
        request_id: context.request_id.clone(),
        justification: None,
        parameters: [("stage".to_owned(), stage.to_owned())].into_iter().collect(),
    }
}


/// The audited stage of a round that did not reach the reload; the reload audits itself.
pub fn failed_stage(outcome: RoundOutcome) -> Option<&'static str> {
    match outcome {
        RoundOutcome::GenerationFailed => Some(STAGE_GENERATION),
        RoundOutcome::ZoneFileMismatch => Some(STAGE_ZONE_FILE),
        RoundOutcome::Published | RoundOutcome::ReloadFailed => None,
    }
}


/// A failed generation or a zone path mismatch is audited by name (the reload audits itself); the previous zone stays.
pub fn audit_failed_round(round_loop: &RoundLoop, zone_file: &Path, outcome: RoundOutcome) {
    if let Some(stage) = failed_stage(outcome) {
        if let Err(audit_error) = (round_loop.audit)(round_failed_entry(round_loop.context, zone_file, stage)) {
            error!(%audit_error, "cannot audit the failed round");
        }
    }
}


/// Unbound reloads the zone file its own configuration names: the policy's `unbound.zonefile` must be the file this service writes.
pub fn zone_file_matches(session: &Session) -> bool {
    Path::new(&current_config(session.engine).unbound.zonefile) == session.output
}


pub fn append_entry(log: &AuditLog<File>, entry: NewEntry) -> Result<Record, AuditError> {
    append_declared(log, entry, &AUDIT_DECLARED_KEYS)
}


pub fn shared_audit(log: &Arc<AuditLog<File>>) -> Box<SharedAuditFn> {
    let shared = Arc::clone(log);
    Box::new(move |entry| append_entry(&shared, entry))
}


/// One round, its failure audit, then the wait; `true` when the wait reported a stop.
pub fn one_round(session: &mut Session, round_loop: &RoundLoop, wait: &WaitFn, round: u64) -> Result<bool, ServiceError> {
    let outcome = if zone_file_matches(session) {
        run_round(session)?
    } else {
        let zone_file = session.output.display().to_string();
        error!(zone_file, "policy unbound.zonefile is not the service zone_file, round skipped");
        RoundOutcome::ZoneFileMismatch
    };
    audit_failed_round(round_loop, session.output, outcome);
    let interval = current_config(round_loop.settings).interval_seconds;
    info!(round, interval, "round finished");
    Ok(wait(Duration::from_secs(interval)))
}


/// Rounds until `wait` reports a stop or `max_rounds` is reached; a failed round never ends the loop.
pub fn serve_rounds(session: &mut Session, round_loop: &RoundLoop, wait: &WaitFn, max_rounds: u64) -> Result<LoopEnd, ServiceError> {
    let flow = (1..=max_rounds).try_for_each(|round| match one_round(session, round_loop, wait, round) {
        Ok(false) => ControlFlow::Continue(()),
        Ok(true) => ControlFlow::Break(Ok(LoopEnd::Stopped)),
        Err(failure) => ControlFlow::Break(Err(failure)),
    });
    match flow {
        ControlFlow::Continue(()) => Ok(LoopEnd::RoundCap),
        ControlFlow::Break(ended) => ended,
    }
}


pub fn service_context(target: &str, request_id: &str) -> ReloadContext {
    ReloadContext {
        actor_id: SERVICE_ACTOR.to_owned(),
        tenant: SERVICE_TENANT.to_owned(),
        module: SERVICE_MODULE.to_owned(),
        target: target.to_owned(),
        request_id: request_id.to_owned(),
    }
}


pub fn exit_code(result: Result<LoopEnd, ServiceError>) -> ExitCode {
    match result {
        Ok(LoopEnd::Stopped) => ExitCode::SUCCESS,
        Ok(LoopEnd::RoundCap) => {
            error!("round cap reached, restart the service");
            ExitCode::from(ROUND_CAP_EXIT_CODE)
        }
        Err(failure) => {
            error!(%failure, "dns-rpz service stopped");
            ExitCode::FAILURE
        }
    }
}
