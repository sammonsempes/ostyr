use crate::error::{ConfigError, ReloadRefusal};
use crate::load::{load_layered, load_module};
use crate::model::ModuleConfig;
use crate::plan::{plan, Change};
use crate::types::{ApplySectionFn, ConfigState, LoaderFn, Plan, SharedAuditFn, StateFn, ValidateFn};
use arc_swap::ArcSwap;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use time::OffsetDateTime;
use tracing::{error, info};


pub const RELOAD_ACTION: &str = "config.reload";


pub const PARAMETER_COUNT: usize = 2;


pub const RELOAD_DECLARED_KEYS: [&str; 3] = ["result", "diff", "reason"];


/// A module's hook per configuration section: `validate` may refuse, `apply` runs after the swap.
pub struct Subscriber<Config> {
    pub section: String,
    pub validate: Box<ValidateFn<Config>>,
    pub apply: Box<ApplySectionFn<Config>>,
}


#[derive(Debug, Clone)]
pub struct ReloadContext {
    pub actor_id: String,
    pub tenant: String,
    pub module: String,
    pub target: String,
    pub request_id: String,
}


/// Readers go through `current_config`; `gate` serialises reloads.
pub struct ReloadEngine<Config> {
    pub current: ArcSwap<Config>,
    pub loader: Box<LoaderFn<Config>>,
    pub to_state: StateFn<Config>,
    pub subscribers: Vec<Subscriber<Config>>,
    pub audit: Box<SharedAuditFn>,
    pub context: ReloadContext,
    pub gate: Mutex<()>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    Unchanged,
    Applied { keys: Vec<String> },
    Refused { reason: String },
}


pub struct Candidate<Config> {
    pub config: Arc<Config>,
    pub changes: Plan,
}


/// Loads the first configuration; subscribers are not called for it.
pub fn open_engine<Config>(
    loader: Box<LoaderFn<Config>>,
    to_state: StateFn<Config>,
    subscribers: Vec<Subscriber<Config>>,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<Config>, ConfigError> {
    let first = loader()?;
    Ok(ReloadEngine {
        current: ArcSwap::from_pointee(first),
        loader,
        to_state,
        subscribers,
        audit,
        context,
        gate: Mutex::new(()),
    })
}


/// Lock-free: the caller holds a whole configuration, old or new.
pub fn current_config<Config>(engine: &ReloadEngine<Config>) -> Arc<Config> {
    engine.current.load_full()
}


pub fn module_loader(path: PathBuf) -> Box<LoaderFn<ModuleConfig>> {
    Box::new(move || load_module(&path))
}


pub fn layered_loader(base: PathBuf, tenant: PathBuf) -> Box<LoaderFn<ModuleConfig>> {
    Box::new(move || load_layered(&base, &tenant))
}


/// Secrets appear as references only.
pub fn module_state(config: &ModuleConfig) -> ConfigState {
    let fixed = [
        ("name", Some(&config.name)),
        ("version", Some(&config.version)),
        ("tenant", config.tenant.as_ref()),
        ("listen", config.listen.as_ref()),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.map(|text| (key.to_owned(), text.clone())));
    let secrets = config.secrets.iter().map(|(key, secret)| (format!("secrets.{key}"), secret.0.clone()));
    let settings = config.settings.iter().map(|(key, value)| (format!("settings.{key}"), value.clone()));
    fixed.chain(secrets).chain(settings).collect()
}


pub fn reload_entry(context: &ReloadContext, outcome: Outcome, parameters: [(&str, String); PARAMETER_COUNT]) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: context.actor_id.clone(),
        },
        tenant: context.tenant.clone(),
        module: context.module.clone(),
        action: RELOAD_ACTION.to_owned(),
        target: context.target.clone(),
        outcome,
        request_id: context.request_id.clone(),
        justification: None,
        parameters: parameters.into_iter().map(|(key, value)| (key.to_owned(), value)).collect(),
    }
}


pub fn diff_text(changes: &[Change]) -> String {
    changes.iter().map(|change| change.diff.as_str()).collect()
}


/// `None` when the new configuration equals the current one.
pub fn prepare<Config>(engine: &ReloadEngine<Config>) -> Result<Option<Candidate<Config>>, ReloadRefusal> {
    let config = Arc::new((engine.loader)()?);
    let changes = plan(&(engine.to_state)(&config), &(engine.to_state)(&current_config(engine)));
    if changes.is_empty() {
        Ok(None)
    } else {
        engine.subscribers.iter().try_for_each(|subscriber| {
            (subscriber.validate)(&config).map_err(|source| ReloadRefusal::Subscriber {
                section: subscriber.section.clone(),
                source,
            })
        })?;
        Ok(Some(Candidate { config, changes }))
    }
}


/// Audits first, then swaps: an audit failure leaves the old configuration in force.
pub fn commit<Config>(engine: &ReloadEngine<Config>, candidate: Candidate<Config>) -> Result<ReloadOutcome, ReloadRefusal> {
    let keys: Vec<String> = candidate.changes.iter().map(|change| change.key.clone()).collect();
    (engine.audit)(reload_entry(
        &engine.context,
        Outcome::Success,
        [("result", "applied".to_owned()), ("diff", diff_text(&candidate.changes))],
    ))?;
    engine.current.store(Arc::clone(&candidate.config));
    engine.subscribers.iter().for_each(|subscriber| (subscriber.apply)(&candidate.config));
    info!(keys = keys.join(","), "configuration reloaded");
    Ok(ReloadOutcome::Applied { keys })
}


pub fn refuse<Config>(engine: &ReloadEngine<Config>, refusal: &ReloadRefusal) -> ReloadOutcome {
    let reason = refusal.to_string();
    error!(%reason, "configuration reload refused, old configuration kept");
    if let Err(audit_error) = (engine.audit)(reload_entry(
        &engine.context,
        Outcome::Denied,
        [("result", "refused".to_owned()), ("reason", reason.clone())],
    )) {
        error!(%audit_error, "cannot audit the refused reload");
    }
    ReloadOutcome::Refused { reason }
}


/// The single reload path shared by the file watch, the signal and explicit calls.
pub fn reload<Config>(engine: &ReloadEngine<Config>) -> ReloadOutcome {
    let _serial = engine.gate.lock().unwrap_or_else(PoisonError::into_inner);
    match prepare(engine) {
        Ok(None) => ReloadOutcome::Unchanged,
        Ok(Some(candidate)) => commit(engine, candidate).unwrap_or_else(|refusal| refuse(engine, &refusal)),
        Err(refusal) => refuse(engine, &refusal),
    }
}
