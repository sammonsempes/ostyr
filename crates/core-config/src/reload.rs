use crate::error::{ConfigError, ReloadRefusal};
use crate::load::{load_layered, load_module};
use crate::model::ModuleConfig;
use crate::plan::{plan, Change};
use crate::types::{ApplySectionFn, ConfigState, LoaderFn, Plan, SharedAuditFn, StateFn, ValidateFn};
use arc_swap::ArcSwap;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_redact::value::redact_text;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use time::OffsetDateTime;
use tracing::{error, info};


pub const RELOAD_ACTION: &str = "config.reload";


pub const PARAMETER_COUNT: usize = 2;


pub const MAX_VALUE_CHARS: usize = 512;


pub const MAX_DIFF_ENTRIES: usize = 64;


pub const MAX_DIFF_CHARS: usize = 8192;


pub const MAX_KEY_ENTRIES: usize = 256;


pub const FILE_KEY_SEPARATOR: &str = "::";


/// The text cut to `max` characters, with a visible marker naming the number of characters omitted.
pub fn bounded_text(value: &str, max: usize, label: &str) -> String {
    let omitted = value.chars().count().saturating_sub(max);
    if omitted == 0 {
        value.to_owned()
    } else {
        let kept: String = value.chars().take(max).collect();
        format!("{kept}[{label} truncated, {omitted} characters omitted]")
    }
}


/// A key list kept as a JSON array: a list over the bound becomes one array holding a visible marker.
pub fn bounded_key_list(label: &str, value: &str) -> String {
    let omitted = value.chars().count().saturating_sub(MAX_DIFF_CHARS);
    if omitted == 0 {
        value.to_owned()
    } else {
        encode_keys(&[format!("[{label} truncated, {omitted} characters omitted]")])
    }
}


pub fn encode_keys(keys: &[String]) -> String {
    serde_json::Value::Array(keys.iter().cloned().map(serde_json::Value::String).collect()).to_string()
}


pub fn bounded_value(value: &str) -> String {
    bounded_text(value, MAX_VALUE_CHARS, "value")
}


pub fn bounded_diff(value: &str) -> String {
    bounded_text(value, MAX_DIFF_CHARS, "diff")
}


pub fn bounded_parameter(key: &str, value: &str) -> String {
    match key {
        "diff" => bounded_diff(value),
        "changed_settings" | "changed_files" => bounded_key_list(key, value),
        _ => bounded_value(value),
    }
}


/// The SHA-256 of the redacted full diff text, lower-case hex: a secret pasted into a value never reaches an unsalted hash.
pub fn diff_digest(diff: &str) -> String {
    format!("{:x}", Sha256::digest(redact_text(diff).as_bytes()))
}


pub const RELOAD_DECLARED_KEYS: [&str; 6] = ["result", "diff", "reason", "changed_settings", "changed_files", "diff_sha256"];


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
        parameters: parameters
            .into_iter()
            .map(|(key, value)| (key.to_owned(), bounded_parameter(key, &value)))
            .collect(),
    }
}


pub fn full_diff(changes: &[Change]) -> String {
    changes.iter().map(|change| change.diff.as_str()).collect()
}


pub const TRUNCATION_MARKER_RESERVE: usize = 64;


/// At most `MAX_DIFF_ENTRIES` entries and `MAX_DIFF_CHARS` characters in all, both markers included, so `bounded_diff` never cuts it again.
pub fn diff_text(changes: &[Change]) -> String {
    let shown: String = changes.iter().take(MAX_DIFF_ENTRIES).map(|change| change.diff.as_str()).collect();
    let omitted = changes.len().saturating_sub(MAX_DIFF_ENTRIES);
    let entry_marker = if omitted == 0 {
        String::new()
    } else {
        format!("[{omitted} more changes omitted]\n")
    };
    let budget = MAX_DIFF_CHARS.saturating_sub(entry_marker.chars().count() + TRUNCATION_MARKER_RESERVE);
    let kept: String = shown.chars().take(budget).collect();
    let body = if kept.len() == shown.len() {
        shown
    } else {
        let cut = full_diff(changes).chars().count() - kept.chars().count();
        format!("{kept}[diff truncated, {cut} characters omitted]")
    };
    format!("{body}{entry_marker}")
}


/// A JSON array of strings: the keys that fit the bound, then one marker element naming how many keys were omitted.
pub fn changed_settings_text(changes: &[Change]) -> String {
    let budget = MAX_DIFF_CHARS.saturating_sub(TRUNCATION_MARKER_RESERVE);
    let shown: Vec<String> = changes
        .iter()
        .take(MAX_KEY_ENTRIES)
        .map(|change| change.key.clone())
        .scan(usize::MIN, |used, key| {
            *used = used.saturating_add(encode_keys(std::slice::from_ref(&key)).chars().count());
            Some((*used, key))
        })
        .take_while(|(used, _)| *used <= budget)
        .map(|(_, key)| key)
        .collect();
    let omitted = changes.len().saturating_sub(shown.len());
    if omitted == 0 {
        encode_keys(&shown)
    } else {
        let marked: Vec<String> = shown
            .into_iter()
            .chain(std::iter::once(format!("[{omitted} more keys omitted]")))
            .collect();
        encode_keys(&marked)
    }
}


/// A JSON array of the distinct files named by the keys (`file::path`, text before the first separator), computed from the full change list.
pub fn changed_files_text(changes: &[Change]) -> String {
    let files: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| change.key.split_once(FILE_KEY_SEPARATOR))
        .map(|(file, _)| file.to_owned())
        .collect();
    encode_keys(&files.into_iter().collect::<Vec<String>>())
}


/// Adds the full list of changed keys (bounded, with an omitted count) and the digest of the whole diff.
pub fn with_changes(entry: NewEntry, changes: &[Change]) -> NewEntry {
    let mut parameters = entry.parameters;
    parameters.insert(
        "changed_settings".to_owned(),
        bounded_parameter("changed_settings", &changed_settings_text(changes)),
    );
    parameters.insert(
        "changed_files".to_owned(),
        bounded_parameter("changed_files", &changed_files_text(changes)),
    );
    parameters.insert("diff_sha256".to_owned(), diff_digest(&full_diff(changes)));
    NewEntry { parameters, ..entry }
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
    (engine.audit)(with_changes(
        reload_entry(
            &engine.context,
            Outcome::Success,
            [("result", "applied".to_owned()), ("diff", diff_text(&candidate.changes))],
        ),
        &candidate.changes,
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
