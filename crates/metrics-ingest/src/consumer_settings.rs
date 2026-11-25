use crate::model::Limits;
use crate::settings::{validate_limits, validated_statement, MetricsSettings, SettingsError};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use serde::Deserialize;
use siem_ingest::error::SettingsError as IngestSettingsError;
use siem_ingest::settings::{settings_state, validate_settings, IngestSettings};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use thiserror::Error;


pub const MODULE: &str = "metrics-ingest";


pub const RELOAD_REQUEST_ID: &str = "metrics-consumer-reload";


pub const INGEST_SECTION: &str = "ingest";


pub const LIMITS_SECTION: &str = "limits";


pub const AUDIT_FILE_KEY: &str = "audit_file";


pub const MAX_METRICS_BATCH_MESSAGES: usize = 1_000;


pub const OTHER_DURABLES: [&str; 2] = ["siem-ingest", "detection"];


/// The consumer's settings file: `ingest` is siem-ingest's own settings (NATS and ClickHouse, nothing copied), `limits` the decode and batch caps, `audit_file` the append-only audit log (read at start only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ConsumerFile {
    pub ingest: IngestSettings,
    pub limits: Limits,
    pub audit_file: PathBuf,
}


#[derive(Debug, Error)]
pub enum ConsumerSettingsError {
    #[error(transparent)]
    Ingest(#[from] IngestSettingsError),
    #[error(transparent)]
    Metrics(#[from] SettingsError),
    #[error("{field} {reason}")]
    Refused { field: &'static str, reason: &'static str },
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Ingest(#[from] ConsumerSettingsError),
    #[error(transparent)]
    Limits(#[from] SettingsError),
}


/// The two settings engines of one file, each reloaded on its own and each keeping its old value when the new file is refused.
pub struct Engines {
    pub ingest: Arc<ReloadEngine<IngestSettings>>,
    pub limits: Arc<ReloadEngine<Limits>>,
}


/// The sender's settings for one cycle: the ClickHouse part of the ingest snapshot and the limits snapshot.
pub fn metrics_view(ingest: &IngestSettings, limits: &Limits) -> MetricsSettings {
    MetricsSettings {
        url: ingest.clickhouse_url.clone(),
        user: ingest.clickhouse_user.clone(),
        password_file: ingest.clickhouse_password_file.clone(),
        ca_file: ingest.clickhouse_ca_file.clone(),
        database: ingest.clickhouse_database.clone(),
        table: ingest.clickhouse_table.clone(),
        timeout_ms: ingest.insert_timeout_ms,
        limits: limits.clone(),
    }
}


/// siem-ingest's rules, then the consumer's own: its durable is not another service's, its fetch is below its message ceiling, its sender settings are valid.
pub fn validate_consumer(ingest: &IngestSettings) -> Result<(), ConsumerSettingsError> {
    validate_settings(ingest)?;
    if OTHER_DURABLES.contains(&ingest.nats_consumer.as_str()) {
        Err(ConsumerSettingsError::Refused {
            field: "nats_consumer",
            reason: "must not be the durable of siem-ingest or detection",
        })
    } else if ingest.max_batch_messages > MAX_METRICS_BATCH_MESSAGES {
        Err(ConsumerSettingsError::Refused {
            field: "max_batch_messages",
            reason: "is above the metrics consumer ceiling of 1000",
        })
    } else {
        validated_statement(&metrics_view(ingest, &Limits::default()))
            .map(drop)
            .map_err(ConsumerSettingsError::from)
    }
}


pub fn limits_state(limits: &Limits) -> ConfigState {
    ConfigState::from([("limits".to_owned(), format!("{limits:?}"))])
}


pub fn context_for(path: &Path, section: &str) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: "all".to_owned(),
        module: MODULE.to_owned(),
        target: format!("{} {section}", path.display()),
        request_id: RELOAD_REQUEST_ID.to_owned(),
    }
}


pub fn shared_audit(audit: &Arc<SharedAuditFn>) -> Box<SharedAuditFn> {
    let shared = Arc::clone(audit);
    Box::new(move |entry| shared(entry))
}


/// A reload whose file names another audit log is refused whole: the log is opened once at start.
pub fn same_audit_file(loaded: &ConsumerFile, running: &Path) -> Result<(), ConfigError> {
    if loaded.audit_file == running {
        Ok(())
    } else {
        Err(ConfigError::WatchedFile {
            file: AUDIT_FILE_KEY.to_owned(),
            reason: "audit_file is read at start only, restart to change it".to_owned(),
        })
    }
}


/// The audit log must be an absolute path: a relative one would follow the working directory.
pub fn validate_audit_file(audit_file: &Path) -> Result<(), ConsumerSettingsError> {
    if audit_file.is_absolute() {
        Ok(())
    } else {
        Err(ConsumerSettingsError::Refused {
            field: AUDIT_FILE_KEY,
            reason: "is required and must be an absolute path",
        })
    }
}


/// The first load of an engine is the part already parsed and validated, so the file is read once at open; later loads read the file again.
pub fn first_then_file<Part: Send + 'static>(
    first: Part,
    (path, audit_file): (PathBuf, PathBuf),
    pick: fn(ConsumerFile) -> Part,
) -> Box<LoaderFn<Part>> {
    let pending = Mutex::new(Some(first));
    Box::new(move || match pending.lock().unwrap_or_else(PoisonError::into_inner).take() {
        Some(part) => Ok(part),
        None => load_file::<ConsumerFile>(&path)
            .and_then(|loaded| same_audit_file(&loaded, &audit_file).map(|()| loaded))
            .map(pick),
    })
}


/// Both engines start from one read of the file; a first file that is unreadable or invalid fails here, a later one is refused by `reload`.
pub fn open_consumer(path: PathBuf, audit: &Arc<SharedAuditFn>) -> Result<Engines, OpenError> {
    let file = load_file::<ConsumerFile>(&path)?;
    validate_audit_file(&file.audit_file)?;
    open_engines(path, file, audit)
}


/// The engines of an already parsed file, so a caller that needs `audit_file` first reads the file once.
pub fn open_engines(path: PathBuf, file: ConsumerFile, audit: &Arc<SharedAuditFn>) -> Result<Engines, OpenError> {
    validate_consumer(&file.ingest)?;
    validate_limits(&file.limits)?;
    let ingest = open_engine(
        first_then_file(file.ingest, (path.clone(), file.audit_file.clone()), |loaded| loaded.ingest),
        settings_state,
        vec![Subscriber {
            section: INGEST_SECTION.to_owned(),
            validate: Box::new(|settings| validate_consumer(settings).map_err(BoxError::from)),
            apply: Box::new(|_| ()),
        }],
        shared_audit(audit),
        context_for(&path, INGEST_SECTION),
    )
    .map_err(OpenError::from);
    let limits = open_engine(
        first_then_file(file.limits, (path.clone(), file.audit_file), |loaded| loaded.limits),
        limits_state,
        vec![Subscriber {
            section: LIMITS_SECTION.to_owned(),
            validate: Box::new(|limits| validate_limits(limits).map_err(BoxError::from)),
            apply: Box::new(|_| ()),
        }],
        shared_audit(audit),
        context_for(&path, LIMITS_SECTION),
    )
    .map_err(OpenError::from);
    ingest.and_then(|opened| {
        limits.map(|limited| Engines {
            ingest: Arc::new(opened),
            limits: Arc::new(limited),
        })
    })
}
