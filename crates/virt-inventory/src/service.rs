//! The settings files of `ostyr-virt-inventory` as one reloadable value, one round (fetch then CMDB sync) and its audit record.

use crate::cmdb_sync::sync;
use crate::error::{FetchError, ParseError, ReadOnlyError, RoundError, ServiceError};
use crate::fetch::fetch_inventory;
use crate::inventory::{inventory_items, inventory_skipped};
use crate::model::{Context, Live, Parsed, RoundReport};
use crate::settings::{load_settings, FetchSettings};
use crate::types::RoundFuture;
use cmdb::model::{Limits, DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use cmdb::pg::pg_executor;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_audit::types::ParameterMap;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::{ConfigState, LoaderFn, SharedAuditFn};
use core_pg::connect::connect;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;


pub const MIN_INTERVAL_SECONDS: u64 = 60;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const AUDIT_TENANT: &str = "all";


pub const MODULE: &str = "virt-inventory";


pub const ROUND_ACTION: &str = "virt.round";


pub const ROUND_REQUEST: &str = "virt-inventory-round";


pub const SETTINGS_LABEL: &str = "settings";


pub const SETTINGS_REQUEST: &str = "settings";


pub const NOT_READ_ONLY: &str = "not_read_only";


pub const START_ONLY: &str =
    "tenant, cluster, api_url, ca_file, token_file, fetch_settings, pg_settings and audit_file are read at start only, restart the service to change them";


pub const ROUND_KEYS: [&str; 17] = [
    "round_error",
    "observed",
    "storage_skipped",
    "refused",
    "created",
    "updated",
    "conflicts",
    "refused_no_room",
    "refused_attribute_room",
    "unapplied",
    "skipped_unparsable",
    "skipped_bad_field",
    "skipped_duplicate",
    "skipped_other_type",
    "skipped_key_lost",
    "name_dropped",
    "field_dropped",
];


/// Start-only: the two file paths and the audit log. Live: the interval and the lab caps. One tenant per process, named by the fetch file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSettings {
    pub fetch_settings: PathBuf,
    pub pg_settings: PathBuf,
    pub audit_file: PathBuf,
    pub interval_seconds: u64,
    #[serde(default = "default_max_assets")]
    pub max_assets: usize,
    #[serde(default = "default_max_child_rows")]
    pub max_child_rows: usize,
}


pub fn default_max_assets() -> usize {
    DEFAULT_MAX_ASSETS
}


pub fn default_max_child_rows() -> usize {
    DEFAULT_MAX_CHILD_ROWS
}


/// The caps can only lower the store's defaults.
pub fn validate_service(settings: &ServiceSettings) -> Result<(), ServiceError> {
    if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&settings.interval_seconds) {
        Err(ServiceError::Interval {
            min: MIN_INTERVAL_SECONDS,
            max: MAX_INTERVAL_SECONDS,
        })
    } else if !(1..=DEFAULT_MAX_ASSETS).contains(&settings.max_assets) {
        Err(ServiceError::MaxAssets { max: DEFAULT_MAX_ASSETS })
    } else if !(1..=DEFAULT_MAX_CHILD_ROWS).contains(&settings.max_child_rows) {
        Err(ServiceError::MaxChildRows { max: DEFAULT_MAX_CHILD_ROWS })
    } else {
        Ok(())
    }
}


pub fn refuse(reason: String) -> ConfigError {
    ConfigError::WatchedFile {
        file: SETTINGS_LABEL.to_owned(),
        reason,
    }
}


pub fn load_service_settings(path: &Path) -> Result<ServiceSettings, ConfigError> {
    let settings = load_file::<ServiceSettings>(path)?;
    validate_service(&settings).map_err(|error| refuse(error.to_string()))?;
    Ok(settings)
}


/// The store limits of validated settings: `validate_service` keeps both caps inside what the store's `check_limits` accepts.
pub fn limits_of(settings: &ServiceSettings) -> Limits {
    Limits {
        max_assets: settings.max_assets,
        max_child_rows: settings.max_child_rows,
        ..Limits::default()
    }
}


/// The service file, then the fetch file it names (its path pinned to the start-up one when `pinned` is given), each read once.
pub fn load_live_with(file: &Path, pinned: Option<&Path>) -> Result<Live, ConfigError> {
    let service = load_service_settings(file)?;
    let limits = limits_of(&service);
    pinned
        .is_none_or(|path| path == service.fetch_settings)
        .then_some(())
        .ok_or_else(|| refuse(START_ONLY.to_owned()))?;
    let fetch = load_settings(&service.fetch_settings).map_err(|error| refuse(error.to_string()))?;
    Ok(Live { service, fetch, limits })
}


pub fn load_live(file: &Path) -> Result<Live, ConfigError> {
    load_live_with(file, None)
}


/// Everything except the live values must equal the start-up snapshot: the interval, the lab caps, the fetch deadline and bounds are live.
pub fn start_only_changed(baseline: &Live, current: &Live) -> bool {
    let same_live = Live {
        service: ServiceSettings {
            interval_seconds: baseline.service.interval_seconds,
            max_assets: baseline.service.max_assets,
            max_child_rows: baseline.service.max_child_rows,
            ..current.service.clone()
        },
        fetch: FetchSettings {
            timeout_ms: baseline.fetch.timeout_ms,
            limits: baseline.fetch.limits.clone(),
            ..current.fetch.clone()
        },
        limits: baseline.limits,
    };
    same_live != *baseline
}


pub fn live_state(live: &Live) -> ConfigState {
    [
        ("fetch_settings", live.service.fetch_settings.display().to_string()),
        ("pg_settings", live.service.pg_settings.display().to_string()),
        ("audit_file", live.service.audit_file.display().to_string()),
        ("interval_seconds", live.service.interval_seconds.to_string()),
        ("max_assets", live.service.max_assets.to_string()),
        ("max_child_rows", live.service.max_child_rows.to_string()),
        ("api_url", live.fetch.api_url.clone()),
        ("ca_file", live.fetch.ca_file.display().to_string()),
        ("token_file", live.fetch.token_file.display().to_string()),
        ("tenant", live.fetch.tenant.clone()),
        ("cluster", live.fetch.cluster.clone()),
        ("timeout_ms", live.fetch.timeout_ms.to_string()),
        ("fetch_limits", format!("{:?}", live.fetch.limits)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}


pub fn live_loader(file: PathBuf, baseline: Live) -> Box<LoaderFn<Live>> {
    Box::new(move || {
        let current = load_live_with(&file, Some(&baseline.service.fetch_settings))?;
        if start_only_changed(&baseline, &current) {
            Err(refuse(START_ONLY.to_owned()))
        } else {
            Ok(current)
        }
    })
}


/// The audit identity of a reload: the tenant is the non-customer `all`, never the customer tenant the sync writes for.
pub fn reload_context(file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        target: file.display().to_string(),
        request_id: SETTINGS_REQUEST.to_owned(),
    }
}


/// The first read is the baseline; a later reload may change only the live values, any other change is refused and audited `denied`.
pub fn open_live_engine(file: &Path, baseline: Live, audit: Box<SharedAuditFn>) -> Result<ReloadEngine<Live>, ConfigError> {
    open_engine(
        live_loader(file.to_path_buf(), baseline),
        live_state,
        Vec::new(),
        audit,
        reload_context(file),
    )
}


/// Fetch (read-only token verified first), then sync into the tenant's CMDB over a connection opened for this round; a failed fetch writes nothing.
pub async fn run_round(context: &Context) -> Result<RoundReport, RoundError> {
    let inventory = fetch_inventory(&context.fetch)?;
    let parsed = Parsed {
        items: inventory_items(&inventory).to_vec(),
        skipped: inventory_skipped(&inventory).clone(),
    };
    let client = connect(&context.pg).await?;
    let executor = pg_executor(&client, Duration::from_secs(context.pg.statement_timeout_secs));
    let report = sync(&executor, &context.fetch, &parsed, &Default::default(), &context.limits).await?;
    Ok(RoundReport {
        sync: report,
        skipped: parsed.skipped,
    })
}


pub fn production_round(context: &Context) -> RoundFuture<'_> {
    Box::pin(run_round(context))
}


/// A fixed category per failure: nothing from the peer, the token or a file reaches the audit.
pub fn parse_reason(error: &ParseError) -> &'static str {
    match error {
        ParseError::Read(_) => "read",
        ParseError::TooLarge { .. } => "too_large",
        ParseError::Malformed { .. } => "malformed",
        ParseError::TooManyItems { .. } => "TooManyItems",
        ParseError::TooManyPrivileges { .. } => "TooManyPrivileges",
        ParseError::TooManyGrants { .. } => "TooManyGrants",
        ParseError::BadPermission => "bad_permission",
    }
}


pub fn fetch_reason(error: &FetchError) -> String {
    match error {
        FetchError::Permissions(cause) => format!("permissions_{}", parse_reason(cause)),
        FetchError::Resources(cause) => format!("resources_{}", parse_reason(cause)),
        FetchError::WritableCredential(ReadOnlyError::NoRights) => "no_rights".to_owned(),
        FetchError::WritableCredential(ReadOnlyError::HasWriteRights { .. }) => NOT_READ_ONLY.to_owned(),
        FetchError::Certificate => "certificate".to_owned(),
        FetchError::Transport(_) => "transport".to_owned(),
        FetchError::Status(_) => "status".to_owned(),
        FetchError::CaFile(_) => "ca_file".to_owned(),
        FetchError::TokenFile(_) | FetchError::TokenShape => "token".to_owned(),
        FetchError::Body(_) | FetchError::TooLarge { .. } => "body".to_owned(),
        FetchError::Config(_) | FetchError::Url | FetchError::Timeout | FetchError::MaxBytes | FetchError::Scope(_) | FetchError::Agent(_) => {
            "fetch_settings".to_owned()
        }
    }
}


pub fn round_reason(error: &RoundError) -> String {
    match error {
        RoundError::Fetch(cause) => fetch_reason(cause),
        RoundError::Pg(_) => "store_unreachable".to_owned(),
        RoundError::Sync(_) => "sync_failed".to_owned(),
    }
}


pub fn round_parameters(result: &Result<RoundReport, RoundError>) -> ParameterMap {
    match result {
        Ok(round) => {
            let report = &round.sync;
            let skipped = &round.skipped;
            [
                ("observed", report.counters.observed),
                ("storage_skipped", report.counters.storage_skipped),
                ("refused", report.counters.refused + report.refused_by_cmdb),
                ("created", report.created),
                ("updated", report.updated),
                ("conflicts", report.conflicts),
                ("refused_no_room", report.refused_no_room),
                ("refused_attribute_room", report.refused_attribute_room),
                ("unapplied", report.unapplied),
                ("skipped_unparsable", skipped.unparsable),
                ("skipped_bad_field", skipped.bad_field),
                ("skipped_duplicate", skipped.duplicate),
                ("skipped_other_type", skipped.other_type),
                ("skipped_key_lost", skipped.key_lost),
                ("name_dropped", skipped.name_dropped),
                ("field_dropped", skipped.field_dropped),
            ]
            .into_iter()
            .map(|(name, count)| (name.to_owned(), count.to_string()))
            .collect()
        }
        Err(error) => [("round_error".to_owned(), round_reason(error))].into_iter().collect(),
    }
}


/// One audit record of a round, always under the non-customer tenant `all`; the target is the cluster.
pub fn round_entry(cluster: &str, result: &Result<RoundReport, RoundError>) -> NewEntry {
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: MODULE.to_owned(),
        },
        tenant: AUDIT_TENANT.to_owned(),
        module: MODULE.to_owned(),
        action: ROUND_ACTION.to_owned(),
        target: cluster.to_owned(),
        outcome: if result.is_ok() { Outcome::Success } else { Outcome::Failure },
        request_id: ROUND_REQUEST.to_owned(),
        justification: None,
        parameters: round_parameters(result),
    }
}
