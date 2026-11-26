//! The settings file of `ostyr-virt-inventory`, one round (fetch then CMDB sync) and its audit record.

use crate::cmdb_sync::{sync, SyncReport};
use crate::error::{RoundError, ServiceError};
use crate::fetch::fetch_inventory;
use crate::inventory::{inventory_items, inventory_skipped};
use crate::model::{Context, Parsed};
use crate::types::RoundFuture;
use cmdb::model::{Limits, DEFAULT_MAX_ASSETS, DEFAULT_MAX_CHILD_ROWS};
use cmdb::pg::pg_executor;
use cmdb::store::check_limits;
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_audit::types::ParameterMap;
use core_config::load::load_file;
use core_pg::connect::connect;
use serde::Deserialize;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::Duration;
use time::OffsetDateTime;


pub const MIN_INTERVAL_SECONDS: u64 = 60;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const AUDIT_TENANT: &str = "all";


pub const MODULE: &str = "virt-inventory";


pub const ROUND_ACTION: &str = "virt.round";


pub const ROUND_REQUEST: &str = "virt-inventory-round";


pub const ROUND_KEYS: [&str; 10] = [
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
];


/// Start-only: the two files the service reads, the audit log and the lab caps. One tenant per process, named by the fetch file.
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


pub fn load_service_settings(path: &Path) -> Result<ServiceSettings, Box<dyn Error>> {
    let settings = load_file::<ServiceSettings>(path)?;
    validate_service(&settings)?;
    Ok(settings)
}


/// The store limits of the settings, checked by the store's own rule.
pub fn limits_of(settings: &ServiceSettings) -> Result<Limits, cmdb::error::StoreError> {
    let limits = Limits {
        max_assets: settings.max_assets,
        max_child_rows: settings.max_child_rows,
        ..Limits::default()
    };
    check_limits(&limits).map(|()| limits)
}


/// Fetch (read-only token verified first), then sync into the tenant's CMDB over a connection opened for this round; a failed fetch writes nothing.
pub async fn run_round(context: &Context) -> Result<SyncReport, RoundError> {
    let inventory = fetch_inventory(&context.fetch)?;
    let parsed = Parsed {
        items: inventory_items(&inventory).to_vec(),
        skipped: inventory_skipped(&inventory).clone(),
    };
    let client = connect(&context.pg).await?;
    let executor = pg_executor(&client, Duration::from_secs(context.pg.statement_timeout_secs));
    Ok(sync(&executor, &context.fetch, &parsed, &Default::default(), &context.limits).await?)
}


pub fn production_round(context: &Context) -> RoundFuture<'_> {
    Box::pin(run_round(context))
}


pub fn round_parameters(result: &Result<SyncReport, RoundError>) -> ParameterMap {
    match result {
        Ok(report) => [
            ("observed", report.counters.observed),
            ("storage_skipped", report.counters.storage_skipped),
            ("refused", report.counters.refused + report.refused_by_cmdb),
            ("created", report.created),
            ("updated", report.updated),
            ("conflicts", report.conflicts),
            ("refused_no_room", report.refused_no_room),
            ("refused_attribute_room", report.refused_attribute_room),
            ("unapplied", report.unapplied),
        ]
        .into_iter()
        .map(|(name, count)| (name.to_owned(), count.to_string()))
        .collect(),
        Err(error) => [("round_error".to_owned(), error.to_string())].into_iter().collect(),
    }
}


/// One audit record of a round, always under the non-customer tenant `all`; the target is the cluster.
pub fn round_entry(cluster: &str, result: &Result<SyncReport, RoundError>) -> NewEntry {
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
