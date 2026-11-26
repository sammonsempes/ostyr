//! One round of `ostyr-k8s-inventory`: the read-only-verified fetch, then the CMDB sync; a refused fetch writes nothing.

use crate::cmdb_sync::{sync, SyncReport};
use crate::error::{FetchError, SyncError};
use crate::fetch::{fetch_with, open_session};
use crate::inventory::Inventory;
use crate::service::{limits_of, ServiceSettings};
use crate::settings::{load_settings, FetchSettings};
use cmdb::pg::pg_executor;
use cmdb::types::TruthMap;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::settings::PgSettings;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::{info, warn};


#[derive(Debug, Error)]
pub enum RoundFault {
    #[error("the cluster fetch was refused: {0}")]
    Fetch(#[from] FetchError),
    #[error("the CMDB store is unreachable: {0}")]
    Pg(#[from] PgError),
    #[error("the CMDB sync failed: {0}")]
    Sync(#[from] SyncError),
}


pub fn fault_class(fault: &RoundFault) -> &'static str {
    match fault {
        RoundFault::Fetch(FetchError::WritableCredential { .. } | FetchError::RulesUnverifiable { .. } | FetchError::MissingRead { .. }) => {
            "not_read_only"
        }
        RoundFault::Fetch(_) => "fetch",
        RoundFault::Pg(_) => "cmdb_store",
        RoundFault::Sync(_) => "cmdb_sync",
    }
}


/// The fetch settings are read once: the access check, the fetch and the sync all use that one read.
pub fn fetch_once(file: &Path) -> Result<(FetchSettings, Inventory), FetchError> {
    let settings = load_settings(file)?;
    let mut session = open_session(&settings)?;
    let inventory = fetch_with(&mut session, &settings)?;
    Ok((settings, inventory))
}


/// The fetch comes first, so a refusal never reaches the CMDB.
pub async fn one_round(pg: &PgSettings, live: &ServiceSettings) -> Result<SyncReport, RoundFault> {
    let (settings, inventory) = fetch_once(&live.fetch_settings)?;
    let client = connect(pg).await?;
    let exec = pg_executor(&client, Duration::from_secs(pg.statement_timeout_secs));
    Ok(sync(&exec, &settings, &inventory, &TruthMap::default(), &limits_of(live)).await?)
}


pub fn log_round(result: &Result<SyncReport, RoundFault>) {
    match result {
        Ok(report) => {
            let SyncReport {
                created,
                updated,
                unchanged,
                conflicts,
                skipped,
                unapplied,
                ..
            } = report;
            info!(created, updated, unchanged, conflicts, skipped, unapplied, "k8s round done");
        }
        Err(fault) => {
            let class = fault_class(fault);
            let reason = fault.to_string();
            warn!(class, reason, "k8s round failed, the CMDB keeps the last sync");
        }
    }
}
