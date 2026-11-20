//! The PostgreSQL backend of the lease REST routes: one `alerts::backend::lease` permit per request, the tenant bound as `$1` by `pg_executor`.

use crate::api_model::DhcpBackend;
use crate::error::HistoryError;
use crate::history::{lease_at, leases_of_mac};
use alerts::backend::lease;
use alerts::error::StoreError;
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub fn lease_failure(error: StoreError) -> HistoryError {
    match error {
        StoreError::Busy => HistoryError::Busy,
        StoreError::Pg(source) => HistoryError::Pg(source),
        _other => HistoryError::Answer,
    }
}


pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> DhcpBackend {
    let at_engine = Arc::clone(&engine);
    let at_permits = Arc::clone(&permits);
    DhcpBackend {
        at: Arc::new(move |scope, address, at| {
            let (held_engine, held_permits) = (Arc::clone(&at_engine), Arc::clone(&at_permits));
            Box::pin(async move {
                let held = lease(&held_engine, &held_permits).await.map_err(lease_failure)?;
                let executor = pg_executor(&held.client, held.deadline);
                lease_at(&executor, &scope, &address, at).await
            })
        }),
        by_mac: Arc::new(move |scope, mac, from, to| {
            let (held_engine, held_permits) = (Arc::clone(&engine), Arc::clone(&permits));
            Box::pin(async move {
                let held = lease(&held_engine, &held_permits).await.map_err(lease_failure)?;
                let executor = pg_executor(&held.client, held.deadline);
                leases_of_mac(&executor, &scope, &mac, from, to).await
            })
        }),
    }
}
