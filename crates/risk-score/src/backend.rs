use crate::error::RiskError;
use crate::model::Weights;
use crate::source::{tenant_scores, Limits, Outcome, MICROS_PER_SECOND};
use crate::types::{ComputeFn, NowFn};
use alerts::backend::{lease, unix_micros};
use alerts::pg::pg_executor;
use core_config::reload::ReloadEngine;
use core_pg::scope::TenantScope;
use core_pg::settings::PgSettings;
use std::sync::Arc;
use tokio::sync::Semaphore;


pub const ACTOR: &str = "risk-score";


pub fn system_now() -> i64 {
    (unix_micros() / MICROS_PER_SECOND).cast_signed()
}


pub fn system_clock() -> NowFn {
    Arc::new(system_now)
}


/// One connection through the alerts `lease` for the whole computation: a permit per running computation, else `Busy`.
pub async fn pg_compute(
    engine: Arc<ReloadEngine<PgSettings>>,
    permits: Arc<Semaphore>,
    scope: TenantScope,
    weights: Arc<Weights>,
    now: i64,
) -> Result<Outcome, RiskError> {
    let held = lease(&engine, &permits).await?;
    let executor = pg_executor(&held.client, held.deadline);
    tenant_scores(&executor, &scope, &weights, now, &Limits::default()).await
}


pub fn pg_backend(engine: Arc<ReloadEngine<PgSettings>>, permits: Arc<Semaphore>) -> ComputeFn {
    Arc::new(move |scope, weights, now| Box::pin(pg_compute(Arc::clone(&engine), Arc::clone(&permits), scope, weights, now)))
}
