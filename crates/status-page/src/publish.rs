use crate::error::{StatusPageError, StoreError};
use crate::model::{IncidentInput, PageConfig, PageState, DEFAULT_LIMITS};
use crate::render::render;
use crate::snapshot::{publish, snapshot_of};
use crate::types::IncidentReadFn;
use core_pg::scope::TenantScope;
use futures_util::StreamExt;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::{sleep, timeout, Instant};


pub const READ_DEADLINE: Duration = Duration::from_secs(30);


pub const UNLIMITED_TICKS: u64 = u64::MAX;


/// A fixed label for a failed read; the error text itself (which may carry database details) is never logged.
pub fn error_class(error: &StoreError) -> &'static str {
    match error {
        StoreError::ReadTimeout => "timeout",
        StoreError::Pg(_) => "database",
        StoreError::Config(_) => "config",
        _ => "rows",
    }
}


/// One read under an overall deadline, on top of the connect and statement timeouts the reader takes from the core-pg settings.
pub async fn fetch(read: &IncidentReadFn, scope: &TenantScope, deadline: Duration) -> Result<Vec<IncidentInput>, StoreError> {
    timeout(deadline, read(scope.clone())).await.map_err(|_elapsed| StoreError::ReadTimeout)?
}


/// Every component is `unknown` (no state is passed) until the checks feed is wired.
pub fn publish_page(config: &PageConfig, state: &PageState, incidents: &[IncidentInput]) -> Result<(), StatusPageError> {
    let rendered = render(config, &[], incidents, &[], 0, &DEFAULT_LIMITS)?;
    publish(state, snapshot_of(&config.tenant, &rendered))
}


/// The page before `serve` accepts: a failed read gives a page without incidents, never a missing one.
pub async fn first_publish(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope) -> Result<(), StatusPageError> {
    let incidents = fetch(read, scope, READ_DEADLINE).await.unwrap_or_else(|error| {
        let class = error_class(&error);
        tracing::warn!(class, "first incident read failed");
        Vec::new()
    });
    publish_page(config, state, &incidents)
}


/// A failed read or render keeps the snapshot already served and logs the error class only.
pub async fn tick(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope) {
    let failed = match fetch(read, scope, READ_DEADLINE).await {
        Ok(incidents) => publish_page(config, state, &incidents).err().map(|_error| "render"),
        Err(error) => Some(error_class(&error)),
    };
    if let Some(class) = failed {
        tracing::warn!(class, "incident publish failed, the previous page stays");
    }
}


/// Runs `ticks` rounds: wait the interval of the current settings, then read and publish; rounds never overlap and the ones a slow read covered are counted.
pub async fn publisher(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope, ticks: u64) {
    futures_util::stream::iter(0..ticks)
        .for_each(|_round| async {
            let interval_seconds = state.settings.load().publish_interval_seconds;
            sleep(Duration::from_secs(interval_seconds)).await;
            let started = Instant::now();
            tick(config, state, read, scope).await;
            let skipped = started.elapsed().as_secs() / interval_seconds.max(1);
            state.publish_skipped.fetch_add(skipped, Ordering::SeqCst);
        })
        .await;
}
