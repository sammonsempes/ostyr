use crate::error::{StatusPageError, StoreError};
use crate::model::{IncidentInput, PageConfig, PageState, RenderedPage, DEFAULT_LIMITS};
use crate::render::render_omitting;
use crate::snapshot::{publish, snapshot_of};
use crate::types::IncidentReadFn;
use core_pg::scope::TenantScope;
use futures_util::StreamExt;
use std::cmp::Reverse;
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


pub const MAX_FIT_ATTEMPTS: u32 = 6;


/// Renders every incident or, when the output is too large, fewer: unresolved ones stay, the resolved set is halved each attempt, newest kept.
pub fn fit_page(config: &PageConfig, incidents: &[IncidentInput]) -> Result<(RenderedPage, usize), StatusPageError> {
    let (mut published, unpublished): (Vec<IncidentInput>, Vec<IncidentInput>) = incidents.iter().cloned().partition(|incident| incident.published);
    published.sort_by_key(|incident| {
        (
            incident.resolved_at.is_some(),
            Reverse(incident.resolved_at),
            Reverse(incident.started_at),
        )
    });
    let total = published.len();
    let unresolved = published.iter().filter(|incident| incident.resolved_at.is_none()).count();
    let resolved = total - unresolved;
    let kept_counts = (0..MAX_FIT_ATTEMPTS)
        .map(|attempt| unresolved + (resolved >> attempt))
        .chain([unresolved, 0]);
    kept_counts
        .map(|kept| {
            let subset: Vec<IncidentInput> = published.iter().take(kept).chain(unpublished.iter()).cloned().collect();
            (render_omitting(config, &[], &subset, &[], 0, &DEFAULT_LIMITS, total - kept), total - kept)
        })
        .find(|(rendered, _omitted)| !matches!(rendered, Err(StatusPageError::OutputTooLarge { .. })))
        .ok_or(StatusPageError::OutputTooLarge {
            format: "json",
            limit: DEFAULT_LIMITS.max_json_bytes,
        })
        .and_then(|(rendered, omitted)| rendered.map(|page| (page, omitted)))
}


/// Every component is `unknown` (no state is passed) until the checks feed is wired; returns how many incidents were left out for size.
pub fn publish_page(config: &PageConfig, state: &PageState, incidents: &[IncidentInput]) -> Result<usize, StatusPageError> {
    let (rendered, omitted) = fit_page(config, incidents)?;
    publish(state, snapshot_of(&config.tenant, &rendered)).map(|()| omitted)
}


/// The page before `serve` accepts: a failed read or render gives a page without incidents, never a missing one.
pub async fn first_publish(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope) -> Result<(), StatusPageError> {
    let incidents = fetch(read, scope, READ_DEADLINE).await.unwrap_or_else(|error| {
        let class = error_class(&error);
        tracing::warn!(class, "first incident read failed");
        Vec::new()
    });
    let omitted = publish_page(config, state, &incidents).or_else(|error| {
        let class = render_class(&error);
        tracing::warn!(class, "first render failed, publishing without incidents");
        publish_page(config, state, &[])
    })?;
    log_omitted(omitted);
    Ok(())
}


/// A fixed label for a failed render.
pub fn render_class(error: &StatusPageError) -> &'static str {
    match error {
        StatusPageError::TenantMismatch => "tenant",
        _ => "render",
    }
}


pub fn log_omitted(omitted: usize) {
    if omitted > 0 {
        tracing::warn!(omitted, "older incidents left out of the page for size");
    }
}


/// A failed read or render keeps the snapshot already served and logs the error class only.
pub async fn tick(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope) {
    let failed = match fetch(read, scope, READ_DEADLINE).await {
        Ok(incidents) => publish_page(config, state, &incidents).map_or_else(
            |error| Some(render_class(&error)),
            |omitted| {
                log_omitted(omitted);
                None
            },
        ),
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
