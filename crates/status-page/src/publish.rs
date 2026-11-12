use crate::error::{StatusPageError, StoreError};
use crate::model::{IncidentInput, Omitted, PageConfig, PageState, RenderedPage, DEFAULT_LIMITS};
use crate::render::render_omitting;
use crate::snapshot::{publish, snapshot_of};
use crate::store_model::PublishedRead;
use crate::types::IncidentReadFn;
use core_pg::scope::TenantScope;
use futures_util::StreamExt;
use std::cmp::Reverse;
use std::collections::BTreeSet;
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
pub async fn fetch(read: &IncidentReadFn, scope: &TenantScope, deadline: Duration) -> Result<PublishedRead, StoreError> {
    timeout(deadline, read(scope.clone())).await.map_err(|_elapsed| StoreError::ReadTimeout)?
}


pub const MAX_FIT_ATTEMPTS: u32 = 6;


/// Renders per tick at most: the halving attempts, then unresolved only, then the empty page.
pub const MAX_RENDERS_PER_TICK: u32 = MAX_FIT_ATTEMPTS + 2;


/// Why the page leaves incidents out, by precedence: the size fit, the read limit, then services no component declares.
pub fn omission_reason(size_cut: bool, beyond_read: usize) -> &'static str {
    if size_cut {
        "size"
    } else if beyond_read > 0 {
        "read_limit"
    } else {
        "undeclared"
    }
}


/// Fits the page: unresolved stay, the resolved set is halved per attempt; returns what it leaves out, rows beyond the limit and undeclared ones included.
pub fn fit_page(config: &PageConfig, read: &PublishedRead) -> Result<(RenderedPage, Omitted), StatusPageError> {
    let declared: BTreeSet<&str> = config.components.iter().map(|component| component.service.as_str()).collect();
    let (published_all, unpublished): (Vec<IncidentInput>, Vec<IncidentInput>) =
        read.incidents.iter().cloned().partition(|incident| incident.published);
    let (mut published, undeclared): (Vec<IncidentInput>, Vec<IncidentInput>) = published_all
        .iter()
        .cloned()
        .partition(|incident| declared.contains(incident.service.as_str()));
    published.sort_by_key(|incident| {
        (
            incident.resolved_at.is_some(),
            Reverse(incident.resolved_at),
            Reverse(incident.started_at),
        )
    });
    let unresolved = published.iter().filter(|incident| incident.resolved_at.is_none()).count();
    let resolved = published.len() - unresolved;
    let total = read.total.max(published_all.len());
    let ongoing = read
        .ongoing
        .max(published_all.iter().filter(|incident| incident.resolved_at.is_none()).count());
    let beyond_read = total - published_all.len();
    let kept_counts = (0..MAX_FIT_ATTEMPTS)
        .map(|attempt| unresolved + (resolved >> attempt))
        .chain([unresolved, 0]);
    kept_counts
        .map(|kept| {
            let subset: Vec<IncidentInput> = published
                .iter()
                .take(kept)
                .chain(undeclared.iter())
                .chain(unpublished.iter())
                .cloned()
                .collect();
            let omitted = Omitted {
                all: total - kept,
                ongoing: ongoing - kept.min(unresolved),
                undeclared: undeclared.len(),
                reason: omission_reason(kept < published.len(), beyond_read),
            };
            (render_omitting(config, &[], &subset, &[], 0, &DEFAULT_LIMITS, omitted), omitted)
        })
        .find(|(rendered, _omitted)| !matches!(rendered, Err(StatusPageError::OutputTooLarge { .. })))
        .ok_or(StatusPageError::OutputTooLarge {
            format: "json",
            limit: DEFAULT_LIMITS.max_json_bytes,
        })
        .and_then(|(rendered, omitted)| rendered.map(|page| (page, omitted)))
}


/// Every component is `unknown` (no state is passed) until the checks feed is wired; returns what the page left out.
pub fn publish_page(config: &PageConfig, state: &PageState, read: &PublishedRead) -> Result<Omitted, StatusPageError> {
    let (rendered, omitted) = fit_page(config, read)?;
    publish(state, snapshot_of(&config.tenant, &rendered)).map(|()| omitted)
}


/// The page before `serve` accepts: a failed read or render gives a page without incidents, never a missing one.
pub async fn first_publish(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope) -> Result<(), StatusPageError> {
    let fetched = fetch(read, scope, READ_DEADLINE).await.unwrap_or_else(|error| {
        let class = error_class(&error);
        tracing::warn!(class, "first incident read failed");
        PublishedRead::default()
    });
    let omitted = publish_page(config, state, &fetched).or_else(|error| {
        let class = render_class(&error);
        tracing::warn!(class, "first render failed, publishing without incidents");
        publish_page(config, state, &PublishedRead::default())
    })?;
    log_omitted(state, omitted);
    Ok(())
}


/// A fixed label for a failed render.
pub fn render_class(error: &StatusPageError) -> &'static str {
    match error {
        StatusPageError::TenantMismatch => "tenant",
        _ => "render",
    }
}


/// True when what the page leaves out differs from the previous tick and something is left out; remembers it.
pub fn omission_changed(state: &PageState, counts: (usize, usize)) -> bool {
    let (omitted, ongoing) = counts;
    let seen = (
        state.omitted_seen.swap(omitted, Ordering::SeqCst),
        state.omitted_ongoing_seen.swap(ongoing, Ordering::SeqCst),
    );
    omitted > 0 && seen != counts
}


/// Logs once per change of what the page leaves out, not at every tick.
pub fn log_omitted(state: &PageState, left_out: Omitted) {
    let (omitted, ongoing, reason) = (left_out.all, left_out.ongoing, left_out.reason);
    if omission_changed(state, (omitted, ongoing)) {
        tracing::warn!(omitted, ongoing, reason, "incidents left out of the page");
    }
}


/// A failed read or render keeps the snapshot already served and logs the error class only.
pub async fn tick(config: &PageConfig, state: &PageState, read: &IncidentReadFn, scope: &TenantScope) {
    let failed = match fetch(read, scope, READ_DEADLINE).await {
        Ok(fetched) => publish_page(config, state, &fetched).map_or_else(
            |error| Some(render_class(&error)),
            |omitted| {
                log_omitted(state, omitted);
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
