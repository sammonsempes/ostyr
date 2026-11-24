//! Retro-match groups as alerts of the alert store: one insert per run, ids derived by the store's own rule, text bounded and escaped.

use crate::limits::{NANOS_PER_MICRO, RETRO_HOST_CHARS};
use crate::retro::{Direction, MatchGroup, RetroRun, RetroSettings, RetroSummary};
use crate::sample::{bounded_text, is_unsafe_char, BLANK_LETTERS};
use crate::types::AlertInsertFn;
use alerts::error::StoreError;
use alerts::id::{absorb, alert_id};
use alerts::model::{Alert, Severity};
use alerts::store::{check_alert, summarise};
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use tracing::{info, warn};


pub const RETRO_RULE_ID: &str = "intel.retro_match.ip";


pub const TRUNCATED_RULE_ID: &str = "intel.retro_match.truncated";


pub const RETRO_TITLE: &str = "Threat intelligence indicator matched stored events";


pub const TRUNCATED_TITLE: &str = "Threat intelligence retro match truncated";


pub const RETRO_SEVERITY: Severity = Severity::Medium;


#[derive(Debug, Error)]
pub enum BuildError {
    #[error("a time cannot be written as RFC 3339")]
    Time(#[source] time::error::Format),
    #[error("a time is outside the supported UTC range")]
    Range,
}


#[derive(Debug, Error)]
pub enum AlertsError {
    #[error("the retro tenant is not a valid tenant name")]
    Tenant(#[source] PgError),
    #[error("the clock is before the epoch or beyond the alert time range")]
    Clock,
    #[error("the alert insert failed")]
    Insert(#[source] StoreError),
}


/// `refused` alerts failed a build or `check_alert` and were skipped (`alert_refused`); `inserted` of `built` were new, the other `known` were already stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreReport {
    pub built: usize,
    pub refused: usize,
    pub inserted: usize,
    pub known: usize,
    pub truncated_alert: bool,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub alerts: Vec<Alert>,
    pub refused: usize,
}


pub fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Source => "source",
        Direction::Destination => "destination",
    }
}


/// `retro:` plus SHA-256 over the length-prefixed tenant, indicator, matched IP text, direction, cut host and UTC event day: the same group on a rerun is the same alert.
pub fn event_id_of(group: &MatchGroup) -> String {
    let mut hasher = Sha256::new();
    let day = group.event_day.to_string();
    [
        group.tenant.as_str(),
        group.indicator.as_str(),
        group.matched_ip.as_str(),
        direction_name(group.direction),
        group.host.as_str(),
        day.as_str(),
    ]
    .into_iter()
    .for_each(|part| absorb(&mut hasher, part));
    format!("retro:{:x}", hasher.finalize())
}


/// Unsafe and blank-rendering characters escaped (the first as `sample::bounded_text` does), then at most `RETRO_HOST_CHARS` characters of the result on a whole-escape boundary; the flag says a cut happened.
pub fn escaped_host(host: &str) -> (String, bool) {
    let pieces: Vec<String> = host
        .chars()
        .map(|character| {
            if is_unsafe_char(character) || BLANK_LETTERS.contains(&character) {
                character.escape_unicode().to_string()
            } else {
                character.to_string()
            }
        })
        .collect();
    let kept: Vec<&String> = pieces
        .iter()
        .scan(0, |used, piece| {
            *used += piece.chars().count();
            Some((*used, piece))
        })
        .take_while(|(used, _piece)| *used <= RETRO_HOST_CHARS)
        .map(|(_used, piece)| piece)
        .collect();
    (kept.iter().map(|piece| piece.as_str()).collect(), kept.len() < pieces.len())
}


pub fn rfc3339(time: OffsetDateTime) -> Result<String, BuildError> {
    time.format(&Rfc3339).map_err(BuildError::Time)
}


/// The group as an alert: a fixed title, the indicator, feed, TLP, count and times only in the summary, the cut and escaped host as the host.
pub fn alert_of(group: &MatchGroup, now_micros: u64) -> Result<Alert, BuildError> {
    let first = rfc3339(group.first_time)?;
    let last = rfc3339(group.last_time)?;
    let (host, escaped_cut) = escaped_host(&group.host);
    let event_ids = vec![event_id_of(group)];
    Ok(Alert {
        id: alert_id(&group.tenant, RETRO_RULE_ID, &event_ids),
        tenant: group.tenant.clone(),
        rule_id: RETRO_RULE_ID.to_owned(),
        rule_title: RETRO_TITLE.to_owned(),
        severity: RETRO_SEVERITY,
        event_time: first.clone(),
        created_micros: now_micros,
        host_name: Some(host).filter(|text| !text.is_empty()),
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "indicator": bounded_text(&group.indicator),
            "feed": bounded_text(&group.feed),
            "tlp": bounded_text(&group.tlp),
            "matched_ip": group.matched_ip,
            "direction": direction_name(group.direction),
            "matches": group.matches,
            "first_time": first,
            "last_time": last,
            "event_day": group.event_day.to_string(),
            "host_cut": group.host_cut || escaped_cut,
        })),
    })
}


/// One alert per UTC day of the window start: `retro-truncated:<day>`, so repeated truncated runs of one day stay one alert (the first insert wins).
pub fn truncated_alert(summary: &RetroSummary, now_micros: u64) -> Result<Alert, BuildError> {
    let start = summary.window_start.checked_to_offset(UtcOffset::UTC).ok_or(BuildError::Range)?;
    let event_ids = vec![format!("retro-truncated:{}", start.date())];
    Ok(Alert {
        id: alert_id(&summary.tenant, TRUNCATED_RULE_ID, &event_ids),
        tenant: summary.tenant.clone(),
        rule_id: TRUNCATED_RULE_ID.to_owned(),
        rule_title: TRUNCATED_TITLE.to_owned(),
        severity: RETRO_SEVERITY,
        event_time: rfc3339(start)?,
        created_micros: now_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "more_than": summary.more_than,
            "window_start": rfc3339(summary.window_start)?,
            "window_end": rfc3339(summary.window_end)?,
        })),
    })
}


/// A build or `check_alert` refusal is the fixed text of its error, never alert content.
pub fn checked(scope: &TenantScope, candidate: Result<Alert, BuildError>) -> Result<Alert, String> {
    let alert = candidate.map_err(|error| error.to_string())?;
    check_alert(scope, &alert).map_err(|error| error.to_string())?;
    Ok(alert)
}


/// Every alert goes through `check_alert` first; a refused one is skipped, counted and logged by its error's fixed text, the rest are kept, sorted by id and distinct.
pub fn build_alerts(scope: &TenantScope, run: &RetroRun, now_micros: u64) -> Built {
    let candidates = run
        .groups
        .iter()
        .map(|group| alert_of(group, now_micros))
        .chain(run.summary.truncated.then(|| truncated_alert(&run.summary, now_micros)));
    let results: Vec<Result<Alert, String>> = candidates.map(|candidate| checked(scope, candidate)).collect();
    let refused = results.iter().filter(|result| result.is_err()).count();
    results
        .iter()
        .filter_map(|result| result.as_ref().err())
        .for_each(|reason| warn!(reason, "alert_refused"));
    let mut alerts: Vec<Alert> = results.into_iter().filter_map(Result::ok).collect();
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    alerts.dedup_by(|right, left| right.id == left.id);
    Built { alerts, refused }
}


pub fn micros_of(now: OffsetDateTime) -> Result<u64, AlertsError> {
    u64::try_from(now.unix_timestamp_nanos() / NANOS_PER_MICRO).map_err(|_| AlertsError::Clock)
}


/// The whole run in one `insert` call under the scope of the run's own tenant ("inserted N of M, M-N already known"; the first insert of an id wins, a later larger count is not written back).
pub fn store_run(settings: &RetroSettings, run: &RetroRun, now: OffsetDateTime, insert: &AlertInsertFn) -> Result<StoreReport, AlertsError> {
    let scope = tenant_scope(&settings.reader.tenant).map_err(AlertsError::Tenant)?;
    let built = build_alerts(&scope, run, micros_of(now)?);
    let inserted = insert(&scope, &built.alerts).map_err(AlertsError::Insert)?;
    let report = StoreReport {
        built: built.alerts.len(),
        refused: built.refused,
        inserted,
        known: built.alerts.len().saturating_sub(inserted),
        truncated_alert: run.summary.truncated,
    };
    let (built_count, refused, known) = (report.built, report.refused, report.known);
    info!(inserted, built_count, known, refused, "retro alerts stored");
    Ok(report)
}
