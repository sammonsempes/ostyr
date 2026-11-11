//! Source side of the on-call lifecycle: new alerts of the alert store become on-call alerts, per tenant, from the alert outbox, no cursor.

use crate::alert::{Param, Statement};
use crate::error::{OncallError, SourceError, StoreError};
use crate::holder::validate_holder;
use crate::limits::{
    LEASE_FACTOR, MAX_FINGERPRINT_BYTES, MAX_PURGE_PER_ROUND, MAX_SKIP_PER_POLL, MAX_SOURCE_INTERVAL_SECONDS, MAX_SOURCE_TENANTS,
    MAX_SOURCE_TEXT_CHARS, PURGE_SERVER_TIMEOUT_MILLIS, SEVERITY_COUNT,
};
use crate::model::AlertNotice;
use crate::rows::{cell_int, cell_text};
use crate::store::{run, valid_text};
use crate::types::{AuditPurgeFn, LiveSettingsFn, NowFn, PurgedCounts, ReportFn, Row, TenantOutcome, WaitFn};
use crate::validate::{check_between, check_name};
use alerts::error::StoreError as AlertsError;
use alerts::model::{Alert as SourceAlert, Severity};
use alerts::store::{alert_from_row, MAX_PAGE_SIZE};
use alerts::types::{Executor as AlertsExecutor, Row as AlertsRow};
use chrono::{DateTime, Utc};
use core_config::parse::parse_document;
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;
use tracing::warn;


pub const COLUMN_HOST: usize = 2;


pub const COLUMN_USER: usize = 3;


/// SQLSTATE of a statement the server cancelled for its `statement_timeout`.
pub const STATEMENT_CANCELLED: &str = "57014";


pub const FINGERPRINT_PREFIX: &str = "alert:";


/// Params: `$2` limit, `$3` the tenant's `added_at` (epoch if none): rows queued since, in arrival order, joined to alerts (`GET_SQL` columns).
pub const UNRECORDED_SQL: &str = "SELECT a.id, a.rule_id, a.rule_title, a.severity, a.event_time, a.created::text, COALESCE(a.host_name, ''), \
    COALESCE(a.user_name, ''), a.event_ids::text, a.summary, a.summary_truncated::text, a.summary_original_bytes::text \
    FROM alert_outbox o JOIN alerts a ON a.tenant = o.tenant AND a.id = o.id \
    WHERE o.tenant = $1 AND o.queued_at >= LEAST($3::text::timestamptz, now()) ORDER BY o.seq LIMIT $2::text::bigint";


/// One transaction: opens the alert unless its source alert is recorded or a live one has the key, stores details, consumes the outbox row; answers (opened, already).
pub const RECORD_SQL: &str = "WITH already AS (SELECT 1 FROM oncall_alert_details WHERE tenant = $1 AND source_alert = $8::text), \
    new_alert AS (INSERT INTO oncall_alerts (tenant, fingerprint, state, opened_at) \
    SELECT $1::text, $2::text, 'open', $3::timestamptz WHERE NOT EXISTS (SELECT 1 FROM already) \
    ON CONFLICT (tenant, fingerprint) WHERE state <> 'resolved' DO NOTHING RETURNING id), \
    detail AS (INSERT INTO oncall_alert_details (tenant, alert, source_alert, severity, title, host, username) \
    SELECT $1::text, id, $8::text, $4::text, $5::text, $6::text, $7::text FROM new_alert \
    ON CONFLICT (tenant, source_alert) DO NOTHING RETURNING alert), \
    consumed AS (DELETE FROM alert_outbox WHERE tenant = $1 AND id = $8::text) \
    SELECT (SELECT count(*) FROM detail), (SELECT count(*) FROM already)";


/// Params: `$2` JSON array of the polled tenants, `$3` limit, `$4` poller id, `$5` margin in milliseconds; `$1` must be a polled tenant. Drops at most `$3` rows of unpolled tenants and only while `$4` holds a lease with more than `$5` ms left (checked inside this statement, the lease row share-locked until the purge ends); answers (tenant, count) rows, or one row with an empty tenant when it does not hold it.
pub const PURGE_SQL: &str = "WITH RECURSIVE held AS (SELECT 1 FROM oncall_poller_lease WHERE holder = $4::text \
    AND expires_at > clock_timestamp() + ($5::text::bigint * interval '1 millisecond') FOR SHARE), \
    seen(tenant) AS (SELECT min(tenant) FROM alert_outbox UNION ALL \
    SELECT (SELECT min(o.tenant) FROM alert_outbox o WHERE o.tenant > seen.tenant) FROM seen WHERE seen.tenant IS NOT NULL), \
    unpolled AS (SELECT tenant FROM seen WHERE tenant IS NOT NULL AND $1::text = ANY(ARRAY(SELECT jsonb_array_elements_text($2::text::jsonb))) \
    AND tenant <> ALL(ARRAY(SELECT jsonb_array_elements_text($2::text::jsonb))) AND EXISTS (SELECT 1 FROM held)), \
    gone AS (DELETE FROM alert_outbox WHERE EXISTS (SELECT 1 FROM held) AND ctid IN (SELECT o.ctid FROM unpolled u \
    CROSS JOIN LATERAL (SELECT ctid FROM alert_outbox WHERE tenant = u.tenant ORDER BY seq LIMIT $3::text::bigint FOR UPDATE SKIP LOCKED) o LIMIT $3::text::bigint) RETURNING tenant) \
    SELECT tenant, count(*)::text FROM gone GROUP BY tenant UNION ALL SELECT '', '0' WHERE NOT EXISTS (SELECT 1 FROM held) ORDER BY 1";


/// Params: `$2` the tenant's `added_at`, `$3` limit. Consumes the tenant's outbox rows queued before `added_at` (never later than now); answers the number consumed.
pub const SKIP_SQL: &str = "WITH gone AS (DELETE FROM alert_outbox WHERE tenant = $1 AND id IN (SELECT id FROM alert_outbox \
    WHERE tenant = $1 AND queued_at < LEAST($2::text::timestamptz, now()) ORDER BY queued_at LIMIT $3::text::bigint) RETURNING 1) \
    SELECT count(*)::text FROM gone";


/// Params: `$2` poller id, `$3` lease seconds; `$1` is only the scope. Takes or renews the lease unless another poller holds it; one row means held.
pub const LEASE_SQL: &str = "INSERT INTO oncall_poller_lease AS lease (singleton, holder, expires_at) \
    SELECT true, $2::text, now() + ($3::bigint * interval '1 second') WHERE $1::text IS NOT NULL \
    ON CONFLICT (singleton) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at \
    WHERE lease.holder = EXCLUDED.holder OR lease.expires_at < now() RETURNING true";


/// Params: `$2` on-call alert id.
pub const DETAILS_SQL: &str =
    "SELECT severity, title, COALESCE(host, ''), COALESCE(username, '') FROM oncall_alert_details WHERE tenant = $1 AND alert = $2";


/// `severity_map` sends each severity (all five required) to an on-call name; `added_at` is when a tenant was added, never later than the load time (its older outbox rows are skipped).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSettings {
    pub tenants: Vec<String>,
    pub max_per_poll: usize,
    pub interval_seconds: u64,
    pub severity_map: BTreeMap<String, String>,
    #[serde(default)]
    pub added_at: BTreeMap<String, DateTime<Utc>>,
}


/// What one poll or one record did: new on-call alerts, alerts already recorded, alerts whose key a live on-call alert held, backlog rows skipped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenantCounts {
    pub opened: usize,
    pub already: usize,
    pub conflict: usize,
    pub skipped_backlog: usize,
}


/// One round: lease state at the last renewal, each tenant outcome, rows purged per unpolled tenant (a tenant with none is absent).
#[derive(Debug)]
pub struct Round {
    pub leased: Result<bool, SourceError>,
    pub purged: Result<PurgedCounts, SourceError>,
    pub outcomes: Vec<TenantOutcome>,
}


/// The injected clock, sleep, report and purge audit (called once per round that purged something) of `run_rounds`.
#[derive(Clone, Copy)]
pub struct RoundHooks<'audit> {
    pub now: NowFn,
    pub wait: WaitFn,
    pub report: ReportFn,
    pub audit_purge: AuditPurgeFn<'audit>,
}


/// The bounded, control-free alert text kept for notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDetails {
    pub severity: String,
    pub title: String,
    pub host: Option<String>,
    pub user: Option<String>,
}


pub fn invalid(field: &'static str) -> OncallError {
    OncallError::InvalidSetting { field }
}


pub fn validate_severity_map(map: &BTreeMap<String, String>) -> Result<(), OncallError> {
    check_between("severity_map", map.len() as u64, SEVERITY_COUNT as u64, SEVERITY_COUNT as u64)?;
    map.keys()
        .try_for_each(|key| key.parse::<Severity>().map(|_known| ()).map_err(|_unknown| invalid("severity_map key")))?;
    map.values().try_for_each(|name| {
        check_name("severity_map value", name)?;
        if name.chars().any(char::is_control) {
            Err(invalid("severity_map value"))
        } else {
            Ok(())
        }
    })
}


pub fn validate_source_settings(settings: &SourceSettings, now: DateTime<Utc>) -> Result<(), OncallError> {
    check_between("source tenants", settings.tenants.len() as u64, 1, MAX_SOURCE_TENANTS)?;
    check_between("max_per_poll", settings.max_per_poll as u64, 1, MAX_PAGE_SIZE as u64)?;
    check_between("interval_seconds", settings.interval_seconds, 1, MAX_SOURCE_INTERVAL_SECONDS)?;
    validate_severity_map(&settings.severity_map)?;
    settings
        .tenants
        .iter()
        .try_for_each(|tenant| tenant_scope(tenant).map(|_scope| ()).map_err(|_bad| invalid("source tenant")))?;
    let distinct: BTreeSet<&String> = settings.tenants.iter().collect();
    if distinct.len() != settings.tenants.len() || !settings.added_at.keys().all(|tenant| distinct.contains(tenant)) {
        Err(invalid("source tenant"))
    } else if settings.added_at.values().any(|added| *added > now) {
        Err(invalid("added_at"))
    } else {
        Ok(())
    }
}


pub fn parse_source_settings(text: &str, file: &str, now: DateTime<Utc>) -> Result<SourceSettings, OncallError> {
    let settings: SourceSettings = parse_document(text, file)?;
    validate_source_settings(&settings, now)?;
    Ok(settings)
}


pub fn map_severity(settings: &SourceSettings, severity: Severity) -> Result<&str, SourceError> {
    let name = severity.to_string();
    settings
        .severity_map
        .get(&name)
        .map(String::as_str)
        .ok_or(SourceError::Unmapped { severity: name })
}


/// Control characters, the Unicode line separators and the bidi and zero-width format characters become spaces; a text over the bound is cut with a visible marker.
pub fn clean_text(text: &str) -> String {
    let total = text.chars().count();
    let cleaned = text.chars().map(|character| {
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'..='\u{200F}' | '\u{061C}' | '\u{FEFF}') {
            ' '
        } else {
            character
        }
    });
    if total > MAX_SOURCE_TEXT_CHARS {
        let kept: String = cleaned.take(MAX_SOURCE_TEXT_CHARS).collect();
        format!("{kept}[cut, {total} chars]")
    } else {
        cleaned.collect()
    }
}


pub fn optional_text(text: &Option<String>) -> Param {
    Param::OptText(text.as_deref().map(clean_text))
}


/// Records one alert, its details and the outbox consumption in one statement; answers which of opened, already or conflict (a held key, logged) it was.
pub async fn record_alert<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    settings: &SourceSettings,
    alert: &SourceAlert,
    now: DateTime<Utc>,
) -> Result<TenantCounts, SourceError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let fingerprint = format!("{FINGERPRINT_PREFIX}{}", alert.id);
    if !valid_text(&fingerprint, MAX_FINGERPRINT_BYTES) {
        Err(StoreError::InvalidFingerprint { max: MAX_FINGERPRINT_BYTES }.into())
    } else {
        let severity = map_severity(settings, alert.severity)?.to_owned();
        let params = vec![
            Param::Text(fingerprint),
            Param::Time(Some(now)),
            Param::Text(severity),
            Param::Text(clean_text(&alert.rule_title)),
            optional_text(&alert.host_name),
            optional_text(&alert.user_name),
            Param::Text(alert.id.clone()),
        ];
        let rows = run(exec, scope, RECORD_SQL, params).await?;
        let row = rows.first().ok_or(StoreError::NotFound)?;
        let opened = cell_int(row, 0, "recorded")?;
        let already = cell_int(row, 1, "already")?;
        let conflict = opened == 0 && already == 0;
        if conflict {
            warn!("an alert key is held by a live on-call alert without details; the outbox row was consumed");
        }
        Ok(TenantCounts {
            opened: usize::from(opened > 0),
            already: usize::from(already > 0),
            conflict: usize::from(conflict),
            skipped_backlog: 0,
        })
    }
}


pub fn add_counts(total: TenantCounts, more: TenantCounts) -> TenantCounts {
    TenantCounts {
        opened: total.opened + more.opened,
        already: total.already + more.already,
        conflict: total.conflict + more.conflict,
        skipped_backlog: total.skipped_backlog + more.skipped_backlog,
    }
}


pub fn count_answer(rows: &[AlertsRow]) -> Result<usize, AlertsError> {
    let cell = rows.first().and_then(|row| row.first()).ok_or(AlertsError::BadRow { column: 0 })?;
    cell.parse::<usize>().map_err(|_bad| AlertsError::BadRow { column: 0 })
}


/// The two statements of one purge transaction, in order: `SET LOCAL statement_timeout` (`PURGE_SERVER_TIMEOUT_MILLIS`) and `PURGE_SQL`; a service executor runs both in one transaction.
pub fn purge_statements() -> (String, String) {
    (
        format!("SET LOCAL statement_timeout = {PURGE_SERVER_TIMEOUT_MILLIS}"),
        PURGE_SQL.to_owned(),
    )
}


/// A purge the server cancelled (SQLSTATE 57014) or the client gave up on.
pub fn purge_error(error: AlertsError) -> SourceError {
    match error {
        AlertsError::Pg(PgError::Server { code, .. }) if code == STATEMENT_CANCELLED => SourceError::PurgeDeadline,
        AlertsError::Pg(PgError::StatementTimeout { .. }) => SourceError::PurgeDeadline,
        other => SourceError::Alerts(other),
    }
}


/// Drops, at most `MAX_PURGE_PER_ROUND` rows, the outbox rows of tenants this poller does not serve, while `holder` holds the lease (checked by the statement itself); `None` when it does not.
pub async fn purge_unpolled(
    alerts_exec: AlertsExecutor<'_, '_>,
    settings: &SourceSettings,
    holder: &str,
) -> Result<Option<PurgedCounts>, SourceError> {
    validate_holder(holder)?;
    let first = settings.tenants.first().ok_or(SourceError::NoTenants)?;
    let polled = serde_json::Value::from(settings.tenants.clone()).to_string();
    let params = vec![
        polled,
        MAX_PURGE_PER_ROUND.to_string(),
        holder.to_owned(),
        PURGE_SERVER_TIMEOUT_MILLIS.to_string(),
    ];
    let rows = alerts_exec(tenant_scope(first)?, PURGE_SQL, params)
        .await
        .map_err(|error| purge_error(AlertsError::from(error)))?;
    let lost = rows.iter().any(|row| row.first().is_some_and(String::is_empty));
    if lost {
        Ok(None)
    } else {
        Ok(Some(purged_counts(&rows)?))
    }
}


/// Decodes (tenant, count) rows; a tenant name the grammar refuses is a bad row, so no foreign text reaches a report or the audit.
pub fn purged_counts(rows: &[AlertsRow]) -> Result<PurgedCounts, AlertsError> {
    rows.iter()
        .map(|row| {
            let tenant = row
                .first()
                .filter(|name| tenant_scope(name).is_ok())
                .ok_or(AlertsError::BadRow { column: 0 })?;
            let count = row
                .get(1)
                .and_then(|cell| cell.parse::<usize>().ok())
                .ok_or(AlertsError::BadRow { column: 1 })?;
            Ok((tenant.clone(), count))
        })
        .collect()
}


/// Consumes, at most `MAX_SKIP_PER_POLL` rows, the tenant's outbox rows queued before its `added_at`, if it has one.
pub async fn skip_backlog(
    alerts_exec: AlertsExecutor<'_, '_>,
    settings: &SourceSettings,
    scope: &TenantScope,
    tenant: &str,
) -> Result<usize, SourceError> {
    match settings.added_at.get(tenant) {
        Some(added) => {
            let rows = alerts_exec(scope.clone(), SKIP_SQL, vec![added.to_rfc3339(), MAX_SKIP_PER_POLL.to_string()])
                .await
                .map_err(AlertsError::from)?;
            Ok(count_answer(&rows)?)
        }
        None => Ok(0),
    }
}


/// One poll of one tenant: at most `max_per_poll` alerts queued since its `added_at`, whatever backlog is left to skip, under that tenant's scope only.
pub async fn poll_tenant<Executor, Pending>(
    alerts_exec: AlertsExecutor<'_, '_>,
    exec: &mut Executor,
    settings: &SourceSettings,
    tenant: &str,
    now: DateTime<Utc>,
) -> Result<TenantCounts, SourceError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let scope = tenant_scope(tenant)?;
    let skipped_backlog = skip_backlog(alerts_exec, settings, &scope, tenant).await?;
    let since = settings.added_at.get(tenant).copied().unwrap_or(DateTime::<Utc>::UNIX_EPOCH).to_rfc3339();
    let rows = alerts_exec(scope.clone(), UNRECORDED_SQL, vec![settings.max_per_poll.to_string(), since])
        .await
        .map_err(AlertsError::from)?;
    let unrecorded = rows
        .iter()
        .map(|row| alert_from_row(&scope, row))
        .collect::<Result<Vec<SourceAlert>, AlertsError>>()?;
    let mut counts = TenantCounts {
        skipped_backlog,
        ..TenantCounts::default()
    };
    for alert in unrecorded.iter().take(settings.max_per_poll) {
        counts = add_counts(counts, record_alert(exec, &scope, settings, alert, now).await?);
    }
    Ok(counts)
}


/// Takes or renews the single poller lease (`LEASE_FACTOR` times the interval); false when another poller holds it. Runs under the first polled tenant's scope.
pub async fn take_lease<Executor, Pending>(exec: &mut Executor, settings: &SourceSettings, holder: &str) -> Result<bool, SourceError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    validate_holder(holder)?;
    let first = settings.tenants.first().ok_or(SourceError::NoTenants)?;
    let seconds =
        i64::try_from(settings.interval_seconds.saturating_mul(LEASE_FACTOR)).map_err(|_big| StoreError::BadRow { column: "lease seconds" })?;
    let params = vec![Param::Text(holder.to_owned()), Param::Int(seconds)];
    let rows = run(exec, &tenant_scope(first)?, LEASE_SQL, params).await?;
    Ok(!rows.is_empty())
}


/// Lease first, renewed before every further tenant and the purge; a poller that loses it stops there, purge included. The purge uses `live()`, read just before it, and the statement re-checks the lease itself.
pub async fn poll_all<Executor, Pending>(
    alerts_exec: AlertsExecutor<'_, '_>,
    exec: &mut Executor,
    settings: &SourceSettings,
    holder: &str,
    now: NowFn,
    live: LiveSettingsFn<'_>,
) -> Round
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let mut leased = take_lease(exec, settings, holder).await;
    let mut outcomes = Vec::with_capacity(settings.tenants.len());
    for (index, tenant) in settings.tenants.iter().enumerate() {
        if index > 0 && matches!(leased, Ok(true)) {
            leased = take_lease(exec, settings, holder).await;
        }
        if matches!(leased, Ok(true)) {
            outcomes.push((tenant.clone(), poll_tenant(alerts_exec, exec, settings, tenant, now()).await));
        }
    }
    if matches!(leased, Ok(true)) {
        leased = take_lease(exec, settings, holder).await;
    }
    let purged = if matches!(leased, Ok(true)) {
        let current = live();
        match purge_unpolled(alerts_exec, &current, holder).await {
            Ok(Some(counts)) => Ok(counts),
            Ok(None) => {
                leased = Ok(false);
                Ok(PurgedCounts::new())
            }
            Err(error) => Err(error),
        }
    } else {
        Ok(PurgedCounts::new())
    };
    Round { leased, purged, outcomes }
}


/// `rounds` polls, each on the snapshot `live()` returns at its start, `report` after each and `wait` for the interval between them; a poller that lost the lease logs it once, until it holds it again.
pub async fn run_rounds<Executor, Pending>(
    rounds: usize,
    alerts_exec: AlertsExecutor<'_, '_>,
    exec: &mut Executor,
    holder: &str,
    hooks: &RoundHooks<'_>,
    live: LiveSettingsFn<'_>,
) where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let mut warned = false;
    for _round in 0..rounds {
        let settings = live();
        let round = poll_all(alerts_exec, exec, &settings, holder, hooks.now, live).await;
        if matches!(round.leased, Ok(false)) && !warned {
            warn!("another on-call poller holds the lease: this poller does nothing until it expires");
        }
        warned = matches!(round.leased, Ok(false));
        if let Some(counts) = round.purged.as_ref().ok().filter(|counts| !counts.is_empty()) {
            warn!("outbox rows of tenants outside this poller's `tenants` were dropped");
            (hooks.audit_purge)(counts);
        }
        (hooks.report)(&round);
        (hooks.wait)(Duration::from_secs(settings.interval_seconds)).await;
    }
}


pub fn non_empty(text: &str) -> Option<String> {
    (!text.is_empty()).then(|| text.to_owned())
}


pub async fn source_details<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, alert: i64) -> Result<Option<SourceDetails>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let rows = run(exec, scope, DETAILS_SQL, vec![Param::Int(alert)]).await?;
    rows.first()
        .map(|row| {
            Ok(SourceDetails {
                severity: cell_text(row, 0, "severity")?.to_owned(),
                title: cell_text(row, 1, "title")?.to_owned(),
                host: non_empty(cell_text(row, COLUMN_HOST, "host")?),
                user: non_empty(cell_text(row, COLUMN_USER, "username")?),
            })
        })
        .transpose()
}


/// The notice that goes through `render`, which does the per-channel escaping: no alert text reaches a channel any other way.
pub fn alert_notice(tenant: &str, details: &SourceDetails) -> AlertNotice {
    let labels = std::iter::once(("severity".to_owned(), details.severity.clone()))
        .chain(details.host.iter().map(|host| ("host".to_owned(), host.clone())))
        .chain(details.user.iter().map(|user| ("user".to_owned(), user.clone())))
        .collect();
    AlertNotice {
        tenant: tenant.to_owned(),
        name: details.title.clone(),
        labels,
        annotations: BTreeMap::new(),
    }
}
