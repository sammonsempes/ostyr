//! Source side of the on-call lifecycle: new alerts of the alert store become on-call alerts, per tenant, from the alert outbox, no cursor.

use crate::alert::{Param, Statement};
use crate::error::{OncallError, SourceError, StoreError};
use crate::limits::{MAX_FINGERPRINT_BYTES, MAX_SOURCE_INTERVAL_SECONDS, MAX_SOURCE_TENANTS, MAX_SOURCE_TEXT_CHARS, SEVERITY_COUNT};
use crate::model::AlertNotice;
use crate::rows::{cell_int, cell_text};
use crate::store::{run, valid_text};
use crate::types::{NowFn, ReportFn, Row, TenantOutcome, WaitFn};
use crate::validate::{check_between, check_name};
use alerts::error::StoreError as AlertsError;
use alerts::model::{Alert as SourceAlert, Severity};
use alerts::store::{alert_from_row, MAX_PAGE_SIZE};
use alerts::types::Executor as AlertsExecutor;
use chrono::{DateTime, Utc};
use core_config::parse::parse_document;
use core_pg::scope::{tenant_scope, TenantScope};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::Duration;
use tracing::warn;


pub const COLUMN_HOST: usize = 2;


pub const COLUMN_USER: usize = 3;


pub const FINGERPRINT_PREFIX: &str = "alert:";


/// Params: `$2` limit. The tenant's outbox in arrival order joined to its alerts; the column list is that of `alerts::store::GET_SQL`.
pub const UNRECORDED_SQL: &str = "SELECT a.id, a.rule_id, a.rule_title, a.severity, a.event_time, a.created::text, COALESCE(a.host_name, ''), \
    COALESCE(a.user_name, ''), a.event_ids::text, a.summary, a.summary_truncated::text, a.summary_original_bytes::text \
    FROM alert_outbox o JOIN alerts a ON a.tenant = o.tenant AND a.id = o.id WHERE o.tenant = $1 ORDER BY o.seq LIMIT $2::text::bigint";


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


/// Params: `$2` on-call alert id.
pub const DETAILS_SQL: &str =
    "SELECT severity, title, COALESCE(host, ''), COALESCE(username, '') FROM oncall_alert_details WHERE tenant = $1 AND alert = $2";


/// `severity_map` sends each alert severity (`informational` to `critical`, all five required) to an on-call severity name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSettings {
    pub tenants: Vec<String>,
    pub max_per_poll: usize,
    pub interval_seconds: u64,
    pub severity_map: BTreeMap<String, String>,
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


pub fn validate_source_settings(settings: &SourceSettings) -> Result<(), OncallError> {
    check_between("source tenants", settings.tenants.len() as u64, 1, MAX_SOURCE_TENANTS)?;
    check_between("max_per_poll", settings.max_per_poll as u64, 1, MAX_PAGE_SIZE as u64)?;
    check_between("interval_seconds", settings.interval_seconds, 1, MAX_SOURCE_INTERVAL_SECONDS)?;
    validate_severity_map(&settings.severity_map)?;
    settings
        .tenants
        .iter()
        .try_for_each(|tenant| tenant_scope(tenant).map(|_scope| ()).map_err(|_bad| invalid("source tenant")))?;
    let distinct: BTreeSet<&String> = settings.tenants.iter().collect();
    if distinct.len() == settings.tenants.len() {
        Ok(())
    } else {
        Err(invalid("source tenant"))
    }
}


pub fn parse_source_settings(text: &str, file: &str) -> Result<SourceSettings, OncallError> {
    let settings: SourceSettings = parse_document(text, file)?;
    validate_source_settings(&settings)?;
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


/// Control characters, the Unicode line separators and the bidi format characters become spaces; a text over the bound is cut with a visible marker.
pub fn clean_text(text: &str) -> String {
    let total = text.chars().count();
    let cleaned = text.chars().map(|character| {
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') {
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


/// Records one alert, its details and the outbox consumption in one statement; answers 1 when a new on-call alert was opened, 0 otherwise (a held key is logged).
pub async fn record_alert<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    settings: &SourceSettings,
    alert: &SourceAlert,
    now: DateTime<Utc>,
) -> Result<usize, SourceError>
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
        if opened == 0 && already == 0 {
            warn!("an alert key is held by a live on-call alert without details; the outbox row was consumed");
        }
        Ok(usize::from(opened > 0))
    }
}


/// One poll of one tenant: at most `max_per_poll` alerts of the outbox, read and written under that tenant's scope only.
pub async fn poll_tenant<Executor, Pending>(
    alerts_exec: AlertsExecutor<'_, '_>,
    exec: &mut Executor,
    settings: &SourceSettings,
    tenant: &str,
    now: DateTime<Utc>,
) -> Result<usize, SourceError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let scope = tenant_scope(tenant)?;
    let rows = alerts_exec(scope.clone(), UNRECORDED_SQL, vec![settings.max_per_poll.to_string()])
        .await
        .map_err(AlertsError::from)?;
    let unrecorded = rows
        .iter()
        .map(|row| alert_from_row(&scope, row))
        .collect::<Result<Vec<SourceAlert>, AlertsError>>()?;
    let mut opened = 0;
    for alert in unrecorded.iter().take(settings.max_per_poll) {
        opened += record_alert(exec, &scope, settings, alert, now).await?;
    }
    Ok(opened)
}


/// Every configured tenant once, in order: a failing tenant is reported and the others still run, each capped at `max_per_poll`.
pub async fn poll_all<Executor, Pending>(
    alerts_exec: AlertsExecutor<'_, '_>,
    exec: &mut Executor,
    settings: &SourceSettings,
    now: NowFn,
) -> Vec<TenantOutcome>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let mut outcomes = Vec::with_capacity(settings.tenants.len());
    for tenant in &settings.tenants {
        let outcome = poll_tenant(alerts_exec, exec, settings, tenant, now()).await;
        outcomes.push((tenant.clone(), outcome));
    }
    outcomes
}


/// `rounds` polls, `report` after each and `wait` for the interval between them; the clock and the sleep are injected function pointers.
pub async fn run_rounds<Executor, Pending>(
    rounds: usize,
    alerts_exec: AlertsExecutor<'_, '_>,
    exec: &mut Executor,
    settings: &SourceSettings,
    now: NowFn,
    wait: WaitFn,
    report: ReportFn,
) where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    for _round in 0..rounds {
        let outcomes = poll_all(alerts_exec, exec, settings, now).await;
        report(&outcomes);
        wait(Duration::from_secs(settings.interval_seconds)).await;
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
