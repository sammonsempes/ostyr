use crate::alert::{Alert, Event, FailureReason, LifecycleState, Opened, Outcome, Param, Phase, Statement};
use crate::error::StoreError;
use crate::lifecycle::transition;
use crate::limits::{MAX_CHANNEL_NAME_BYTES, MAX_FINGERPRINT_BYTES, MAX_OPEN_ALERTS};
use crate::rows::{cell_bool, cell_int, decode_alert, phase_name, COL_CREATED};
use crate::types::Row;
use chrono::{DateTime, Utc};
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;
use std::future::Future;


pub const MIGRATION_NAMESPACE: &str = "oncall";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "oncall_0001",
    sql: include_str!("../migrations/oncall_0001.sql"),
}];


/// Params: `$2` fingerprint, `$3` now. A live alert with the same fingerprint is reused and its counter incremented.
pub const OPEN_SQL: &str = "INSERT INTO oncall_alerts (tenant, fingerprint, state, opened_at) VALUES ($1, $2, 'open', $3) \
    ON CONFLICT (tenant, fingerprint) WHERE state <> 'resolved' DO UPDATE SET occurrences = oncall_alerts.occurrences + 1 \
    RETURNING id, fingerprint, state, level, occurrences, version, opened_at, acknowledged_at, resolved_at, (xmax = 0)";


/// Params: `$2` alert id.
pub const GET_SQL: &str = "SELECT id, fingerprint, state, level, occurrences, version, opened_at, acknowledged_at, resolved_at \
    FROM oncall_alerts WHERE tenant = $1 AND id = $2";


/// Params: `$2` id, `$3` state, `$4` level, `$5` acknowledged_at, `$6` resolved_at, `$7` expected version.
pub const UPDATE_SQL: &str = "UPDATE oncall_alerts SET state = $3, level = $4, acknowledged_at = $5, resolved_at = $6, version = version + 1 \
    WHERE tenant = $1 AND id = $2 AND version = $7 \
    RETURNING id, fingerprint, state, level, occurrences, version, opened_at, acknowledged_at, resolved_at";


/// Params: `$2` limit.
pub const LIST_SQL: &str = "SELECT id, fingerprint, state, level, occurrences, version, opened_at, acknowledged_at, resolved_at \
    FROM oncall_alerts WHERE tenant = $1 AND state <> 'resolved' ORDER BY opened_at, id LIMIT $2";


/// Params: `$2` alert id, `$3` channel, `$4` outcome, `$5` reason, `$6` at. No row when the alert is not the tenant's.
pub const NOTIFY_SQL: &str = "INSERT INTO oncall_notifications (tenant, alert, channel, outcome, reason, at) \
    SELECT $1, id, $3::text, $4::text, $5::text, $6::timestamptz FROM oncall_alerts WHERE tenant = $1 AND id = $2 RETURNING seq";


pub fn valid_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}


pub async fn run<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, sql: &'static str, params: Vec<Param>) -> Result<Vec<Row>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    exec(scope, Statement { sql, params }).await
}


/// An open, acknowledged or escalated alert with this fingerprint is reused; a resolved one gives a new alert.
pub async fn open_alert<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    fingerprint: &str,
    now: DateTime<Utc>,
) -> Result<Opened, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    if !valid_text(fingerprint, MAX_FINGERPRINT_BYTES) {
        Err(StoreError::InvalidFingerprint { max: MAX_FINGERPRINT_BYTES })
    } else {
        let rows = run(exec, scope, OPEN_SQL, vec![Param::Text(fingerprint.to_owned()), Param::Time(Some(now))]).await?;
        let row = rows.first().ok_or(StoreError::NotFound)?;
        Ok(Opened {
            alert: decode_alert(row)?,
            created: cell_bool(row, COL_CREATED, "created")?,
        })
    }
}


pub async fn get_alert<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, id: i64) -> Result<Alert, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let rows = run(exec, scope, GET_SQL, vec![Param::Int(id)]).await?;
    decode_alert(rows.first().ok_or(StoreError::NotFound)?)
}


pub fn timestamps(alert: &Alert, next: LifecycleState, now: DateTime<Utc>) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let acknowledged = if next.phase == Phase::Acknowledged {
        Some(now)
    } else {
        alert.acknowledged_at
    };
    let resolved = if next.phase == Phase::Resolved { Some(now) } else { alert.resolved_at };
    (acknowledged, resolved)
}


/// Reads the alert, applies the pure transition, writes with `version = expected`: a concurrent change is `Conflict`.
pub async fn apply_event<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    id: i64,
    event: Event,
    now: DateTime<Utc>,
) -> Result<Alert, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let alert = get_alert(exec, scope, id).await?;
    let next = transition(alert.state, event)?;
    let (acknowledged, resolved) = timestamps(&alert, next, now);
    let params = vec![
        Param::Int(id),
        Param::Text(phase_name(next.phase).to_owned()),
        Param::Int(i64::from(next.level)),
        Param::Time(acknowledged),
        Param::Time(resolved),
        Param::Int(alert.version),
    ];
    let rows = run(exec, scope, UPDATE_SQL, params).await?;
    decode_alert(rows.first().ok_or(StoreError::Conflict)?)
}


pub const REASON_OTHER_TENANT: &str = "channel belongs to another tenant";


pub const REASON_SENDER_FAILED: &str = "sender failed";


pub const REASON_INVALID_MESSAGE: &str = "invalid channel or message";


pub fn reason_text(reason: FailureReason) -> &'static str {
    match reason {
        FailureReason::OtherTenant => REASON_OTHER_TENANT,
        FailureReason::SenderFailed => REASON_SENDER_FAILED,
        FailureReason::InvalidMessage => REASON_INVALID_MESSAGE,
    }
}


/// Appends one row; a failure is stored as one of the fixed reason texts, never as caller text.
pub async fn record_notification<Executor, Pending>(
    exec: &mut Executor,
    scope: &TenantScope,
    alert: i64,
    channel: &str,
    outcome: &Outcome,
    now: DateTime<Utc>,
) -> Result<i64, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    if !valid_text(channel, MAX_CHANNEL_NAME_BYTES) {
        Err(StoreError::InvalidChannel { max: MAX_CHANNEL_NAME_BYTES })
    } else {
        let (name, reason) = match outcome {
            Outcome::Sent => ("sent", None),
            Outcome::Failed { reason } => ("failed", Some(reason_text(*reason).to_owned())),
        };
        let params = vec![
            Param::Int(alert),
            Param::Text(channel.to_owned()),
            Param::Text(name.to_owned()),
            Param::OptText(reason),
            Param::Time(Some(now)),
        ];
        let rows = run(exec, scope, NOTIFY_SQL, params).await?;
        cell_int(rows.first().ok_or(StoreError::NotFound)?, 0, "seq")
    }
}


/// The oldest unresolved alerts of the tenant, at most `limit`, which itself is at most `MAX_OPEN_ALERTS`.
pub async fn open_alerts<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, limit: u32) -> Result<Vec<Alert>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    if limit == 0 || limit > MAX_OPEN_ALERTS {
        Err(StoreError::LimitOutOfRange { limit, max: MAX_OPEN_ALERTS })
    } else {
        let rows = run(exec, scope, LIST_SQL, vec![Param::Int(i64::from(limit))]).await?;
        rows.iter().map(decode_alert).collect()
    }
}
