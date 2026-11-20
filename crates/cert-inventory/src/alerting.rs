//! Certificate expiry findings as alerts of the alert store (spec section 23).

use crate::expiry::{expiry_state, SECONDS_PER_DAY};
use crate::model::{CertRecord, ExpiryState};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;
use time::{Date, OffsetDateTime};


pub const EXPIRY_RULE_ID: &str = "cert.expiry";


pub const NEAR_DAYS: u32 = 30;


pub const MAX_DNS_NAME_BYTES: usize = 253;


pub const MAX_LABEL_BYTES: usize = 63;


pub const SHA256_HEX_LENGTH: usize = 64;


pub const FINGERPRINT_SHORT_CHARS: usize = 12;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


pub const MAX_CREATED_MICROS: u64 = i64::MAX as u64;


pub const MAX_NOW_SECONDS: i64 = (MAX_CREATED_MICROS / MICROS_PER_SECOND) as i64;


pub const COMMON_NAME_PREFIX: &str = "CN=";


pub const RDN_SEPARATOR: &str = ", ";


pub const WILDCARD_PREFIX: &str = "*.";


pub const STATE_EXPIRED: &str = "expired";


pub const STATE_NEAR: &str = "near";


/// Letters, digits, `-` and `_`, 1 to `MAX_LABEL_BYTES` bytes, no leading or trailing `-`.
pub fn is_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_LABEL_BYTES
        && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && !label.starts_with('-')
        && !label.ends_with('-')
}


/// A DNS name of at most `MAX_DNS_NAME_BYTES` bytes, optionally starting with `*.`; no root dot, no empty label.
pub fn is_dns_name(text: &str) -> bool {
    let body = text.strip_prefix(WILDCARD_PREFIX).unwrap_or(text);
    text.len() <= MAX_DNS_NAME_BYTES && body.split('.').all(is_label)
}


/// Lowercase hexadecimal SHA-256.
pub fn is_fingerprint(text: &str) -> bool {
    text.len() == SHA256_HEX_LENGTH && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


/// The single `CN=` component of the subject when it is a DNS name; several `CN=` components are ambiguous and give `None`.
pub fn cn_of(subject: &str) -> Option<&str> {
    let mut names = subject.split(RDN_SEPARATOR).filter_map(|part| part.strip_prefix(COMMON_NAME_PREFIX));
    let first = names.next()?;
    names.next().is_none().then_some(first).filter(|name| is_dns_name(name))
}


/// The calendar date of a Unix time in seconds, `None` outside the range of the `time` crate.
pub fn date_of(seconds: i64) -> Option<Date> {
    OffsetDateTime::from_unix_timestamp(seconds).map(OffsetDateTime::date).ok()
}


/// Expired is high, within `NEAR_DAYS` is medium, anything else raises nothing.
pub fn level_of(record: &CertRecord, now: i64) -> Option<(Severity, &'static str)> {
    match expiry_state(record, now, &[NEAR_DAYS]) {
        ExpiryState::Expired => Some((Severity::High, STATE_EXPIRED)),
        ExpiryState::Crossed { .. } => Some((Severity::Medium, STATE_NEAR)),
        ExpiryState::Valid => None,
    }
}


/// Microseconds of a Unix time in seconds, clamped to the range the store accepts; a negative time gives 0.
pub fn micros_of(seconds: i64) -> u64 {
    u64::try_from(seconds)
        .unwrap_or(0)
        .saturating_mul(MICROS_PER_SECOND)
        .min(MAX_CREATED_MICROS)
}


/// The moment the state began: `not_after` when expired, `not_after` minus `NEAR_DAYS` days otherwise.
pub fn state_start_of(record: &CertRecord, state: &str) -> i64 {
    if state == STATE_EXPIRED {
        record.not_after
    } else {
        record.not_after.saturating_sub(i64::from(NEAR_DAYS).saturating_mul(SECONDS_PER_DAY))
    }
}


/// One alert, or `None` when the certificate is not expiring or its fingerprint or `not_after` is outside the grammar.
pub fn alert_of(scope: &TenantScope, record: &CertRecord, now: i64) -> Option<Alert> {
    let (severity, state) = level_of(record, now).filter(|_level| now >= 0)?;
    let date = date_of(record.not_after)?;
    let tenant = tenant_of(scope).to_owned();
    let name = cn_of(&record.subject);
    let label: String = name.map_or_else(
        || record.fingerprint_sha256.chars().take(FINGERPRINT_SHORT_CHARS).collect(),
        str::to_owned,
    );
    let verb = if state == STATE_EXPIRED { "expired on" } else { "expires on" };
    let event_ids = vec![format!("sha256:{}", record.fingerprint_sha256), format!("state:{state}")];
    let created_micros = micros_of(now);
    let state_start = state_start_of(record, state);
    is_fingerprint(&record.fingerprint_sha256).then(|| Alert {
        id: alert_id(&tenant, EXPIRY_RULE_ID, &event_ids),
        tenant,
        rule_id: EXPIRY_RULE_ID.to_owned(),
        rule_title: format!("Certificate {label} {verb} {date}"),
        severity,
        event_time: micros_of(state_start).to_string(),
        created_micros,
        host_name: name.map(str::to_owned),
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "sha256": record.fingerprint_sha256,
            "subject_cn": name,
            "not_after": date.to_string(),
            "state": state,
        })),
    })
}


/// Alerts built and the per-record counts of one `expiry_alerts` pass.
pub struct Pass {
    pub alerts: Vec<Alert>,
    pub expiring: usize,
    pub clamped: usize,
}


/// Adds one record to the pass: its alert is built once, the counts come from the same visit.
pub fn tally(scope: &TenantScope, now: i64, mut pass: Pass, record: &CertRecord) -> Pass {
    let level = level_of(record, now);
    let alert = alert_of(scope, record, now);
    let negative_start = level.is_some_and(|(_severity, state)| state_start_of(record, state) < 0);
    pass.expiring += usize::from(level.is_some());
    pass.clamped += usize::from(alert.is_some() && negative_start);
    pass.alerts.extend(alert);
    pass
}


/// One alert per distinct (certificate, state) of the tenant, sorted by id; counts are per record: rejected, duplicates and a bad `now` in one warning, clamped start times in another.
pub fn expiry_alerts(scope: &TenantScope, records: &[CertRecord], now: i64) -> Vec<Alert> {
    let start = Pass {
        alerts: Vec::new(),
        expiring: 0,
        clamped: 0,
    };
    let Pass {
        mut alerts,
        expiring,
        clamped,
    } = records.iter().fold(start, |pass, record| tally(scope, now, pass, record));
    let now_dropped = if now < 0 { expiring } else { 0 };
    let bad_now = if !(0..=MAX_NOW_SECONDS).contains(&now) { expiring } else { 0 };
    let rejected = expiring.saturating_sub(alerts.len()).saturating_sub(now_dropped);
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    let built = alerts.len();
    alerts.dedup_by(|right, left| right.id == left.id);
    let duplicates = built - alerts.len();
    if rejected > 0 || bad_now > 0 || duplicates > 0 {
        tracing::warn!(rejected, bad_now, duplicates, "expiring certificates were not turned into alerts");
    }
    if clamped > 0 {
        tracing::warn!(clamped, "expiring certificates got their state start clamped to 1970");
    }
    alerts
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_expiry_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}
