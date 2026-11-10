//! Failed controls as alerts of the alert store.

use crate::model::{DriftFinding, Severity as ControlSeverity, Verdict};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;


pub const RULE_PREFIX: &str = "compliance.";


/// Longest baseline name or control id; `RULE_PREFIX`, both and a dot stay under the store's rule id limit.
pub const MAX_ID_CHARS: usize = 50;


pub const MAX_ASSET_CHARS: usize = 100;


pub const MAX_TITLE_CHARS: usize = 100;


pub const ID_PUNCTUATION: &str = "._-";


pub const ASSET_PUNCTUATION: &str = "._+-:@/~^";


pub const TITLE_PUNCTUATION: &str = " ._-:,()/";


/// Alphanumeric first (so never a leading `-`), then alphanumerics and `punctuation`, at most `max` characters.
pub fn is_grammar(text: &str, max: usize, punctuation: &str) -> bool {
    let mut characters = text.chars();
    text.chars().take(max + 1).count() <= max
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || punctuation.contains(next))
}


/// A baseline name or control id: at most `MAX_ID_CHARS` characters of alphanumerics and `._-`, alphanumeric first.
pub fn is_id(text: &str) -> bool {
    is_grammar(text, MAX_ID_CHARS, ID_PUNCTUATION)
}


pub fn severity_of(severity: ControlSeverity) -> Severity {
    match severity {
        ControlSeverity::Low => Severity::Low,
        ControlSeverity::Medium => Severity::Medium,
        ControlSeverity::High => Severity::High,
        ControlSeverity::Critical => Severity::Critical,
    }
}


/// The number of offending rows of a failed verdict; `None` for any other verdict, which never raises an alert.
pub fn failed_total(verdict: &Verdict) -> Option<usize> {
    match verdict {
        Verdict::Fail { total, .. } => Some(*total),
        Verdict::Pass | Verdict::Error { .. } | Verdict::Excepted { .. } => None,
    }
}


/// One alert, or `None` when the verdict is not a failure or a field that reaches the alert is outside its grammar.
pub fn alert_of(scope: &TenantScope, item: &DriftFinding, now_micros: u64) -> Option<Alert> {
    let total = failed_total(&item.verdict)?;
    let valid = is_id(&item.baseline)
        && is_id(&item.control)
        && is_grammar(&item.title, MAX_TITLE_CHARS, TITLE_PUNCTUATION)
        && is_grammar(&item.asset, MAX_ASSET_CHARS, ASSET_PUNCTUATION);
    let tenant = tenant_of(scope).to_owned();
    let rule_id = format!("{RULE_PREFIX}{}.{}", item.baseline, item.control);
    let event_ids = vec![
        format!("baseline:{}", item.baseline),
        format!("control:{}", item.control),
        format!("asset:{}", item.asset),
        format!("failed:{}", item.first_failed_micros),
    ];
    valid.then(|| Alert {
        id: alert_id(&tenant, &rule_id, &event_ids),
        tenant,
        rule_title: format!("Control {} failed: {}", item.control, item.title),
        severity: severity_of(item.severity),
        event_time: item.first_failed_micros.to_string(),
        created_micros: now_micros,
        host_name: Some(item.asset.clone()),
        user_name: None,
        summary: summarise(&json!({
            "baseline": item.baseline,
            "control": item.control,
            "offending_rows": total,
        })),
        rule_id,
        event_ids,
    })
}


/// One alert per distinct failure of the tenant (sorted by id, duplicates merged); rejected failures are counted in a warning.
pub fn drift_alerts(scope: &TenantScope, findings: &[DriftFinding], now_micros: u64) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = findings.iter().filter_map(|item| alert_of(scope, item, now_micros)).collect();
    let rejected = findings
        .iter()
        .filter(|item| failed_total(&item.verdict).is_some())
        .count()
        .saturating_sub(alerts.len());
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    alerts.dedup_by(|right, left| right.id == left.id);
    if rejected > 0 {
        tracing::warn!(rejected, "failed controls outside the alert grammar were not turned into alerts");
    }
    alerts
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_drift_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}
