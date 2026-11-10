//! Firing metric rules as alerts of the alert store.

use crate::fingerprint::fingerprint;
use crate::model::Severity as RuleSeverity;
use crate::token::{is_token, shown};
use crate::types::{Labels, Timestamp};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_TITLE_CHARS};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;


pub const RULE_ID_PREFIX: &str = "metric.";


pub const TITLE_PREFIX: &str = "Metric alert ";


pub const ASSET_LABEL: &str = "asset";


pub const MAX_LABELS: usize = 16;


pub const MORE_RESERVE: usize = 16;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


/// One firing period of a rule on one series; `since` is the breach start in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Firing {
    pub tenant: TenantScope,
    pub rule_id: String,
    pub labels: Labels,
    pub severity: RuleSeverity,
    pub since: Timestamp,
}


pub fn severity_of(severity: RuleSeverity) -> Severity {
    match severity {
        RuleSeverity::Low => Severity::Low,
        RuleSeverity::Medium => Severity::Medium,
        RuleSeverity::High => Severity::High,
        RuleSeverity::Critical => Severity::Critical,
    }
}


/// The rule id is a token and `since` fits in alert microseconds; labels never invalidate a firing.
pub fn is_valid(firing: &Firing) -> bool {
    firing
        .since
        .checked_mul(MICROS_PER_SECOND)
        .is_some_and(|micros| micros <= MAX_CREATED_MICROS)
        && is_token(&firing.rule_id)
}


/// The prefix, the rule id, then the first `MAX_LABELS` `name=value` pieces that fit within `MAX_TITLE_CHARS`, each part shown as itself or as `#digest`; the rest is `(+N more)`.
pub fn title_of(rule_id: &str, labels: &Labels) -> String {
    let (listed, omitted) = labels.iter().enumerate().fold(
        (format!("{TITLE_PREFIX}{rule_id}"), usize::default()),
        |(text, count), (index, (name, value))| {
            let piece = format!(" {}={}", shown(name), shown(value));
            if index < MAX_LABELS && text.chars().count() + piece.chars().count() + MORE_RESERVE <= MAX_TITLE_CHARS {
                (text + &piece, count)
            } else {
                (text, count + 1)
            }
        },
    );
    if omitted > 0 {
        format!("{listed} (+{omitted} more)")
    } else {
        listed
    }
}


/// One alert, or `None` when the rule id or `since` is outside its bounds.
pub fn alert_of(scope: &TenantScope, firing: &Firing, now: Timestamp) -> Option<Alert> {
    let tenant = tenant_of(scope).to_owned();
    let rule_id = format!("{RULE_ID_PREFIX}{}", firing.rule_id);
    let pairs: Vec<(String, String)> = firing.labels.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
    let event_ids = vec![
        format!("rule:{}", firing.rule_id),
        format!("series:{}", fingerprint(&firing.rule_id, &pairs)),
        format!("since:{}", firing.since),
    ];
    let created_micros = now.saturating_mul(MICROS_PER_SECOND).min(MAX_CREATED_MICROS);
    is_valid(firing).then(|| Alert {
        id: alert_id(&tenant, &rule_id, &event_ids),
        tenant,
        rule_id,
        rule_title: title_of(&firing.rule_id, &firing.labels),
        severity: severity_of(firing.severity),
        event_time: firing.since.saturating_mul(MICROS_PER_SECOND).to_string(),
        created_micros,
        host_name: firing.labels.get(ASSET_LABEL).map(|asset| shown(asset)),
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "rule": firing.rule_id,
            "labels": firing.labels,
            "since": firing.since,
        })),
    })
}


/// One alert per distinct firing of the tenant (sorted by id, duplicates merged); a firing of another tenant or outside the bounds is dropped and counted in a warning.
pub fn firing_alerts(scope: &TenantScope, firings: &[Firing], now: Timestamp) -> Vec<Alert> {
    let own: Vec<&Firing> = firings.iter().filter(|firing| tenant_of(&firing.tenant) == tenant_of(scope)).collect();
    let foreign = firings.len().saturating_sub(own.len());
    let mut alerts: Vec<Alert> = own.into_iter().filter_map(|firing| alert_of(scope, firing, now)).collect();
    let rejected = firings.len().saturating_sub(foreign).saturating_sub(alerts.len());
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    alerts.dedup_by(|right, left| right.id == left.id);
    if rejected > 0 || foreign > 0 {
        tracing::warn!(rejected, foreign, "firings dropped: bad rule id or time, or another tenant");
    }
    alerts
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_firing_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}
