//! KEV findings as alerts of the alert store.

use crate::model::AssetFinding;
use crate::priority::priority_of;
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;


pub const KEV_RULE_ID: &str = "vuln.kev";


pub const MAX_TOKEN_CHARS: usize = 100;


pub const CVE_PREFIX: &str = "CVE-";


pub const CVE_YEAR_DIGITS: usize = 4;


pub const CVE_SEQUENCE_MIN_DIGITS: usize = 4;


pub const CVE_SEQUENCE_MAX_DIGITS: usize = 19;


pub const CRITICAL_FROM_PRIORITY: u32 = 15_000;


pub const HIGH_FROM_PRIORITY: u32 = 12_000;


pub const TOKEN_PUNCTUATION: &str = "._+-:@/~^";


/// Alphanumeric or `@` first (so never a leading `-`), then alphanumerics and `TOKEN_PUNCTUATION`, at most `MAX_TOKEN_CHARS` characters.
pub fn is_token(text: &str) -> bool {
    let mut characters = text.chars();
    text.chars().take(MAX_TOKEN_CHARS + 1).count() <= MAX_TOKEN_CHARS
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric() || first == '@')
        && characters.all(|next| next.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(next))
}


/// `CVE-` then four year digits, `-`, then 4 to 19 digits; uppercase only.
pub fn is_cve_id(text: &str) -> bool {
    let sequence = text.strip_prefix(CVE_PREFIX).and_then(|rest| rest.split_once('-'));
    sequence.is_some_and(|(year, number)| {
        year.len() == CVE_YEAR_DIGITS
            && year.bytes().all(|byte| byte.is_ascii_digit())
            && (CVE_SEQUENCE_MIN_DIGITS..=CVE_SEQUENCE_MAX_DIGITS).contains(&number.len())
            && number.bytes().all(|byte| byte.is_ascii_digit())
    })
}


/// The smallest valid CVE id among the CVE aliases and the record id, so the choice does not depend on alias order.
pub fn cve_of(item: &AssetFinding) -> Option<&String> {
    let finding = &item.scored.finding;
    finding
        .cve_aliases
        .iter()
        .chain(std::iter::once(&finding.record_id))
        .filter(|id| is_cve_id(id))
        .min()
}


/// KEV findings rank from 10 000: at least 15 000 is critical, at least 12 000 high, the rest medium; a KEV alert is never below medium.
pub fn severity_of(priority: u32) -> Severity {
    if priority >= CRITICAL_FROM_PRIORITY {
        Severity::Critical
    } else if priority >= HIGH_FROM_PRIORITY {
        Severity::High
    } else {
        Severity::Medium
    }
}


/// One alert, or `None` when the finding is not KEV or a field that reaches the alert is outside its grammar.
pub fn alert_of(scope: &TenantScope, item: &AssetFinding, now_micros: u64) -> Option<Alert> {
    let finding = &item.scored.finding;
    let cve = cve_of(item)?;
    let fixed = finding.fixed_version.as_deref().filter(|version| is_token(version));
    let valid = item.scored.kev && is_token(&item.asset) && is_token(&finding.package) && is_token(&finding.installed_version);
    let tenant = tenant_of(scope).to_owned();
    let event_ids = vec![
        format!("asset:{}", item.asset),
        format!("package:{}", finding.package),
        format!("version:{}", finding.installed_version),
        format!("cve:{cve}"),
    ];
    valid.then(|| Alert {
        id: alert_id(&tenant, KEV_RULE_ID, &event_ids),
        tenant,
        rule_id: KEV_RULE_ID.to_owned(),
        rule_title: format!("Known exploited vulnerability {cve} in {}", finding.package),
        severity: severity_of(priority_of(&item.scored)),
        event_time: now_micros.to_string(),
        created_micros: now_micros,
        host_name: Some(item.asset.clone()),
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "cve": cve,
            "package": finding.package,
            "installed_version": finding.installed_version,
            "fixed_version": fixed,
        })),
    })
}


/// One alert per distinct KEV finding of the tenant (sorted by id, duplicates merged); rejected KEV findings are counted in a warning.
pub fn kev_alerts(scope: &TenantScope, findings: &[AssetFinding], now_micros: u64) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = findings.iter().filter_map(|item| alert_of(scope, item, now_micros)).collect();
    let rejected = findings.iter().filter(|item| item.scored.kev).count().saturating_sub(alerts.len());
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    alerts.dedup_by(|right, left| right.id == left.id);
    if rejected > 0 {
        tracing::warn!(rejected, "KEV findings outside the alert grammar were not turned into alerts");
    }
    alerts
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_kev_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}
