//! Check outages as alerts of the alert store (spec section 20).

use crate::model::{CheckKind, MAX_LOCATIONS};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_TITLE_CHARS};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use metric_alerts::token::shown;
use serde_json::json;


pub const RULE_ID_PREFIX: &str = "synthetic.";


pub const TITLE_PREFIX: &str = "Synthetic check ";


pub const MORE_FIXED_CHARS: usize = 9;


pub const MICROS_PER_SECOND: u64 = 1_000_000;


/// One outage of a check: `since` is the first failure of the current run, in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outage {
    pub tenant: String,
    pub check: String,
    pub kind: CheckKind,
    pub failing_locations: Vec<String>,
    pub since: u64,
}


pub fn kind_name(kind: CheckKind) -> &'static str {
    match kind {
        CheckKind::Http => "http",
        CheckKind::Tcp => "tcp",
        CheckKind::Icmp => "icmp",
        CheckKind::Dns => "dns",
        CheckKind::Tls => "tls",
    }
}


/// The microseconds of `since` when they fit the store, never clamped.
pub fn since_micros(since: u64) -> Option<u64> {
    since.checked_mul(MICROS_PER_SECOND).filter(|micros| *micros <= MAX_CREATED_MICROS)
}


/// The head, then up to `MAX_LOCATIONS` locations that fit within `MAX_TITLE_CHARS`, each shown as itself or as `#digest`; the rest is `(+N more)`.
pub fn title_of(check: &str, locations: &[String]) -> String {
    let reserve = MORE_FIXED_CHARS + locations.len().to_string().len();
    let head = format!("{TITLE_PREFIX}{} failing at {} locations", shown(check), locations.len());
    let (text, _listed, omitted) = locations
        .iter()
        .fold((head, usize::default(), usize::default()), |(text, listed, omitted), location| {
            let separator = if listed == 0 { ": " } else { ", " };
            let piece = format!("{separator}{}", shown(location));
            if listed < MAX_LOCATIONS && text.chars().count() + piece.chars().count() + reserve <= MAX_TITLE_CHARS {
                (text + &piece, listed + 1, omitted)
            } else {
                (text, listed, omitted + 1)
            }
        });
    if omitted > 0 {
        format!("{text} (+{omitted} more)")
    } else {
        text
    }
}


/// One alert, or `None` when the outage is of another tenant or its `since` does not fit the store.
pub fn alert_of(scope: &TenantScope, outage: &Outage, now: u64) -> Option<Alert> {
    let tenant = tenant_of(scope).to_owned();
    let rule_id = format!("{RULE_ID_PREFIX}{}", kind_name(outage.kind));
    let event_ids = vec![format!("check:{}", shown(&outage.check)), format!("since:{}", outage.since)];
    let created_micros = now.saturating_mul(MICROS_PER_SECOND).min(MAX_CREATED_MICROS);
    let listed: Vec<&String> = outage.failing_locations.iter().take(MAX_LOCATIONS).collect();
    let omitted = outage.failing_locations.len().saturating_sub(listed.len());
    let micros = since_micros(outage.since).filter(|_fits| outage.tenant == tenant)?;
    Some(Alert {
        id: alert_id(&tenant, &rule_id, &event_ids),
        tenant,
        rule_id,
        rule_title: title_of(&outage.check, &outage.failing_locations),
        severity: Severity::High,
        event_time: micros.to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(&json!({
            "check": outage.check,
            "kind": kind_name(outage.kind),
            "locations": listed,
            "locations_omitted": omitted,
            "since": outage.since,
        })),
    })
}


/// One alert per distinct outage of the tenant (sorted by id, duplicates merged); an outage of another tenant or with a bad `since` is dropped and counted in a warning.
pub fn outage_alerts(scope: &TenantScope, outages: &[Outage], now: u64) -> Vec<Alert> {
    let own = outages.iter().filter(|outage| outage.tenant == tenant_of(scope)).count();
    let foreign = outages.len().saturating_sub(own);
    let mut alerts: Vec<Alert> = outages.iter().filter_map(|outage| alert_of(scope, outage, now)).collect();
    let rejected = own.saturating_sub(alerts.len());
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    alerts.dedup_by(|right, left| right.id == left.id);
    if rejected > 0 || foreign > 0 {
        tracing::warn!(rejected, foreign, "outages dropped: another tenant or a bad time");
    }
    alerts
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_outage_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}
