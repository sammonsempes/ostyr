//! IP, MAC and hostname lease history in PostgreSQL (spec section 14, DHCP module): one row per lease interval, caps enforced by the store.

use crate::alerting::{mac_of, MAX_DAY_SECONDS};
use crate::error::HistoryError;
use crate::row::{normalise_mac, valid_hostname, Converted};
use alerts::types::Executor;
use core_pg::scope::TenantScope;
use serde_json::json;
use std::net::IpAddr;
use std::str::FromStr;


pub const MAX_HISTORY_ROWS_PER_TENANT: u64 = 5_000_000;


pub const DEFAULT_RETENTION_DAYS: u32 = 400;


pub const MAX_RETENTION_DAYS: u32 = 3_650;


pub const MAX_HISTORY_BATCH: usize = 1_000;


pub const MAX_LOOKUP_ROWS: usize = 100;


pub const COUNT_COLUMNS: usize = 5;


pub const LOOKUP_COLUMNS: usize = 7;


pub const MAX_ACTION_CHARS: usize = 40;


pub const STORE_SQL: &str = "SELECT n_expired::text, n_inserted::text, n_duplicate::text, n_refused_full::text, n_stale::text \
                             FROM dhcp_history_store($1, $2::text::jsonb, $3::text::bigint, $4::text::bigint, $5::text::bigint)";


pub const AT_SQL: &str = "SELECT host(address), mac, hostname, extract(epoch FROM starts)::bigint::text, extract(epoch FROM ends)::bigint::text, \
                          action, subnet_id::text FROM dhcp_lease_history \
                          WHERE tenant = $1 AND address = $2::text::inet AND starts <= to_timestamp($3::text::bigint) AND ends > to_timestamp($3::text::bigint) \
                          ORDER BY starts DESC LIMIT $4::text::bigint";


pub const MAC_SQL: &str = "SELECT host(address), mac, hostname, extract(epoch FROM starts)::bigint::text, extract(epoch FROM ends)::bigint::text, \
                           action, subnet_id::text FROM dhcp_lease_history \
                           WHERE tenant = $1 AND mac = $2 AND starts < to_timestamp($4::text::bigint) AND ends > to_timestamp($3::text::bigint) \
                           ORDER BY starts DESC LIMIT $5::text::bigint";


/// The per-tenant row cap and the retention in days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistorySettings {
    pub retention_days: u32,
    pub max_rows: u64,
}


impl Default for HistorySettings {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_RETENTION_DAYS,
            max_rows: MAX_HISTORY_ROWS_PER_TENANT,
        }
    }
}


/// What one call did with its batch; every row is in exactly one of `inserted`, `duplicate`, `stale`, `refused_full`, `refused`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryCounts {
    pub inserted: u64,
    pub duplicate: u64,
    pub expired: u64,
    pub refused_full: u64,
    pub stale: u64,
    pub refused: u64,
}


/// One stored lease interval, times in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseInterval {
    pub address: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub starts: i64,
    pub ends: i64,
    pub action: String,
    pub subnet_id: i64,
}


/// A lookup answer: at most `MAX_LOOKUP_ROWS` intervals, newest first, and whether more matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupResult {
    pub intervals: Vec<LeaseInterval>,
    pub truncated: bool,
}


pub fn check_settings(settings: &HistorySettings) -> Result<(), HistoryError> {
    let valid = (1..=MAX_RETENTION_DAYS).contains(&settings.retention_days) && (1..=MAX_HISTORY_ROWS_PER_TENANT).contains(&settings.max_rows);
    valid.then_some(()).ok_or(HistoryError::Settings)
}


fn in_range(seconds: i64) -> bool {
    u64::try_from(seconds).is_ok_and(|found| found <= MAX_DAY_SECONDS)
}


fn valid_action(action: &str) -> bool {
    action.len() <= MAX_ACTION_CHARS && action.chars().all(|found| found.is_ascii_alphanumeric() || found == '-')
}


/// The JSON document of one lease, `None` when its address, times or action cannot be stored. Every value ends up a bound parameter.
pub fn lease_doc(lease: &Converted) -> Option<serde_json::Value> {
    let (starts, ends, key_address, key_mac, key_state) = &lease.key;
    let address = lease
        .event
        .source
        .as_ref()
        .and_then(|source| source.ip.as_deref())
        .and_then(|text| IpAddr::from_str(text).ok())?;
    let action = lease.event.event.action.as_deref().filter(|text| valid_action(text))?;
    let hostname = lease
        .event
        .host
        .as_ref()
        .and_then(|host| host.hostname.as_deref())
        .and_then(valid_hostname);
    let times_fit = in_range(*starts) && in_range(*ends) && starts <= ends;
    let subnet_id = lease
        .event
        .labels
        .iter()
        .find(|(name, _value)| name.as_str() == "subnet_id")
        .and_then(|(_name, value)| value.parse::<i64>().ok())?;
    times_fit.then(|| {
        json!({
            "identity": format!("{starts}|{ends}|{key_address}|{key_mac}|{key_state}"),
            "address": address.to_string(),
            "mac": mac_of(lease),
            "hostname": hostname,
            "starts": starts,
            "ends": ends,
            "action": action,
            "subnet_id": subnet_id,
        })
    })
}


fn parse_counts(rows: &[Vec<String>]) -> Result<[u64; COUNT_COLUMNS], HistoryError> {
    let row = rows.first().ok_or(HistoryError::Answer)?;
    let parsed: Vec<u64> = row.iter().filter_map(|text| text.parse::<u64>().ok()).collect();
    <[u64; COUNT_COLUMNS]>::try_from(parsed).map_err(|_bad| HistoryError::Answer)
}


fn add_counts(total: HistoryCounts, [expired, inserted, duplicate, refused_full, stale]: [u64; COUNT_COLUMNS]) -> HistoryCounts {
    HistoryCounts {
        inserted: total.inserted + inserted,
        duplicate: total.duplicate + duplicate,
        expired: total.expired + expired,
        refused_full: total.refused_full + refused_full,
        stale: total.stale + stale,
        refused: total.refused,
    }
}


/// Stores a batch for the scope's tenant in groups of `MAX_HISTORY_BATCH`; `now` is Unix seconds. The store enforces the row cap and the retention under a per-tenant lock.
pub async fn store_history(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    settings: &HistorySettings,
    now: i64,
    batch: &[Converted],
) -> Result<HistoryCounts, HistoryError> {
    check_settings(settings)?;
    let docs: Vec<serde_json::Value> = batch.iter().filter_map(lease_doc).collect();
    let refused = u64::try_from(batch.len() - docs.len()).map_err(|_bad| HistoryError::Answer)?;
    let mut total = HistoryCounts {
        refused,
        ..HistoryCounts::default()
    };
    let empty: [serde_json::Value; 0] = [];
    let groups: Vec<&[serde_json::Value]> = if docs.is_empty() {
        vec![&empty]
    } else {
        docs.chunks(MAX_HISTORY_BATCH).collect()
    };
    for group in groups {
        let params = vec![
            serde_json::Value::Array(group.to_vec()).to_string(),
            settings.max_rows.to_string(),
            settings.retention_days.to_string(),
            now.to_string(),
        ];
        let rows = exec(scope.clone(), STORE_SQL, params).await?;
        let counts = parse_counts(&rows)?;
        total = add_counts(total, counts);
    }
    let refused_full = total.refused_full;
    if refused_full > 0 {
        tracing::warn!(refused_full, "dhcp history cap reached, rows refused");
    }
    Ok(total)
}


fn interval_of(row: &[String]) -> Option<LeaseInterval> {
    let [address, mac, hostname, starts, ends, action, subnet_id] = <&[String; LOOKUP_COLUMNS]>::try_from(row).ok()?;
    let optional = |text: &String| (!text.is_empty()).then(|| text.clone());
    Some(LeaseInterval {
        address: address.clone(),
        mac: optional(mac),
        hostname: optional(hostname),
        starts: starts.parse().ok()?,
        ends: ends.parse().ok()?,
        action: action.clone(),
        subnet_id: subnet_id.parse().ok()?,
    })
}


fn bounded(rows: &[Vec<String>]) -> Result<LookupResult, HistoryError> {
    let intervals: Vec<LeaseInterval> = rows
        .iter()
        .take(MAX_LOOKUP_ROWS)
        .map(|row| interval_of(row).ok_or(HistoryError::Answer))
        .collect::<Result<_, _>>()?;
    Ok(LookupResult {
        intervals,
        truncated: rows.len() > MAX_LOOKUP_ROWS,
    })
}


/// The intervals of the tenant's address with `starts <= at < ends`, newest first.
pub async fn lease_at(exec: Executor<'_, '_>, scope: &TenantScope, address: &str, at: i64) -> Result<LookupResult, HistoryError> {
    let parsed = IpAddr::from_str(address).map_err(|_bad| HistoryError::Address)?;
    in_range(at).then_some(()).ok_or(HistoryError::TimeRange)?;
    let limit = MAX_LOOKUP_ROWS + 1;
    let rows = exec(scope.clone(), AT_SQL, vec![parsed.to_string(), at.to_string(), limit.to_string()]).await?;
    bounded(&rows)
}


/// The intervals of the tenant's MAC overlapping `from..to`, newest first.
pub async fn leases_of_mac(exec: Executor<'_, '_>, scope: &TenantScope, mac: &str, from: i64, to: i64) -> Result<LookupResult, HistoryError> {
    let normal = normalise_mac(mac).ok_or(HistoryError::Mac)?;
    (in_range(from) && in_range(to)).then_some(()).ok_or(HistoryError::TimeRange)?;
    let limit = MAX_LOOKUP_ROWS + 1;
    let rows = exec(scope.clone(), MAC_SQL, vec![normal, from.to_string(), to.to_string(), limit.to_string()]).await?;
    bounded(&rows)
}
