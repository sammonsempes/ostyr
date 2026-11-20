//! Per-tenant findings store: one scan of one asset is the full truth for that asset (spec section 23).

use crate::error::StoreError;
use crate::limits::{
    CURSOR_FIELDS, LAST_SEEN_GRANULARITY_MICROS, MAX_ALIASES_PER_FINDING, MAX_CURSOR_BYTES, MAX_FIELD_BYTES, MAX_FINDINGS_PER_SCAN,
    MAX_OPEN_FINDINGS_PER_TENANT, MAX_PAGE_LIMIT, MAX_RESOLVED_FINDINGS_PER_ASSET, MAX_RESOLVED_FINDINGS_PER_TENANT,
};
use crate::model::{AssetFinding, FindingsPage, ScanCaps, ScanOutcome, StoredFinding};
use crate::priority::priority_of;
use crate::text::is_cve_id;
use crate::types::CursorSplit;
use alerts::types::Executor;
use core_pg::migrate::Migration;
use core_pg::scope::TenantScope;
use serde_json::{json, Value};
use std::time::Duration;


pub const MIGRATION_NAMESPACE: &str = "vuln";


pub const MIGRATIONS: [Migration; 3] = [
    Migration {
        version: "vuln_0001",
        sql: include_str!("../migrations/vuln_0001.sql"),
    },
    Migration {
        version: "vuln_0002",
        sql: include_str!("../migrations/vuln_0002.sql"),
    },
    Migration {
        version: "vuln_0003",
        sql: include_str!("../migrations/vuln_0003.sql"),
    },
];


pub const OUTCOME_COLUMNS: usize = 7;


pub const COL_ASSET: usize = 0;


pub const COL_ECOSYSTEM: usize = 1;


pub const COL_PACKAGE: usize = 2;


pub const COL_RECORD: usize = 3;


pub const COL_INSTALLED: usize = 4;


pub const COL_FIXED: usize = 5;


pub const COL_CVSS: usize = 6;


pub const COL_EPSS: usize = 7;


pub const COL_KEV: usize = 8;


pub const COL_PRIORITY: usize = 9;


pub const COL_FIRST_SEEN: usize = 10;


pub const COL_LAST_SEEN: usize = 11;


pub const SCORE_MIN: f64 = 0.0;


pub const CVSS_MAX: f64 = 10.0;


pub const EPSS_MAX: f64 = 1.0;


pub const CURSOR_SEPARATOR: char = ' ';


/// One statement under a per-tenant lock: `$1` tenant, `$2` asset, `$3` findings JSON, `$4` open cap, `$5` now, `$6` resolved cap, `$7` granularity, `$8` resolved cap of the asset.
pub const SCAN_SQL: &str = "SELECT n_inserted::text, n_updated::text, n_resolved::text, n_refused_no_room::text, n_evicted::text, n_duplicates::text, n_counters_missing::text \
                            FROM vuln_scan_store($1, $2, $3::text::jsonb, $4::text::bigint, $5::text::bigint, $6::text::bigint, $7::text::bigint, $8::text::bigint)";


/// `$1` tenant: builds the tenant and per-asset counters of a tenant that has none, in its own statement under the tenant lock; the answer is 1 when it built them.
pub const REBUILD_SQL: &str = "SELECT vuln_counters_rebuild($1)::text";


/// Deadline of the rebuild statement: it counts the whole tenant once, so it gets the migration deadline and never a scan's.
pub const MIGRATION_DEADLINE: Duration = Duration::from_secs(120);


/// `$1` tenant, `$2` limit.
pub const FIRST_SQL: &str = "SELECT asset, ecosystem, package, record_id, installed_version, coalesce(fixed_version, ''), cvss::text, epss::text, \
                             kev::text, priority::text, first_seen_micros::text, last_seen_micros::text FROM vuln_findings \
                             WHERE tenant = $1 AND resolved_micros IS NULL \
                             ORDER BY vuln_findings.priority DESC, asset, ecosystem, package, record_id LIMIT $2::text::bigint";


/// `$1` tenant, `$2` priority, `$3` asset, `$4` ecosystem, `$5` package, `$6` record id of the last row seen, `$7` limit: two index-bounded branches.
pub const NEXT_SQL: &str = "SELECT asset, ecosystem, package, record_id, installed_version, coalesce(fixed_version, ''), cvss::text, epss::text, \
                            kev::text, priority::text, first_seen_micros::text, last_seen_micros::text FROM ( \
                            (SELECT asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, \
                            first_seen_micros, last_seen_micros FROM vuln_findings \
                            WHERE tenant = $1 AND resolved_micros IS NULL AND priority = $2::text::bigint \
                            AND (asset, ecosystem, package, record_id) > ($3::text, $4::text, $5::text, $6::text) \
                            ORDER BY asset, ecosystem, package, record_id LIMIT $7::text::bigint) \
                            UNION ALL \
                            (SELECT asset, ecosystem, package, record_id, installed_version, fixed_version, cvss, epss, kev, priority, \
                            first_seen_micros, last_seen_micros FROM vuln_findings \
                            WHERE tenant = $1 AND resolved_micros IS NULL AND priority < $2::text::bigint \
                            ORDER BY priority DESC, asset, ecosystem, package, record_id LIMIT $7::text::bigint) \
                            ) page ORDER BY page.priority DESC, asset, ecosystem, package, record_id LIMIT $7::text::bigint";


/// `$1` tenant, `$2` asset, `$3` limit: the open rows of one asset through `vuln_findings_open_asset_rank`.
pub const ASSET_SQL: &str = "SELECT asset, ecosystem, package, record_id, installed_version, coalesce(fixed_version, ''), cvss::text, epss::text, \
                             kev::text, priority::text, first_seen_micros::text, last_seen_micros::text FROM vuln_findings \
                             WHERE tenant = $1 AND asset = $2 AND resolved_micros IS NULL \
                             ORDER BY vuln_findings.priority DESC, ecosystem, package, record_id LIMIT $3::text::bigint";


/// Printable ASCII without space or a leading `-`, 1 to `MAX_FIELD_BYTES` bytes: the one grammar of every stored text.
pub fn is_field(text: &str) -> bool {
    (1..=MAX_FIELD_BYTES).contains(&text.len()) && !text.starts_with('-') && text.chars().all(|found| found.is_ascii_graphic())
}


/// The JSON document of one finding of `asset`, `None` when a text, an alias or a score is outside its grammar or range.
pub fn finding_doc(asset: &str, item: &AssetFinding) -> Option<Value> {
    let scored = &item.scored;
    let finding = &scored.finding;
    let texts_fit = [&finding.ecosystem, &finding.package, &finding.record_id, &finding.installed_version]
        .iter()
        .all(|text| is_field(text))
        && finding.fixed_version.as_deref().is_none_or(is_field);
    let aliases_fit = finding.cve_aliases.len() <= MAX_ALIASES_PER_FINDING && finding.cve_aliases.iter().all(|alias| is_cve_id(alias));
    let scores_fit = (SCORE_MIN..=CVSS_MAX).contains(&scored.cvss) && (SCORE_MIN..=EPSS_MAX).contains(&scored.epss);
    (item.asset == asset && texts_fit && aliases_fit && scores_fit).then(|| {
        json!({
            "ecosystem": finding.ecosystem,
            "package": finding.package,
            "record_id": finding.record_id,
            "installed_version": finding.installed_version,
            "fixed_version": finding.fixed_version,
            "cvss": scored.cvss,
            "epss": scored.epss,
            "kev": scored.kev,
            "priority": priority_of(scored),
        })
    })
}


fn parse_outcome(rows: &[Vec<String>], refused: u64) -> Result<ScanOutcome, StoreError> {
    let row = rows.first().ok_or(StoreError::BadAnswer)?;
    let numbers: Vec<u64> = row.iter().filter_map(|text| text.parse::<u64>().ok()).collect();
    let [inserted, updated, resolved, refused_no_room, evicted_resolved, duplicates, counters_missing] =
        <[u64; OUTCOME_COLUMNS]>::try_from(numbers).map_err(|_bad| StoreError::BadAnswer)?;
    if counters_missing > 0 {
        Err(StoreError::CountersMissing)
    } else {
        Ok(ScanOutcome {
            inserted,
            updated,
            resolved,
            refused_no_room,
            evicted_resolved,
            refused,
            duplicates,
        })
    }
}


/// Builds the counters of the scope's tenant when it has none (run it on an executor with `MIGRATION_DEADLINE`); true when it built them.
pub async fn rebuild_counters(exec: Executor<'_, '_>, scope: &TenantScope) -> Result<bool, StoreError> {
    let rows = exec(scope.clone(), REBUILD_SQL, Vec::new()).await?;
    let answer = rows.first().and_then(|row| row.first()).ok_or(StoreError::BadAnswer)?;
    match answer.as_str() {
        "1" => Ok(true),
        "0" => Ok(false),
        _other => Err(StoreError::BadAnswer),
    }
}


/// Stores one full scan of `asset` under the scope's tenant with the default open and resolved row caps.
pub async fn record_scan(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    asset: &str,
    findings: &[AssetFinding],
    now_micros: u64,
) -> Result<ScanOutcome, StoreError> {
    let caps = ScanCaps {
        max_open: MAX_OPEN_FINDINGS_PER_TENANT,
        max_resolved: MAX_RESOLVED_FINDINGS_PER_TENANT,
        max_asset_resolved: MAX_RESOLVED_FINDINGS_PER_ASSET,
    };
    record_scan_capped(exec, scope, asset, findings, now_micros, &caps).await
}


/// As `record_scan` with explicit open, tenant resolved and asset resolved caps (1 to their defaults), every bound checked before any I/O.
pub async fn record_scan_capped(
    exec: Executor<'_, '_>,
    scope: &TenantScope,
    asset: &str,
    findings: &[AssetFinding],
    now_micros: u64,
    caps: &ScanCaps,
) -> Result<ScanOutcome, StoreError> {
    if findings.len() > MAX_FINDINGS_PER_SCAN {
        Err(StoreError::TooManyFindings { max: MAX_FINDINGS_PER_SCAN })
    } else if !is_field(asset) {
        Err(StoreError::BadAsset)
    } else if !(1..=MAX_OPEN_FINDINGS_PER_TENANT).contains(&caps.max_open)
        || !(1..=MAX_RESOLVED_FINDINGS_PER_TENANT).contains(&caps.max_resolved)
        || !(1..=MAX_RESOLVED_FINDINGS_PER_ASSET).contains(&caps.max_asset_resolved)
    {
        Err(StoreError::BadCap {
            max: MAX_OPEN_FINDINGS_PER_TENANT,
        })
    } else {
        let now = i64::try_from(now_micros).map_err(|_bad| StoreError::BadTime)?;
        let docs: Vec<Value> = findings.iter().filter_map(|item| finding_doc(asset, item)).collect();
        let refused = u64::try_from(findings.len() - docs.len()).map_err(|_bad| StoreError::BadAnswer)?;
        let params = vec![
            asset.to_owned(),
            Value::Array(docs).to_string(),
            caps.max_open.to_string(),
            now.to_string(),
            caps.max_resolved.to_string(),
            LAST_SEEN_GRANULARITY_MICROS.to_string(),
            caps.max_asset_resolved.to_string(),
        ];
        let rows = exec(scope.clone(), SCAN_SQL, params).await?;
        let outcome = parse_outcome(&rows, refused)?;
        let no_room = outcome.refused_no_room;
        let evicted = outcome.evicted_resolved;
        if no_room > 0 {
            tracing::warn!(no_room, "vulnerability findings cap reached, new findings refused");
        }
        if evicted > 0 {
            tracing::warn!(evicted, "resolved vulnerability findings over the cap were deleted, oldest first");
        }
        let duplicates = outcome.duplicates;
        if duplicates > 0 {
            tracing::warn!(duplicates, "repeated vulnerability finding keys in one scan were merged");
        }
        if refused > 0 {
            tracing::warn!(refused, "vulnerability findings outside the grammar were refused");
        }
        Ok(outcome)
    }
}


/// The cursor of a stored finding: priority and key, separated by spaces, which no field holds.
pub fn cursor_of(finding: &StoredFinding) -> String {
    [
        finding.priority.to_string(),
        finding.asset.clone(),
        finding.ecosystem.clone(),
        finding.package.clone(),
        finding.record_id.clone(),
    ]
    .join(&CURSOR_SEPARATOR.to_string())
}


/// Splits a cursor on the separator; the production splitter of `parse_cursor`.
pub fn split_cursor(cursor: &str) -> Result<Vec<&str>, StoreError> {
    Ok(cursor.split(CURSOR_SEPARATOR).collect())
}


/// The parameters of `NEXT_SQL` after the tenant, minus the limit; a cursor that is not exactly a priority and four fields is `BadCursor`.
pub fn parse_cursor(cursor: &str) -> Result<Vec<String>, StoreError> {
    parse_cursor_with(cursor, split_cursor)
}


/// As `parse_cursor` with an injected splitter, which is never called for a cursor over `MAX_CURSOR_BYTES`.
pub fn parse_cursor_with(cursor: &str, split: CursorSplit) -> Result<Vec<String>, StoreError> {
    if cursor.len() > MAX_CURSOR_BYTES {
        Err(StoreError::BadCursor)
    } else {
        let parts = split(cursor)?;
        let priority_fits = parts
            .first()
            .is_some_and(|text| text.parse::<u32>().is_ok_and(|parsed| parsed.to_string() == *text));
        let fields_fit = parts.iter().skip(1).all(|text| is_field(text));
        (parts.len() == CURSOR_FIELDS && priority_fits && fields_fit)
            .then(|| parts.iter().map(|text| (*text).to_owned()).collect())
            .ok_or(StoreError::BadCursor)
    }
}


fn column(row: &[String], index: usize) -> Result<&str, StoreError> {
    row.get(index).map(String::as_str).ok_or(StoreError::BadAnswer)
}


fn number<Number: std::str::FromStr>(row: &[String], index: usize) -> Result<Number, StoreError> {
    column(row, index)?.parse().map_err(|_bad| StoreError::BadAnswer)
}


pub fn stored_of(row: &[String]) -> Result<StoredFinding, StoreError> {
    let text = |index: usize| column(row, index).map(str::to_owned);
    let fixed = text(COL_FIXED)?;
    Ok(StoredFinding {
        asset: text(COL_ASSET)?,
        ecosystem: text(COL_ECOSYSTEM)?,
        package: text(COL_PACKAGE)?,
        record_id: text(COL_RECORD)?,
        installed_version: text(COL_INSTALLED)?,
        fixed_version: (!fixed.is_empty()).then_some(fixed),
        cvss: number(row, COL_CVSS)?,
        epss: number(row, COL_EPSS)?,
        kev: number(row, COL_KEV)?,
        priority: number(row, COL_PRIORITY)?,
        first_seen_micros: number(row, COL_FIRST_SEEN)?,
        last_seen_micros: number(row, COL_LAST_SEEN)?,
    })
}


/// The cursor of a raw row straight from the store: `StoredValue` when its priority or a key text is outside the grammar (an unmigrated schema).
pub fn raw_cursor(row: &[String]) -> Result<String, StoreError> {
    let keys = [COL_ASSET, COL_ECOSYSTEM, COL_PACKAGE, COL_RECORD]
        .iter()
        .map(|index| column(row, *index))
        .collect::<Result<Vec<_>, _>>()?;
    let priority = column(row, COL_PRIORITY)?;
    let priority_fits = priority.parse::<u32>().is_ok_and(|parsed| parsed.to_string() == priority);
    (priority_fits && keys.iter().all(|text| is_field(text)))
        .then(|| {
            std::iter::once(priority)
                .chain(keys.iter().copied())
                .collect::<Vec<_>>()
                .join(&CURSOR_SEPARATOR.to_string())
        })
        .ok_or(StoreError::StoredValue)
}


/// The page of `rows`, fetched with one row more than `limit`: a row `stored_of` refuses is skipped and counted, the cursor is the raw key of the last of the first `limit`.
pub fn page_of(rows: &[Vec<String>], limit: usize) -> Result<FindingsPage, StoreError> {
    let cursors = rows.iter().map(|row| raw_cursor(row)).collect::<Result<Vec<_>, _>>()?;
    let findings: Vec<StoredFinding> = rows.iter().take(limit).filter_map(|row| stored_of(row).ok()).collect();
    let skipped = rows.len().min(limit) - findings.len();
    let next = cursors.get(limit.saturating_sub(1)).filter(|_last| rows.len() > limit).cloned();
    if skipped > 0 {
        tracing::warn!(skipped, "stored vulnerability findings that cannot be served were skipped");
    }
    Ok(FindingsPage { findings, skipped, next })
}


/// A keyset page of the tenant's open findings, highest priority first then by key; `limit` is 1 to `MAX_PAGE_LIMIT`.
pub async fn open_findings(exec: Executor<'_, '_>, scope: &TenantScope, cursor: Option<&str>, limit: usize) -> Result<FindingsPage, StoreError> {
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        Err(StoreError::BadLimit { max: MAX_PAGE_LIMIT })
    } else {
        let fetch = (limit + 1).to_string();
        let rows = match cursor {
            None => exec(scope.clone(), FIRST_SQL, vec![fetch]).await?,
            Some(text) => {
                let mut params = parse_cursor(text)?;
                params.push(fetch);
                exec(scope.clone(), NEXT_SQL, params).await?
            }
        };
        page_of(&rows, limit)
    }
}


/// The open findings of one asset by priority then key, `limit` (1 to `MAX_FINDINGS_PER_SCAN`) of them and `next` set when more exist; `limit + 1` rows are fetched.
pub async fn open_findings_of_asset(exec: Executor<'_, '_>, scope: &TenantScope, asset: &str, limit: usize) -> Result<FindingsPage, StoreError> {
    if !is_field(asset) {
        Err(StoreError::BadAsset)
    } else if !(1..=MAX_FINDINGS_PER_SCAN).contains(&limit) {
        Err(StoreError::BadLimit { max: MAX_FINDINGS_PER_SCAN })
    } else {
        let rows = exec(scope.clone(), ASSET_SQL, vec![asset.to_owned(), (limit + 1).to_string()]).await?;
        page_of(&rows, limit)
    }
}
