use crate::model::HuntPack;
use crate::schedule::{checked_time, ScheduleError};
use crate::store::{Param, StateError};
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use thiserror::Error;


pub const SECONDS_PER_DAY: i64 = 86_400;


pub const MAX_REPORT_DAYS: i64 = 400;


/// Most rows of either statement that are read; one more is fetched to tell "more than".
pub const MAX_STORED_ROWS: i64 = 4_096;


/// Params: `$2` row limit. At most one row per pack (the table key); the literal 64 is the stored id byte cap.
pub const RUNS_SQL: &str =
    "SELECT pack_id, last_done_end FROM hunt_pack_runs WHERE tenant = $1 AND octet_length(pack_id) <= 64 ORDER BY pack_id LIMIT $2";


/// Params: `$2` period start, `$3` period end, `$4` row limit. One row per pack; the sum is clamped to `i64::MAX` and flagged.
pub const FINDINGS_SQL: &str = "SELECT pack_id, count(*), LEAST(sum(matches), 9223372036854775807)::bigint, sum(matches) > 9223372036854775807 \
    FROM hunt_pack_findings WHERE tenant = $1 AND window_end >= $2 AND window_end < $3 AND octet_length(pack_id) <= 64 \
    GROUP BY pack_id ORDER BY pack_id LIMIT $4";


/// The last completed run end of one stored pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub pack_id: String,
    pub last_done_end: i64,
}


/// The finding windows of one stored pack that end inside the period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsRow {
    pub pack_id: String,
    pub windows: i64,
    pub matches: i64,
    pub saturated: bool,
}


/// The period `[from, to)` in unix seconds, checked by `check_period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoveragePeriod {
    pub from: i64,
    pub to: i64,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechniqueState {
    NotHunted,
    HuntedClear,
    HuntedFindings,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TechniqueCoverage {
    pub technique: String,
    pub packs: Vec<String>,
    pub last_hunted: Option<i64>,
    pub state: TechniqueState,
    pub findings: u64,
    pub matches: i64,
    pub matches_saturated: bool,
}


/// `unknown_packs` counts distinct stored pack ids no loaded pack has, `skipped` the rows of a loaded pack that do not parse, `truncated` a statement that hit `MAX_STORED_ROWS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageReport {
    pub from: i64,
    pub to: i64,
    pub packs_loaded: usize,
    pub techniques: usize,
    pub unknown_packs: usize,
    pub skipped: usize,
    pub truncated: bool,
    pub entries: Vec<TechniqueCoverage>,
}


#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("`{field}` is outside years 0 to 9999")]
    OutOfRange {
        field: &'static str,
        #[source]
        source: ScheduleError,
    },
    #[error("`{field}` must be after `from`")]
    Reversed { field: &'static str },
    #[error("`{field}` is more than {MAX_REPORT_DAYS} days after `from`")]
    TooLong { field: &'static str },
    #[error("the store failed")]
    Store(#[from] StateError),
}


#[derive(Debug, Clone, Copy, Default)]
struct Found {
    windows: u64,
    matches: i64,
    saturated: bool,
}


/// The period `[from, to)`: both in years 0 to 9999, `to` after `from`, at most `MAX_REPORT_DAYS` long.
pub fn check_period(from: i64, to: i64) -> Result<CoveragePeriod, CoverageError> {
    checked_time(from).map_err(|source| CoverageError::OutOfRange { field: "from", source })?;
    checked_time(to).map_err(|source| CoverageError::OutOfRange { field: "to", source })?;
    (to > from).then_some(()).ok_or(CoverageError::Reversed { field: "to" })?;
    (to - from <= MAX_REPORT_DAYS * SECONDS_PER_DAY)
        .then_some(CoveragePeriod { from, to })
        .ok_or(CoverageError::TooLong { field: "to" })
}


fn latest_runs<'rows>(loaded: &BTreeSet<&str>, runs: &'rows [RunRow]) -> (BTreeMap<&'rows str, i64>, usize) {
    let (valid, bad): (Vec<&RunRow>, Vec<&RunRow>) = runs
        .iter()
        .filter(|row| loaded.contains(row.pack_id.as_str()))
        .partition(|row| checked_time(row.last_done_end).is_ok());
    let latest = valid.into_iter().fold(BTreeMap::new(), |mut table: BTreeMap<&str, i64>, row| {
        table
            .entry(row.pack_id.as_str())
            .and_modify(|end| *end = (*end).max(row.last_done_end))
            .or_insert(row.last_done_end);
        table
    });
    (latest, bad.len())
}


fn add_found(total: Found, more: Found) -> Found {
    let sum = total.matches.checked_add(more.matches);
    Found {
        windows: total.windows.saturating_add(more.windows),
        matches: sum.unwrap_or(i64::MAX),
        saturated: total.saturated | more.saturated | sum.is_none(),
    }
}


fn found_by_pack<'rows>(loaded: &BTreeSet<&str>, findings: &'rows [FindingsRow]) -> (BTreeMap<&'rows str, Found>, usize) {
    let (valid, bad): (Vec<&FindingsRow>, Vec<&FindingsRow>) = findings
        .iter()
        .filter(|row| loaded.contains(row.pack_id.as_str()))
        .partition(|row| row.windows >= 1 && row.matches >= 0);
    let table = valid.into_iter().fold(BTreeMap::new(), |mut found: BTreeMap<&str, Found>, row| {
        let one = Found {
            windows: row.windows.unsigned_abs(),
            matches: row.matches,
            saturated: row.saturated,
        };
        let merged = found.get(row.pack_id.as_str()).map_or(one, |previous| add_found(*previous, one));
        found.insert(row.pack_id.as_str(), merged);
        found
    });
    (table, bad.len())
}


fn technique_entry(
    technique: &str,
    group: &[&HuntPack],
    runs: &BTreeMap<&str, i64>,
    found: &BTreeMap<&str, Found>,
    period: &CoveragePeriod,
) -> TechniqueCoverage {
    let ids: BTreeSet<&str> = group.iter().map(|pack| pack.id.as_str()).collect();
    let ends: Vec<i64> = ids.iter().filter_map(|id| runs.get(id).copied()).collect();
    let totals = ids.iter().filter_map(|id| found.get(id).copied()).fold(Found::default(), add_found);
    let state = if totals.windows > 0 {
        TechniqueState::HuntedFindings
    } else if ends.iter().any(|end| (period.from..period.to).contains(end)) {
        TechniqueState::HuntedClear
    } else {
        TechniqueState::NotHunted
    };
    TechniqueCoverage {
        technique: technique.to_owned(),
        packs: ids.iter().map(|id| (*id).to_owned()).collect(),
        last_hunted: ends.iter().copied().max(),
        state,
        findings: totals.windows,
        matches: totals.matches,
        matches_saturated: totals.saturated,
    }
}


/// One entry per technique of the loaded packs; a run ending in `[from, to)` or a finding window ending in it counts as hunted in the period.
pub fn coverage_report(packs: &[HuntPack], runs: &[RunRow], findings: &[FindingsRow], period: &CoveragePeriod) -> CoverageReport {
    let loaded: BTreeSet<&str> = packs.iter().map(|pack| pack.id.as_str()).collect();
    let (latest, skipped_runs) = latest_runs(&loaded, runs);
    let (found, skipped_findings) = found_by_pack(&loaded, findings);
    let stored_ids = runs
        .iter()
        .map(|row| row.pack_id.as_str())
        .chain(findings.iter().map(|row| row.pack_id.as_str()));
    let unknown: BTreeSet<&str> = stored_ids.filter(|id| !loaded.contains(id)).collect();
    let by_technique = packs.iter().fold(BTreeMap::new(), |mut groups: BTreeMap<&str, Vec<&HuntPack>>, pack| {
        groups.entry(pack.technique.as_str()).or_default().push(pack);
        groups
    });
    let entries: Vec<TechniqueCoverage> = by_technique
        .iter()
        .map(|(technique, group)| technique_entry(technique, group, &latest, &found, period))
        .collect();
    CoverageReport {
        from: period.from,
        to: period.to,
        packs_loaded: packs.len(),
        techniques: entries.len(),
        unknown_packs: unknown.len(),
        skipped: skipped_runs + skipped_findings,
        truncated: false,
        entries,
    }
}


fn cap_rows<Row>(mut rows: Vec<Row>) -> (Vec<Row>, bool) {
    let cap = usize::try_from(MAX_STORED_ROWS).unwrap_or(usize::MAX);
    let over = rows.len() > cap;
    rows.truncate(cap);
    (rows, over)
}


/// Reads the tenant's last runs and finding counts with two tenant-scoped statements and builds the report.
pub async fn read_coverage<RunsExec, RunsPending, FindingsExec, FindingsPending>(
    runs_exec: &mut RunsExec,
    findings_exec: &mut FindingsExec,
    tenant: &str,
    packs: &[HuntPack],
    period: &CoveragePeriod,
) -> Result<CoverageReport, CoverageError>
where
    RunsExec: FnMut(&TenantScope, &'static str, Vec<Param>) -> RunsPending,
    RunsPending: Future<Output = Result<Vec<RunRow>, PgError>>,
    FindingsExec: FnMut(&TenantScope, &'static str, Vec<Param>) -> FindingsPending,
    FindingsPending: Future<Output = Result<Vec<FindingsRow>, PgError>>,
{
    let scope = tenant_scope(tenant).map_err(StateError::from)?;
    let fetch = MAX_STORED_ROWS + 1;
    let run_rows = runs_exec(&scope, RUNS_SQL, vec![Param::Int(fetch)]).await.map_err(StateError::from)?;
    let finding_params = vec![Param::Int(period.from), Param::Int(period.to), Param::Int(fetch)];
    let finding_rows = findings_exec(&scope, FINDINGS_SQL, finding_params).await.map_err(StateError::from)?;
    let (kept_runs, runs_over) = cap_rows(run_rows);
    let (kept_findings, findings_over) = cap_rows(finding_rows);
    let report = coverage_report(packs, &kept_runs, &kept_findings, period);
    Ok(CoverageReport {
        truncated: runs_over | findings_over,
        ..report
    })
}
