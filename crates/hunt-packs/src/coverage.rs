use crate::model::HuntPack;
use crate::packs::is_pack_id;
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


/// Most loaded packs one report reads; more is refused, never cut.
pub const MAX_REPORT_PACKS: usize = 4_096;


/// Row kinds of both statements: a loaded pack's row, then the count of stored ids no loaded pack has, then the count of over-long ids.
pub const KIND_PACK: i32 = 0;


pub const KIND_UNKNOWN: i32 = 1;


pub const KIND_OVERSIZED: i32 = 2;


/// SQLSTATE of a statement cancelled by `statement_timeout`.
pub const QUERY_CANCELED: &str = "57014";


/// Params: `$2` the loaded pack ids joined by commas (ids never hold one). Rows: at most one per loaded pack (the table key) plus two counts; 64 is the stored id byte cap.
pub const RUNS_SQL: &str = "SELECT 0, pack_id, last_done_end FROM hunt_pack_runs WHERE tenant = $1 AND pack_id = ANY(string_to_array($2, ',')) \
    UNION ALL SELECT 1, '', count(*) FROM hunt_pack_runs WHERE tenant = $1 AND octet_length(pack_id) <= 64 AND pack_id <> ALL(string_to_array($2, ',')) \
    UNION ALL SELECT 2, '', count(*) FROM hunt_pack_runs WHERE tenant = $1 AND octet_length(pack_id) > 64";


/// Params: `$2` period start, `$3` period end, `$4` the loaded ids. Rows with `matches` below 0 are counted apart; the sum is clamped to `i64::MAX` and flagged.
pub const FINDINGS_SQL: &str = "SELECT 0, pack_id, count(*) FILTER (WHERE matches >= 0), \
    LEAST(COALESCE(sum(matches) FILTER (WHERE matches >= 0)::numeric, 0), 9223372036854775807)::bigint, \
    COALESCE(sum(matches) FILTER (WHERE matches >= 0)::numeric > 9223372036854775807, false), count(*) FILTER (WHERE matches < 0) \
    FROM hunt_pack_findings WHERE tenant = $1 AND window_end >= $2 AND window_end < $3 AND octet_length(pack_id) <= 64 \
    AND pack_id = ANY(string_to_array($4, ',')) GROUP BY pack_id \
    UNION ALL SELECT 1, '', count(DISTINCT pack_id), 0, false, 0 FROM hunt_pack_findings \
    WHERE tenant = $1 AND window_end >= $2 AND window_end < $3 AND octet_length(pack_id) <= 64 AND pack_id <> ALL(string_to_array($4, ',')) \
    UNION ALL SELECT 2, '', count(DISTINCT pack_id), 0, false, 0 FROM hunt_pack_findings \
    WHERE tenant = $1 AND window_end >= $2 AND window_end < $3 AND octet_length(pack_id) > 64";


/// A run row: `value` is the last completed run end for `KIND_PACK`, else a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub kind: i32,
    pub pack_id: String,
    pub value: i64,
}


/// A findings row: for `KIND_PACK` the valid windows, their matches and the rows with negative matches, else `windows` is a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsRow {
    pub kind: i32,
    pub pack_id: String,
    pub windows: i64,
    pub matches: i64,
    pub saturated: bool,
    pub negative: i64,
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


/// Counts, never ids: `unknown_packs` and `unknown_finding_packs` are stored ids no loaded pack has, `oversized_*` ids over 64 bytes, `skipped` values that do not parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageReport {
    pub from: i64,
    pub to: i64,
    pub packs_loaded: usize,
    pub techniques: usize,
    pub unknown_packs: u64,
    pub unknown_finding_packs: u64,
    pub oversized_run_ids: u64,
    pub oversized_finding_ids: u64,
    pub skipped: u64,
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
    #[error("{count} packs are loaded, at most {MAX_REPORT_PACKS} are reported")]
    TooManyPacks { count: usize },
    #[error("pack {index} of the list has an invalid id")]
    BadPackId { index: usize },
    #[error("the statement deadline was reached reading {packs} packs from {from} to {to}: narrow the period")]
    DeadlineReached { from: i64, to: i64, packs: usize },
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


fn count_kind(rows: &[(i32, i64)], kind: i32) -> (u64, u64) {
    rows.iter().filter(|row| row.0 == kind).fold((0, 0), |(total, bad), row| {
        u64::try_from(row.1).map_or((total, bad + 1), |count| (total.saturating_add(count), bad))
    })
}


fn stray_kinds(kinds: impl Iterator<Item = i32>) -> u64 {
    kinds.filter(|kind| ![KIND_PACK, KIND_UNKNOWN, KIND_OVERSIZED].contains(kind)).count() as u64
}


fn latest_runs<'rows>(loaded: &BTreeSet<&str>, runs: &'rows [RunRow]) -> (BTreeMap<&'rows str, i64>, u64) {
    let (valid, bad): (Vec<&RunRow>, Vec<&RunRow>) = runs
        .iter()
        .filter(|row| row.kind == KIND_PACK)
        .partition(|row| loaded.contains(row.pack_id.as_str()) && checked_time(row.value).is_ok());
    let latest = valid.into_iter().fold(BTreeMap::new(), |mut table: BTreeMap<&str, i64>, row| {
        table
            .entry(row.pack_id.as_str())
            .and_modify(|end| *end = (*end).max(row.value))
            .or_insert(row.value);
        table
    });
    (latest, bad.len() as u64)
}


fn add_found(total: Found, more: Found) -> Found {
    let sum = total.matches.checked_add(more.matches);
    Found {
        windows: total.windows.saturating_add(more.windows),
        matches: sum.unwrap_or(i64::MAX),
        saturated: total.saturated | more.saturated | sum.is_none(),
    }
}


fn valid_found(row: &FindingsRow) -> Option<Found> {
    let windows = u64::try_from(row.windows).ok()?;
    let negative = u64::try_from(row.negative).ok()?;
    windows.checked_add(negative).filter(|total| *total >= 1)?;
    (row.matches >= 0).then_some(Found {
        windows,
        matches: row.matches,
        saturated: row.saturated,
    })
}


fn found_by_pack<'rows>(loaded: &BTreeSet<&str>, findings: &'rows [FindingsRow]) -> (BTreeMap<&'rows str, Found>, u64) {
    let packed: Vec<&FindingsRow> = findings.iter().filter(|row| row.kind == KIND_PACK).collect();
    let (known, stray): (Vec<&FindingsRow>, Vec<&FindingsRow>) = packed.into_iter().partition(|row| loaded.contains(row.pack_id.as_str()));
    let parsed: Vec<(&FindingsRow, Option<Found>)> = known.into_iter().map(|row| (row, valid_found(row))).collect();
    let bad = parsed.iter().filter(|entry| entry.1.is_none()).count() as u64;
    let negative: u64 = parsed
        .iter()
        .filter(|entry| entry.1.is_some())
        .map(|entry| entry.0.negative.unsigned_abs())
        .fold(0, u64::saturating_add);
    let table = parsed.into_iter().fold(BTreeMap::new(), |mut found: BTreeMap<&str, Found>, entry| {
        entry.1.into_iter().for_each(|one| {
            let merged = found.get(entry.0.pack_id.as_str()).map_or(one, |previous| add_found(*previous, one));
            found.insert(entry.0.pack_id.as_str(), merged);
        });
        found
    });
    (table, bad + stray.len() as u64 + negative)
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
    let run_counts: Vec<(i32, i64)> = runs.iter().map(|row| (row.kind, row.value)).collect();
    let finding_counts: Vec<(i32, i64)> = findings.iter().map(|row| (row.kind, row.windows)).collect();
    let (unknown_runs, bad_unknown_runs) = count_kind(&run_counts, KIND_UNKNOWN);
    let (oversized_runs, bad_oversized_runs) = count_kind(&run_counts, KIND_OVERSIZED);
    let (unknown_findings, bad_unknown_findings) = count_kind(&finding_counts, KIND_UNKNOWN);
    let (oversized_findings, bad_oversized_findings) = count_kind(&finding_counts, KIND_OVERSIZED);
    let stray = stray_kinds(runs.iter().map(|row| row.kind)) + stray_kinds(findings.iter().map(|row| row.kind));
    let by_technique = packs.iter().fold(BTreeMap::new(), |mut groups: BTreeMap<&str, Vec<&HuntPack>>, pack| {
        groups.entry(pack.technique.as_str()).or_default().push(pack);
        groups
    });
    let entries: Vec<TechniqueCoverage> = by_technique
        .iter()
        .map(|(technique, group)| technique_entry(technique, group, &latest, &found, period))
        .collect();
    let bad_counts = bad_unknown_runs + bad_oversized_runs + bad_unknown_findings + bad_oversized_findings;
    CoverageReport {
        from: period.from,
        to: period.to,
        packs_loaded: packs.len(),
        techniques: entries.len(),
        unknown_packs: unknown_runs,
        unknown_finding_packs: unknown_findings,
        oversized_run_ids: oversized_runs,
        oversized_finding_ids: oversized_findings,
        skipped: skipped_runs + skipped_findings + bad_counts + stray,
        entries,
    }
}


/// The loaded ids joined by commas, each once; an id never holds a comma.
pub fn joined_ids(packs: &[HuntPack]) -> String {
    let unique: BTreeSet<&str> = packs.iter().map(|pack| pack.id.as_str()).collect();
    unique.into_iter().collect::<Vec<&str>>().join(",")
}


/// The statement deadline (client or server side) names the period and the pack count; any other failure is a store failure.
pub fn read_error(error: PgError, period: &CoveragePeriod, packs: usize) -> CoverageError {
    match error {
        PgError::StatementTimeout { .. } => CoverageError::DeadlineReached {
            from: period.from,
            to: period.to,
            packs,
        },
        PgError::Server { ref code, .. } if code == QUERY_CANCELED => CoverageError::DeadlineReached {
            from: period.from,
            to: period.to,
            packs,
        },
        other => CoverageError::Store(StateError::from(other)),
    }
}


/// The first pack of the list whose id `is_pack_id` refuses.
pub fn bad_pack_index(packs: &[HuntPack]) -> Option<usize> {
    packs.iter().position(|pack| !is_pack_id(&pack.id))
}


/// Reads the tenant's last runs and finding counts of the loaded packs with two tenant-scoped statements and builds the report.
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
    (packs.len() <= MAX_REPORT_PACKS)
        .then_some(())
        .ok_or(CoverageError::TooManyPacks { count: packs.len() })?;
    bad_pack_index(packs).map_or(Ok(()), |index| Err(CoverageError::BadPackId { index }))?;
    let scope = tenant_scope(tenant).map_err(StateError::from)?;
    let ids = joined_ids(packs);
    let run_rows = runs_exec(&scope, RUNS_SQL, vec![Param::Text(ids.clone())])
        .await
        .map_err(|error| read_error(error, period, packs.len()))?;
    let finding_params = vec![Param::Int(period.from), Param::Int(period.to), Param::Text(ids)];
    let finding_rows = findings_exec(&scope, FINDINGS_SQL, finding_params)
        .await
        .map_err(|error| read_error(error, period, packs.len()))?;
    Ok(coverage_report(packs, &run_rows, &finding_rows, period))
}
