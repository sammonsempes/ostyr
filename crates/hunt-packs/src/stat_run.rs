use crate::run::{failure_line, fetch_reply, HuntOutcome, ReadRequest, RunError};
use crate::stat_model::{stat_pack, StatHunt, Statistic};
use crate::types::StatRow;
use hunt_stats::beacon::beaconing;
use hunt_stats::model::{BeaconLimits, StackLimits};
use hunt_stats::stack::rare_keys;
use metric_alerts::fetch::{FetchSettings, FORMAT_SUFFIX};
use siem_ingest::reader_profile::pin_clause;
use std::collections::BTreeMap;
use std::io::Read;
use std::time::{Duration, Instant};
use tracing::warn;
use ureq::Agent;


/// Longest kept entity or key in characters; a longer one is cut, so a long name still groups with itself.
pub const MAX_FIELD_CHARS: usize = 128;


/// The byte budget of one row: `read_rows` buffers at most this many bytes per allowed row.
pub const MAX_LINE_BYTES: u64 = 1_024;


/// The pack query as a subquery with a row limit one above the bound, so a reply of `max_rows + 1` rows says the bound was passed.
pub fn rows_statement(query: &str, limits: &[(&'static str, String)], max_rows: u32) -> String {
    let body = query.trim_end().trim_end_matches(';').trim_end();
    let cap = u64::from(max_rows) + 1;
    let pins = pin_clause(limits, cap);
    format!("SELECT * FROM (\n{body}\n) LIMIT {cap}{pins}{FORMAT_SUFFIX}")
}


/// One `entity<TAB>key` line; TSV escapes tabs and newlines inside a value, so more than one tab is not a row.
pub fn parse_line(line: &str) -> Result<StatRow, RunError> {
    let (entity, key) = line.split_once('\t').ok_or(RunError::BadRows)?;
    (!key.contains('\t'))
        .then(|| {
            (
                entity.chars().take(MAX_FIELD_CHARS).collect(),
                key.chars().take(MAX_FIELD_CHARS).collect(),
            )
        })
        .ok_or(RunError::BadRows)
}


/// Every line of the body, or `BadRows` for the first line that is not a row (an exception text is never skipped).
pub fn parse_rows(bytes: &[u8]) -> Result<Vec<StatRow>, RunError> {
    let text = std::str::from_utf8(bytes).map_err(|_| RunError::BadRows)?;
    if text.is_empty() {
        Ok(Vec::new())
    } else {
        text.strip_suffix('\n').ok_or(RunError::BadRows)?.split('\n').map(parse_line).collect()
    }
}


/// The rows of a reply, or `None` when it holds more than `max_rows` rows or more bytes than the row budget; at most one byte past the budget is ever buffered.
pub fn read_rows(reader: &mut dyn Read, max_rows: u32) -> Result<Option<Vec<StatRow>>, RunError> {
    let budget = (u64::from(max_rows) + 1) * MAX_LINE_BYTES;
    let mut bytes = Vec::new();
    reader.take(budget + 1).read_to_end(&mut bytes).map_err(RunError::Body)?;
    let lines = bytes.iter().filter(|byte| **byte == b'\n').count() as u64;
    if bytes.len() as u64 > budget || lines > u64::from(max_rows) {
        Ok(None)
    } else {
        parse_rows(&bytes).map(Some)
    }
}


/// Rows of `entity<TAB>unix seconds` grouped by entity.
pub fn timestamps_by_entity(rows: &[StatRow]) -> Result<BTreeMap<&str, Vec<i64>>, RunError> {
    rows.iter()
        .try_fold(BTreeMap::new(), |mut groups: BTreeMap<&str, Vec<i64>>, (entity, seconds)| {
            let value = seconds.parse::<i64>().map_err(|_| RunError::BadRows)?;
            groups.entry(entity.as_str()).or_default().push(value);
            Ok(groups)
        })
}


/// The number of rare keys, or of entities whose events beacon.
pub fn count_matches(hunt: &StatHunt, rows: &[StatRow]) -> Result<u64, RunError> {
    let capacity = hunt.max_rows as usize;
    match hunt.statistic {
        Statistic::Rarity { max_entities } => {
            let limits = StackLimits {
                max_rows: capacity,
                max_keys: capacity,
                max_examples: 0,
            };
            rare_keys(rows, max_entities, &limits)
                .map(|report| report.keys.len() as u64)
                .map_err(RunError::Stats)
        }
        Statistic::Beaconing { min_regularity_ppm } => {
            let limits = BeaconLimits {
                max_timestamps: capacity,
                ..BeaconLimits::default()
            };
            let floor = i128::from(min_regularity_ppm);
            timestamps_by_entity(rows)?
                .values()
                .map(|seconds| {
                    beaconing(seconds, &limits)
                        .map(|score| u64::from(score.is_some_and(|scored| scored.regularity_ppm >= floor)))
                        .map_err(RunError::Stats)
                })
                .sum()
        }
    }
}


/// The outcome of the rows read, or the bound outcome when the reply passed `max_rows`: matches `max_rows + 1`, a finding stored under the bound id.
pub fn outcome_of(hunt: &StatHunt, rows: Option<Vec<StatRow>>) -> Result<HuntOutcome, RunError> {
    match rows {
        Some(found) => {
            let matches = count_matches(hunt, &found)?;
            Ok(HuntOutcome {
                matches,
                finding: matches > hunt.max_matches,
                bound: None,
            })
        }
        None => Ok(HuntOutcome {
            matches: u64::from(hunt.max_rows) + 1,
            finding: true,
            bound: Some(u64::from(hunt.max_rows)),
        }),
    }
}


/// The same reader path as a pack (`fetch_reply`: settings check, pins, one deadline), then the statistic over the rows.
pub fn execute_stat_timed(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    hunt: &StatHunt,
    tenant: &str,
    now: u64,
    budget: &dyn Fn() -> Duration,
) -> Result<HuntOutcome, RunError> {
    let pack = stat_pack(hunt);
    let request = ReadRequest { pack: &pack, tenant, now };
    let response = fetch_reply(agent, settings, password, &request, budget, &|limits| {
        rows_statement(&hunt.query, limits, hunt.max_rows)
    })?;
    let rows = read_rows(&mut response.into_body().into_reader(), hunt.max_rows)?;
    outcome_of(hunt, rows)
}


/// Runs one statistical hunt once for one tenant and window; one `warn!` per failed run and one `warn!` per bound hit.
pub fn run_stat(
    agent: &Agent,
    settings: &FetchSettings,
    password: &str,
    hunt: &StatHunt,
    tenant: &str,
    now: u64,
    remaining: Duration,
) -> Result<HuntOutcome, RunError> {
    let started = Instant::now();
    let outcome = execute_stat_timed(agent, settings, password, hunt, tenant, now, &|| {
        remaining.saturating_sub(started.elapsed())
    });
    match &outcome {
        Err(error) => {
            let line = failure_line(&stat_pack(hunt), tenant, error);
            warn!("{line}");
        }
        Ok(found) if found.bound.is_some() => {
            let id = &hunt.id;
            warn!("stat hunt {id}: more than the row bound, stored as a bound finding");
        }
        Ok(_) => (),
    }
    outcome
}
