//! One `ostyr-grc` round: gather the indicator files, evaluate each framework, store each report and name every outcome.

use crate::error::{GrcError, StoreError};
use crate::evaluate::evaluate_framework;
use crate::inputs::load_indicators;
use crate::model::{Framework, IndicatorValue, ManualEvidence};
use crate::report::{build_report, ComplianceReport};
use crate::risk::Register;
use crate::service::Declarations;
use crate::store::{get_report, list_reports, store_report_with_cap, StoreOutcome};
use crate::types::{ClockFn, Executor};
use alerts::pg::pg_executor;
use core_pg::connect::connect;
use core_pg::error::PgError;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{error, info, warn};


pub const MAX_INDICATOR_FILES: usize = 16;


pub const MAX_DIRECTORY_ENTRIES: usize = 1_000;


pub const MAX_NAMED_SKIPPED: usize = 8;


pub const REASON_FILES_CUT: &str = "indicator_files_cut";


pub const MAX_DIRECTORY_SCAN: usize = 100_000;


pub const INDICATOR_EXTENSION: &str = "json";


/// What the indicator directory gave: the usable values and a count of everything refused alone.
#[derive(Debug, Default, PartialEq)]
pub struct Gathered {
    pub values: Vec<IndicatorValue>,
    pub files: usize,
    pub refused_files: usize,
    pub beyond_cap: usize,
    pub foreign: usize,
    pub duplicated: usize,
    pub entries: usize,
    pub scan_cut: bool,
    pub unreadable_directory: bool,
}


#[derive(Debug, Default, PartialEq, Eq)]
pub struct RoundSummary {
    pub stored: usize,
    pub already_stored: usize,
    pub cap_reached: usize,
    pub failed: usize,
    pub unknown: usize,
    pub changed: usize,
    pub no_evidence: usize,
    pub unavailable: bool,
}


#[derive(Debug, Error)]
pub enum RoundFault {
    #[error("the framework could not be evaluated into a report")]
    Report(#[from] GrcError),
    #[error("the report could not be stored")]
    Store(#[from] StoreError),
}


#[derive(Debug, Deserialize)]
pub struct PreviousRow {
    pub id: String,
    pub evidence_digest: Option<String>,
}


#[derive(Debug, Deserialize)]
pub struct PreviousBody {
    pub controls: Vec<PreviousRow>,
}


/// A store whose statement may have committed (a lost reply, a bad answer after the statement) is unknown, never "not stored".
pub fn store_outcome_unknown(failure: &StoreError) -> bool {
    match failure {
        StoreError::Store(PgError::Server { .. } | PgError::StatementTimeout { .. } | PgError::ConnectTimeout { .. }) => false,
        StoreError::Store(_) | StoreError::BadRow => true,
        _ => false,
    }
}


pub fn fault_class(fault: &RoundFault) -> &'static str {
    match fault {
        RoundFault::Report(_) => "report",
        RoundFault::Store(StoreError::CapReached { .. }) => "cap_reached",
        RoundFault::Store(failure) if store_outcome_unknown(failure) => "unknown",
        RoundFault::Store(_) => "store",
    }
}


/// A fixed category of a refused indicator file: the error text holds the file path, which a hostile name could forge into a log line.
pub fn refusal_class(refusal: &GrcError) -> &'static str {
    match refusal {
        GrcError::Config(_) => "unreadable, not a regular file, or too large",
        GrcError::Json { .. } => "malformed JSON",
        GrcError::Invalid { .. } => "invalid content",
        _ => "refused",
    }
}


/// Every entry is counted up to `scan_cap`; the files named `*.json` are all kept, so foreign entries never hide a producer file.
pub fn indicator_files(directory: &Path, scan_cap: usize) -> std::io::Result<(Vec<PathBuf>, usize, bool)> {
    let mut listing = std::fs::read_dir(directory)?;
    let listed: Vec<std::io::Result<PathBuf>> = listing.by_ref().take(scan_cap).map(|found| found.map(|entry| entry.path())).collect();
    let scan_cut = listing.next().is_some();
    let entries = listed.len();
    Ok((indicator_paths(listed), entries, scan_cut))
}


/// The `*.json` paths, sorted; unreadable entries are counted in one warning per listing.
pub fn indicator_paths(listed: Vec<std::io::Result<PathBuf>>) -> Vec<PathBuf> {
    let unreadable = listed.iter().filter(|entry| entry.is_err()).count();
    if unreadable > 0 {
        warn!(unreadable, "indicator directory entries unreadable, skipped");
    }
    let mut files: Vec<PathBuf> = listed
        .into_iter()
        .flatten()
        .filter(|path| path.extension().is_some_and(|extension| extension == INDICATOR_EXTENSION))
        .collect();
    files.sort();
    files
}


/// Files beyond the cap are one warning naming the count and the first names; their controls are marked by `mark_files_cut`.
pub fn warn_files_cut(skipped: &[PathBuf]) {
    if !skipped.is_empty() {
        let count = skipped.len();
        let names: Vec<_> = skipped.iter().take(MAX_NAMED_SKIPPED).map(|path| path.file_name()).collect();
        let omitted = count.saturating_sub(MAX_NAMED_SKIPPED);
        warn!(count, ?names, omitted, "indicator files beyond the cap skipped, their controls are cut");
    }
}


/// With files cut, a technical control with no value may be fed by a skipped file: its row carries the reason `indicator_files_cut`.
pub fn mark_files_cut(report: &mut ComplianceReport, framework: &Framework, values: &[IndicatorValue]) {
    report.controls.iter_mut().for_each(|row| {
        let fed = framework
            .controls
            .iter()
            .find(|control| control.id == row.id)
            .and_then(|control| control.indicator.as_ref())
            .map(|indicator| values.iter().any(|value| &value.name == indicator));
        if fed == Some(false) {
            row.reason = Some(REASON_FILES_CUT.to_owned());
        }
    });
}


/// An unreadable file is refused alone and named; values of another tenant are dropped; a name given twice is dropped everywhere.
pub fn gather_indicators(directory: &Path, tenant: &str) -> Gathered {
    gather_indicators_bounded(directory, tenant, MAX_DIRECTORY_SCAN)
}


/// `gather_indicators` with an explicit scan bound; a directory over `MAX_DIRECTORY_ENTRIES` or cut by the scan bound is a named warning.
pub fn gather_indicators_bounded(directory: &Path, tenant: &str, scan_cap: usize) -> Gathered {
    match indicator_files(directory, scan_cap) {
        Err(failure) => {
            let kind = failure.kind();
            warn!(?kind, "indicator directory unreadable, every technical control has no evidence");
            Gathered {
                unreadable_directory: true,
                ..Gathered::default()
            }
        }
        Ok((files, entries, scan_cut)) => {
            if entries > MAX_DIRECTORY_ENTRIES || scan_cut {
                let max = MAX_DIRECTORY_ENTRIES;
                warn!(entries, scan_cut, max, "indicator directory over its entry bound");
            }
            let beyond_cap = files.len().saturating_sub(MAX_INDICATOR_FILES);
            warn_files_cut(files.get(MAX_INDICATOR_FILES..).unwrap_or(&[]));
            let read: Vec<Option<Vec<IndicatorValue>>> = files
                .iter()
                .take(MAX_INDICATOR_FILES)
                .map(|path| {
                    load_indicators(path)
                        .inspect_err(|refusal| {
                            let class = refusal_class(refusal);
                            warn!(file = ?path.file_name(), class, "indicator file refused, its controls have no evidence");
                        })
                        .ok()
                })
                .collect();
            let refused_files = read.iter().filter(|outcome| outcome.is_none()).count();
            let all: Vec<IndicatorValue> = read.into_iter().flatten().flatten().collect();
            let total = all.len();
            let own: Vec<IndicatorValue> = all.into_iter().filter(|value| value.tenant == tenant).collect();
            let foreign = total - own.len();
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            own.iter().for_each(|value| *counts.entry(value.name.clone()).or_default() += 1);
            let duplicated = counts.values().filter(|count| **count > 1).count();
            counts
                .iter()
                .filter(|(_, count)| **count > 1)
                .for_each(|(name, _)| warn!(indicator = %name, "indicator given more than once, no evidence for it"));
            let values: Vec<IndicatorValue> = own.into_iter().filter(|value| counts.get(&value.name) == Some(&1)).collect();
            Gathered {
                values,
                files: files.len().min(MAX_INDICATOR_FILES),
                refused_files,
                beyond_cap,
                foreign,
                duplicated,
                entries,
                scan_cut,
                unreadable_directory: false,
            }
        }
    }
}


/// The evidence digest per control of the last stored report of the framework, none when there is no report yet.
pub async fn previous_digests(exec: Executor<'_, '_>, tenant: &str, framework: &str) -> Result<BTreeMap<String, String>, StoreError> {
    let newest = list_reports(exec, tenant, Some(framework), 1).await?;
    match newest.first() {
        None => Ok(BTreeMap::new()),
        Some(meta) => {
            let stored = get_report(exec, tenant, meta.id).await?.ok_or(StoreError::BadRow)?;
            let body: PreviousBody = serde_json::from_str(&stored.body).map_err(|_refused| StoreError::BadRow)?;
            Ok(body
                .controls
                .into_iter()
                .filter_map(|row| row.evidence_digest.map(|digest| (row.id, digest)))
                .collect())
        }
    }
}


pub fn changed_controls(report: &ComplianceReport, previous: &BTreeMap<String, String>) -> usize {
    report
        .controls
        .iter()
        .filter(|row| previous.get(&row.id).map(String::as_str) != row.evidence_digest.as_deref())
        .count()
}


pub fn report_of(
    tenant: &str,
    framework: &Framework,
    (indicators, manual): (&[IndicatorValue], &[ManualEvidence]),
    now: OffsetDateTime,
) -> Result<ComplianceReport, RoundFault> {
    let evaluated = evaluate_framework(tenant, framework, indicators, manual, now)?;
    let register = Register {
        tenant: tenant.to_owned(),
        risks: Vec::new(),
        actions: Vec::new(),
    };
    Ok(build_report(framework, &evaluated, &register, now.date())?)
}


/// One framework: the stored outcome, the controls whose evidence changed since the last report, and the controls with no evidence.
pub async fn framework_round(
    exec: Executor<'_, '_>,
    declarations: &Declarations,
    framework: &Framework,
    (indicators, cut, now): (&[IndicatorValue], bool, OffsetDateTime),
) -> Result<(StoreOutcome, usize, usize), RoundFault> {
    let tenant = declarations.settings.tenant.as_str();
    let mut report = report_of(tenant, framework, (indicators, &declarations.manual), now)?;
    if cut {
        mark_files_cut(&mut report, framework, indicators);
    }
    let previous = previous_digests(exec, tenant, &report.framework).await.unwrap_or_else(|fault| {
        warn!(%fault, "previous report unreadable, every control counts as changed");
        BTreeMap::new()
    });
    let changed = changed_controls(&report, &previous);
    let outcome = store_report_with_cap(exec, tenant, &report, declarations.settings.max_reports).await?;
    Ok((outcome, changed, report.counts.not_assessable))
}


/// Every framework of the snapshot is attempted; each outcome is logged by name and counted, a cap is an error line.
pub async fn run_round_with(exec: Executor<'_, '_>, declarations: &Declarations, gathered: &Gathered, now: OffsetDateTime) -> RoundSummary {
    let mut summary = RoundSummary::default();
    for framework in &declarations.frameworks {
        let name = framework.framework.as_str();
        match framework_round(
            exec,
            declarations,
            framework,
            (&gathered.values, gathered.beyond_cap > 0 || gathered.scan_cut, now),
        )
        .await
        {
            Ok((outcome, changed, no_evidence)) => {
                let (label, id) = match outcome {
                    StoreOutcome::Stored { id } => ("stored", id),
                    StoreOutcome::AlreadyStored { id } => ("already_stored", id),
                };
                info!(framework = name, outcome = label, id, changed, no_evidence, "framework round done");
                summary.stored += usize::from(label == "stored");
                summary.already_stored += usize::from(label == "already_stored");
                summary.changed += changed;
                summary.no_evidence += no_evidence;
            }
            Err(fault) => {
                let class = fault_class(&fault);
                if class == "cap_reached" {
                    error!(framework = name, class, "report cap reached, nothing stored and nothing deleted");
                    summary.cap_reached += 1;
                } else if class == "unknown" {
                    error!(framework = name, class, "report store outcome unknown, the report may be stored");
                    summary.unknown += 1;
                } else {
                    warn!(framework = name, class, "framework round failed");
                    summary.failed += 1;
                }
            }
        }
    }
    summary
}


/// One round: read the indicator directory, connect with the snapshot's database settings, run every framework.
pub async fn run_round(declarations: &Declarations, clock: &ClockFn) -> RoundSummary {
    let now = clock();
    let gathered = gather_indicators(&declarations.settings.indicators_dir, &declarations.settings.tenant);
    let files = gathered.files;
    let refused_files = gathered.refused_files;
    let beyond_cap = gathered.beyond_cap;
    let foreign = gathered.foreign;
    let duplicated = gathered.duplicated;
    info!(files, refused_files, beyond_cap, foreign, duplicated, "indicator files read");
    let summary = match connect(&declarations.pg).await {
        Ok(client) => {
            let exec = pg_executor(&client, Duration::from_secs(declarations.pg.statement_timeout_secs));
            run_round_with(&exec, declarations, &gathered, now).await
        }
        Err(fault) => {
            warn!(%fault, "database unreachable, round not run, retrying after the pause");
            RoundSummary {
                unavailable: true,
                ..RoundSummary::default()
            }
        }
    };
    let (stored, already_stored, cap_reached) = (summary.stored, summary.already_stored, summary.cap_reached);
    let (failed, unknown) = (summary.failed, summary.unknown);
    info!(stored, already_stored, cap_reached, failed, unknown, "grc round done");
    summary
}
