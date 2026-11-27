//! The winget update run: one fixed command as SYSTEM, its table parsed by `patch-inventory`, spooled as update lines and one summary line.

use crate::error::RunError;
use crate::model::{RunEnd, RunRequest};
use crate::types::Runner;
use crate::winget_find::{finding_name, FindError, Located};
use patch_inventory::error::{InventoryError, WingetError};
use patch_inventory::limits::{default_limits, MAX_WINGET_UPDATES};
use patch_inventory::model::{CliInventory, Device, Update, WingetSkip, WingetSource};
use patch_inventory::winget::parse_winget_cli;
use serde_json::{json, Map, Value};
use tracing::warn;


pub const WINGET_ARGUMENTS: [&str; 5] = ["upgrade", "--source", "winget", "--accept-source-agreements", "--disable-interactivity"];


pub const SYSTEM_ROOT_PAIR: (&str, &str) = ("SystemRoot", r"C:\Windows");


pub const ENVIRONMENT_PAIRS: usize = 2;


pub const PATH_NAME: &str = "PATH";


pub const WINGET_DEADLINE_SECONDS: u64 = 900;


pub const MIN_UPDATES_INTERVAL_SECONDS: u64 = 3_600;


pub const DEFAULT_UPDATES_INTERVAL_SECONDS: u64 = 21_600;


pub const MAX_UPDATES_INTERVAL_SECONDS: u64 = 86_400;


pub const DATASET_UPDATE: &str = "ostyr.updates";


pub const DATASET_SUMMARY: &str = "ostyr.updates.summary";


pub const ORIGIN: &str = "winget";


pub const DEVICE_PLACEHOLDER: &str = "local";


pub const OUTCOME_OK: &str = "ok";


pub const OUTCOME_ALL_MALFORMED: &str = "all_rows_malformed";


pub const OUTCOME_SPOOL_FULL: &str = "spool_full";


pub const SKIP_EVENT_TOO_LONG: &str = "event_too_long";


/// What one run produced: the lines to spool, in order, the last being the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WingetLines {
    pub lines: Vec<String>,
    pub updates: usize,
}


/// What the summary says apart from the counts.
#[derive(Debug, Clone, Default)]
pub struct SummaryFacts {
    pub run_id: u64,
    pub outcome: String,
    pub count: usize,
    pub exit_code: Option<i32>,
    pub truncated: usize,
    pub oversized: usize,
    pub preamble_lines: usize,
    pub skipped: Map<String, Value>,
}


pub fn winget_arguments() -> Vec<String> {
    WINGET_ARGUMENTS.iter().map(|argument| (*argument).to_owned()).collect()
}


/// Exactly `PATH` (the VCLibs directory) and `SystemRoot`: nothing is inherited.
pub fn winget_environment(vclibs_dir: &str) -> [(&str, &str); ENVIRONMENT_PAIRS] {
    [(PATH_NAME, vclibs_dir), SYSTEM_ROOT_PAIR]
}


pub fn skip_name(skip: WingetSkip) -> &'static str {
    match skip {
        WingetSkip::Malformed => "winget_malformed",
        WingetSkip::UnknownInstalledVersion => "winget_unknown_installed_version",
        WingetSkip::Duplicate => "winget_duplicate",
        WingetSkip::Truncated => "winget_truncated",
        WingetSkip::LineTooLong => "winget_line_too_long",
        WingetSkip::ControlCharacters => "winget_control_characters",
    }
}


pub fn error_name(error: &WingetError) -> &'static str {
    match error {
        WingetError::Input(InventoryError::TooLarge { .. }) => "output_capped",
        WingetError::Input(_) => "input_error",
        WingetError::Encoding => "encoding",
        WingetError::SourceOpenFailed => "source_open_failed",
        WingetError::Exit { .. } => "exit_nonzero",
        WingetError::UnrecognisedLayout => "unrecognised_layout",
        WingetError::TooManyTables { .. } => "too_many_tables",
        WingetError::TooManyUpdates { .. } => "too_many_updates",
        WingetError::FooterUnreadable => "footer_unreadable",
        WingetError::FooterMissing => "footer_missing",
        WingetError::RowAfterTableEnd => "row_after_table_end",
        WingetError::LineBreakInTable => "line_break_in_table",
        WingetError::FooterTooLarge => "footer_too_large",
        WingetError::FooterMismatch { .. } => "footer_mismatch",
    }
}


pub fn error_exit_code(error: &WingetError) -> Option<i32> {
    match error {
        WingetError::Exit { code } => Some(*code),
        _ => None,
    }
}


pub fn update_line(run_id: u64, update: &Update) -> String {
    let mut package = Map::new();
    package.insert("name".to_owned(), json!(update.package));
    package.insert("architecture".to_owned(), json!(update.architecture));
    if let Some(version) = &update.installed_version {
        package.insert("version".to_owned(), json!(version));
    }
    let details = json!({
        "run_id": run_id,
        "candidate_version": update.candidate_version,
        "security": update.security,
        "origin": ORIGIN,
    });
    json!({
        "event": {"kind": "state", "category": ["package"], "type": ["info"], "dataset": DATASET_UPDATE},
        "package": package,
        "ostyr": {"update": details},
    })
    .to_string()
}


pub fn summary_line(facts: &SummaryFacts) -> String {
    let mut skipped = facts.skipped.clone();
    if facts.oversized > 0 {
        skipped.insert(SKIP_EVENT_TOO_LONG.to_owned(), json!(facts.oversized));
    }
    let mut details = Map::new();
    details.insert("run_id".to_owned(), json!(facts.run_id));
    details.insert("count".to_owned(), json!(facts.count));
    details.insert("outcome".to_owned(), json!(facts.outcome));
    details.insert("origin".to_owned(), json!(ORIGIN));
    details.insert("skipped".to_owned(), Value::Object(skipped));
    if let Some(code) = facts.exit_code {
        details.insert("exit_code".to_owned(), json!(code));
    }
    if facts.truncated > 0 {
        details.insert("truncated".to_owned(), json!(facts.truncated));
    }
    if facts.preamble_lines > 0 {
        details.insert("preamble_lines".to_owned(), json!(facts.preamble_lines));
        details.insert("stale_source".to_owned(), json!(true));
    }
    json!({
        "event": {"kind": "state", "category": ["package"], "type": ["info"], "dataset": DATASET_SUMMARY},
        "ostyr": {"update": details},
    })
    .to_string()
}


/// A run that produced no table: one summary line naming why, no update line.
pub fn failure_lines(run_id: u64, outcome: &str, exit_code: Option<i32>) -> WingetLines {
    let facts = SummaryFacts {
        run_id,
        outcome: outcome.to_owned(),
        exit_code,
        ..SummaryFacts::default()
    };
    WingetLines {
        lines: vec![summary_line(&facts)],
        updates: 0,
    }
}


/// The `spool_full` summary that replaces a run whose lines would not fit.
pub fn spool_full_line(run_id: u64) -> String {
    let facts = SummaryFacts {
        run_id,
        outcome: OUTCOME_SPOOL_FULL.to_owned(),
        ..SummaryFacts::default()
    };
    summary_line(&facts)
}


pub fn skipped_map(inventory: &CliInventory) -> Map<String, Value> {
    inventory
        .skipped
        .iter()
        .map(|(skip, total)| (skip_name(*skip).to_owned(), json!(total)))
        .collect()
}


/// The lines of a parsed table: one per update within the caps, then the summary; a table of malformed rows only is never `ok`.
pub fn inventory_lines(run_id: u64, line_limit: usize, inventory: &CliInventory) -> WingetLines {
    let scanned = inventory.updates.len().min(MAX_WINGET_UPDATES);
    let mut lines: Vec<String> = inventory
        .updates
        .iter()
        .take(scanned)
        .map(|update| update_line(run_id, update))
        .filter(|line| line.len() <= line_limit)
        .collect();
    let all_malformed = inventory.updates.is_empty() && inventory.skipped.get(&WingetSkip::Malformed).is_some_and(|total| *total > 0);
    let facts = SummaryFacts {
        run_id,
        outcome: if all_malformed { OUTCOME_ALL_MALFORMED } else { OUTCOME_OK }.to_owned(),
        count: lines.len(),
        truncated: inventory.updates.len() - scanned,
        oversized: scanned - lines.len(),
        preamble_lines: inventory.preamble_lines,
        skipped: skipped_map(inventory),
        ..SummaryFacts::default()
    };
    let updates = lines.len();
    lines.push(summary_line(&facts));
    WingetLines { lines, updates }
}


pub fn device_of() -> Device {
    Device {
        tenant: DEVICE_PLACEHOLDER.to_owned(),
        device_id: DEVICE_PLACEHOLDER.to_owned(),
    }
}


/// Parses the captured bytes with the exit code of the run: a parser error is one named summary line and no update line.
pub fn parsed_lines(run_id: u64, line_limit: usize, output: &[u8], code: i32) -> WingetLines {
    match parse_winget_cli(&device_of(), output, code, WingetSource::Winget, &default_limits()) {
        Ok(inventory) => inventory_lines(run_id, line_limit, &inventory),
        Err(error) => failure_lines(run_id, error_name(&error), error_exit_code(&error)),
    }
}


pub fn run_failure_lines(run_id: u64, error: &RunError) -> WingetLines {
    let text = error.to_string();
    warn!(error = %text, "winget run failed");
    failure_lines(run_id, "spawn_failed", None)
}


/// One run through the injected runner: the program, arguments and environment are consts and the one directory found.
pub fn winget_lines(runner: Runner<'_>, located: &Result<Located, FindError>, run_id: u64, line_limit: usize) -> WingetLines {
    match located {
        Err(error) => failure_lines(run_id, finding_name(error), None),
        Ok(found) => {
            let args = winget_arguments();
            let pairs = winget_environment(&found.vclibs_dir);
            let request = RunRequest {
                program: &found.winget,
                args: &args,
                max_bytes: default_limits().max_bytes,
                deadline_seconds: WINGET_DEADLINE_SECONDS,
                environment: Some(&pairs),
            };
            let mut output: Vec<u8> = Vec::new();
            match runner(&request, &mut |chunk| output.extend_from_slice(chunk)) {
                Ok(RunEnd::Done) => parsed_lines(run_id, line_limit, &output, 0),
                Ok(RunEnd::Failed(Some(code))) => parsed_lines(run_id, line_limit, &output, code),
                Ok(RunEnd::Failed(None)) => failure_lines(run_id, "no_exit_code", None),
                Ok(RunEnd::Capped) => failure_lines(run_id, "output_capped", None),
                Ok(RunEnd::Deadline) => failure_lines(run_id, "deadline", None),
                Err(error) => run_failure_lines(run_id, &error),
            }
        }
    }
}
