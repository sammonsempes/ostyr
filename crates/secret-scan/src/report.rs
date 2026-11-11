use crate::alerting::path_digest;
use crate::error::ReportError;
use crate::mask::{escape_bounded, escape_marked, masked_excerpt, MAX_FIELD_CHARS};
use crate::model::{Finding, Limits, Report, ScanScope};
use core_pg::scope::tenant_scope;
use glob::Pattern;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::io::Read;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};


#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct RawFinding {
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "StartLine")]
    start_line: u64,
    #[serde(rename = "EndLine")]
    end_line: u64,
    #[serde(rename = "Commit", default)]
    commit: Option<String>,
    #[serde(rename = "RuleID")]
    rule_id: String,
    #[serde(rename = "Match", default)]
    match_text: Zeroizing<String>,
    #[serde(rename = "Secret", default)]
    secret: Zeroizing<String>,
}


pub const MAX_BYTES_CEILING: usize = 1 << 30;


enum Outcome {
    Kept(Finding),
    Skipped,
    Malformed,
}


/// Reads at most `max_bytes` (itself capped at `MAX_BYTES_CEILING`); the buffer grows with the input and is zeroised on drop.
pub fn read_bounded<Source: Read>(reader: Source, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, ReportError> {
    if max_bytes > MAX_BYTES_CEILING {
        Err(ReportError::InvalidLimits { max_bytes })
    } else {
        let mut buffer = Zeroizing::new(Vec::new());
        reader.take(max_bytes as u64 + 1).read_to_end(&mut buffer).map_err(ReportError::Read)?;
        if buffer.len() > max_bytes {
            Err(ReportError::TooLarge { max: max_bytes })
        } else {
            Ok(buffer)
        }
    }
}


fn not_an_array(error: serde_json::Error) -> ReportError {
    ReportError::NotAnArray {
        line: error.line(),
        column: error.column(),
    }
}


fn classify(entry: &RawValue, patterns: &[Pattern], limits: &Limits) -> Outcome {
    match serde_json::from_str::<RawFinding>(entry.get()) {
        Ok(raw) if patterns.iter().any(|pattern| pattern.matches(&raw.file)) => Outcome::Skipped,
        Ok(raw) => Outcome::Kept(Finding {
            file: escape_marked(&raw.file, MAX_FIELD_CHARS),
            file_digest: path_digest(&raw.file),
            start_line: raw.start_line,
            end_line: raw.end_line,
            commit: raw
                .commit
                .as_deref()
                .filter(|commit| !commit.is_empty())
                .map(|commit| escape_bounded(commit, MAX_FIELD_CHARS)),
            rule_id: escape_bounded(&raw.rule_id, MAX_FIELD_CHARS),
            excerpt: masked_excerpt(&raw.match_text, &raw.secret, limits.kept_chars, limits.excerpt_chars),
        }),
        Err(error) => {
            tracing::warn!(category = ?error.classify(), "malformed gitleaks finding skipped");
            Outcome::Malformed
        }
    }
}


/// Parses one gitleaks JSON report for one tenant and scan scope into masked findings.
pub fn parse_report<Source: Read>(reader: Source, limits: &Limits, tenant: &str, scope_id: &str, scope: &ScanScope) -> Result<Report, ReportError> {
    tenant_scope(tenant).map_err(ReportError::InvalidTenant)?;
    let patterns = scope
        .skipped_paths
        .iter()
        .map(|glob| Pattern::new(glob))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReportError::InvalidPattern)?;
    let buffer = read_bounded(reader, limits.max_bytes)?;
    let count = serde_json::from_slice::<Vec<IgnoredAny>>(&buffer).map_err(not_an_array)?.len();
    if count > limits.max_findings {
        Err(ReportError::TooManyFindings { max: limits.max_findings })
    } else {
        let entries = serde_json::from_slice::<Vec<&RawValue>>(&buffer).map_err(not_an_array)?;
        let outcomes = entries.iter().map(|entry| classify(entry, &patterns, limits)).collect::<Vec<_>>();
        let malformed = outcomes.iter().filter(|outcome| matches!(outcome, Outcome::Malformed)).count();
        let skipped = outcomes.iter().filter(|outcome| matches!(outcome, Outcome::Skipped)).count();
        let findings = outcomes
            .into_iter()
            .filter_map(|outcome| match outcome {
                Outcome::Kept(finding) => Some(finding),
                Outcome::Skipped | Outcome::Malformed => None,
            })
            .collect();
        Ok(Report {
            tenant: tenant.to_string(),
            scope_id: scope_id.to_string(),
            findings,
            malformed,
            skipped,
        })
    }
}
