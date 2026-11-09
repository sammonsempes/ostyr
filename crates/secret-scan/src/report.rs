use crate::error::ReportError;
use crate::mask::{escape_bounded, masked_excerpt, MAX_FIELD_CHARS};
use crate::model::{Finding, Limits, Report, ScanScope};
use glob::Pattern;
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
    match_text: String,
    #[serde(rename = "Secret", default)]
    secret: String,
}


enum Outcome {
    Kept(Finding),
    Skipped,
    Malformed,
}


/// Reads at most `max_bytes`; the buffer is allocated once, so no unzeroed copy is left behind, and zeroised on drop.
pub fn read_bounded<Source: Read>(reader: Source, max_bytes: usize) -> Result<Zeroizing<Vec<u8>>, ReportError> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(max_bytes.saturating_add(1)));
    reader.take(max_bytes as u64 + 1).read_to_end(&mut buffer).map_err(ReportError::Read)?;
    if buffer.len() > max_bytes {
        Err(ReportError::TooLarge { max: max_bytes })
    } else {
        Ok(buffer)
    }
}


fn classify(entry: &RawValue, patterns: &[Pattern], limits: &Limits) -> Outcome {
    match serde_json::from_str::<RawFinding>(entry.get()) {
        Ok(raw) if patterns.iter().any(|pattern| pattern.matches(&raw.file)) => Outcome::Skipped,
        Ok(raw) => Outcome::Kept(Finding {
            file: escape_bounded(&raw.file, MAX_FIELD_CHARS),
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
    let patterns = scope
        .skipped_paths
        .iter()
        .map(|glob| Pattern::new(glob))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReportError::InvalidPattern)?;
    let buffer = read_bounded(reader, limits.max_bytes)?;
    let entries = serde_json::from_slice::<Vec<&RawValue>>(&buffer).map_err(|error| ReportError::NotAnArray {
        line: error.line(),
        column: error.column(),
    })?;
    if entries.len() > limits.max_findings {
        Err(ReportError::TooManyFindings { max: limits.max_findings })
    } else {
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
