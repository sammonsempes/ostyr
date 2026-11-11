//! Secret findings as alerts of the alert store (spec section 23); nothing derived from the secret reaches an alert.

use crate::model::{Finding, Report};
use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_TITLE_CHARS};
use alerts::types::Executor;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::json;
use sha2::{Digest, Sha256};


pub const RULE_PREFIX: &str = "secret.";


pub const MAX_TOKEN_CHARS: usize = 100;


pub const MAX_PATH_CHARS: usize = 200;


pub const TOKEN_PUNCTUATION: &str = "._-";


pub const DIGEST_CHARS: usize = 12;


pub const COMMIT_HEX_CHARS: usize = 40;


pub const NO_COMMIT: &str = "none";


/// Alphanumeric first (so never a leading `-`), then alphanumerics and `._-`, at most `MAX_TOKEN_CHARS` characters.
pub fn is_token(text: &str) -> bool {
    let mut characters = text.chars();
    text.chars().take(MAX_TOKEN_CHARS + 1).count() <= MAX_TOKEN_CHARS
        && characters.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && characters.all(|next| next.is_ascii_alphanumeric() || TOKEN_PUNCTUATION.contains(next))
}


/// Printable ASCII (space included), no leading `-`, 1 to `MAX_PATH_CHARS` characters.
pub fn is_path(text: &str) -> bool {
    !text.is_empty()
        && text.chars().take(MAX_PATH_CHARS + 1).count() <= MAX_PATH_CHARS
        && text.chars().all(|character| character == ' ' || character.is_ascii_graphic())
        && !text.starts_with('-')
}


/// Lowercase hexadecimal SHA-256 of the path text.
pub fn path_digest(path: &str) -> String {
    format!("{:x}", Sha256::digest(path.as_bytes()))
}


/// `#` and the first `DIGEST_CHARS` hex characters of a path digest.
pub fn short_digest(digest: &str) -> String {
    format!("#{}", digest.chars().take(DIGEST_CHARS).collect::<String>())
}


/// Forty lowercase hex characters.
pub fn is_commit(text: &str) -> bool {
    text.len() == COMMIT_HEX_CHARS && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


/// The commit id, `NO_COMMIT` when the finding has none, `None` when the text is not a commit id.
pub fn commit_label(finding: &Finding) -> Option<&str> {
    finding
        .commit
        .as_deref()
        .map_or(Some(NO_COMMIT), |commit| is_commit(commit).then_some(commit))
}


/// The path when it passes the grammar, its short digest otherwise.
pub fn shown_path(path: &str, digest: &str) -> String {
    if is_path(path) {
        path.to_owned()
    } else {
        short_digest(digest)
    }
}


/// The title with the path; with its short digest instead when the path would push the title over the store's limit.
pub fn title_of(finding: &Finding) -> String {
    let long = format!(
        "Secret {} in {}:{}",
        finding.rule_id,
        shown_path(&finding.file, &finding.file_digest),
        finding.start_line
    );
    if long.chars().count() > MAX_TITLE_CHARS {
        format!(
            "Secret {} in {}:{}",
            finding.rule_id,
            short_digest(&finding.file_digest),
            finding.start_line
        )
    } else {
        long
    }
}


/// One alert, or `None` when the report is of another tenant or the scope id, rule id or commit is outside its grammar.
pub fn alert_of(scope: &TenantScope, report: &Report, finding: &Finding, now_micros: u64) -> Option<Alert> {
    let commit = commit_label(finding)?;
    let valid = report.tenant == tenant_of(scope) && is_token(&report.scope_id) && is_token(&finding.rule_id);
    let tenant = tenant_of(scope).to_owned();
    let rule_id = format!("{RULE_PREFIX}{}", finding.rule_id);
    let event_ids = vec![
        format!("scope:{}", report.scope_id),
        format!("file:{}", finding.file_digest),
        format!("line:{}", finding.start_line),
        format!("commit:{commit}"),
    ];
    let created_micros = now_micros.min(MAX_CREATED_MICROS);
    valid.then(|| Alert {
        id: alert_id(&tenant, &rule_id, &event_ids),
        tenant,
        rule_title: title_of(finding),
        severity: Severity::High,
        event_time: created_micros.to_string(),
        created_micros,
        host_name: None,
        user_name: None,
        summary: summarise(&json!({
            "scope_id": report.scope_id,
            "file": shown_path(&finding.file, &finding.file_digest),
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "commit": commit,
            "rule_id": finding.rule_id,
        })),
        rule_id,
        event_ids,
    })
}


/// One alert per distinct leak (sorted by id, duplicates merged); a report of another tenant raises none; rejected findings are counted in a warning.
pub fn secret_alerts(scope: &TenantScope, report: &Report, now_micros: u64) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = report
        .findings
        .iter()
        .filter_map(|finding| alert_of(scope, report, finding, now_micros))
        .collect();
    let foreign_tenant = if report.tenant == tenant_of(scope) { 0 } else { report.findings.len() };
    let rejected = report.findings.len().saturating_sub(foreign_tenant).saturating_sub(alerts.len());
    alerts.sort_by(|left, right| left.id.cmp(&right.id));
    alerts.dedup_by(|right, left| right.id == left.id);
    if rejected > 0 || foreign_tenant > 0 {
        tracing::warn!(rejected, foreign_tenant, "secret findings were not turned into alerts");
    }
    alerts
}


/// Stores the alerts in batches of `MAX_ALERTS_PER_INSERT` under the scope; answers how many were new.
pub async fn store_secret_alerts(exec: Executor<'_, '_>, scope: &TenantScope, alerts: &[Alert]) -> Result<usize, StoreError> {
    let mut inserted = 0;
    for batch in alerts.chunks(MAX_ALERTS_PER_INSERT) {
        inserted += insert_alerts(exec, scope, batch).await?;
    }
    Ok(inserted)
}
