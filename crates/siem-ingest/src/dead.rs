use crate::model::{DeadGroups, DeadLetterClass, LoopReport};
use crate::parse::{NOT_ECS_PREFIX, OVERSIZE_PREFIX};
use crate::pipeline::POISON_REASON;
use serde_json::error::Category;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};


pub const MAX_DEAD_LETTER_GROUPS: usize = 16;


pub const SUMMARY_SECONDS: i64 = 60;


/// The fixed text of a class; the serde category and an identity class are enum names, never payload text.
pub fn class_text(class: &DeadLetterClass) -> String {
    match class {
        DeadLetterClass::Oversize => "oversize".to_owned(),
        DeadLetterClass::NotEcs(category) => format!("not_ecs:{category:?}"),
        DeadLetterClass::Poison => "poison".to_owned(),
        DeadLetterClass::Identity(name) => format!("identity_unusable:{name}"),
        DeadLetterClass::Other => "other".to_owned(),
    }
}


/// The serde category named right after the prefix of a reason `check_message` wrote.
pub fn category_of(rest: &str) -> Category {
    match rest.split(' ').next() {
        Some("Io") => Category::Io,
        Some("Syntax") => Category::Syntax,
        Some("Eof") => Category::Eof,
        _ => Category::Data,
    }
}


/// The class of a dead-letter reason produced by this crate.
pub fn class_of_reason(reason: &str) -> DeadLetterClass {
    if reason == POISON_REASON {
        DeadLetterClass::Poison
    } else if reason.starts_with(OVERSIZE_PREFIX) {
        DeadLetterClass::Oversize
    } else if let Some(rest) = reason.strip_prefix(NOT_ECS_PREFIX) {
        DeadLetterClass::NotEcs(category_of(rest))
    } else {
        DeadLetterClass::Other
    }
}


/// Counts one confirmed dead letter; past `MAX_DEAD_LETTER_GROUPS` distinct groups it is counted in `other_groups`.
pub fn record_dead_letter(groups: &mut DeadGroups, tenant: &str, class: &DeadLetterClass) {
    let key = (tenant.to_owned(), class_text(class));
    if groups.groups.contains_key(&key) || groups.groups.len() < MAX_DEAD_LETTER_GROUPS {
        *groups.groups.entry(key).or_insert(0) += 1;
    } else {
        groups.other_groups += 1;
    }
}


pub fn groups_text(groups: &DeadGroups) -> String {
    groups
        .groups
        .iter()
        .map(|((tenant, class), amount)| format!("{tenant}/{class}={amount}"))
        .collect::<Vec<_>>()
        .join(" ")
}


/// One line per cycle for every group of confirmed dead letters, then the record is emptied.
pub fn log_dead_groups(groups: &mut DeadGroups) {
    let taken = std::mem::take(groups);
    if !taken.groups.is_empty() {
        let text = groups_text(&taken);
        let other_groups = taken.other_groups;
        warn!(groups = %text, other_groups, "dead letters of this cycle");
    }
}


pub fn summary_due(last: OffsetDateTime, now: OffsetDateTime) -> bool {
    now - last >= Duration::seconds(SUMMARY_SECONDS)
}


pub fn log_summary(report: &LoopReport) {
    let dead_lettered = report.dead_lettered;
    let dead_letter_failed = report.dead_letter_failed;
    let host_metrics_skipped = report.host_metrics_skipped;
    info!(dead_lettered, dead_letter_failed, host_metrics_skipped, "ingest summary");
}
