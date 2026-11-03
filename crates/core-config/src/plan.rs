use crate::types::{ConfigState, Plan};
use similar::TextDiff;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Create,
    Update,
    Delete,
}


/// `before` is empty for a create and `after` is empty for a delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub key: String,
    pub before: String,
    pub after: String,
    pub diff: String,
}


pub fn action_name(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Create => "config.create",
        ChangeKind::Update => "config.update",
        ChangeKind::Delete => "config.delete",
    }
}


/// Unified diff of one key, `a/<key>` being the current text and `b/<key>` the wanted one.
pub fn diff_text(key: &str, before: &str, after: &str) -> String {
    TextDiff::from_lines(before, after)
        .unified_diff()
        .header(&format!("a/{key}"), &format!("b/{key}"))
        .to_string()
}


pub fn change_of(kind: ChangeKind, key: &str, before: &str, after: &str) -> Change {
    Change {
        kind,
        key: key.to_owned(),
        before: before.to_owned(),
        after: after.to_owned(),
        diff: diff_text(key, before, after),
    }
}


/// Creates, then updates, then deletes, each group in key order; empty when `current` equals `desired`.
pub fn plan(desired: &ConfigState, current: &ConfigState) -> Plan {
    let creates = desired
        .iter()
        .filter(|(key, _)| !current.contains_key(*key))
        .map(|(key, wanted)| change_of(ChangeKind::Create, key, "", wanted));
    let updates = desired.iter().filter_map(|(key, wanted)| {
        current
            .get(key)
            .filter(|existing| *existing != wanted)
            .map(|existing| change_of(ChangeKind::Update, key, existing, wanted))
    });
    let deletes = current
        .iter()
        .filter(|(key, _)| !desired.contains_key(*key))
        .map(|(key, existing)| change_of(ChangeKind::Delete, key, existing, ""));
    creates.chain(updates).chain(deletes).collect()
}


/// Changes made outside Git: what would bring the real state back to the repository.
pub fn drift(desired: &ConfigState, current: &ConfigState) -> Plan {
    plan(desired, current)
}


/// Rolling back is the plan from the current state to an earlier configuration.
pub fn rollback(previous: &ConfigState, current: &ConfigState) -> Plan {
    plan(previous, current)
}
