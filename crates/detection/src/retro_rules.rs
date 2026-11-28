//! Which base rules run in retro: those whose Sigma `tags` hold exactly `ostyr.retro`.

use crate::id::payload_hash;
use crate::retro::id_allowed;
use alerts::store::MAX_RULE_ID_CHARS;
use sigma_sql::rule::parse_rule;
use stream_correlation::base::BaseRule;
use stream_correlation::level::Level;
use stream_correlation::ruleset::RuleSet;
use tracing::warn;


pub const RETRO_TAG: &str = "ostyr.retro";


pub const RETRO_ID_PREFIX: &str = "retro:";


pub const LOSS_ID_PREFIX: &str = "retro.loss:";


/// A base rule that runs in retro: `rule_id` and `loss_id` are the ids of its alerts, `fingerprint` the SHA-256 of its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroRule {
    pub rule_id: String,
    pub loss_id: String,
    pub title: String,
    pub level: Level,
    pub source: String,
    pub fingerprint: String,
}


/// What one base rule is for retro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    NotRetro,
    Skipped,
    Selected(RetroRule),
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetroSelection {
    pub rules: Vec<RetroRule>,
    pub skipped: usize,
}


/// An id the store accepts in both alert ids: not empty, no refused character, and `retro.loss:<id>` (the longer one) fits the store's limit.
pub fn usable_id(id: &str) -> bool {
    !id.is_empty() && id_allowed(id) && LOSS_ID_PREFIX.len() + id.chars().count() <= MAX_RULE_ID_CHARS
}


pub fn retro_rule(base: &BaseRule, id: &str) -> RetroRule {
    RetroRule {
        rule_id: format!("{RETRO_ID_PREFIX}{id}"),
        loss_id: format!("{LOSS_ID_PREFIX}{id}"),
        title: base.title.clone(),
        level: base.level,
        source: base.source.clone(),
        fingerprint: payload_hash(base.source.as_bytes()),
    }
}


/// A source that does not parse or a tagged rule without a usable `id` is skipped (counted by the caller), an untagged one is no retro rule.
pub fn candidate_of(base: &BaseRule) -> Candidate {
    match parse_rule(&base.source) {
        Err(_) => Candidate::Skipped,
        Ok(rule) if !rule.tags.iter().any(|tag| tag == RETRO_TAG) => Candidate::NotRetro,
        Ok(_) => match base.id.as_deref() {
            Some(id) if usable_id(id) => Candidate::Selected(retro_rule(base, id)),
            _ => Candidate::Skipped,
        },
    }
}


/// The retro rules of a rule set and how many tagged rules were skipped; the count is logged without any rule text.
pub fn select_retro_rules(ruleset: &RuleSet) -> RetroSelection {
    let selection = ruleset
        .bases
        .iter()
        .map(candidate_of)
        .fold(RetroSelection::default(), |mut found, candidate| {
            match candidate {
                Candidate::Selected(rule) => found.rules.push(rule),
                Candidate::Skipped => found.skipped += 1,
                Candidate::NotRetro => {}
            }
            found
        });
    if selection.skipped > 0 {
        let skipped = selection.skipped;
        warn!(skipped, "retro rules skipped");
    }
    selection
}
