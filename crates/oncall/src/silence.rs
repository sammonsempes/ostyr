use crate::limits::MAX_REGEX_BYTES;
use crate::model::{MatchKind, Matcher, Silence, Window};
use chrono::{DateTime, Utc};
use regex::{Regex, RegexBuilder};
use std::collections::BTreeMap;


/// Compiles the pattern anchored on the whole value, with a bounded automaton size.
pub fn compile_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(&format!("^(?:{pattern})$")).size_limit(MAX_REGEX_BYTES).build()
}


pub fn matcher_matches(matcher: &Matcher, labels: &BTreeMap<String, String>) -> bool {
    labels.get(&matcher.label).is_some_and(|value| match matcher.kind {
        MatchKind::Equal => *value == matcher.value,
        MatchKind::Regex => compile_regex(&matcher.value).is_ok_and(|regex| regex.is_match(value)),
    })
}


/// A silence applies from `starts_at` (included) up to `expires_at` (excluded).
pub fn silence_applies(silence: &Silence, labels: &BTreeMap<String, String>, now: DateTime<Utc>) -> bool {
    silence.starts_at <= now && now < silence.expires_at && silence.matchers.iter().all(|matcher| matcher_matches(matcher, labels))
}


pub fn is_silenced(alert_labels: &BTreeMap<String, String>, silences: &[Silence], now: DateTime<Utc>) -> bool {
    silences.iter().any(|silence| silence_applies(silence, alert_labels, now))
}


pub fn in_maintenance(asset: &str, windows: &[Window], now: DateTime<Utc>) -> bool {
    windows
        .iter()
        .any(|window| window.starts_at <= now && now < window.ends_at && window.assets.iter().any(|candidate| candidate == asset))
}
