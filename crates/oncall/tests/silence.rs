#[path = "common/types.rs"]
mod types;


use chrono::{DateTime, Duration, Utc};
use oncall::error::OncallError;
use oncall::grouping::group_alerts;
use oncall::limits::{MAX_ALERTS, MAX_ASSETS, MAX_GROUP_LABELS, MAX_MATCHERS, MAX_REGEX_LEN, MAX_SILENCES, MAX_TEXT_LEN, MAX_VALUE_LEN, MAX_WINDOWS};
use oncall::load::{load_silences, load_windows, parse_silences, parse_windows};
use oncall::model::{Alert, MatchKind, Matcher, Silence, Window};
use oncall::silence::{in_maintenance, is_silenced};
use std::collections::BTreeMap;
use types::TestResult;


const SILENCES_YAML: &str = include_str!("fixtures/silences.yaml");


const WINDOWS_YAML: &str = include_str!("fixtures/windows.yaml");


const DB_ALERTS: usize = 2;


const MATCHER_LINE: &str = "      - { label: host, kind: equal, value: a }\n";


fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
}


fn instant(text: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    Ok(text.parse()?)
}


fn silences() -> Result<Vec<Silence>, Box<dyn std::error::Error>> {
    Ok(parse_silences(SILENCES_YAML, "silences.yaml")?)
}


fn windows() -> Result<Vec<Window>, Box<dyn std::error::Error>> {
    Ok(parse_windows(WINDOWS_YAML, "windows.yaml")?)
}


fn alert(fingerprint: &str, pairs: &[(&str, &str)]) -> Alert {
    Alert {
        fingerprint: fingerprint.to_string(),
        labels: labels(pairs),
    }
}


fn silence_yaml(matchers: &str, reason: &str) -> String {
    format!(
        "silences:\n  - name: s\n    matchers:\n{matchers}    author: alice\n    reason: \"{reason}\"\n    starts_at: 2026-01-01T10:00:00Z\n    expires_at: 2026-01-01T12:00:00Z\n"
    )
}


fn regex_line(pattern: &str) -> String {
    format!("      - {{ label: host, kind: regex, value: \"{pattern}\" }}\n")
}


fn silence_error(text: &str) -> Result<OncallError, Box<dyn std::error::Error>> {
    parse_silences(text, "edited.yaml").err().ok_or_else(|| "expected an error".into())
}


fn window_error(text: &str) -> Result<OncallError, Box<dyn std::error::Error>> {
    parse_windows(text, "edited.yaml").err().ok_or_else(|| "expected an error".into())
}


fn is_out_of_bounds(error: &OncallError, expected: &str) -> bool {
    matches!(error, OncallError::OutOfBounds { what, .. } if *what == expected)
}


#[test]
fn a_silence_expires_at_the_exact_boundary() -> TestResult {
    let list = silences()?;
    let alert_labels = labels(&[("service", "db"), ("host", "web-12")]);
    let start = instant("2026-01-01T10:00:00Z")?;
    let expiry = instant("2026-01-01T12:00:00Z")?;
    assert!(!is_silenced(&alert_labels, &list, start - Duration::nanoseconds(1)));
    assert!(is_silenced(&alert_labels, &list, start));
    assert!(is_silenced(&alert_labels, &list, expiry - Duration::nanoseconds(1)));
    assert!(!is_silenced(&alert_labels, &list, expiry));
    Ok(())
}


#[test]
fn matchers_are_anchored_and_all_required() -> TestResult {
    let list = silences()?;
    let now = instant("2026-01-01T11:00:00Z")?;
    assert!(!is_silenced(&labels(&[("service", "db"), ("host", "web-1x")]), &list, now));
    assert!(!is_silenced(&labels(&[("service", "db"), ("host", "xweb-1")]), &list, now));
    assert!(!is_silenced(&labels(&[("service", "api"), ("host", "web-1")]), &list, now));
    assert!(!is_silenced(&labels(&[("service", "db")]), &list, now));
    Ok(())
}


#[test]
fn an_unvalidated_bad_regex_never_matches() -> TestResult {
    let base = silences()?.into_iter().next().ok_or("no silence")?;
    let list = vec![Silence {
        matchers: vec![Matcher {
            label: "host".to_string(),
            kind: MatchKind::Regex,
            value: "(".to_string(),
        }],
        ..base
    }];
    assert!(!is_silenced(&labels(&[("host", "(")]), &list, instant("2026-01-01T11:00:00Z")?));
    Ok(())
}


#[test]
fn maintenance_windows_apply_to_their_assets() -> TestResult {
    let list = windows()?;
    let start = instant("2026-01-01T22:00:00Z")?;
    let end = instant("2026-01-02T02:00:00Z")?;
    assert!(in_maintenance("srv-2", &list, start));
    assert!(!in_maintenance("srv-2", &list, start - Duration::nanoseconds(1)));
    assert!(!in_maintenance("srv-2", &list, end));
    assert!(!in_maintenance("srv-3", &list, start));
    Ok(())
}


#[test]
fn a_silence_without_expiry_is_refused() -> TestResult {
    let text = SILENCES_YAML.replace("    expires_at: 2026-01-01T12:00:00Z\n", "");
    let error = silence_error(&text)?;
    assert!(matches!(error, OncallError::Config(_)));
    assert!(error.to_string().contains("expires_at"), "{error}");
    Ok(())
}


#[test]
fn a_reversed_range_is_refused() -> TestResult {
    let silence = SILENCES_YAML.replace("2026-01-01T12:00:00Z", "2026-01-01T10:00:00Z");
    assert!(matches!(silence_error(&silence)?, OncallError::ExpiryRange { .. }));
    let window = WINDOWS_YAML.replace("2026-01-02T02:00:00Z", "2026-01-01T22:00:00Z");
    assert!(matches!(window_error(&window)?, OncallError::ExpiryRange { .. }));
    Ok(())
}


#[test]
fn regex_bounds_are_enforced() -> TestResult {
    let long = "a".repeat(MAX_REGEX_LEN as usize + 1);
    assert!(is_out_of_bounds(&silence_error(&silence_yaml(&regex_line(&long), "r"))?, "matcher regex"));
    assert!(is_out_of_bounds(&silence_error(&silence_yaml(&regex_line(""), "r"))?, "matcher regex"));
    let invalid = silence_error(&silence_yaml(&regex_line("("), "r"))?;
    assert!(matches!(invalid, OncallError::InvalidRegex { .. }));
    assert!(std::error::Error::source(&invalid).is_some());
    let huge = silence_error(&silence_yaml(&regex_line("((a{100}){100}){100}"), "r"))?;
    assert!(matches!(huge, OncallError::InvalidRegex { .. }));
    Ok(())
}


#[test]
fn silence_bounds_are_enforced() -> TestResult {
    let value = "v".repeat(MAX_VALUE_LEN as usize + 1);
    let long_value = format!("      - {{ label: host, kind: equal, value: {value} }}\n");
    assert!(is_out_of_bounds(&silence_error(&silence_yaml(&long_value, "r"))?, "matcher value"));
    let empty_label = "      - { label: \"\", kind: equal, value: a }\n";
    assert!(is_out_of_bounds(&silence_error(&silence_yaml(empty_label, "r"))?, "matcher label"));
    assert!(is_out_of_bounds(&silence_error("silences:\n  - name: s\n    matchers: []\n    author: a\n    reason: r\n    starts_at: 2026-01-01T10:00:00Z\n    expires_at: 2026-01-01T12:00:00Z\n")?, "matchers"));
    let too_many = MATCHER_LINE.repeat(MAX_MATCHERS as usize + 1);
    assert!(is_out_of_bounds(&silence_error(&silence_yaml(&too_many, "r"))?, "matchers"));
    assert!(is_out_of_bounds(&silence_error(&silence_yaml(MATCHER_LINE, ""))?, "silence reason"));
    let long_reason = "r".repeat(MAX_TEXT_LEN as usize + 1);
    assert!(is_out_of_bounds(
        &silence_error(&silence_yaml(MATCHER_LINE, &long_reason))?,
        "silence reason"
    ));
    let text = silence_yaml(MATCHER_LINE, "r");
    assert!(is_out_of_bounds(&silence_error(&text.replace("name: s", "name: \"\""))?, "silence name"));
    assert!(is_out_of_bounds(
        &silence_error(&text.replace("author: alice", "author: \"\""))?,
        "silence author"
    ));
    Ok(())
}


#[test]
fn file_and_window_bounds_are_enforced() -> TestResult {
    let silence_item = silence_yaml(MATCHER_LINE, "r").replace("silences:\n", "");
    let many = format!("silences:\n{}", silence_item.repeat(MAX_SILENCES as usize + 1));
    assert!(is_out_of_bounds(&silence_error(&many)?, "silences"));
    let window_item = WINDOWS_YAML.replace("windows:\n", "");
    let many_windows = format!("windows:\n{}", window_item.repeat(MAX_WINDOWS as usize + 1));
    assert!(is_out_of_bounds(&window_error(&many_windows)?, "windows"));
    let assets = (0..=MAX_ASSETS).map(|i| format!("a{i}")).collect::<Vec<_>>().join(", ");
    let text = WINDOWS_YAML.replace("srv-1, srv-2", &assets);
    assert!(is_out_of_bounds(&window_error(&text)?, "assets"));
    let blank = WINDOWS_YAML.replace("[srv-1, srv-2]", "[\"\"]");
    assert!(is_out_of_bounds(&window_error(&blank)?, "asset"));
    let cases = [
        ("name: patch-night", "name: \"\"", "window name"),
        ("author: bob", "author: \"\"", "window author"),
        ("reason: monthly patching", "reason: \"\"", "window reason"),
    ];
    cases.iter().try_for_each(|(from, to, what)| -> TestResult {
        assert!(is_out_of_bounds(&window_error(&WINDOWS_YAML.replace(from, to))?, what));
        Ok(())
    })
}


#[test]
fn files_are_loaded_from_disk() -> TestResult {
    let directory = tempfile::tempdir()?;
    let silence_path = directory.path().join("silences.yaml");
    std::fs::write(&silence_path, SILENCES_YAML)?;
    assert_eq!(load_silences(&silence_path)?.len(), 1);
    let window_path = directory.path().join("windows.yaml");
    std::fs::write(&window_path, WINDOWS_YAML)?;
    assert_eq!(load_windows(&window_path)?.len(), 1);
    Ok(())
}


#[test]
fn alerts_are_deduplicated_and_grouped() -> TestResult {
    let alerts = vec![
        alert("f1", &[("service", "db"), ("host", "a")]),
        alert("f1", &[("service", "db"), ("host", "b")]),
        alert("f2", &[("service", "db"), ("host", "c")]),
        alert("f3", &[("service", "api")]),
        alert("f4", &[("host", "d")]),
    ];
    let groups = group_alerts(&alerts, &["service".to_string()])?;
    let sizes: Vec<(String, usize)> = groups
        .iter()
        .map(|group| (group.labels.get("service").cloned().unwrap_or_default(), group.alerts.len()))
        .collect();
    assert_eq!(sizes, vec![(String::new(), 1), ("api".to_string(), 1), ("db".to_string(), DB_ALERTS)]);
    let first = groups
        .iter()
        .flat_map(|group| group.alerts.iter())
        .find(|item| item.fingerprint == "f1")
        .ok_or("f1 missing")?;
    assert_eq!(first.labels.get("host").map(String::as_str), Some("a"));
    assert_eq!(group_alerts(&alerts, &[])?.len(), 1);
    Ok(())
}


#[test]
fn grouping_bounds_are_enforced() -> TestResult {
    let many = vec![alert("f", &[]); MAX_ALERTS as usize + 1];
    assert!(matches!(
        group_alerts(&many, &[]).err(),
        Some(OncallError::OutOfBounds { what: "alerts", .. })
    ));
    let labels_over: Vec<String> = (0..=MAX_GROUP_LABELS).map(|i| format!("l{i}")).collect();
    assert!(matches!(
        group_alerts(&[], &labels_over).err(),
        Some(OncallError::OutOfBounds { what: "group_by", .. })
    ));
    Ok(())
}
