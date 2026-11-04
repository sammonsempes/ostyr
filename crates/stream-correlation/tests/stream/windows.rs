use crate::support::{
    bench, connection, failed_login, feed, process, stamp, Bench, ANY_ORDER, BEACON, BRUTE_FORCE, DISTINCT_DESTINATIONS, DOWNLOAD, DROPPER, EXECUTE,
    LOGIN, SEC_2, SEC_200, SEC_3, SEC_4, SEC_400, SEC_450,
};
use crate::types::TestResult;
use serde_json::json;
use std::collections::BTreeMap;
use stream_correlation::correlation::{Comparison, Threshold};
use stream_correlation::engine::snapshot;
use stream_correlation::field::event_time_ms;
use stream_correlation::window::{compare, LATENESS_MS, MAX_EVENTS_PER_GROUP, MAX_GROUPS_PER_RULE};


const MILLIS_PER_SECOND: i64 = 1000;


const BELOW: u64 = 2;


const AT: u64 = 3;


const ABOVE: u64 = 4;


const INVALID_EVENTS: u64 = 2;


const WIDE_THRESHOLD: &str = "title: Never\nid: never\ncorrelation:\n  type: event_count\n  rules: [failed-login]\n  group-by: [host.name]\n  timespan: 5m\n  condition:\n    gte: 5000\n";


const UNGROUPED: &str =
    "title: Global\nid: global\ncorrelation:\n  type: event_count\n  rules: [failed-login]\n  timespan: 5m\n  condition:\n    gte: 2\n";


const LATE_SECONDS: i64 = 1000;


fn brute() -> Result<Bench, Box<dyn std::error::Error>> {
    bench(&[LOGIN, BRUTE_FORCE])
}


#[test]
fn comparisons_hold_at_and_around_the_threshold() -> TestResult {
    let at = |comparison: Comparison, count: u64| compare(&Threshold { comparison, value: AT }, count);
    assert_eq!(
        [at(Comparison::Gt, BELOW), at(Comparison::Gt, AT), at(Comparison::Gt, ABOVE)],
        [false, false, true]
    );
    assert_eq!(
        [at(Comparison::Gte, BELOW), at(Comparison::Gte, AT), at(Comparison::Gte, ABOVE)],
        [false, true, true]
    );
    assert_eq!(
        [at(Comparison::Lt, BELOW), at(Comparison::Lt, AT), at(Comparison::Lt, ABOVE)],
        [true, false, false]
    );
    assert_eq!(
        [at(Comparison::Lte, BELOW), at(Comparison::Lte, AT), at(Comparison::Lte, ABOVE)],
        [true, true, false]
    );
    assert_eq!(
        [at(Comparison::Eq, BELOW), at(Comparison::Eq, AT), at(Comparison::Eq, ABOVE)],
        [false, true, false]
    );
    Ok(())
}


#[test]
fn event_count_fires_at_the_threshold_and_resets() -> TestResult {
    let bench = brute()?;
    assert!(feed(&bench.engine, &failed_login(0, "a", "h1")).is_empty());
    assert!(feed(&bench.engine, &failed_login(1, "b", "h1")).is_empty());
    let alerts = feed(&bench.engine, &failed_login(SEC_2, "c", "h1"));
    assert_eq!(alerts.len(), 1);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alert.rule_id, "brute-force");
    assert_eq!(alert.event_ids, vec!["a", "b", "c"]);
    assert_eq!(alert.group, BTreeMap::from([("host.name".to_string(), "h1".to_string())]));
    assert_eq!(alert.first_ms, event_time_ms(&failed_login(0, "a", "h1"))?);
    assert_eq!(alert.last_ms, event_time_ms(&failed_login(SEC_2, "c", "h1"))?);
    assert!(feed(&bench.engine, &failed_login(SEC_3, "d", "h1")).is_empty());
    assert_eq!(snapshot(&bench.engine).counters.alerts, 1);
    Ok(())
}


#[test]
fn events_outside_the_window_do_not_count() -> TestResult {
    let bench = brute()?;
    assert!(feed(&bench.engine, &failed_login(0, "a", "h1")).is_empty());
    assert!(feed(&bench.engine, &failed_login(SEC_200, "b", "h1")).is_empty());
    assert!(feed(&bench.engine, &failed_login(SEC_400, "c", "h1")).is_empty());
    let alerts = feed(&bench.engine, &failed_login(SEC_450, "d", "h1"));
    assert_eq!(
        alerts.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["b".to_string(), "c".to_string(), "d".to_string()])
    );
    Ok(())
}


#[test]
fn groups_are_isolated() -> TestResult {
    let bench = brute()?;
    assert!(feed(&bench.engine, &failed_login(0, "a", "h1")).is_empty());
    assert!(feed(&bench.engine, &failed_login(1, "b", "h2")).is_empty());
    assert!(feed(&bench.engine, &failed_login(SEC_2, "c", "h1")).is_empty());
    assert!(feed(&bench.engine, &failed_login(SEC_3, "d", "h2")).is_empty());
    let alerts = feed(&bench.engine, &failed_login(SEC_4, "e", "h1"));
    assert_eq!(
        alerts.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["a".to_string(), "c".to_string(), "e".to_string()])
    );
    Ok(())
}


#[test]
fn unmatched_and_ungroupable_events_are_skipped() -> TestResult {
    let bench = brute()?;
    assert!(feed(&bench.engine, &process(0, "a", "h1", "/bin/ls", "ls")).is_empty());
    let no_host = json!({
        "@timestamp": stamp(1),
        "event": {"category": ["process"]},
        "host": {"os": {"type": "linux"}},
        "process": {"command_line": "login failed"},
    });
    assert!(feed(&bench.engine, &no_host).is_empty());
    assert!(snapshot(&bench.engine).rules.values().all(|state| state.groups.is_empty()));
    Ok(())
}


#[test]
fn rules_without_group_by_use_one_global_group() -> TestResult {
    let bench = bench(&[LOGIN, UNGROUPED])?;
    assert!(feed(&bench.engine, &failed_login(0, "a", "h1")).is_empty());
    let alerts = feed(&bench.engine, &failed_login(1, "b", "h2"));
    let alert = alerts.first().ok_or("no alert")?;
    assert!(alert.group.is_empty());
    assert_eq!(alert.event_ids, vec!["a", "b"]);
    Ok(())
}


#[test]
fn value_count_counts_distinct_values_only() -> TestResult {
    let bench = bench(&[BEACON, DISTINCT_DESTINATIONS])?;
    assert!(feed(&bench.engine, &connection(0, "a", "h1", "10.0.0.1")).is_empty());
    assert!(feed(&bench.engine, &connection(1, "b", "h1", "10.0.0.1")).is_empty());
    assert!(feed(&bench.engine, &connection(SEC_2, "c", "h1", "10.0.0.2")).is_empty());
    let no_destination = json!({
        "@timestamp": stamp(SEC_3),
        "event": {"category": ["network"]},
        "host": {"name": "h1"},
        "process": {"executable": "/opt/beacon"},
    });
    assert!(feed(&bench.engine, &no_destination).is_empty());
    let alerts = feed(&bench.engine, &connection(SEC_4, "d", "h1", "10.0.0.3"));
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alert.event_ids, vec!["a", "b", "c", "d"]);
    Ok(())
}


#[test]
fn temporal_needs_every_rule_in_any_order() -> TestResult {
    let bench = bench(&[DOWNLOAD, EXECUTE, ANY_ORDER])?;
    assert!(feed(&bench.engine, &process(0, "a", "h1", "/bin/payload", "run")).is_empty());
    assert!(feed(&bench.engine, &process(1, "b", "h1", "/bin/payload", "run")).is_empty());
    let alerts = feed(&bench.engine, &process(SEC_2, "c", "h1", "/usr/bin/curl", "curl"));
    assert_eq!(alerts.first().map(|alert| alert.rule_id.as_str()), Some("any-order"));
    Ok(())
}


#[test]
fn temporal_window_expires() -> TestResult {
    let bench = bench(&[DOWNLOAD, EXECUTE, ANY_ORDER])?;
    assert!(feed(&bench.engine, &process(0, "a", "h1", "/bin/payload", "run")).is_empty());
    assert!(feed(&bench.engine, &process(SEC_200, "b", "h1", "/usr/bin/curl", "curl")).is_empty());
    Ok(())
}


#[test]
fn temporal_ordered_needs_the_listed_order() -> TestResult {
    let bench = bench(&[DOWNLOAD, EXECUTE, DROPPER])?;
    assert!(feed(&bench.engine, &process(0, "a", "h1", "/bin/payload", "run")).is_empty());
    assert!(feed(&bench.engine, &process(1, "b", "h1", "/usr/bin/curl", "curl")).is_empty());
    assert!(feed(&bench.engine, &process(SEC_2, "c", "h2", "/usr/bin/curl", "curl")).is_empty());
    let alerts = feed(&bench.engine, &process(SEC_3, "d", "h1", "/bin/payload", "run"));
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alert.rule_id, "dropper");
    assert_eq!(alert.event_ids, vec!["a", "b", "d"]);
    Ok(())
}


#[test]
fn late_events_are_counted_and_ignored() -> TestResult {
    let bench = brute()?;
    assert!(feed(&bench.engine, &failed_login(LATE_SECONDS, "a", "h1")).is_empty());
    let lateness_seconds = LATENESS_MS / MILLIS_PER_SECOND;
    assert!(feed(&bench.engine, &failed_login(LATE_SECONDS - lateness_seconds - 1, "late", "h1")).is_empty());
    assert_eq!(snapshot(&bench.engine).counters.late, 1);
    assert!(feed(&bench.engine, &failed_login(LATE_SECONDS - lateness_seconds, "edge", "h1")).is_empty());
    assert_eq!(snapshot(&bench.engine).counters.late, 1);
    let alerts = feed(&bench.engine, &failed_login(LATE_SECONDS, "b", "h1"));
    assert_eq!(
        alerts.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["edge".to_string(), "a".to_string(), "b".to_string()])
    );
    Ok(())
}


#[test]
fn events_without_a_usable_timestamp_are_counted() -> TestResult {
    let bench = brute()?;
    assert!(feed(&bench.engine, &json!({"event": {"id": "none"}})).is_empty());
    assert!(feed(&bench.engine, &json!({"@timestamp": "soon"})).is_empty());
    let counters = snapshot(&bench.engine).counters;
    assert_eq!((counters.invalid, counters.processed), (INVALID_EVENTS, INVALID_EVENTS));
    Ok(())
}


#[test]
fn events_per_group_are_capped_and_counted() -> TestResult {
    let bench = bench(&[LOGIN, WIDE_THRESHOLD])?;
    (0..=MAX_EVENTS_PER_GROUP).for_each(|index| {
        feed(&bench.engine, &failed_login(0, &format!("e{index}"), "h1"));
    });
    let state = snapshot(&bench.engine);
    assert_eq!(state.counters.dropped_events, 1);
    let group = state.rules.get("never").and_then(|rule| rule.groups.values().next()).ok_or("no group")?;
    assert_eq!(group.len(), MAX_EVENTS_PER_GROUP);
    assert_eq!(group.first().map(|hit| hit.event_id.as_str()), Some("e1"));
    Ok(())
}


#[test]
fn groups_per_rule_are_capped_and_the_idlest_is_evicted() -> TestResult {
    let bench = bench(&[LOGIN, WIDE_THRESHOLD])?;
    feed(&bench.engine, &failed_login(0, "first", "idle"));
    (0..MAX_GROUPS_PER_RULE).for_each(|index| {
        feed(&bench.engine, &failed_login(1, &format!("e{index}"), &format!("host-{index}")));
    });
    let state = snapshot(&bench.engine);
    assert_eq!(state.counters.dropped_groups, 1);
    let groups = &state.rules.get("never").ok_or("no state")?.groups;
    assert_eq!(groups.len(), MAX_GROUPS_PER_RULE);
    assert!(!groups.contains_key("idle"));
    Ok(())
}
