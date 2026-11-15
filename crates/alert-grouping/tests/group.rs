use alert_grouping::error::GroupError;
use alert_grouping::group::{group_alerts, severity_rank};
use alert_grouping::model::GroupLimits;
use alerts::model::{Alert, Severity, Summary};
use types::TestResult;


#[path = "common/types.rs"]
mod types;


const TWO: u64 = 2;


const THREE: u64 = 3;


const FOUR: u64 = 4;


const TWO_COUNT: usize = 2;


const THREE_COUNT: usize = 3;


const FOUR_COUNT: usize = 4;


const WINDOW: u64 = 100;


const MAX_ALERTS: usize = 50;


const MAX_GROUPS: usize = 10;


const PER_GROUP: usize = 3;


const START: u64 = 1_000;


const FAR: u64 = 5_000;


const OVER_CAP_ALERTS: usize = 5;


fn limits() -> GroupLimits {
    GroupLimits {
        window_micros: WINDOW,
        max_alerts: MAX_ALERTS,
        max_groups: MAX_GROUPS,
        max_alerts_per_group: PER_GROUP,
    }
}


fn alert(id: &str, tenant: &str, rule: &str, created: u64, events: &[&str]) -> Alert {
    Alert {
        id: id.to_string(),
        tenant: tenant.to_string(),
        rule_id: rule.to_string(),
        rule_title: "title".to_string(),
        severity: Severity::Low,
        event_time: "2026-01-01T00:00:00Z".to_string(),
        created_micros: created,
        host_name: Some("h1".to_string()),
        user_name: None,
        event_ids: events.iter().map(|event| event.to_string()).collect(),
        summary: Summary {
            text: String::new(),
            truncated: false,
            original_bytes: 0,
        },
    }
}


fn with_severity(mut base: Alert, severity: Severity) -> Alert {
    base.severity = severity;
    base
}


#[test]
fn same_key_within_window_is_one_group() -> TestResult {
    let alerts = vec![alert("a1", "t", "r", START, &["e1"]), alert("a2", "t", "r", START + WINDOW, &["e2"])];
    let groups = group_alerts(&alerts, &limits())?;
    assert_eq!(groups.len(), 1);
    let group = groups.first().ok_or("no group")?;
    assert_eq!(group.alert_count, TWO);
    assert_eq!(group.alert_ids, vec!["a1", "a2"]);
    assert_eq!(group.first_micros, START);
    assert_eq!(group.last_micros, START + WINDOW);
    assert_eq!(group.duplicates, 0);
    assert!(!group.omitted);
    Ok(())
}


#[test]
fn beyond_window_is_two_groups() -> TestResult {
    let alerts = vec![alert("a1", "t", "r", START, &["e1"]), alert("a2", "t", "r", START + WINDOW + 1, &["e2"])];
    let groups = group_alerts(&alerts, &limits())?;
    assert_eq!(groups.len(), TWO_COUNT);
    assert_eq!(
        groups.iter().map(|group| group.alert_ids.clone()).collect::<Vec<_>>(),
        vec![vec!["a1"], vec!["a2"]]
    );
    Ok(())
}


#[test]
fn window_slides_on_the_last_alert() -> TestResult {
    let alerts = vec![
        alert("a1", "t", "r", START, &[]),
        alert("a2", "t", "r", START + WINDOW, &[]),
        alert("a3", "t", "r", START + TWO * WINDOW, &[]),
    ];
    assert_eq!(group_alerts(&alerts, &limits())?.len(), 1);
    Ok(())
}


#[test]
fn tenants_never_share_a_group() -> TestResult {
    let alerts = vec![alert("a1", "t1", "r", START, &["e"]), alert("a2", "t2", "r", START, &["e"])];
    let groups = group_alerts(&alerts, &limits())?;
    assert_eq!(groups.len(), TWO_COUNT);
    assert_eq!(groups.iter().map(|group| group.key.tenant.as_str()).collect::<Vec<_>>(), vec!["t1", "t2"]);
    Ok(())
}


#[test]
fn host_user_and_rule_split_groups() -> TestResult {
    let mut other_host = alert("a2", "t", "r", START, &[]);
    other_host.host_name = Some("h2".to_string());
    let mut other_user = alert("a3", "t", "r", START, &[]);
    other_user.user_name = Some("u".to_string());
    let alerts = vec![
        alert("a1", "t", "r", START, &[]),
        other_host,
        other_user,
        alert("a4", "t", "r2", START, &[]),
    ];
    assert_eq!(group_alerts(&alerts, &limits())?.len(), FOUR_COUNT);
    Ok(())
}


#[test]
fn equal_event_sets_are_duplicates_a_superset_is_not() -> TestResult {
    let alerts = vec![
        alert("a1", "t", "r", START, &["e1", "e2"]),
        alert("a2", "t", "r", START + 1, &["e2", "e1"]),
        alert("a3", "t", "r", START + TWO, &["e1", "e2", "e3"]),
        alert("a4", "t", "r", START + THREE, &["e1", "e1", "e2"]),
    ];
    let groups = group_alerts(&alerts, &limits())?;
    let group = groups.first().ok_or("no group")?;
    assert_eq!(group.duplicates, TWO);
    assert_eq!(group.alert_count, FOUR);
    Ok(())
}


#[test]
fn representative_is_highest_severity_then_earliest() -> TestResult {
    let alerts = vec![
        with_severity(alert("a1", "t", "r", START, &[]), Severity::Medium),
        with_severity(alert("a2", "t", "r", START + 1, &[]), Severity::High),
        with_severity(alert("a3", "t", "r", START + TWO, &[]), Severity::High),
        with_severity(alert("a4", "t", "r", START + THREE, &[]), Severity::Low),
    ];
    let groups = group_alerts(&alerts, &limits())?;
    let group = groups.first().ok_or("no group")?;
    assert_eq!(group.representative, "a2");
    assert_eq!(group.max_severity, Severity::High);
    Ok(())
}


#[test]
fn same_time_ties_break_on_id() -> TestResult {
    let alerts = vec![
        with_severity(alert("b", "t", "r", START, &[]), Severity::High),
        with_severity(alert("a", "t", "r", START, &[]), Severity::High),
    ];
    let groups = group_alerts(&alerts, &limits())?;
    assert_eq!(groups.first().ok_or("no group")?.representative, "a");
    Ok(())
}


#[test]
fn severity_ranks_ascend() -> TestResult {
    let ranks: Vec<u8> = [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .into_iter()
    .map(severity_rank)
    .collect();
    assert!(ranks.windows(TWO_COUNT).all(|pair| pair.first() < pair.get(1)));
    Ok(())
}


#[test]
fn output_is_stable_across_permutations() -> TestResult {
    let alerts = vec![
        with_severity(alert("a1", "t1", "r", START, &["e1"]), Severity::Low),
        alert("a2", "t1", "r", START + 1, &["e1"]),
        alert("a3", "t1", "r", FAR, &["e3"]),
        alert("a4", "t2", "r", START, &["e1"]),
        alert("a5", "t1", "r2", START + TWO, &[]),
    ];
    let expected = group_alerts(&alerts, &limits())?;
    let mut reversed = alerts.clone();
    reversed.reverse();
    let mut rotated = alerts.clone();
    rotated.rotate_left(TWO_COUNT);
    let mut swapped = alerts.clone();
    swapped.swap(0, FOUR_COUNT);
    assert_eq!(group_alerts(&reversed, &limits())?, expected);
    assert_eq!(group_alerts(&rotated, &limits())?, expected);
    assert_eq!(group_alerts(&swapped, &limits())?, expected);
    assert_eq!(expected.len(), FOUR_COUNT);
    Ok(())
}


#[test]
fn over_max_alerts_is_refused() -> TestResult {
    let mut small = limits();
    small.max_alerts = 1;
    let alerts = vec![alert("a1", "t", "r", START, &[]), alert("a2", "t", "r", START, &[])];
    assert!(matches!(
        group_alerts(&alerts, &small),
        Err(GroupError::TooManyAlerts { count: TWO_COUNT, max: 1 })
    ));
    Ok(())
}


#[test]
fn over_max_groups_is_refused() -> TestResult {
    let mut small = limits();
    small.max_groups = 1;
    let alerts = vec![alert("a1", "t", "r", START, &[]), alert("a2", "t", "r2", START, &[])];
    assert!(matches!(group_alerts(&alerts, &small), Err(GroupError::TooManyGroups { max: 1 })));
    Ok(())
}


#[test]
fn reopened_groups_count_against_max_groups() -> TestResult {
    let mut small = limits();
    small.max_groups = 1;
    let alerts = vec![alert("a1", "t", "r", START, &[]), alert("a2", "t", "r", FAR, &[])];
    assert!(matches!(group_alerts(&alerts, &small), Err(GroupError::TooManyGroups { max: 1 })));
    Ok(())
}


#[test]
fn a_big_group_keeps_exact_counts_and_a_visible_cut() -> TestResult {
    let alerts: Vec<Alert> = (0..OVER_CAP_ALERTS as u64)
        .map(|index| alert(&format!("a{index}"), "t", "r", START + index, &["e"]))
        .collect();
    let groups = group_alerts(&alerts, &limits())?;
    let group = groups.first().ok_or("no group")?;
    assert_eq!(group.alert_count, OVER_CAP_ALERTS as u64);
    assert_eq!(group.duplicates, OVER_CAP_ALERTS as u64 - 1);
    assert_eq!(group.alert_ids, vec!["a0", "a1", "a2"]);
    assert!(group.omitted);
    Ok(())
}


#[test]
fn error_messages_name_the_limit() -> TestResult {
    assert_eq!(
        GroupError::TooManyAlerts {
            count: THREE_COUNT,
            max: TWO_COUNT
        }
        .to_string(),
        "3 alerts exceed the limit of 2"
    );
    assert_eq!(GroupError::TooManyGroups { max: TWO_COUNT }.to_string(), "more than 2 groups");
    Ok(())
}
