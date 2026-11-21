use super::memory::{lock, Db, Stored, Triage, JOIN_BIND};
use super::types::TestResult;
use super::{host, limits, run, stored, value_of, CRITICAL_SCORE, NOW, THREE, TWO};
use risk_score::model::{Contribution, Severity};
use risk_score::source::{
    fp_rate, with_false_positive_rates, FpRule, Limit, Limits, Outcome, Verdicts, MAX_FP_RATE_PPM, MAX_NAMED_FP_RULES, MIN_VERDICTS,
    RISK_ALERTS_NEXT_SQL, RISK_ALERTS_SQL,
};
use std::collections::BTreeMap;


const DAY_SECONDS: u64 = 86_400;


const NOISY_RATE: u32 = 500_000;


const OVER_CAP_RULES: usize = 101;


const FLOOD_CAP: usize = 25;


const FLOOD_ALERTS: usize = 30;


const ODD_PAGE: usize = 7;


const SPREAD: usize = 5;


const HI_SCORE_HALVED: u8 = 5;


const HI_SCORE_TENTH: u8 = 1;


const RULE_STRIDE: usize = 100;


const HALF_VERDICTS: usize = 10;


const FLOOR: usize = MIN_VERDICTS as usize;


const HALF_FLOOR: u64 = 10;


struct Spread {
    hosts: usize,
    days: usize,
}


fn verdicts_of(tenant: &str, rule: &str, base: usize, false_positives: usize, closed: usize, spread: &Spread) -> (Vec<Stored>, Vec<Triage>) {
    let kinds = std::iter::repeat_n("false_positive", false_positives).chain(std::iter::repeat_n("closed", closed));
    let mut alerts = Vec::new();
    let mut triage = Vec::new();
    for (index, status) in kinds.enumerate() {
        let host_name = if status == "closed" {
            "closed-host".to_owned()
        } else {
            format!("fp-host-{}", index % spread.hosts)
        };
        let age = (index % spread.days) as u64 * DAY_SECONDS;
        alerts.push(stored(tenant, base + index, rule, "high", age, &host_name, ""));
        triage.push(Triage {
            tenant: tenant.to_owned(),
            alert_id: format!("{:064x}", base + index),
            status: status.to_owned(),
        });
    }
    (alerts, triage)
}


fn db_of(parts: Vec<(Vec<Stored>, Vec<Triage>)>) -> Db {
    let mut db = Db::default();
    for (alerts, triage) in parts {
        db.rows.extend(alerts);
        db.triage.extend(triage);
    }
    db
}


fn three_by_three() -> Spread {
    Spread { hosts: THREE, days: THREE }
}


fn rules_of(outcome: &Outcome) -> Vec<(&str, u32)> {
    outcome.fp_rules.iter().map(|rule| (rule.rule_id.as_str(), rule.rate_ppm)).collect()
}


fn triaged(alert: usize, status: &str) -> Triage {
    Triage {
        tenant: "a".to_owned(),
        alert_id: format!("{alert:064x}"),
        status: status.to_owned(),
    }
}


#[tokio::test]
async fn nineteen_verdicts_leave_the_rate_at_zero_and_twenty_apply_it() -> TestResult {
    let nineteen = db_of(vec![verdicts_of("a", "noisy", 1, HALF_VERDICTS, HALF_VERDICTS - 1, &three_by_three())]);
    let none = run(&nineteen, "a", &Limits::default()).await?;
    assert!(none.fp_rules.is_empty());
    let twenty = db_of(vec![verdicts_of("a", "noisy", 1, HALF_VERDICTS, HALF_VERDICTS, &three_by_three())]);
    let some = run(&twenty, "a", &Limits::default()).await?;
    assert_eq!(
        some.fp_rules,
        vec![FpRule {
            rule_id: "noisy".to_owned(),
            false_positive: HALF_VERDICTS as u64,
            closed: HALF_VERDICTS as u64,
            rate_ppm: NOISY_RATE,
            capped: false
        }]
    );
    assert_eq!(some.unknown_verdicts, 0);
    Ok(())
}


#[tokio::test]
async fn every_alert_marked_false_positive_stops_at_ninety_percent_and_is_named() -> TestResult {
    let db = db_of(vec![
        verdicts_of("a", "noisy", 1, FLOOR, 0, &three_by_three()),
        (vec![stored("a", RULE_STRIDE, "noisy", "high", 0, "lone", "")], Vec::new()),
    ]);
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(rules_of(&outcome), vec![("noisy", MAX_FP_RATE_PPM)]);
    assert!(outcome.fp_rules.iter().all(|rule| rule.capped));
    assert_eq!(value_of(&outcome, &host("lone")), Some(HI_SCORE_TENTH));
    Ok(())
}


#[tokio::test]
async fn another_tenants_verdicts_never_move_this_tenants_rates() -> TestResult {
    let foreign = verdicts_of("b", "noisy", 1, FLOOR + 1, 0, &three_by_three());
    let plain: Vec<Stored> = (1..=FLOOR + 1)
        .map(|index| stored("a", index, "noisy", "high", 0, &format!("p{index}"), ""))
        .collect();
    let alone = db_of(vec![(plain.clone(), Vec::new())]);
    let before = run(&alone, "a", &Limits::default()).await?;
    let shared = db_of(vec![foreign, (plain, Vec::new())]);
    let after = run(&shared, "a", &Limits::default()).await?;
    assert!(after.fp_rules.is_empty());
    assert_eq!(before, after);
    assert!(lock(&shared.statements).iter().all(|(_tenant, sql)| sql.contains(JOIN_BIND)));
    let other = run(&shared, "b", &Limits::default()).await?;
    assert_eq!(rules_of(&other), vec![("noisy", MAX_FP_RATE_PPM)]);
    Ok(())
}


#[tokio::test]
async fn one_host_repeating_a_behaviour_cannot_lower_a_rule() -> TestResult {
    let total = FLOOR + SPREAD;
    for (hosts, days, applied) in [
        (1, SPREAD, false),
        (SPREAD, 1, false),
        (SPREAD, TWO, false),
        (TWO, SPREAD, false),
        (THREE, THREE, true),
    ] {
        let db = db_of(vec![verdicts_of("a", "noisy", 1, total, 0, &Spread { hosts, days })]);
        let outcome = run(&db, "a", &Limits::default()).await?;
        assert_eq!(outcome.fp_rules.is_empty(), !applied);
    }
    Ok(())
}


#[tokio::test]
async fn a_rule_at_half_is_listed_and_a_critical_contribution_keeps_full_weight() -> TestResult {
    let db = db_of(vec![
        verdicts_of("a", "noisy", 1, HALF_VERDICTS, HALF_VERDICTS, &three_by_three()),
        (
            vec![
                stored("a", RULE_STRIDE, "noisy", "high", 0, "hi", ""),
                stored("a", RULE_STRIDE + 1, "noisy", "critical", 0, "crit", ""),
            ],
            Vec::new(),
        ),
    ]);
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(rules_of(&outcome), vec![("noisy", NOISY_RATE)]);
    assert_eq!(value_of(&outcome, &host("hi")), Some(HI_SCORE_HALVED));
    assert_eq!(value_of(&outcome, &host("crit")), Some(CRITICAL_SCORE));
    Ok(())
}


#[tokio::test]
async fn alerts_without_a_host_name_give_no_host_toward_the_floor() -> TestResult {
    let (alerts, triage) = verdicts_of("a", "noisy", 1, FLOOR, 0, &three_by_three());
    let nameless: Vec<Stored> = alerts
        .into_iter()
        .map(|alert| Stored {
            host: String::new(),
            user: "someone".to_owned(),
            ..alert
        })
        .collect();
    let outcome = run(&db_of(vec![(nameless, triage)]), "a", &Limits::default()).await?;
    assert!(outcome.fp_rules.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_capped_rule_leaves_a_critical_contribution_at_full_weight() -> TestResult {
    let db = db_of(vec![
        verdicts_of("a", "noisy", 1, FLOOR, 0, &three_by_three()),
        (vec![stored("a", RULE_STRIDE, "noisy", "critical", 0, "crit", "")], Vec::new()),
    ]);
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(value_of(&outcome, &host("crit")), Some(CRITICAL_SCORE));
    Ok(())
}


#[tokio::test]
async fn rules_are_ordered_by_rate_then_id_and_cut_at_the_named_maximum() -> TestResult {
    let mut parts = Vec::new();
    for rule in 0..OVER_CAP_RULES {
        let (false_positives, closed) = if rule + 1 == OVER_CAP_RULES {
            (HALF_VERDICTS, HALF_VERDICTS)
        } else {
            (FLOOR, 0)
        };
        parts.push(verdicts_of(
            "a",
            &format!("r{rule:03}"),
            rule * RULE_STRIDE,
            false_positives,
            closed,
            &three_by_three(),
        ));
    }
    let outcome = run(&db_of(parts), "a", &Limits::default()).await?;
    assert_eq!(outcome.fp_rules.len(), MAX_NAMED_FP_RULES);
    assert_eq!(outcome.fp_rules_omitted, 1);
    assert_eq!(outcome.fp_rules.first().map(|rule| rule.rule_id.as_str()), Some("r000"));
    assert_eq!(outcome.fp_rules.last().map(|rule| rule.rule_id.as_str()), Some("r099"));
    let mixed = db_of(vec![
        verdicts_of("a", "b-half", 1, HALF_VERDICTS, HALF_VERDICTS, &three_by_three()),
        verdicts_of("a", "a-half", RULE_STRIDE, HALF_VERDICTS, HALF_VERDICTS, &three_by_three()),
        verdicts_of("a", "c-all", RULE_STRIDE * TWO, FLOOR, 0, &three_by_three()),
    ]);
    let order = run(&mixed, "a", &Limits::default()).await?;
    assert_eq!(
        rules_of(&order),
        vec![("c-all", MAX_FP_RATE_PPM), ("a-half", NOISY_RATE), ("b-half", NOISY_RATE)]
    );
    assert_eq!(order.fp_rules_omitted, 0);
    Ok(())
}


#[tokio::test]
async fn verdicts_count_only_the_alerts_read_before_the_cap_and_pages_do_not_matter() -> TestResult {
    let db = db_of(vec![verdicts_of("a", "noisy", 1, FLOOD_ALERTS, 0, &three_by_three())]);
    let capped = Limits {
        max_alerts: FLOOD_CAP,
        ..Limits::default()
    };
    let outcome = run(&db, "a", &capped).await?;
    assert_eq!(outcome.alerts_read, FLOOD_CAP);
    assert_eq!(outcome.truncated.map(|cut| cut.limit), Some(Limit::Alerts));
    assert_eq!(
        outcome.fp_rules.iter().map(|rule| rule.false_positive).collect::<Vec<_>>(),
        vec![FLOOD_CAP as u64]
    );
    let whole = run(&db, "a", &Limits::default()).await?;
    let paged = run(&db, "a", &limits(ODD_PAGE)).await?;
    assert_eq!(whole, paged);
    Ok(())
}


#[tokio::test]
async fn every_severity_counts_and_an_unknown_status_is_counted_apart() -> TestResult {
    let mut db = Db::default();
    for index in 0..FLOOR {
        let host_name = format!("h{}", index % THREE);
        db.rows.push(stored(
            "a",
            index,
            "quiet",
            "informational",
            (index % THREE) as u64 * DAY_SECONDS,
            &host_name,
            "",
        ));
        db.triage.push(triaged(index, "false_positive"));
    }
    db.rows.push(stored("a", RULE_STRIDE, "odd", "high", 0, "h9", ""));
    db.rows.push(stored("a", RULE_STRIDE + 1, "odd", "high", 0, "h9", ""));
    db.triage.push(triaged(RULE_STRIDE, "weird"));
    db.triage.push(triaged(RULE_STRIDE + 1, "acknowledged"));
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(rules_of(&outcome), vec![("quiet", MAX_FP_RATE_PPM)]);
    assert_eq!(outcome.unknown_verdicts, 1);
    Ok(())
}


#[test]
fn the_rate_edges_and_the_critical_exemption_hold_on_their_own() -> TestResult {
    let verdicts = |false_positive: u64, closed: u64, hosts: usize, days: usize| Verdicts {
        false_positive,
        closed,
        hosts: (0..hosts).map(|index| index.to_string()).collect(),
        days: (0..days as u64).collect(),
    };
    assert_eq!(fp_rate(&verdicts(MIN_VERDICTS, 0, THREE, THREE)), (MAX_FP_RATE_PPM, true));
    assert_eq!(fp_rate(&verdicts(HALF_FLOOR, HALF_FLOOR, THREE, THREE)), (NOISY_RATE, false));
    assert_eq!(fp_rate(&verdicts(MIN_VERDICTS - 1, 0, THREE, THREE)), (0, false));
    assert_eq!(fp_rate(&verdicts(MIN_VERDICTS, 0, TWO, THREE)), (0, false));
    assert_eq!(fp_rate(&verdicts(MIN_VERDICTS, 0, THREE, TWO)), (0, false));
    let mut counted = BTreeMap::new();
    counted.insert("rule".to_owned(), verdicts(HALF_FLOOR, HALF_FLOOR, THREE, THREE));
    let hit = |severity: Severity, rule: &str| Contribution {
        entity: host("x"),
        rule_id: rule.to_owned(),
        severity,
        observed_at: NOW,
        fleet_rate: 0,
        entity_rate: 0,
        false_positive_rate: 0,
    };
    let rated = with_false_positive_rates(
        vec![hit(Severity::High, "rule"), hit(Severity::Critical, "rule"), hit(Severity::High, "other")],
        &counted,
    );
    let rates: Vec<u32> = rated.iter().map(|contribution| contribution.false_positive_rate).collect();
    assert_eq!(rates, vec![NOISY_RATE, 0, 0]);
    assert!(RISK_ALERTS_SQL.contains(JOIN_BIND) && RISK_ALERTS_NEXT_SQL.contains(JOIN_BIND));
    Ok(())
}
