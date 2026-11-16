mod memory;
mod types;


use core_pg::scope::{tenant_scope, TenantScope};
use memory::{executor, lock, row_of, Db, Stored, TENANT_BIND};
use risk_score::error::RiskError;
use risk_score::model::{Contribution, EntityKind, EntityRef, Severity, SeverityPoints, Weights};
use risk_score::source::{
    per_million, rates_of, risk_severity, tenant_scores, window_start_micros, with_rates, Limit, Limits, Outcome, Truncated, MAX_ALERTS, PAGE_SIZE,
    RISK_ALERTS_NEXT_SQL, RISK_ALERTS_SQL,
};
use std::error::Error;
use types::TestResult;


const NOW: i64 = 10_000_000;


const MICROS: u64 = 1_000_000;


const WINDOW_SECONDS: u64 = 604_800;


const NOW_MICROS: u64 = 10_000_000 * MICROS;


const SEVEN: usize = 7;


const HALF_BATCH: usize = 50_001;


const HOST_POOL: usize = 100;


const SMALL_ENTITIES: usize = 5;


const SMALL_ALERTS: usize = 4;


const THREE: usize = 3;


const FIVE: usize = 5;


const TWO: usize = 2;


const LONG_NAME: usize = 300;


const MEDIUM_POINTS: u32 = 5;


const HIGH_POINTS: u32 = 10;


const CRITICAL_POINTS: u32 = 20;


const RARE_THRESHOLD: u32 = 1_000;


const RARE_BONUS: u32 = 500;


const FULL_SCORE_POINTS: u32 = 100;


const ONE_THIRD: u32 = 333_333;


const TWO_THIRDS: u32 = 666_666;


const WHOLE: u32 = 1_000_000;


const LOW_SCORE: u8 = 1;


const CRITICAL_SCORE: u8 = 20;


const MAX_TOTAL: usize = 100_000;


const MAX_HOSTS: usize = 10_000;


fn stored(tenant: &str, index: usize, rule: &str, severity: &str, age_seconds: u64, host: &str, user: &str) -> Stored {
    Stored {
        tenant: tenant.to_owned(),
        id: format!("{index:064x}"),
        rule: rule.to_owned(),
        severity: severity.to_owned(),
        created: NOW_MICROS - age_seconds * MICROS,
        host: host.to_owned(),
        user: user.to_owned(),
    }
}


fn scope(tenant: &str) -> Result<TenantScope, Box<dyn Error>> {
    Ok(tenant_scope(tenant)?)
}


fn limits(page_size: usize) -> Limits {
    Limits {
        page_size,
        ..Limits::default()
    }
}


async fn run(db: &Db, tenant: &str, limits: &Limits) -> Result<Outcome, Box<dyn Error>> {
    let exec = executor(db);
    Ok(tenant_scores(&exec, &scope(tenant)?, &weights(), NOW, limits).await?)
}


fn host(id: &str) -> EntityRef {
    EntityRef {
        kind: EntityKind::Host,
        id: id.to_owned(),
    }
}


fn weights() -> Weights {
    Weights {
        severity_points: SeverityPoints {
            low: 1,
            medium: MEDIUM_POINTS,
            high: HIGH_POINTS,
            critical: CRITICAL_POINTS,
        },
        rare_threshold_per_million: RARE_THRESHOLD,
        entity_rare_bonus_permille: RARE_BONUS,
        fleet_rare_bonus_permille: RARE_BONUS,
        full_score_points: FULL_SCORE_POINTS,
    }
}


fn value_of(outcome: &Outcome, entity: &EntityRef) -> Option<u8> {
    outcome.scores.iter().find(|score| &score.entity == entity).map(|score| score.value)
}


#[tokio::test]
async fn two_tenants_with_one_host_name_are_scored_apart() -> TestResult {
    let db = Db {
        rows: vec![
            stored("a", 1, "r1", "critical", 0, "h1", ""),
            stored("b", TWO, "r1", "low", 0, "h1", ""),
            stored("b", THREE, "r1", "low", 1, "only-b", ""),
        ],
        ..Db::default()
    };
    let in_a = run(&db, "a", &limits(1)).await?;
    let in_b = run(&db, "b", &limits(1)).await?;
    assert_eq!(value_of(&in_a, &host("h1")), Some(CRITICAL_SCORE));
    assert_eq!(value_of(&in_a, &host("only-b")), None);
    assert_eq!(in_a.scores.len(), 1);
    assert_eq!(value_of(&in_b, &host("h1")), Some(LOW_SCORE));
    assert_eq!(in_b.scores.len(), TWO);
    assert!(lock(&db.statements).iter().all(|(_tenant, sql)| sql.contains(TENANT_BIND)));
    assert!(lock(&db.statements).iter().any(|(_tenant, sql)| *sql == RISK_ALERTS_NEXT_SQL));
    assert!(lock(&db.statements).iter().any(|(_tenant, sql)| *sql == RISK_ALERTS_SQL));
    Ok(())
}


#[tokio::test]
async fn an_alert_exactly_seven_days_old_is_excluded() -> TestResult {
    let db = Db {
        rows: vec![
            stored("a", 1, "r1", "critical", WINDOW_SECONDS, "exactly-seven-days", ""),
            stored("a", TWO, "r1", "critical", WINDOW_SECONDS - 1, "just-inside", ""),
        ],
        ..Db::default()
    };
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(value_of(&outcome, &host("exactly-seven-days")), None);
    assert_eq!(value_of(&outcome, &host("just-inside")), Some(0));
    assert_eq!(outcome.alerts_read, 1);
    assert_eq!(window_start_micros(NOW), (NOW_MICROS - WINDOW_SECONDS * MICROS).cast_signed());
    assert_eq!(window_start_micros(0), 0);
    Ok(())
}


#[tokio::test]
async fn a_refused_host_leaves_the_user_of_the_same_alert_counting() -> TestResult {
    let long = "h".repeat(LONG_NAME);
    let db = Db {
        rows: vec![
            stored("a", 1, "r1", "high", 0, "evil\u{202e}host", "alice"),
            stored("a", TWO, "r1", "high", 0, "\u{3164}", "bob"),
            stored("a", THREE, "r1", "high", 0, &long, ""),
            stored("a", FIVE, "r1", "high", 0, "", "carol\u{202e}"),
            stored("a", SEVEN, "r1", "high", 0, "", "dave"),
        ],
        ..Db::default()
    };
    let outcome = run(&db, "a", &Limits::default()).await?;
    let user = |name: &str| EntityRef {
        kind: EntityKind::User,
        id: name.to_owned(),
    };
    assert!(value_of(&outcome, &user("alice")).is_some());
    assert!(value_of(&outcome, &user("bob")).is_some());
    assert!(value_of(&outcome, &user("dave")).is_some());
    assert_eq!(outcome.scores.len(), THREE);
    assert_eq!(outcome.refused.get(&EntityKind::Host), Some(&THREE));
    assert_eq!(outcome.refused.get(&EntityKind::User), Some(&1));
    assert_eq!(outcome.alerts_read, FIVE);
    Ok(())
}


#[tokio::test]
async fn informational_alerts_contribute_nothing() -> TestResult {
    let db = Db {
        rows: vec![
            stored("a", 1, "r1", "informational", 0, "quiet", ""),
            stored("a", TWO, "r1", "low", 0, "loud", ""),
        ],
        ..Db::default()
    };
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(outcome.informational, 1);
    assert_eq!(outcome.scores.len(), 1);
    assert_eq!(value_of(&outcome, &host("quiet")), None);
    Ok(())
}


#[tokio::test]
async fn more_than_the_contribution_cap_is_a_loud_truncation_with_scores() -> TestResult {
    let rows = (0..HALF_BATCH)
        .map(|index| {
            let name = format!("h{}", index % HOST_POOL);
            let user = format!("u{}", index % HOST_POOL);
            stored("a", index, "r1", "low", 0, &name, &user)
        })
        .collect();
    let db = Db { rows, ..Db::default() };
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(
        outcome.truncated,
        Some(Truncated {
            limit: Limit::Contributions,
            read: MAX_TOTAL,
            cap: MAX_TOTAL
        })
    );
    assert_eq!(outcome.scores.len(), HOST_POOL * TWO);
    assert_eq!(outcome.alerts_read, HALF_BATCH - 1);
    Ok(())
}


#[tokio::test]
async fn more_than_the_entity_cap_is_a_loud_truncation_keeping_earlier_entities() -> TestResult {
    let rows = (0..=MAX_HOSTS)
        .map(|index| stored("a", index, "r1", "low", MAX_HOSTS as u64 - index as u64, &format!("h{index}"), ""))
        .collect();
    let db = Db { rows, ..Db::default() };
    let outcome = run(&db, "a", &Limits::default()).await?;
    assert_eq!(
        outcome.truncated,
        Some(Truncated {
            limit: Limit::Entities,
            read: MAX_HOSTS,
            cap: MAX_HOSTS
        })
    );
    assert_eq!(outcome.scores.len(), MAX_HOSTS);
    assert!(value_of(&outcome, &host("h0")).is_some());
    assert_eq!(value_of(&outcome, &host(&format!("h{MAX_HOSTS}"))), None);
    Ok(())
}


#[tokio::test]
async fn a_flood_of_ignored_alerts_stops_at_the_alert_cap() -> TestResult {
    let rows = (0..SMALL_ALERTS + 1)
        .map(|index| stored("a", index, "r1", "informational", 0, "quiet", ""))
        .collect();
    let db = Db { rows, ..Db::default() };
    let small = Limits {
        page_size: TWO,
        max_alerts: SMALL_ALERTS,
        ..Limits::default()
    };
    let outcome = run(&db, "a", &small).await?;
    assert_eq!(
        outcome.truncated,
        Some(Truncated {
            limit: Limit::Alerts,
            read: SMALL_ALERTS,
            cap: SMALL_ALERTS
        })
    );
    assert_eq!(outcome.informational, SMALL_ALERTS);
    assert!(outcome.scores.is_empty());
    Ok(())
}


#[tokio::test]
async fn small_limits_truncate_at_the_injected_bounds() -> TestResult {
    let rows = (0..SMALL_ENTITIES + 1)
        .map(|index| stored("a", index, "r1", "low", 0, &format!("h{index}"), ""))
        .collect();
    let db = Db { rows, ..Db::default() };
    let small = Limits {
        page_size: SEVEN,
        max_alerts: MAX_ALERTS,
        max_contributions: SMALL_ENTITIES - 1,
        max_entities: SMALL_ENTITIES,
    };
    let outcome = run(&db, "a", &small).await?;
    assert_eq!(outcome.truncated.map(|truncated| truncated.limit), Some(Limit::Contributions));
    assert_eq!(outcome.scores.len(), SMALL_ENTITIES - 1);
    Ok(())
}


#[tokio::test]
async fn pages_of_any_size_give_the_same_outcome() -> TestResult {
    let rows = (0..SEVEN * TWO)
        .map(|index| {
            let rule = if index % TWO == 0 { "r1" } else { "r2" };
            let severity = if index % THREE == 0 { "high" } else { "medium" };
            stored(
                "a",
                index,
                rule,
                severity,
                (index % SEVEN) as u64,
                &format!("h{}", index % THREE),
                &format!("u{}", index % TWO),
            )
        })
        .collect();
    let db = Db { rows, ..Db::default() };
    let one_page = run(&db, "a", &limits(PAGE_SIZE)).await?;
    let by_one = run(&db, "a", &limits(1)).await?;
    let by_seven = run(&db, "a", &limits(SEVEN)).await?;
    let by_zero = run(&db, "a", &limits(0)).await?;
    assert_eq!(by_one, one_page);
    assert_eq!(by_seven, one_page);
    assert_eq!(by_zero, one_page);
    assert_eq!(one_page.alerts_read, SEVEN * TWO);
    assert_eq!(one_page.truncated, None);
    Ok(())
}


#[test]
fn rates_match_a_hand_computed_fixture() -> TestResult {
    let hit = |id: &str, rule: &str| Contribution {
        entity: host(id),
        rule_id: rule.to_owned(),
        severity: Severity::High,
        observed_at: NOW,
        fleet_rate: 0,
        entity_rate: 0,
        false_positive_rate: 0,
    };
    let rated = with_rates(vec![hit("A", "r1"), hit("A", "r1"), hit("A", "r2"), hit("B", "r1"), hit("C", "r2")]);
    let rates: Vec<(u32, u32)> = rated
        .iter()
        .map(|contribution| (contribution.fleet_rate, contribution.entity_rate))
        .collect();
    assert_eq!(
        rates,
        vec![
            (TWO_THIRDS, TWO_THIRDS),
            (TWO_THIRDS, TWO_THIRDS),
            (TWO_THIRDS, ONE_THIRD),
            (TWO_THIRDS, WHOLE),
            (TWO_THIRDS, WHOLE)
        ]
    );
    assert!(rated.iter().all(|contribution| contribution.false_positive_rate == 0));
    assert!(rates_of(&[]).is_empty());
    Ok(())
}


#[test]
fn small_helpers_cover_their_edges() -> TestResult {
    assert_eq!(per_million(1, 0), 0);
    assert_eq!(per_million(THREE as u64, 1), WHOLE);
    assert_eq!(risk_severity(alerts::model::Severity::Informational), None);
    assert_eq!(risk_severity(alerts::model::Severity::Low), Some(Severity::Low));
    assert_eq!(risk_severity(alerts::model::Severity::Medium), Some(Severity::Medium));
    assert_eq!(risk_severity(alerts::model::Severity::High), Some(Severity::High));
    assert_eq!(risk_severity(alerts::model::Severity::Critical), Some(Severity::Critical));
    let defaults = Limits::default();
    assert_eq!((defaults.page_size, defaults.max_alerts), (PAGE_SIZE, MAX_ALERTS));
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_a_typed_error_not_partial_scores() -> TestResult {
    let db = Db { fail: true, ..Db::default() };
    let exec = executor(&db);
    let result = tenant_scores(&exec, &scope("a")?, &weights(), NOW, &Limits::default()).await;
    assert!(matches!(result, Err(RiskError::Store(_))));
    Ok(())
}


#[tokio::test]
async fn malformed_rows_are_typed_errors() -> TestResult {
    let good = row_of(&stored("a", 1, "r1", "high", 0, "h", ""));
    let with = |column: usize, value: &str| {
        let mut row = good.clone();
        if let Some(cell) = row.get_mut(column) {
            *cell = value.to_owned();
        }
        row
    };
    let cases = vec![
        vec![],
        good.iter().take(THREE).cloned().collect(),
        good.iter().take(THREE + 1).cloned().collect(),
        good.iter().take(THREE + TWO).cloned().collect(),
        with(TWO, "bogus"),
        with(THREE, "-1"),
        with(0, ""),
    ];
    let outcomes = cases.into_iter().map(|row| async {
        let db = Db {
            forced: Some(vec![row]),
            ..Db::default()
        };
        run(&db, "a", &Limits::default()).await.is_err()
    });
    let mut errors = 0;
    for outcome in outcomes {
        errors += usize::from(outcome.await);
    }
    assert_eq!(errors, SEVEN - 1);
    Ok(())
}
