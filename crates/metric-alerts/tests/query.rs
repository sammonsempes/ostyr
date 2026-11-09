mod common;


use common::types::TestResult;
use metric_alerts::error::RuleError;
use metric_alerts::model::{Capacity, Condition, Direction, Rule, Severity, TenantId};
use metric_alerts::query::{parse_tenant_id, rule_sql, window_and_step, MetricQuery, MAX_TENANT_LEN};
use siem_schema::metrics::{MetricsRetention, MetricsTable};
use std::collections::BTreeMap;


const NOW: u64 = 1_000_000_000;


const EIGHT_DAYS: u64 = 691_200;


const TWO_DAYS: u64 = 172_800;


const THIRTY_DAYS: u64 = 2_592_000;


const FIVE_MINUTES: u64 = 300;


const STEP: u64 = 60;


const TOO_MANY: usize = 17;


const FORECAST_POINTS: usize = 2;


const HOUR_POINTS: usize = 48;


const HOUR_RETENTION: u32 = 3;


const ONE_DAY_RETENTION: u32 = 1;


const LEVEL: f64 = 90.0;


const RATE_LEVEL: f64 = 1.0;


const CONFIDENCE: f64 = 0.5;


const HORIZON: u64 = 3600;


const INTERVAL: u64 = 30;


const RATE_HOLD: u64 = 10;


const SMALL_WINDOW: u64 = 100;


const SMALL_POINTS: usize = 4;


const QUARTER: u64 = 25;


const ABSENCE_WINDOW: u64 = 120;


const RATE_WINDOW: u64 = 130;


pub fn rule(condition: Condition, hold_for: u64, selector: &[(&str, &str)]) -> Rule {
    Rule {
        id: "r".to_string(),
        metric: "disk.used".to_string(),
        selector: selector
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>(),
        condition,
        hold_for,
        close_after: STEP,
        severity: Severity::High,
        labels: BTreeMap::new(),
        runbook: "https://r.example.org".to_string(),
    }
}


pub fn threshold(direction: Direction) -> Condition {
    Condition::Threshold {
        direction,
        threshold: LEVEL,
        clear: None,
    }
}


pub fn rate(direction: Direction) -> Condition {
    Condition::Rate {
        direction,
        threshold: RATE_LEVEL,
        clear: None,
    }
}


pub fn forecast(window: u64, min_points: usize) -> Condition {
    Condition::Forecast {
        window,
        capacity: Capacity::Fixed { value: LEVEL },
        horizon: HORIZON,
        min_confidence: CONFIDENCE,
        min_points,
    }
}


pub fn compile(rule: &Rule, settings: &MetricsRetention) -> Result<MetricQuery, RuleError> {
    rule_sql(rule, &TenantId("acme".to_string()), NOW, settings)
}


pub fn short_rollups() -> MetricsRetention {
    let mut settings = MetricsRetention::default();
    settings.raw.days = ONE_DAY_RETENTION;
    settings.minute.days = ONE_DAY_RETENTION;
    settings.hour.days = HOUR_RETENTION;
    settings
}


pub fn too_many_pairs(names: &[String]) -> Vec<(&str, &str)> {
    names.iter().map(|name| (name.as_str(), "v")).collect()
}


pub fn many_names() -> Vec<String> {
    (0..TOO_MANY).map(|index| format!("label{index}")).collect()
}


#[test]
fn golden_threshold_above_raw() -> TestResult {
    let query = compile(
        &rule(threshold(Direction::Above), FIVE_MINUTES, &[("mount", "/")]),
        &MetricsRetention::default(),
    )?;
    let expected = "SELECT toUnixTimestamp(`@timestamp`) AS `ts`, max(`value`) AS `value`\nFROM `metric_samples`\nWHERE `tenant` = {tenant:String}\n    AND `metric` = {metric:String}\n    AND `@timestamp` >= toDateTime64({from:UInt64}, 3, 'UTC')\n    AND `@timestamp` <= toDateTime64({to:UInt64}, 3, 'UTC')\n    AND `labels`[{label_name_0:String}] = {label_value_0:String}\nGROUP BY `ts`\nORDER BY `ts` ASC\n";
    assert_eq!(query.sql, expected);
    assert_eq!(query.table, MetricsTable::Raw);
    let from = (NOW - FIVE_MINUTES - STEP).to_string();
    let params: Vec<(&str, &str)> = query.params.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    let wanted = vec![
        ("tenant", "acme"),
        ("metric", "disk.used"),
        ("from", from.as_str()),
        ("to", "1000000000"),
        ("label_name_0", "mount"),
        ("label_value_0", "/"),
    ];
    assert_eq!(params, wanted);
    Ok(())
}


#[test]
fn threshold_below_and_rate_use_raw_functions() -> TestResult {
    let below = compile(&rule(threshold(Direction::Below), 0, &[]), &MetricsRetention::default())?;
    assert!(below.sql.contains("min(`value`)"));
    let rate_query = compile(&rule(rate(Direction::Above), 0, &[]), &MetricsRetention::default())?;
    assert!(rate_query.sql.contains("anyLast(`value`)"));
    assert!(!rate_query.sql.contains("AND `labels`"));
    Ok(())
}


#[test]
fn long_window_reads_minute_rollup() -> TestResult {
    let above = compile(&rule(threshold(Direction::Above), EIGHT_DAYS, &[]), &MetricsRetention::default())?;
    assert_eq!(above.table, MetricsTable::Minute);
    assert!(above.sql.contains("FROM `metric_rollup_1m`"));
    assert!(above.sql.contains("max(`value_max`)"));
    assert!(above.sql.contains("toUnixTimestamp(`bucket`)"));
    let below = compile(&rule(threshold(Direction::Below), EIGHT_DAYS, &[]), &MetricsRetention::default())?;
    assert!(below.sql.contains("min(`value_min`)"));
    Ok(())
}


#[test]
fn thirty_day_window_never_reads_raw() -> TestResult {
    let query = compile(&rule(forecast(THIRTY_DAYS, FORECAST_POINTS), 0, &[]), &MetricsRetention::default())?;
    assert_eq!(query.table, MetricsTable::Minute);
    assert!(query.sql.contains("anyLast(`value_last`)"));
    Ok(())
}


#[test]
fn coarse_steps_pick_hour_and_day() -> TestResult {
    let hour = compile(&rule(forecast(TWO_DAYS, HOUR_POINTS), 0, &[]), &short_rollups())?;
    assert_eq!(hour.table, MetricsTable::Hour);
    let day = compile(&rule(forecast(THIRTY_DAYS, FORECAST_POINTS), 0, &[]), &short_rollups())?;
    assert_eq!(day.table, MetricsTable::Day);
    Ok(())
}


#[test]
fn no_table_covers_a_month_of_fine_steps() -> TestResult {
    let result = compile(&rule(threshold(Direction::Above), THIRTY_DAYS, &[]), &MetricsRetention::default());
    assert!(matches!(result, Err(RuleError::Schema(_))));
    Ok(())
}


#[test]
fn windows_and_steps_per_condition() -> TestResult {
    assert_eq!(
        window_and_step(&rule(Condition::Absence { interval: INTERVAL }, 0, &[])),
        (ABSENCE_WINDOW, INTERVAL)
    );
    assert_eq!(window_and_step(&rule(Condition::Absence { interval: 0 }, 0, &[])), (0, 1));
    assert_eq!(window_and_step(&rule(forecast(SMALL_WINDOW, 0), 0, &[])), (SMALL_WINDOW, SMALL_WINDOW));
    assert_eq!(
        window_and_step(&rule(forecast(SMALL_WINDOW, SMALL_POINTS), 0, &[])),
        (SMALL_WINDOW, QUARTER)
    );
    assert_eq!(window_and_step(&rule(forecast(1, SMALL_POINTS), 0, &[])), (1, 1));
    assert_eq!(window_and_step(&rule(rate(Direction::Below), RATE_HOLD, &[])), (RATE_WINDOW, STEP));
    Ok(())
}


#[test]
fn hostile_label_value_stays_a_parameter() -> TestResult {
    let hostile = "x' OR 1=1; DROP TABLE metric_samples --";
    let query = compile(&rule(threshold(Direction::Above), 0, &[("mount", hostile)]), &MetricsRetention::default())?;
    assert!(!query.sql.contains("DROP"));
    assert!(!query.sql.contains("1=1"));
    assert!(query.params.contains(&("label_value_0".to_string(), hostile.to_string())));
    Ok(())
}


#[test]
fn invalid_label_name_is_refused() -> TestResult {
    let result = compile(&rule(threshold(Direction::Above), 0, &[("bad`name", "v")]), &MetricsRetention::default());
    assert!(matches!(result, Err(RuleError::Schema(_))));
    Ok(())
}


#[test]
fn too_many_selectors_are_refused() -> TestResult {
    let names = many_names();
    let result = compile(
        &rule(threshold(Direction::Above), 0, &too_many_pairs(&names)),
        &MetricsRetention::default(),
    );
    assert!(matches!(result, Err(RuleError::TooManySelectors { count: TOO_MANY, .. })));
    let text = result.err().map(|error| error.to_string());
    assert_eq!(text.as_deref(), Some("rule `r`: 17 selector labels, at most 16 allowed"));
    Ok(())
}


#[test]
fn tenants_never_mix() -> TestResult {
    let settings = MetricsRetention::default();
    let rule_value = rule(threshold(Direction::Above), 0, &[]);
    let first = rule_sql(&rule_value, &TenantId("acme".to_string()), NOW, &settings)?;
    let second = rule_sql(&rule_value, &TenantId("globex".to_string()), NOW, &settings)?;
    assert_eq!(first.sql, second.sql);
    assert!(first.sql.contains("WHERE `tenant` = {tenant:String}"));
    assert!(first.params.contains(&("tenant".to_string(), "acme".to_string())));
    assert!(second.params.contains(&("tenant".to_string(), "globex".to_string())));
    assert!(!second.params.contains(&("tenant".to_string(), "acme".to_string())));
    Ok(())
}


#[test]
fn hostile_tenant_id_stays_a_parameter() -> TestResult {
    let hostile = "x' OR 1=1; --";
    let tenant = parse_tenant_id(hostile)?;
    let query = rule_sql(&rule(threshold(Direction::Above), 0, &[]), &tenant, NOW, &MetricsRetention::default())?;
    assert!(!query.sql.contains("1=1"));
    assert!(query.params.contains(&("tenant".to_string(), hostile.to_string())));
    Ok(())
}


#[test]
fn tenant_id_is_bounded() -> TestResult {
    assert_eq!(parse_tenant_id("acme")?, TenantId("acme".to_string()));
    assert!(matches!(parse_tenant_id(""), Err(RuleError::InvalidTenant)));
    assert!(matches!(parse_tenant_id("a\nb"), Err(RuleError::InvalidTenant)));
    assert!(matches!(parse_tenant_id(&"a".repeat(MAX_TENANT_LEN + 1)), Err(RuleError::InvalidTenant)));
    assert!(parse_tenant_id(&"a".repeat(MAX_TENANT_LEN)).is_ok());
    assert_eq!(RuleError::InvalidTenant.to_string(), "invalid tenant id");
    Ok(())
}
