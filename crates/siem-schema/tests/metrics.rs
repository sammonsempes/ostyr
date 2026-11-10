use siem_schema::error::SchemaError;
use siem_schema::metrics::{
    check_retention, interval_sql, pick_table, render_metrics_ddl, resolution_seconds, table_name, MetricsRetention, MetricsTable, TableRetention,
    SECONDS_PER_DAY, SECONDS_PER_HOUR, SECONDS_PER_MINUTE,
};


const DAYS_30: u64 = 30;


const DAYS_7: u64 = 7;


const TOO_LONG_RAW_DAYS: u32 = 15;


const MAX_RAW_DAYS: u32 = 14;


const SHORT_DAYS: u32 = 2;


const RAW: u32 = 7;


const MINUTE: u32 = 30;


const HOUR: u32 = 180;


const DAY: u32 = 1825;


const BEYOND_DAY_RETENTION: u64 = 4000 * SECONDS_PER_DAY;


const STATEMENT_COUNT: usize = 7;


const VIEW_HOUR_INDEX: usize = 5;


const DAY_TABLE_INDEX: usize = 3;


const VIEW_DAY_INDEX: usize = 6;


const VIEW_MINUTE_INDEX: usize = 4;


const HOUR_TABLE_INDEX: usize = 2;


const SAMPLE_STEP: usize = 997;


fn policy(days: u32, name: &str) -> TableRetention {
    TableRetention {
        days,
        storage_policy: name.to_string(),
    }
}


fn with_days(raw: u32, minute: u32, hour: u32, day: u32) -> MetricsRetention {
    MetricsRetention {
        raw: policy(raw, "default"),
        minute: policy(minute, "default"),
        hour: policy(hour, "default"),
        day: policy(day, "default"),
    }
}


#[test]
fn golden_ddl() -> Result<(), SchemaError> {
    let statements = render_metrics_ddl(&MetricsRetention::default())?;
    let expected_raw = "CREATE TABLE `metric_samples`
(
    `tenant` LowCardinality(String),
    `metric` LowCardinality(String),
    `unit` LowCardinality(String),
    `kind` Enum8('gauge' = 1, 'counter' = 2, 'histogram' = 3),
    `labels` Map(LowCardinality(String), String),
    `@timestamp` DateTime64(3, 'UTC'),
    `value` Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(`@timestamp`)
ORDER BY (`tenant`, `metric`, `unit`, `kind`, `labels`, `@timestamp`)
TTL toDateTime(`@timestamp`) + toIntervalDay(7)
SETTINGS storage_policy = 'default'
";
    let expected_minute = "CREATE TABLE `metric_rollup_1m`
(
    `tenant` LowCardinality(String),
    `metric` LowCardinality(String),
    `unit` LowCardinality(String),
    `kind` Enum8('gauge' = 1, 'counter' = 2, 'histogram' = 3),
    `labels` Map(LowCardinality(String), String),
    `bucket` DateTime64(3, 'UTC'),
    `value_min` SimpleAggregateFunction(min, Float64),
    `value_max` SimpleAggregateFunction(max, Float64),
    `value_sum` SimpleAggregateFunction(sum, Float64),
    `value_count` SimpleAggregateFunction(sum, UInt64),
    `value_last` SimpleAggregateFunction(anyLast, Float64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(`bucket`)
ORDER BY (`tenant`, `metric`, `unit`, `kind`, `labels`, `bucket`)
TTL toDateTime(`bucket`) + toIntervalDay(30)
SETTINGS storage_policy = 'default'
";
    let expected_view = "CREATE MATERIALIZED VIEW `metric_rollup_1h_mv` TO `metric_rollup_1h` AS
SELECT `tenant`, `metric`, `unit`, `kind`, `labels`,
    toStartOfInterval(`@timestamp`, INTERVAL 1 HOUR) AS `bucket`,
    min(`value`) AS `value_min`,
    max(`value`) AS `value_max`,
    sum(`value`) AS `value_sum`,
    count() AS `value_count`,
    anyLast(`value`) AS `value_last`
FROM `metric_samples`
GROUP BY `tenant`, `metric`, `unit`, `kind`, `labels`, `bucket`
";
    assert_eq!(statements.len(), STATEMENT_COUNT);
    assert_eq!(statements.first().map(String::as_str), Some(expected_raw));
    assert_eq!(statements.get(1).map(String::as_str), Some(expected_minute));
    assert_eq!(statements.get(VIEW_HOUR_INDEX).map(String::as_str), Some(expected_view));
    assert!(statements.get(DAY_TABLE_INDEX).is_some_and(|sql| sql.contains("toIntervalDay(1825)")));
    assert!(statements.get(VIEW_DAY_INDEX).is_some_and(|sql| sql.contains("INTERVAL 1 DAY")));
    assert!(statements.get(VIEW_MINUTE_INDEX).is_some_and(|sql| sql.contains("INTERVAL 1 MINUTE")));
    Ok(())
}


#[test]
fn custom_policy_is_rendered() -> Result<(), SchemaError> {
    let mut settings = MetricsRetention::default();
    settings.hour.storage_policy = "cold_s3".to_string();
    let statements = render_metrics_ddl(&settings)?;
    assert!(statements
        .get(HOUR_TABLE_INDEX)
        .is_some_and(|sql| sql.contains("storage_policy = 'cold_s3'")));
    Ok(())
}


#[test]
fn invalid_policy_is_refused() -> Result<(), SchemaError> {
    let mut settings = MetricsRetention::default();
    settings.day.storage_policy = "x'; DROP".to_string();
    assert!(matches!(check_retention(&settings), Err(SchemaError::InvalidIdentifier(_))));
    Ok(())
}


#[test]
fn invalid_days_are_refused() -> Result<(), SchemaError> {
    assert!(matches!(
        check_retention(&with_days(0, MINUTE, HOUR, DAY)),
        Err(SchemaError::InvalidDays(0, _))
    ));
    Ok(())
}


#[test]
fn raw_kept_too_long_is_refused() -> Result<(), SchemaError> {
    let settings = with_days(TOO_LONG_RAW_DAYS, MINUTE, HOUR, DAY);
    assert_eq!(
        check_retention(&settings),
        Err(SchemaError::RawRetentionTooLong(TOO_LONG_RAW_DAYS, MAX_RAW_DAYS))
    );
    Ok(())
}


#[test]
fn rollup_shorter_than_finer_table_is_refused() -> Result<(), SchemaError> {
    let minute = check_retention(&with_days(RAW, SHORT_DAYS, HOUR, DAY));
    let hour = check_retention(&with_days(RAW, MINUTE, SHORT_DAYS, DAY));
    let day = check_retention(&with_days(RAW, MINUTE, HOUR, SHORT_DAYS));
    assert!(matches!(
        minute,
        Err(SchemaError::RetentionOrder {
            coarse_days: SHORT_DAYS,
            fine_days: RAW,
            ..
        })
    ));
    assert!(matches!(
        hour,
        Err(SchemaError::RetentionOrder {
            coarse_days: SHORT_DAYS,
            fine_days: MINUTE,
            ..
        })
    ));
    assert!(matches!(
        day,
        Err(SchemaError::RetentionOrder {
            coarse_days: SHORT_DAYS,
            fine_days: HOUR,
            ..
        })
    ));
    assert!(render_metrics_ddl(&with_days(RAW, SHORT_DAYS, HOUR, DAY)).is_err());
    Ok(())
}


#[test]
fn pick_table_at_boundaries() -> Result<(), SchemaError> {
    let settings = MetricsRetention::default();
    let week = DAYS_7 * SECONDS_PER_DAY;
    let month = DAYS_30 * SECONDS_PER_DAY;
    assert_eq!(pick_table(&settings, week, 1)?, MetricsTable::Raw);
    assert_eq!(pick_table(&settings, week + 1, 1).ok(), None);
    assert_eq!(pick_table(&settings, week + 1, SECONDS_PER_MINUTE)?, MetricsTable::Minute);
    assert_eq!(pick_table(&settings, week, SECONDS_PER_MINUTE)?, MetricsTable::Raw);
    assert_eq!(pick_table(&settings, 1, SECONDS_PER_HOUR)?, MetricsTable::Raw);
    assert_eq!(pick_table(&settings, month, SECONDS_PER_MINUTE)?, MetricsTable::Minute);
    assert_eq!(pick_table(&settings, month, SECONDS_PER_MINUTE - 1).ok(), None);
    assert_eq!(pick_table(&settings, month + 1, SECONDS_PER_MINUTE).ok(), None);
    assert_eq!(pick_table(&settings, month + 1, SECONDS_PER_HOUR)?, MetricsTable::Hour);
    assert_eq!(pick_table(&settings, month + 1, SECONDS_PER_DAY)?, MetricsTable::Hour);
    assert_eq!(
        pick_table(&settings, u64::from(HOUR) * SECONDS_PER_DAY + 1, SECONDS_PER_DAY)?,
        MetricsTable::Day
    );
    Ok(())
}


#[test]
fn pick_table_refuses_uncovered_and_invalid() -> Result<(), SchemaError> {
    let settings = MetricsRetention::default();
    assert_eq!(pick_table(&settings, 1, 0), Err(SchemaError::NoMetricsTable(1, 0)));
    assert_eq!(
        pick_table(&settings, BEYOND_DAY_RETENTION, SECONDS_PER_DAY),
        Err(SchemaError::NoMetricsTable(BEYOND_DAY_RETENTION, SECONDS_PER_DAY))
    );
    assert!(pick_table(&with_days(0, 1, 1, 1), 1, 1).is_err());
    Ok(())
}


#[test]
fn thirty_days_never_reads_raw() -> Result<(), SchemaError> {
    let settings = MetricsRetention::default();
    let month = DAYS_30 * SECONDS_PER_DAY;
    let steps = (1..=SECONDS_PER_DAY).step_by(SAMPLE_STEP);
    assert!(steps
        .map(|step| pick_table(&settings, month, step).ok())
        .all(|table| table != Some(MetricsTable::Raw)));
    Ok(())
}


#[test]
fn table_helpers() -> Result<(), SchemaError> {
    assert_eq!(table_name(MetricsTable::Raw), "metric_samples");
    assert_eq!(resolution_seconds(MetricsTable::Hour), SECONDS_PER_HOUR);
    assert_eq!(interval_sql(MetricsTable::Raw), "INTERVAL 1 SECOND");
    Ok(())
}
