use siem_schema::error::SchemaError;
use siem_schema::traces::{check_trace_retention, render_traces_ddl, TracesRetention, MAX_TRACE_DAYS};


fn settings(days: u32, policy: &str) -> TracesRetention {
    TracesRetention {
        days,
        storage_policy: policy.to_string(),
    }
}


#[test]
fn golden_ddl() -> Result<(), SchemaError> {
    let expected = "CREATE TABLE `trace_spans`
(
    `tenant` LowCardinality(String),
    `trace_id` FixedString(16),
    `span_id` FixedString(8),
    `parent_span_id` FixedString(8),
    `service_name` LowCardinality(String),
    `name` String,
    `kind` LowCardinality(String),
    `start` DateTime64(9, 'UTC'),
    `duration_nanos` UInt64,
    `status_code` LowCardinality(String),
    `status_message` String,
    `attributes` Map(String, String),
    `event_count` UInt32,
    `link_count` UInt32,
    INDEX `trace_id_bloom` `trace_id` TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(`start`)
ORDER BY (`tenant`, `service_name`, `start`)
TTL toDateTime(`start`) + toIntervalDay(7)
SETTINGS storage_policy = 'default'
";
    assert_eq!(render_traces_ddl(&TracesRetention::default())?, expected);
    Ok(())
}


#[test]
fn retention_bounds() -> Result<(), SchemaError> {
    assert_eq!(
        check_trace_retention(&settings(0, "default")),
        Err(SchemaError::InvalidTraceDays(0, MAX_TRACE_DAYS))
    );
    assert_eq!(
        check_trace_retention(&settings(MAX_TRACE_DAYS + 1, "default")),
        Err(SchemaError::InvalidTraceDays(MAX_TRACE_DAYS + 1, MAX_TRACE_DAYS))
    );
    check_trace_retention(&settings(MAX_TRACE_DAYS, "default"))?;
    check_trace_retention(&settings(1, "default"))?;
    Ok(())
}


#[test]
fn bad_policy_refused() -> Result<(), SchemaError> {
    assert!(render_traces_ddl(&settings(1, "a'b")).is_err());
    assert!(render_traces_ddl(&settings(1, "a b")).is_err());
    Ok(())
}


#[test]
fn out_of_range_refused_when_rendering() -> Result<(), SchemaError> {
    assert!(render_traces_ddl(&settings(0, "default")).is_err());
    Ok(())
}
