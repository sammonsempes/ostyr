CREATE TABLE IF NOT EXISTS `events`
(
    `@timestamp` DateTime64(3, 'UTC'),
    `tenant` LowCardinality(String),
    `tenant_tier` LowCardinality(String),
    `ecs.version` LowCardinality(String),
    `event.id` String,
    `event.kind` LowCardinality(String),
    `event.category` Array(LowCardinality(String)),
    `event.type` Array(LowCardinality(String)),
    `event.action` LowCardinality(String),
    `event.outcome` LowCardinality(String),
    `event.dataset` LowCardinality(String),
    `event.module` LowCardinality(String),
    `event.severity` UInt32,
    `event.sequence` UInt64,
    `message` String,
    `host.name` String,
    `host.id` String,
    `host.ip` Array(String),
    `host.os.type` LowCardinality(String),
    `user.name` String,
    `user.id` String,
    `user.domain` String,
    `source.ip` String,
    `source.port` UInt16,
    `source.domain` String,
    `destination.ip` String,
    `destination.port` UInt16,
    `destination.domain` String,
    `network.transport` LowCardinality(String),
    `network.direction` LowCardinality(String),
    `process.pid` UInt32,
    `process.name` String,
    `process.executable` String,
    `process.command_line` String,
    `process.args` Array(String),
    `process.working_directory` String,
    `process.parent.pid` UInt32,
    `process.parent.executable` String,
    `process.parent.command_line` String,
    `file.path` String,
    `file.size` UInt64,
    `event.code` LowCardinality(String),
    `event.provider` LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toDate(`@timestamp`)
ORDER BY (`tenant`, `@timestamp`)
TTL toDateTime(`@timestamp`) + toIntervalDay(90)
;
CREATE TABLE IF NOT EXISTS `metric_samples`
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
;
CREATE TABLE IF NOT EXISTS `metric_rollup_1m`
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
;
CREATE TABLE IF NOT EXISTS `metric_rollup_1h`
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
TTL toDateTime(`bucket`) + toIntervalDay(180)
SETTINGS storage_policy = 'default'
;
CREATE TABLE IF NOT EXISTS `metric_rollup_1d`
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
TTL toDateTime(`bucket`) + toIntervalDay(1825)
SETTINGS storage_policy = 'default'
;
CREATE MATERIALIZED VIEW IF NOT EXISTS `metric_rollup_1m_mv` TO `metric_rollup_1m` AS
SELECT `tenant`, `metric`, `unit`, `kind`, `labels`,
    toStartOfInterval(`@timestamp`, INTERVAL 1 MINUTE) AS `bucket`,
    min(`value`) AS `value_min`,
    max(`value`) AS `value_max`,
    sum(`value`) AS `value_sum`,
    count() AS `value_count`,
    anyLast(`value`) AS `value_last`
FROM `metric_samples`
GROUP BY `tenant`, `metric`, `unit`, `kind`, `labels`, `bucket`
;
CREATE MATERIALIZED VIEW IF NOT EXISTS `metric_rollup_1h_mv` TO `metric_rollup_1h` AS
SELECT `tenant`, `metric`, `unit`, `kind`, `labels`,
    toStartOfInterval(`@timestamp`, INTERVAL 1 HOUR) AS `bucket`,
    min(`value`) AS `value_min`,
    max(`value`) AS `value_max`,
    sum(`value`) AS `value_sum`,
    count() AS `value_count`,
    anyLast(`value`) AS `value_last`
FROM `metric_samples`
GROUP BY `tenant`, `metric`, `unit`, `kind`, `labels`, `bucket`
;
CREATE MATERIALIZED VIEW IF NOT EXISTS `metric_rollup_1d_mv` TO `metric_rollup_1d` AS
SELECT `tenant`, `metric`, `unit`, `kind`, `labels`,
    toStartOfInterval(`@timestamp`, INTERVAL 1 DAY) AS `bucket`,
    min(`value`) AS `value_min`,
    max(`value`) AS `value_max`,
    sum(`value`) AS `value_sum`,
    count() AS `value_count`,
    anyLast(`value`) AS `value_last`
FROM `metric_samples`
GROUP BY `tenant`, `metric`, `unit`, `kind`, `labels`, `bucket`
;
CREATE TABLE IF NOT EXISTS `trace_spans`
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
;
