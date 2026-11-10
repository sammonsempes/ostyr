CREATE TABLE `events_cold`
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
    `file.size` UInt64
)
ENGINE = MergeTree
PARTITION BY toDate(`@timestamp`)
ORDER BY (`tenant`, `@timestamp`)
TTL toDateTime(`@timestamp`) + multiIf(`tenant_tier` = 'premium', toIntervalDay(2), toIntervalDay(1)) TO VOLUME 'cold', toDateTime(`@timestamp`) + multiIf(`tenant_tier` = 'premium', toIntervalDay(90), toIntervalDay(30)) DELETE
SETTINGS storage_policy = 'hot_cold'
