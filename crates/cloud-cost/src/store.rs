use crate::model::CostTable;
use crate::settings::CostLoadConfig;
use crate::types::{DayRange, Point};
use serde_json::json;
use siem_schema::error::SchemaError;
use siem_schema::identifier::quote_identifier;
use time::Date;


pub const ROWS_PER_BATCH: usize = 10_000;


pub const DECIMAL_SCALE: u32 = 9;


/// One stored aggregate; `cost` is exact decimal text, never a float.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostRow {
    pub tenant: String,
    pub account: String,
    pub source: String,
    pub day: Date,
    pub dimension: &'static str,
    pub key1: String,
    pub key2: String,
    pub cost: String,
    pub currency: String,
    pub version: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub rows: usize,
    pub body: String,
}


pub fn qualified(database: &str, table: &str) -> Result<String, SchemaError> {
    Ok(format!("{}.{}", quote_identifier(database)?, quote_identifier(table)?))
}


pub fn database_ddl(config: &CostLoadConfig) -> Result<String, SchemaError> {
    Ok(format!("CREATE DATABASE IF NOT EXISTS {}", quote_identifier(&config.database)?))
}


/// `ReplacingMergeTree(version)` keyed by tenant, billing account, source digest, day, dimension and the two key parts; rows expire `ttl_days` after their day.
pub fn table_ddl(config: &CostLoadConfig) -> Result<String, SchemaError> {
    let target = qualified(&config.database, &config.table)?;
    let ttl_days = config.ttl_days;
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {target} (\n    \
         `tenant` String,\n    \
         `account` String,\n    \
         `source` String,\n    \
         `day` Date,\n    \
         `dimension` LowCardinality(String),\n    \
         `key1` String,\n    \
         `key2` String,\n    \
         `cost` Decimal(38, {DECIMAL_SCALE}),\n    \
         `currency` LowCardinality(String),\n    \
         `version` UInt64\n\
         )\n\
         ENGINE = ReplacingMergeTree(`version`)\n\
         ORDER BY (`tenant`, `account`, `source`, `day`, `dimension`, `key1`, `key2`)\n\
         TTL `day` + INTERVAL {ttl_days} DAY DELETE"
    ))
}


pub const STATE_IN_PROGRESS: &str = "in_progress";


pub const STATE_DONE: &str = "done";


pub const STATE_SUFFIX: &str = "_load_state";


/// The load-state table of the cost table: `<table>_load_state` in the same database.
pub fn state_target(config: &CostLoadConfig) -> Result<String, SchemaError> {
    qualified(&config.database, &format!("{}{STATE_SUFFIX}", config.table))
}


/// One row per (tenant, export digest), the highest `generation` wins (same generation: the last insert, so `done` follows `in_progress`); rows expire `ttl_days` after `loaded_at`, like the figures they guard.
pub fn state_ddl(config: &CostLoadConfig) -> Result<String, SchemaError> {
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {} (\n    \
         `tenant` String,\n    \
         `source` String,\n    \
         `generation` UInt64,\n    \
         `state` LowCardinality(String),\n    \
         `loaded_at` DateTime DEFAULT now()\n\
         )\n\
         ENGINE = ReplacingMergeTree(`generation`)\n\
         ORDER BY (`tenant`, `source`)\n\
         TTL `loaded_at` + INTERVAL {} DAY DELETE",
        state_target(config)?,
        config.ttl_days
    ))
}


/// A state write is synchronous whatever the loader's profile says, so `done` always lands after `in_progress`.
pub fn state_insert_statement(config: &CostLoadConfig) -> Result<String, SchemaError> {
    Ok(format!(
        "INSERT INTO {} SETTINGS async_insert = 0 FORMAT JSONEachRow",
        state_target(config)?
    ))
}


/// The one JSON line of a state write.
pub fn state_row(tenant: &str, digest: &str, generation: u64, state: &str) -> String {
    json!({ "tenant": tenant, "source": digest, "generation": generation, "state": state }).to_string()
}


/// The highest generation ever written for the export digest (0 when none), as text.
pub fn generation_statement(config: &CostLoadConfig) -> Result<String, SchemaError> {
    Ok(format!(
        "SELECT toString(max(`generation`)) FROM {} WHERE `tenant` = {{tenant:String}} AND `source` = {{source:String}}",
        state_target(config)?
    ))
}


/// The next generation of a digest: after its previous one, and after the clock when the clock is ahead, so a clock set back never goes under it.
pub fn next_generation(previous: u64, now_ms: u64) -> u64 {
    previous.saturating_add(1).max(now_ms)
}


pub fn insert_statement(config: &CostLoadConfig) -> Result<String, SchemaError> {
    Ok(format!("INSERT INTO {} FORMAT JSONEachRow", qualified(&config.database, &config.table)?))
}


/// Lightweight delete of the tenant's rows of the export's billing accounts in a day range; every value is a bound parameter.
pub fn delete_statement(config: &CostLoadConfig) -> Result<String, SchemaError> {
    Ok(format!(
        "DELETE FROM {} WHERE tenant = {{tenant:String}} AND account IN {{accounts:Array(String)}} AND day >= {{first:Date}} AND day <= {{last:Date}}",
        qualified(&config.database, &config.table)?
    ))
}


/// The distinct billing account labels seen in any row of the export, skipped or not, in order.
pub fn account_set(table: &CostTable) -> Vec<String> {
    table.seen_accounts.iter().cloned().collect()
}


/// One quoted `String` item with backslash and quote escaped.
pub fn quote_item(item: &str) -> String {
    format!("'{}'", item.replace('\\', "\\\\").replace('\'', "\\'"))
}


/// ClickHouse text of an `Array(String)` parameter: quoted items with backslash and quote escaped.
pub fn array_literal(items: &[String]) -> String {
    let quoted = items.iter().map(|item| quote_item(item)).collect::<Vec<_>>();
    format!("[{}]", quoted.join(","))
}


/// First and last readable day of any row naming a valid account, accepted or skipped; `None` when there is none.
pub fn covered_days(table: &CostTable) -> Option<DayRange> {
    table.seen_days
}


pub fn points(table: &CostTable) -> Vec<Point> {
    table
        .account_rows
        .iter()
        .map(|((day, account, dimension, key1, key2), cost)| (*day, account.clone(), *dimension, key1.clone(), key2.clone(), *cost))
        .collect()
}


/// Every aggregate of the table with the tenant, the source digest, the currency and the load version; costs rounded to the column's scale.
pub fn plan_rows(table: &CostTable, tenant: &str, source: &str, version: u64) -> Vec<CostRow> {
    let currency = table.currency.as_deref().unwrap_or("");
    points(table)
        .into_iter()
        .map(|(day, account, dimension, key1, key2, cost)| CostRow {
            account,
            tenant: tenant.to_owned(),
            source: source.to_owned(),
            day,
            dimension,
            key1,
            key2,
            cost: cost.round_dp(DECIMAL_SCALE).to_string(),
            currency: currency.to_owned(),
            version,
        })
        .collect()
}


/// One JSON object per row; the cost stays a string so no float ever sees it.
pub fn encode_row(row: &CostRow) -> String {
    json!({
        "tenant": row.tenant,
        "account": row.account,
        "source": row.source,
        "day": row.day.to_string(),
        "dimension": row.dimension,
        "key1": row.key1,
        "key2": row.key2,
        "cost": row.cost,
        "currency": row.currency,
        "version": row.version,
    })
    .to_string()
}


pub fn insert_plan(rows: &[CostRow]) -> Vec<Batch> {
    rows.chunks(ROWS_PER_BATCH)
        .map(|chunk| Batch {
            rows: chunk.len(),
            body: chunk.iter().map(encode_row).collect::<Vec<_>>().join("\n"),
        })
        .collect()
}
