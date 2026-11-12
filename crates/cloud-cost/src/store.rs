use crate::model::CostTable;
use crate::settings::CostLoadConfig;
use crate::types::Point;
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


/// ClickHouse text of an `Array(String)` parameter: quoted items with backslash and quote escaped.
pub fn array_literal(items: &[String]) -> String {
    let quoted = items
        .iter()
        .map(|item| format!("'{}'", item.replace('\\', "\\\\").replace('\'', "\\'")))
        .collect::<Vec<_>>();
    format!("[{}]", quoted.join(","))
}


/// First and last day of the export; `None` for a table without a day.
pub fn covered_days(table: &CostTable) -> Option<(Date, Date)> {
    let first = table.day_totals.first_key_value().map(|(day, _)| *day);
    let last = table.day_totals.last_key_value().map(|(day, _)| *day);
    first.zip(last)
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
