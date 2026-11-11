use crate::config::FeedConfig;
use crate::limits::{DEFAULT_TTL_SECONDS, MAX_BATCH_BYTES, MAX_IDENTIFIER_BYTES, MAX_ROWS_PER_BATCH};
use crate::model::Ioc;
use crate::types::TtlDefaults;
use serde_json::json;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tracing::warn;


#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid identifier `{0}`")]
    Identifier(String),
}


/// The per-feed default TTL by feed name, and the TTL used when neither the IOC nor its feed has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSettings {
    pub tenant: String,
    pub feed_ttl_seconds: TtlDefaults,
    pub fallback_ttl_seconds: u32,
}


/// Each batch body is JSON lines, ready for `INSERT … FORMAT JSONEachRow`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InsertPlan {
    pub batches: Vec<Batch>,
    pub rows: usize,
    pub expired: u64,
    pub unsourced: u64,
    pub oversized: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Batch {
    pub body: String,
    pub rows: usize,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowOutcome {
    Kept(String),
    Expired,
    Unsourced,
}


pub fn settings_for(tenant: &str, feeds: &[FeedConfig]) -> StoreSettings {
    StoreSettings {
        tenant: tenant.to_owned(),
        feed_ttl_seconds: feeds
            .iter()
            .filter_map(|feed| feed.ttl_seconds.map(|ttl| (feed.name.clone(), ttl)))
            .collect(),
        fallback_ttl_seconds: DEFAULT_TTL_SECONDS,
    }
}


/// Letters, digits and underscore, not starting with a digit, at most `MAX_IDENTIFIER_BYTES`.
pub fn quote_identifier(name: &str) -> Result<String, StoreError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_IDENTIFIER_BYTES
        && name.chars().all(|character| character.is_ascii_alphanumeric() || character == '_')
        && !name.starts_with(|character: char| character.is_ascii_digit());
    if valid {
        Ok(format!("`{name}`"))
    } else {
        Err(StoreError::Identifier(name.to_owned()))
    }
}


pub fn qualified(database: &str, table: &str) -> Result<String, StoreError> {
    Ok(format!("{}.{}", quote_identifier(database)?, quote_identifier(table)?))
}


pub fn table_ddl(database: &str, table: &str) -> Result<String, StoreError> {
    let target = qualified(database, table)?;
    Ok(format!(
        "CREATE TABLE IF NOT EXISTS {target} (\n    \
         `tenant` String,\n    \
         `ioc_type` LowCardinality(String),\n    \
         `value` String,\n    \
         `feed` String,\n    \
         `feed_version` String,\n    \
         `confidence` UInt8,\n    \
         `first_seen` DateTime('UTC'),\n    \
         `last_seen` DateTime('UTC'),\n    \
         `expires_at` DateTime('UTC'),\n    \
         `version` UInt32\n\
         )\n\
         ENGINE = ReplacingMergeTree(`version`)\n\
         ORDER BY (`tenant`, `ioc_type`, `value`)\n\
         TTL `expires_at` DELETE"
    ))
}


/// The dictionary reads the whole table as `user`, a loopback no-password identity over the secure native `port`: no credential is in the DDL text.
pub fn dictionary_ddl(database: &str, table: &str, dictionary: &str, user: &str, port: u16) -> Result<String, StoreError> {
    let source = qualified(database, table)?;
    quote_identifier(user)?;
    let target = qualified(database, dictionary)?;
    Ok(format!(
        "CREATE DICTIONARY IF NOT EXISTS {target} (\n    \
         `prefix` String,\n    \
         `feed` String,\n    \
         `feed_version` String,\n    \
         `confidence` UInt8,\n    \
         `first_seen` DateTime('UTC'),\n    \
         `last_seen` DateTime('UTC'),\n    \
         `expires_at` DateTime('UTC')\n\
         )\n\
         PRIMARY KEY `prefix`\n\
         SOURCE(CLICKHOUSE(USER '{user}' HOST '127.0.0.1' PORT {port} SECURE 1 QUERY 'SELECT `value` AS `prefix`, `feed`, `feed_version`, `confidence`, `first_seen`, `last_seen`, `expires_at` \
         FROM {source} FINAL WHERE `ioc_type` IN (\\'ipv4\\', \\'ipv6\\', \\'cidr\\') AND `expires_at` > now()'))\n\
         LAYOUT(IP_TRIE)\n\
         LIFETIME(MIN 30 MAX 300)"
    ))
}


pub fn insert_statement(database: &str, table: &str) -> Result<String, StoreError> {
    Ok(format!("INSERT INTO {} FORMAT JSONEachRow", qualified(database, table)?))
}


/// The IOC's own expiry, else last-seen plus the feed default, else last-seen plus the fallback; seconds since the epoch.
pub fn expiry_epoch(ioc: &Ioc, settings: &StoreSettings) -> i64 {
    ioc.expires_at.map_or_else(
        || {
            let ttl = ioc
                .sources
                .first()
                .and_then(|source| settings.feed_ttl_seconds.get(&source.feed))
                .copied()
                .unwrap_or(settings.fallback_ttl_seconds);
            ioc.last_seen
                .checked_add(Duration::seconds(i64::from(ttl)))
                .map_or(i64::MAX, OffsetDateTime::unix_timestamp)
        },
        OffsetDateTime::unix_timestamp,
    )
}


pub fn epoch_u32(seconds: i64) -> u32 {
    seconds.clamp(0, i64::from(u32::MAX)) as u32
}


pub fn row_of(ioc: &Ioc, settings: &StoreSettings, now: OffsetDateTime) -> RowOutcome {
    let expires = expiry_epoch(ioc, settings);
    match ioc.sources.first() {
        None => RowOutcome::Unsourced,
        Some(_) if expires <= now.unix_timestamp() => RowOutcome::Expired,
        Some(source) => RowOutcome::Kept(
            json!({
                "tenant": settings.tenant,
                "ioc_type": ioc.ioc_type,
                "value": ioc.value,
                "feed": source.feed,
                "feed_version": source.version,
                "confidence": ioc.confidence,
                "first_seen": epoch_u32(ioc.first_seen.unix_timestamp()),
                "last_seen": epoch_u32(ioc.last_seen.unix_timestamp()),
                "expires_at": epoch_u32(expires),
                "version": epoch_u32(ioc.last_seen.unix_timestamp()),
            })
            .to_string(),
        ),
    }
}


/// Appends one JSON line to the last batch while both bounds hold, else opens a new batch; a line over the byte bound alone is dropped.
pub fn push_line(plan: &mut InsertPlan, line: &str) {
    let needed = line.len() + 1;
    if needed > MAX_BATCH_BYTES {
        plan.oversized += 1;
    } else {
        let fits = |batch: &Batch| batch.rows < MAX_ROWS_PER_BATCH && batch.body.len() + needed <= MAX_BATCH_BYTES;
        if let Some(batch) = plan.batches.last_mut().filter(|batch| fits(batch)) {
            batch.body.push_str(line);
            batch.body.push('\n');
            batch.rows += 1;
        } else {
            plan.batches.push(Batch {
                body: format!("{line}\n"),
                rows: 1,
            });
        }
        plan.rows += 1;
    }
}


/// Past expiries are dropped and logged once for the whole call.
pub fn insert_plan(iocs: &[Ioc], settings: &StoreSettings, now: OffsetDateTime) -> InsertPlan {
    let mut plan = InsertPlan::default();
    iocs.iter().for_each(|ioc| match row_of(ioc, settings, now) {
        RowOutcome::Kept(line) => push_line(&mut plan, &line),
        RowOutcome::Expired => plan.expired += 1,
        RowOutcome::Unsourced => plan.unsourced += 1,
    });
    let left_out = (plan.expired, plan.unsourced, plan.oversized);
    if left_out.0 + left_out.1 + left_out.2 > 0 {
        warn!(?left_out, "IOCs left out: expired, unsourced, oversized");
    }
    plan
}
