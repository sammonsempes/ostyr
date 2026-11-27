use crate::canon::canonicalise;
use crate::config::FeedConfig;
use crate::limits::{DEFAULT_TTL_SECONDS, MAX_BATCH_BYTES, MAX_IDENTIFIER_BYTES, MAX_LOGGED_FEED_NAMES, MAX_READ_ROWS, MAX_ROWS_PER_BATCH};
use crate::model::Ioc;
use crate::types::TtlDefaults;
use serde_json::json;
use siem_ingest::reader_profile::pin_clause;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tracing::warn;


pub const COUNT_ROWS: u64 = 2;


pub const ROW_OVERHEAD: u64 = 197;


pub const BYTES_CLAMP: u64 = u32::MAX as u64;


pub const QUOTES: u64 = 2;


pub const SHORT_ESCAPE: u64 = 2;


pub const UNICODE_ESCAPE: u64 = 6;


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
    pub not_canonical: u64,
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
    NotCanonical,
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
         `tlp` LowCardinality(String),\n    \
         `first_seen` DateTime('UTC'),\n    \
         `last_seen` DateTime('UTC'),\n    \
         `expires_at` DateTime('UTC'),\n    \
         `version` UInt32,\n    \
         `checked` UInt8 DEFAULT 0\n\
         )\n\
         ENGINE = ReplacingMergeTree(`version`)\n\
         ORDER BY (`tenant`, `ioc_type`, `value`)\n\
         TTL `expires_at` DELETE"
    ))
}


/// Adds the TLP column to a table created before it existed; such rows read as `red` until the next load rewrites them.
pub fn tlp_column_ddl(database: &str, table: &str) -> Result<String, StoreError> {
    Ok(format!(
        "ALTER TABLE {} ADD COLUMN IF NOT EXISTS `tlp` LowCardinality(String) DEFAULT 'red'",
        qualified(database, table)?
    ))
}


/// Adds the checked flag to a table created before it existed; such rows read as 0 and stay out of the dictionary until a load rewrites them.
pub fn checked_column_ddl(database: &str, table: &str) -> Result<String, StoreError> {
    Ok(format!(
        "ALTER TABLE {} ADD COLUMN IF NOT EXISTS `checked` UInt8 DEFAULT 0",
        qualified(database, table)?
    ))
}


/// The one `FROM … FINAL WHERE` of the read and of the writer's key query: what the reader counts, the writer counts.
pub fn read_source(database: &str, table: &str) -> Result<String, StoreError> {
    Ok(format!(
        "FROM {} FINAL WHERE `tenant` = {{tenant:String}} AND `ioc_type` IN ('domain', 'ipv4', 'ipv6', 'cidr') \
         AND `checked` = 1 AND `expires_at` > toDateTime({{now:UInt32}})",
        qualified(database, table)?
    ))
}


/// One tenant's live network and domain IOCs, one more than the cap so the reader can tell a truncated list from a full one; the pins are in its `SETTINGS` clause.
pub fn read_statement(database: &str, table: &str) -> Result<String, StoreError> {
    let pins = pin_clause(&[], MAX_READ_ROWS as u64 + 1);
    Ok(format!(
        "SELECT `ioc_type`, `value`, `feed`, `feed_version`, `confidence`, `tlp`, `first_seen`, `last_seen`, `expires_at` \
         {} ORDER BY `ioc_type`, `value` LIMIT {{limit:UInt64}}{pins} FORMAT JSONEachRow",
        read_source(database, table)?
    ))
}


/// The keys the read would return, on the same source, for the writer's budget.
pub fn keys_statement(database: &str, table: &str) -> Result<String, StoreError> {
    let pins = pin_clause(&[], MAX_READ_ROWS as u64 + 1);
    Ok(format!(
        "SELECT `ioc_type`, `value` {} LIMIT {{limit:UInt64}}{pins} FORMAT JSONEachRow",
        read_source(database, table)?
    ))
}


/// The tenant's live rows of every type, one number.
pub fn count_statement(database: &str, table: &str) -> Result<String, StoreError> {
    let pins = pin_clause(&[], COUNT_ROWS);
    Ok(format!(
        "SELECT toUInt32(count()) AS `live` FROM {} FINAL WHERE `tenant` = {{tenant:String}} AND `expires_at` > toDateTime({{now:UInt32}}) \
         LIMIT {{limit:UInt64}}{pins} FORMAT JSONEachRow",
        qualified(database, table)?
    ))
}


/// The feeds holding the most live rows of the tenant, whatever the settings say today.
pub fn top_statement(database: &str, table: &str) -> Result<String, StoreError> {
    let pins = pin_clause(&[], MAX_LOGGED_FEED_NAMES as u64 + 1);
    Ok(format!(
        "SELECT `feed`, toUInt32(count()) AS `live` FROM {} FINAL WHERE `tenant` = {{tenant:String}} AND `expires_at` > toDateTime({{now:UInt32}}) \
         GROUP BY `feed` ORDER BY `live` DESC, `feed` LIMIT {MAX_LOGGED_FEED_NAMES}{pins} FORMAT JSONEachRow",
        qualified(database, table)?
    ))
}


/// The bytes the read reply would hold for the same rows: the JSON size of the three strings plus a fixed overhead per row, clamped to a `UInt32`.
pub fn bytes_statement(database: &str, table: &str) -> Result<String, StoreError> {
    let pins = pin_clause(&[], COUNT_ROWS);
    Ok(format!(
        "SELECT toUInt32(least(sum(length(toJSONString(`value`)) + length(toJSONString(`feed`)) + length(toJSONString(`feed_version`)) \
         + {ROW_OVERHEAD}), {BYTES_CLAMP})) AS `bytes` {} LIMIT {{limit:UInt64}}{pins} FORMAT JSONEachRow",
        read_source(database, table)?
    ))
}


/// The size of a string as ClickHouse writes it in `JSONEachRow`: quotes included, `/` escaped, control characters as `\u00XX`; never below the real size.
pub fn json_len(text: &str) -> u64 {
    text.chars().fold(QUOTES, |total, character| {
        total
            + match character {
                '"' | '\\' | '/' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => SHORT_ESCAPE,
                control if control < ' ' => UNICODE_ESCAPE,
                '\u{2028}' | '\u{2029}' => UNICODE_ESCAPE,
                other => other.len_utf8() as u64,
            }
    })
}


/// The bytes of one read row, the line end included: the budget and the writer both count with it.
pub fn row_bytes(value: &str, feed: &str, version: &str) -> u64 {
    json_len(value) + json_len(feed) + json_len(version) + ROW_OVERHEAD
}


/// What replacing a row already counted can add: its feed and version, whatever the old ones were.
pub fn replacement_bytes(feed: &str, version: &str) -> u64 {
    json_len(feed) + json_len(version)
}


/// The dictionary reads the whole table as `user`, a loopback no-password identity over the secure native `port`: no credential is in the DDL text.
pub fn dictionary_ddl(database: &str, table: &str, dictionary: &str, user: &str, port: u16) -> Result<String, StoreError> {
    let source = qualified(database, table)?;
    quote_identifier(user)?;
    let target = qualified(database, dictionary)?;
    Ok(format!(
        "CREATE OR REPLACE DICTIONARY {target} (\n    \
         `prefix` String,\n    \
         `tenant` String,\n    \
         `indicator` String,\n    \
         `tlp` String,\n    \
         `feed` String,\n    \
         `feed_version` String,\n    \
         `confidence` UInt8,\n    \
         `first_seen` DateTime('UTC'),\n    \
         `last_seen` DateTime('UTC'),\n    \
         `expires_at` DateTime('UTC')\n\
         )\n\
         PRIMARY KEY `prefix`\n\
         SOURCE(CLICKHOUSE(USER '{user}' HOST '127.0.0.1' PORT {port} SECURE 1 QUERY 'SELECT `value` AS `prefix`, `tenant`, `value` AS `indicator`, `tlp`, `feed`, `feed_version`, `confidence`, `first_seen`, `last_seen`, `expires_at` \
         FROM {source} FINAL WHERE `ioc_type` IN (\\'ipv4\\', \\'ipv6\\', \\'cidr\\') AND `checked` = 1 AND `expires_at` > now()'))\n\
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


/// True when `canonicalise` gives back exactly this type and value, so `checked = 1` is true whatever the caller.
pub fn is_canonical(ioc: &Ioc) -> bool {
    canonicalise(ioc.ioc_type, &ioc.value).is_ok_and(|canonical| canonical.ioc_type == ioc.ioc_type && canonical.value == ioc.value)
}


pub fn row_of(ioc: &Ioc, settings: &StoreSettings, now: OffsetDateTime) -> RowOutcome {
    let expires = expiry_epoch(ioc, settings);
    match ioc.sources.first() {
        _ if !is_canonical(ioc) => RowOutcome::NotCanonical,
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
                "tlp": ioc.tlp,
                "first_seen": epoch_u32(ioc.first_seen.unix_timestamp()),
                "last_seen": epoch_u32(ioc.last_seen.unix_timestamp()),
                "expires_at": epoch_u32(expires),
                "version": epoch_u32(ioc.last_seen.unix_timestamp()),
                "checked": 1,
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
        RowOutcome::NotCanonical => plan.not_canonical += 1,
    });
    let left_out = (plan.expired, plan.unsourced, plan.oversized, plan.not_canonical);
    if left_out.0 + left_out.1 + left_out.2 + left_out.3 > 0 {
        warn!(?left_out, "IOCs left out: expired, unsourced, oversized, not canonical");
    }
    plan
}
