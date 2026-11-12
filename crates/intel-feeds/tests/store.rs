#[path = "common/types.rs"]
mod types;


use intel_feeds::canon::canonicalise;
use intel_feeds::config::{FeedConfig, FeedFormat, Mapping};
use intel_feeds::limits::{DEFAULT_TTL_SECONDS, MAX_BATCH_BYTES, MAX_ROWS_PER_BATCH};
use intel_feeds::model::{Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::store::{
    checked_column_ddl, dictionary_ddl, epoch_u32, expiry_epoch, insert_plan, insert_statement, push_line, quote_identifier, read_statement, row_of,
    settings_for, table_ddl, tlp_column_ddl, InsertPlan, RowOutcome, StoreError, StoreSettings,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const PORT: u16 = 9440;


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const SEEN: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const LATER: OffsetDateTime = datetime!(2026-11-10 00:00:00 UTC);


const END_OF_TIME: OffsetDateTime = datetime!(9999-12-31 23:59:59 UTC);


const EXPIRED_COUNT: u64 = 2;


const HALF: usize = 2;


const REFUSED_COUNT: u64 = 5;


const ROWS_KEPT: usize = 3;


const NEGATIVE: i64 = 5;


const FEED_TTL: u32 = 3_600;


const CONFIDENCE: u8 = 70;


const MAX_NAME_BYTES: usize = 64;


fn ioc(value: &str, expires_at: Option<OffsetDateTime>, sources: Vec<Source>) -> Ioc {
    Ioc {
        ioc_type: IocType::Domain,
        value: value.to_owned(),
        sources,
        first_seen: SEEN,
        last_seen: SEEN,
        confidence: CONFIDENCE,
        tlp: Tlp::Amber,
        expires_at,
        tags: Tags::default(),
    }
}


fn source(feed: &str) -> Vec<Source> {
    vec![Source {
        feed: feed.to_owned(),
        version: "v1".to_owned(),
    }]
}


fn settings() -> StoreSettings {
    StoreSettings {
        tenant: "acme".to_owned(),
        feed_ttl_seconds: BTreeMap::from([("short".to_owned(), FEED_TTL)]),
        fallback_ttl_seconds: DEFAULT_TTL_SECONDS,
    }
}


fn first_body(plan: &InsertPlan) -> &str {
    plan.batches.first().map_or("", |batch| batch.body.as_str())
}


#[test]
fn table_ddl_golden() -> TestResult {
    let expected = "CREATE TABLE IF NOT EXISTS `intel`.`ioc` (\n    `tenant` String,\n    `ioc_type` LowCardinality(String),\n    `value` String,\n    \
        `feed` String,\n    `feed_version` String,\n    `confidence` UInt8,\n    `tlp` LowCardinality(String),\n    `first_seen` DateTime('UTC'),\n    `last_seen` DateTime('UTC'),\n    \
        `expires_at` DateTime('UTC'),\n    `version` UInt32,\n    `checked` UInt8 DEFAULT 0\n)\nENGINE = ReplacingMergeTree(`version`)\n\
        ORDER BY (`tenant`, `ioc_type`, `value`)\nTTL `expires_at` DELETE";
    assert_eq!(table_ddl("intel", "ioc")?, expected);
    Ok(())
}


#[test]
fn dictionary_ddl_golden() -> TestResult {
    let expected = "CREATE OR REPLACE DICTIONARY `intel`.`ioc_ip` (\n    `prefix` String,\n    `feed` String,\n    `feed_version` String,\n    \
        `confidence` UInt8,\n    `first_seen` DateTime('UTC'),\n    `last_seen` DateTime('UTC'),\n    `expires_at` DateTime('UTC')\n)\n\
        PRIMARY KEY `prefix`\n\
        SOURCE(CLICKHOUSE(USER 'ostyr_dict' HOST '127.0.0.1' PORT 9440 SECURE 1 QUERY 'SELECT `value` AS `prefix`, `feed`, `feed_version`, `confidence`, `first_seen`, `last_seen`, `expires_at` \
        FROM `intel`.`ioc` FINAL WHERE `ioc_type` IN (\\'ipv4\\', \\'ipv6\\', \\'cidr\\') AND `checked` = 1 AND `expires_at` > now()'))\n\
        LAYOUT(IP_TRIE)\nLIFETIME(MIN 30 MAX 300)";
    assert_eq!(dictionary_ddl("intel", "ioc", "ioc_ip", "ostyr_dict", PORT)?, expected);
    assert!(!expected.contains("PASSWORD"));
    Ok(())
}


#[test]
fn insert_statement_golden() -> TestResult {
    assert_eq!(insert_statement("intel", "ioc")?, "INSERT INTO `intel`.`ioc` FORMAT JSONEachRow");
    Ok(())
}


#[test]
fn identifiers_are_validated() -> TestResult {
    let too_long = "a".repeat(MAX_NAME_BYTES + 1);
    let bad = ["", "1abc", "a`b", "a b", "a;drop", "caf\u{e9}", too_long.as_str()];
    assert!(bad.iter().all(|name| matches!(quote_identifier(name), Err(StoreError::Identifier(_)))));
    assert_eq!(quote_identifier("_ok9")?, "`_ok9`");
    assert!(quote_identifier(&"a".repeat(MAX_NAME_BYTES)).is_ok());
    assert!(table_ddl("db", "bad name").is_err());
    assert!(table_ddl("bad name", "t").is_err());
    assert!(dictionary_ddl("db", "bad name", "d", "u", PORT).is_err());
    assert!(dictionary_ddl("db", "t", "bad name", "u", PORT).is_err());
    assert!(["", "a' b", "x`y", "-x", "a;b", "u\\"]
        .iter()
        .all(|user| dictionary_ddl("db", "t", "d", user, PORT).is_err()));
    assert!(dictionary_ddl("bad name", "t", "d", "u", PORT).is_err());
    assert!(insert_statement("db", "x`").is_err());
    assert_eq!(StoreError::Identifier("x".to_owned()).to_string(), "invalid identifier `x`");
    Ok(())
}


#[test]
fn row_carries_source_dates_and_expiry() -> TestResult {
    let plan = insert_plan(&[ioc("evil.example", Some(LATER), source("feed"))], &settings(), NOW);
    assert_eq!((plan.batches.len(), plan.rows), (1, 1));
    let row: Value = serde_json::from_str(first_body(&plan).trim_end())?;
    let expected = json!({
        "tenant": "acme",
        "ioc_type": "domain",
        "value": "evil.example",
        "feed": "feed",
        "feed_version": "v1",
        "confidence": CONFIDENCE,
        "tlp": "amber",
        "first_seen": SEEN.unix_timestamp(),
        "last_seen": SEEN.unix_timestamp(),
        "expires_at": LATER.unix_timestamp(),
        "version": SEEN.unix_timestamp(),
        "checked": 1,
    });
    assert_eq!(row, expected);
    Ok(())
}


#[test]
fn ttl_falls_back_to_feed_then_default() -> TestResult {
    let config = settings();
    assert_eq!(
        expiry_epoch(&ioc("a", None, source("short")), &config),
        SEEN.unix_timestamp() + i64::from(FEED_TTL)
    );
    assert_eq!(
        expiry_epoch(&ioc("a", None, source("other")), &config),
        SEEN.unix_timestamp() + i64::from(DEFAULT_TTL_SECONDS)
    );
    assert_eq!(
        expiry_epoch(&ioc("a", None, vec![]), &config),
        SEEN.unix_timestamp() + i64::from(DEFAULT_TTL_SECONDS)
    );
    let late = Ioc {
        last_seen: END_OF_TIME,
        ..ioc("a", None, source("other"))
    };
    assert_eq!(expiry_epoch(&late, &config), i64::MAX);
    Ok(())
}


#[test]
fn past_expiry_and_unsourced_are_dropped() -> TestResult {
    let kept = ioc("kept.example", None, source("feed"));
    let iocs = [
        ioc("old.example", Some(NOW), source("feed")),
        ioc("short.example", None, source("short")),
        ioc("nosource.example", Some(LATER), vec![]),
        kept.clone(),
    ];
    let plan = insert_plan(&iocs, &settings(), NOW);
    assert_eq!((plan.expired, plan.unsourced, plan.oversized, plan.rows), (EXPIRED_COUNT, 1, 0, 1));
    let clean = insert_plan(&[kept], &settings(), NOW);
    assert_eq!((clean.expired, clean.rows), (0, 1));
    Ok(())
}


#[test]
fn batches_split_at_the_row_bound() -> TestResult {
    let mut plan = InsertPlan::default();
    (0..=MAX_ROWS_PER_BATCH).for_each(|_| push_line(&mut plan, "{}"));
    let sizes: Vec<usize> = plan.batches.iter().map(|batch| batch.rows).collect();
    assert_eq!(sizes, vec![MAX_ROWS_PER_BATCH, 1]);
    assert_eq!(plan.rows, MAX_ROWS_PER_BATCH + 1);
    Ok(())
}


#[test]
fn batches_split_at_the_byte_bound_and_oversized_is_dropped() -> TestResult {
    let mut plan = InsertPlan::default();
    let half = "x".repeat(MAX_BATCH_BYTES / HALF - 1);
    push_line(&mut plan, &half);
    push_line(&mut plan, &half);
    assert_eq!(plan.batches.len(), 1);
    push_line(&mut plan, "y");
    assert_eq!(plan.batches.len(), HALF);
    assert!(plan.batches.iter().all(|batch| batch.body.len() <= MAX_BATCH_BYTES));
    push_line(&mut plan, &"z".repeat(MAX_BATCH_BYTES));
    assert_eq!((plan.oversized, plan.rows), (1, ROWS_KEPT));
    Ok(())
}


#[test]
fn quotes_and_backticks_round_trip_as_json() -> TestResult {
    let nasty = "a'b\"c`d\\e\nf";
    assert_eq!(insert_plan(&[ioc(nasty, None, source("feed"))], &settings(), NOW).not_canonical, 1);
    let plan = insert_plan(&[ioc("good.example", None, source("fe`ed'"))], &settings(), NOW);
    let body = first_body(&plan);
    assert_eq!(body.matches('\n').count(), 1);
    let row: Value = serde_json::from_str(body.trim_end())?;
    assert_eq!(row.get("value"), Some(&json!("good.example")));
    assert_eq!(row.get("feed"), Some(&json!("fe`ed'")));
    Ok(())
}


#[test]
fn a_canonical_value_that_json_escapes_round_trips() -> TestResult {
    let canonical = canonicalise(IocType::Url, "foo://h/a\\b\"c'd`e")?;
    let row_ioc = Ioc {
        ioc_type: IocType::Url,
        value: canonical.value.clone(),
        ..ioc("x", None, source("feed"))
    };
    let plan = insert_plan(&[row_ioc], &settings(), NOW);
    assert_eq!(plan.not_canonical, 0);
    let body = first_body(&plan);
    assert_eq!(body.matches('\n').count(), 1);
    let row: Value = serde_json::from_str(body.trim_end())?;
    assert_eq!(row.get("value"), Some(&json!(canonical.value)));
    Ok(())
}


#[test]
fn epochs_are_clamped() -> TestResult {
    assert_eq!((epoch_u32(-NEGATIVE), epoch_u32(1), epoch_u32(i64::MAX)), (0, 1, u32::MAX));
    Ok(())
}


#[test]
fn settings_collect_feed_ttls() -> TestResult {
    let feed = |name: &str, ttl: Option<u32>| FeedConfig {
        name: name.to_owned(),
        format: FeedFormat::Crowdsec,
        path: name.into(),
        version: None,
        mapping: Mapping::default(),
        default_confidence: CONFIDENCE,
        tlp: Tlp::Amber,
        ttl_seconds: ttl,
    };
    let built = settings_for("acme", &[feed("a", Some(1)), feed("b", None)]);
    assert_eq!(built.feed_ttl_seconds, BTreeMap::from([("a".to_owned(), 1)]));
    assert_eq!((built.tenant.as_str(), built.fallback_ttl_seconds), ("acme", DEFAULT_TTL_SECONDS));
    Ok(())
}


#[test]
fn the_tlp_is_written_for_each_value() -> TestResult {
    let names = [
        (Tlp::Clear, "clear"),
        (Tlp::Green, "green"),
        (Tlp::Amber, "amber"),
        (Tlp::AmberStrict, "amber_strict"),
        (Tlp::Red, "red"),
    ];
    names.iter().try_for_each(|(tlp, name)| -> TestResult {
        let marked = Ioc {
            tlp: *tlp,
            ..ioc("x.example", Some(LATER), source("feed"))
        };
        let plan = insert_plan(&[marked], &settings(), NOW);
        let row: Value = serde_json::from_str(first_body(&plan).trim_end())?;
        assert_eq!(row.get("tlp").and_then(Value::as_str), Some(*name));
        Ok(())
    })
}


#[test]
fn checked_column_golden() -> TestResult {
    assert_eq!(
        checked_column_ddl("intel", "ioc")?,
        "ALTER TABLE `intel`.`ioc` ADD COLUMN IF NOT EXISTS `checked` UInt8 DEFAULT 0"
    );
    assert!(checked_column_ddl("a b", "ioc").is_err());
    Ok(())
}


#[test]
fn tlp_column_and_read_statement_golden() -> TestResult {
    assert_eq!(
        tlp_column_ddl("intel", "ioc")?,
        "ALTER TABLE `intel`.`ioc` ADD COLUMN IF NOT EXISTS `tlp` LowCardinality(String) DEFAULT 'red'"
    );
    let expected = "SELECT `ioc_type`, `value`, `feed`, `feed_version`, `confidence`, `tlp`, `first_seen`, `last_seen`, `expires_at` \
        FROM `intel`.`ioc` FINAL WHERE `tenant` = {tenant:String} AND `ioc_type` IN ('domain', 'ipv4', 'ipv6', 'cidr') \
        AND `checked` = 1 AND `expires_at` > toDateTime({now:UInt32}) ORDER BY `ioc_type`, `value` LIMIT {limit:UInt64} FORMAT JSONEachRow";
    assert_eq!(read_statement("intel", "ioc")?, expected);
    assert!(read_statement("intel", "a;b").is_err());
    assert!(tlp_column_ddl("a b", "ioc").is_err());
    Ok(())
}


#[test]
fn row_of_refuses_a_non_canonical_ioc() -> TestResult {
    let with = |ioc_type: IocType, value: &str| Ioc {
        ioc_type,
        ..ioc(value, None, source("feed"))
    };
    let refused = [
        with(IocType::Ipv6, "::ffff:0:0/97"),
        with(IocType::Domain, "Example.COM"),
        with(IocType::Cidr, "0.0.0.0/0"),
        with(IocType::Ipv4, "not an address"),
        with(IocType::Ipv6, "::ffff:192.0.2.1"),
    ];
    refused
        .iter()
        .for_each(|candidate| assert_eq!(row_of(candidate, &settings(), NOW), RowOutcome::NotCanonical));
    assert!(matches!(
        row_of(&ioc("good.example", None, source("feed")), &settings(), NOW),
        RowOutcome::Kept(_)
    ));
    let mut all = refused.to_vec();
    all.push(ioc("good.example", None, source("feed")));
    let plan = insert_plan(&all, &settings(), NOW);
    assert_eq!((plan.not_canonical, plan.rows), (REFUSED_COUNT, 1));
    Ok(())
}
