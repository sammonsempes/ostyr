#[path = "common/types.rs"]
mod types;


use cloud_cost::error::CostError;
use cloud_cost::model::{CostTable, Limits, OtherBucket};
use cloud_cost::settings::CostLoadConfig;
use cloud_cost::source::read_export;
use cloud_cost::store::{
    covered_days, database_ddl, delete_statement, encode_row, insert_plan, insert_statement, plan_rows, table_ddl, CostRow, ROWS_PER_BATCH,
};
use core_pg::scope::tenant_scope;
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::PathBuf;
use time::{Date, Month};
use types::TestResult;


const HEADER: &str = "BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,Tags";


const VERSION: u64 = 1_700_000_000_000;


const YEAR: i32 = 2026;


const FIRST_DAY: u8 = 5;


const SECOND_DAY: u8 = 6;


const TTL: u32 = 400;


const TIMEOUT: u64 = 30_000;


const SMALL_LIMIT: usize = 1;


const EXTRA_ROWS: usize = 3;


const TOO_MANY: usize = 10_001;


const DIGEST_HEX: usize = 64;


const TINY: u64 = 10;


const DAYS: usize = 2;


pub struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("device failure"))
    }
}


fn config() -> CostLoadConfig {
    CostLoadConfig {
        url: "http://127.0.0.1:8123".to_owned(),
        user: "ostyr".to_owned(),
        password_file: PathBuf::from("/nonexistent"),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "cloud_cost_daily".to_owned(),
        timeout_ms: TIMEOUT,
        ttl_days: TTL,
        tenant: "acme".to_owned(),
    }
}


fn csv(lines: &[&str]) -> String {
    format!("{HEADER}\n{}\n", lines.join("\n"))
}


const SAMPLE: [&str; 3] = [
    "1234567890123456789.1234567896,USD,acct,2026-01-05T10:00:00Z,compute,\"{\"\"env\"\":\"\"prod\"\"}\"",
    "2.5,USD,acct,2026-01-06T10:00:00Z,storage,",
    "1.10,USD,acct,2026-01-06T11:00:00Z,network,",
];


#[test]
fn schema_statements_match_their_goldens() -> TestResult {
    let config = config();
    assert_eq!(database_ddl(&config)?, "CREATE DATABASE IF NOT EXISTS `ostyr`");
    assert_eq!(
        table_ddl(&config)?,
        "CREATE TABLE IF NOT EXISTS `ostyr`.`cloud_cost_daily` (\n    `tenant` String,\n    `source` String,\n    `day` Date,\n    \
         `dimension` LowCardinality(String),\n    `key1` String,\n    `key2` String,\n    `cost` Decimal(38, 9),\n    \
         `currency` LowCardinality(String),\n    `version` UInt64\n)\nENGINE = ReplacingMergeTree(`version`)\n\
         ORDER BY (`tenant`, `source`, `day`, `dimension`, `key1`, `key2`)\nTTL `day` + INTERVAL 400 DAY DELETE"
    );
    assert_eq!(insert_statement(&config)?, "INSERT INTO `ostyr`.`cloud_cost_daily` FORMAT JSONEachRow");
    assert_eq!(
        delete_statement(&config)?,
        "DELETE FROM `ostyr`.`cloud_cost_daily` WHERE tenant = {tenant:String} AND day >= {first:Date} AND day <= {last:Date}"
    );
    let mut bad = config;
    bad.table = "x`y".to_owned();
    assert!(table_ddl(&bad).is_err());
    assert!(insert_statement(&bad).is_err());
    assert!(delete_statement(&bad).is_err());
    bad.database = "x y".to_owned();
    assert!(database_ddl(&bad).is_err());
    Ok(())
}


#[test]
fn rows_are_exact_decimal_text_with_every_dimension() -> TestResult {
    let limits = Limits {
        max_series: SMALL_LIMIT,
        ..Limits::default()
    };
    let export = read_export(csv(&SAMPLE).as_bytes(), &limits, "acme")?;
    let rows = plan_rows(&export.table, "acme", &export.source, VERSION);
    let find = |dimension: &str| rows.iter().filter(|row| row.dimension == dimension).collect::<Vec<_>>();
    assert_eq!(find("total").len(), DAYS);
    assert_eq!(find("total").first().ok_or("no total")?.cost, "1234567890123456789.123456790");
    assert_eq!(find("total").get(1).ok_or("no total")?.cost, "3.60");
    assert_eq!(find("tag").len(), 1);
    assert_eq!(find("account_service").len(), 1);
    let other = find("other");
    assert_eq!(other.len(), 1);
    assert_eq!(
        other.first().ok_or("no other")?.day,
        Date::from_calendar_date(YEAR, Month::January, SECOND_DAY)?
    );
    assert_eq!(find("tag_other").len(), 0);
    let line = encode_row(find("total").get(1).ok_or("no total")?);
    assert!(line.contains("\"cost\":\"3.60\""), "{line}");
    assert!(line.contains("\"day\":\"2026-01-06\""), "{line}");
    assert!(line.contains("\"tenant\":\"acme\""), "{line}");
    assert!(line.contains(&format!("\"version\":{VERSION}")), "{line}");
    assert!(line.contains(&format!("\"source\":\"{}\"", export.source)), "{line}");
    Ok(())
}


#[test]
fn tag_overflow_is_stored_as_its_own_dimension() -> TestResult {
    let limits = Limits {
        max_series: SMALL_LIMIT,
        ..Limits::default()
    };
    let lines = [
        "1,USD,a,2026-01-05T00:00:00Z,s,\"{\"\"k\"\":\"\"v\"\"}\"",
        "1,USD,a,2026-01-05T00:00:00Z,s,\"{\"\"k2\"\":\"\"v2\"\"}\"",
    ];
    let export = read_export(csv(&lines).as_bytes(), &limits, "acme")?;
    let rows = plan_rows(&export.table, "acme", &export.source, VERSION);
    assert!(rows.iter().any(|row| row.dimension == "tag_other"));
    Ok(())
}


#[test]
fn the_same_bytes_give_the_same_source_and_rows() -> TestResult {
    let text = csv(&SAMPLE);
    let first = read_export(text.as_bytes(), &Limits::default(), "acme")?;
    let second = read_export(text.as_bytes(), &Limits::default(), "acme")?;
    assert_eq!(first.source, second.source);
    assert_eq!(first.source.len(), DIGEST_HEX);
    assert_eq!(
        insert_plan(&plan_rows(&first.table, "acme", &first.source, VERSION)),
        insert_plan(&plan_rows(&second.table, "acme", &second.source, VERSION))
    );
    let changed = read_export(csv(&SAMPLE[..1]).as_bytes(), &Limits::default(), "acme")?;
    assert_ne!(first.source, changed.source);
    Ok(())
}


#[test]
fn an_empty_table_has_no_days_and_no_rows() -> TestResult {
    let table = CostTable {
        tenant: tenant_scope("acme")?,
        currency: None,
        accepted: 0,
        day_totals: BTreeMap::new(),
        by_account_service: BTreeMap::new(),
        by_tag: BTreeMap::new(),
        other: OtherBucket {
            cost: Decimal::ZERO,
            count: 0,
        },
        tag_other: OtherBucket {
            cost: Decimal::ZERO,
            count: 0,
        },
        skipped: BTreeMap::new(),
    };
    assert_eq!(covered_days(&table), None);
    assert!(plan_rows(&table, "acme", "s", VERSION).is_empty());
    assert!(insert_plan(&[]).is_empty());
    Ok(())
}


#[test]
fn rows_are_cut_into_batches() -> TestResult {
    let day = Date::from_calendar_date(YEAR, Month::January, FIRST_DAY)?;
    let row = CostRow {
        tenant: "acme".to_owned(),
        source: "s".to_owned(),
        day,
        dimension: "total",
        key1: String::new(),
        key2: String::new(),
        cost: "1".to_owned(),
        currency: "USD".to_owned(),
        version: VERSION,
    };
    let rows = vec![row; TOO_MANY + EXTRA_ROWS];
    let batches = insert_plan(&rows);
    assert_eq!(
        batches.iter().map(|batch| batch.rows).collect::<Vec<_>>(),
        vec![ROWS_PER_BATCH, EXTRA_ROWS + 1]
    );
    Ok(())
}


#[test]
fn read_export_bounds_and_errors() -> TestResult {
    let small = Limits {
        max_bytes: TINY,
        ..Limits::default()
    };
    assert!(matches!(
        read_export(csv(&SAMPLE).as_bytes(), &small, "acme"),
        Err(CostError::TooLarge { .. })
    ));
    assert!(matches!(read_export(Broken, &Limits::default(), "acme"), Err(CostError::Read(_))));
    assert!(matches!(
        read_export(csv(&SAMPLE).as_bytes(), &Limits::default(), "-x"),
        Err(CostError::Tenant(_))
    ));
    Ok(())
}
