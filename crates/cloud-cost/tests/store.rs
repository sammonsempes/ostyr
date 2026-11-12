#[path = "common/types.rs"]
mod types;


use cloud_cost::error::CostError;
use cloud_cost::model::{CostTable, Limits, OtherBucket};
use cloud_cost::settings::CostLoadConfig;
use cloud_cost::source::read_export;
use cloud_cost::store::{
    account_set, array_literal, covered_days, database_ddl, delete_statement, encode_row, insert_plan, insert_statement, plan_rows, table_ddl,
    CostRow, ROWS_PER_BATCH,
};
use core_pg::scope::tenant_scope;
use rust_decimal::Decimal;
use std::collections::{BTreeMap, BTreeSet};
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
        "CREATE TABLE IF NOT EXISTS `ostyr`.`cloud_cost_daily` (\n    `tenant` String,\n    `account` String,\n    `source` String,\n    `day` Date,\n    \
         `dimension` LowCardinality(String),\n    `key1` String,\n    `key2` String,\n    `cost` Decimal(38, 9),\n    \
         `currency` LowCardinality(String),\n    `version` UInt64\n)\nENGINE = ReplacingMergeTree(`version`)\n\
         ORDER BY (`tenant`, `account`, `source`, `day`, `dimension`, `key1`, `key2`)\nTTL `day` + INTERVAL 400 DAY DELETE"
    );
    assert_eq!(insert_statement(&config)?, "INSERT INTO `ostyr`.`cloud_cost_daily` FORMAT JSONEachRow");
    assert_eq!(
        delete_statement(&config)?,
        "DELETE FROM `ostyr`.`cloud_cost_daily` WHERE tenant = {tenant:String} AND account IN {accounts:Array(String)} AND day >= {first:Date} AND day <= {last:Date}"
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
    assert_eq!(other.first().ok_or("no other")?.account, "acct");
    assert_eq!(other.first().ok_or("no other")?.cost, "3.60");
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
        account_rows: BTreeMap::new(),
        seen_accounts: BTreeSet::new(),
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
        account: "acct".to_owned(),
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


const TWO_ACCOUNTS: [&str; 3] = [
    "1,USD,acct1,2026-01-05T10:00:00Z,compute,\"{\"\"env\"\":\"\"prod\"\"}\"",
    "2,USD,acct2,2026-01-05T10:00:00Z,compute,",
    "4,USD,acct2,2026-01-06T10:00:00Z,compute,",
];


#[test]
fn every_row_is_stored_under_its_billing_account() -> TestResult {
    let export = read_export(csv(&TWO_ACCOUNTS).as_bytes(), &Limits::default(), "acme")?;
    let rows = plan_rows(&export.table, "acme", &export.source, VERSION);
    let total = |account: &str, day: u8| {
        rows.iter()
            .find(|row| row.dimension == "total" && row.account == account && row.day.day() == day)
            .map(|row| row.cost.clone())
    };
    assert_eq!(total("acct1", FIRST_DAY), Some("1".to_owned()));
    assert_eq!(total("acct2", FIRST_DAY), Some("2".to_owned()));
    assert_eq!(total("acct2", SECOND_DAY), Some("4".to_owned()));
    assert_eq!(total("acct1", SECOND_DAY), None);
    let tag = rows.iter().find(|row| row.dimension == "tag").ok_or("no tag")?;
    assert_eq!(tag.account, "acct1");
    let service = rows
        .iter()
        .find(|row| row.dimension == "account_service" && row.account == "acct2")
        .ok_or("no service")?;
    assert_eq!(service.key1, "compute");
    assert_eq!(account_set(&export.table), vec!["acct1".to_owned(), "acct2".to_owned()]);
    assert!(encode_row(service).contains("\"account\":\"acct2\""));
    Ok(())
}


#[test]
fn accounts_beyond_the_cap_keep_their_own_names() -> TestResult {
    let limits = Limits {
        max_series: SMALL_LIMIT,
        ..Limits::default()
    };
    let export = read_export(csv(&TWO_ACCOUNTS).as_bytes(), &limits, "acme")?;
    assert_eq!(account_set(&export.table), vec!["acct1".to_owned(), "acct2".to_owned()]);
    let rows = plan_rows(&export.table, "acme", &export.source, VERSION);
    assert!(rows.iter().any(|row| row.dimension == "other" && row.account == "acct2"));
    assert!(rows.iter().all(|row| !row.account.is_empty()));
    Ok(())
}


#[test]
fn disjoint_overflowing_exports_name_disjoint_accounts() -> TestResult {
    let limits = Limits {
        max_series: SMALL_LIMIT,
        ..Limits::default()
    };
    let first = read_export(
        csv(&["1,USD,a0,2026-01-05T10:00:00Z,s,", "1,USD,a1,2026-01-05T10:00:00Z,s,"]).as_bytes(),
        &limits,
        "acme",
    )?;
    let second = read_export(
        csv(&["1,USD,b0,2026-01-05T10:00:00Z,s,", "1,USD,b1,2026-01-05T10:00:00Z,s,"]).as_bytes(),
        &limits,
        "acme",
    )?;
    let named = |accounts: Vec<String>| accounts.into_iter().collect::<std::collections::BTreeSet<_>>();
    assert!(named(account_set(&first.table)).is_disjoint(&named(account_set(&second.table))));
    Ok(())
}


#[test]
fn row_order_does_not_change_the_planned_rows() -> TestResult {
    let limits = Limits {
        max_series: SMALL_LIMIT,
        ..Limits::default()
    };
    let (one, two, three) = (
        "1,USD,a0,2026-01-05T10:00:00Z,s,",
        "2,USD,a1,2026-01-05T10:00:00Z,s,",
        "3,USD,a2,2026-01-05T10:00:00Z,s,",
    );
    let lines = [one, two, three];
    let reversed = [three, two, one];
    let forward = read_export(csv(&lines).as_bytes(), &limits, "acme")?;
    let backward = read_export(csv(&reversed).as_bytes(), &limits, "acme")?;
    assert_eq!(account_set(&forward.table), account_set(&backward.table));
    let total_of = |export: &cloud_cost::source::Export| {
        plan_rows(&export.table, "acme", "", VERSION)
            .into_iter()
            .filter(|row| row.dimension == "total")
            .map(|row| (row.account, row.cost))
            .collect::<Vec<_>>()
    };
    assert_eq!(total_of(&forward), total_of(&backward));
    Ok(())
}


#[test]
fn array_literals_escape_quotes_and_backslashes() -> TestResult {
    assert_eq!(array_literal(&[]), "[]");
    assert_eq!(array_literal(&["a".to_owned(), "b'c\\d".to_owned()]), "['a','b\\'c\\\\d']");
    Ok(())
}
