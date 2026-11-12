use cloud_cost::error::CostError;
use cloud_cost::focus::{add_cost, parse_amount, read_focus};
use cloud_cost::model::{CostTable, Limits, SkipReason};
use core_pg::scope::tenant_of;
use rust_decimal::Decimal;
use std::error::Error;
use std::io::{self, Read};
use std::str::FromStr;
use time::{Date, Month};


const TENANT: &str = "acme";


const HEADER: &str = "BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,Tags,Extra";


const YEAR: i32 = 2026;


const SECOND_DAY: u8 = 2;


const DECIMAL_MAX: &str = "79228162514264337593543950335";


const DECIMAL_MIN: &str = "-79228162514264337593543950335";


const MALFORMED_ROWS: u64 = 3;


const BAD_TAG_ROWS: u64 = 4;


const SERIES_CAP: usize = 2;


const FIELD_CAP: usize = 24;


const TAG_CAP: usize = 2;


const ROW_COUNT: u64 = 5;


const OTHER_ROWS: u64 = 2;


pub struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("device failure"))
    }
}


fn dec(text: &str) -> Result<Decimal, Box<dyn Error>> {
    Ok(Decimal::from_str(text)?)
}


fn day(number: u8) -> Result<Date, Box<dyn Error>> {
    Ok(Date::from_calendar_date(YEAR, Month::November, number)?)
}


fn row(cost: &str, account: &str, moment: &str, service: &str, tags: &str) -> String {
    format!("{cost},USD,{account},{moment},{service},\"{}\",ignored", tags.replace('"', "\"\""))
}


fn at(date: &str) -> String {
    format!("{date}T00:00:00Z")
}


fn export(rows: &[String]) -> String {
    let mut lines = vec![HEADER.to_string()];
    lines.extend(rows.iter().cloned());
    lines.join("\n")
}


fn read(rows: &[String], limits: &Limits) -> Result<CostTable, CostError> {
    read_focus(export(rows).as_bytes(), limits, TENANT)
}


fn skipped(table: &CostTable, reason: SkipReason) -> u64 {
    table.skipped.get(&reason).copied().unwrap_or(0)
}


fn key(date: Date, account: &str, service: &str) -> (Date, String, String) {
    (date, account.to_string(), service.to_string())
}


fn sample() -> Vec<String> {
    vec![
        row("10.50", "acct1", &at("2026-11-01"), "Compute", r#"{"team":"a","env":"prod"}"#),
        row("4.50", "acct1", &at("2026-11-01"), "Storage", r#"{"team":"a"}"#),
        row("20", "acct2", &at("2026-11-01"), "Compute", "{}"),
        row("1.25", "acct3", &at("2026-11-02"), "Network", ""),
        row("2.75", "acct1", &at("2026-11-02"), "Compute", r#"{"team":"b"}"#),
    ]
}


#[test]
fn aggregates_three_accounts_services_and_tags() -> Result<(), Box<dyn Error>> {
    let table = read(&sample(), &Limits::default())?;
    assert_eq!(tenant_of(&table.tenant), TENANT);
    assert_eq!(table.currency.as_deref(), Some("USD"));
    assert_eq!(table.accepted, ROW_COUNT);
    assert!(table.skipped.is_empty());
    assert_eq!(table.day_totals.get(&day(1)?), Some(&dec("35")?));
    assert_eq!(table.day_totals.get(&day(SECOND_DAY)?), Some(&dec("4")?));
    assert_eq!(table.by_account_service.get(&key(day(1)?, "acct1", "Compute")), Some(&dec("10.5")?));
    assert_eq!(table.by_account_service.get(&key(day(1)?, "acct2", "Compute")), Some(&dec("20")?));
    assert_eq!(
        table.by_account_service.get(&key(day(SECOND_DAY)?, "acct3", "Network")),
        Some(&dec("1.25")?)
    );
    assert_eq!(table.by_tag.get(&key(day(1)?, "team", "a")), Some(&dec("15")?));
    assert_eq!(table.by_tag.get(&key(day(1)?, "env", "prod")), Some(&dec("10.5")?));
    assert_eq!(table.by_tag.get(&key(day(SECOND_DAY)?, "team", "b")), Some(&dec("2.75")?));
    assert_eq!(table.other.count, 0);
    assert_eq!(table.tag_other.count, 0);
    Ok(())
}


#[test]
fn charge_start_gives_the_utc_day() -> Result<(), Box<dyn Error>> {
    let rows = vec![row("3", "acct1", "2026-11-01T23:30:00-02:00", "Compute", "")];
    let table = read(&rows, &Limits::default())?;
    assert_eq!(table.day_totals.get(&day(SECOND_DAY)?), Some(&dec("3")?));
    Ok(())
}


#[test]
fn negative_amount_is_a_credit() -> Result<(), Box<dyn Error>> {
    let rows = vec![row("-3.5", "acct1", &at("2026-11-01"), "Compute", "")];
    let table = read(&rows, &Limits::default())?;
    assert_eq!(table.day_totals.get(&day(1)?), Some(&dec("-3.5")?));
    Ok(())
}


#[test]
fn sub_account_replaces_the_billing_account_when_present() -> Result<(), Box<dyn Error>> {
    let text = "BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,SubAccountId\n\
                1,USD,bill,2026-11-01T00:00:00Z,Compute,sub\n\
                2,USD,bill,2026-11-01T00:00:00Z,Compute,\n";
    let table = read_focus(text.as_bytes(), &Limits::default(), TENANT)?;
    assert_eq!(table.by_account_service.get(&key(day(1)?, "sub", "Compute")), Some(&dec("1")?));
    assert_eq!(table.by_account_service.get(&key(day(1)?, "bill", "Compute")), Some(&dec("2")?));
    assert!(table.by_tag.is_empty());
    Ok(())
}


#[test]
fn each_skip_reason_is_counted_and_the_row_skipped() -> Result<(), Box<dyn Error>> {
    let rows = vec![
        row("1", "acct1", &at("2026-11-01"), "service-name-over-the-cap", ""),
        "1,USD,acct1".to_string(),
        row("1", "", &at("2026-11-01"), "Compute", ""),
        row("1", "acct1", &at("2026-11-01"), "Comp\u{202e}ute", ""),
        row("1e3", "acct1", &at("2026-11-01"), "Compute", ""),
        row("abc", "acct1", &at("2026-11-01"), "Compute", ""),
        row("", "acct1", &at("2026-11-01"), "Compute", ""),
        row("1", "acct1", "yesterday", "Compute", ""),
        row("1", "acct1", &at("2026-11-01"), "Compute", "not json"),
        row("1", "acct1", &at("2026-11-01"), "Compute", r#"{"k":1}"#),
        row("1", "acct1", &at("2026-11-01"), "Compute", r#"{"k\u0007":"v"}"#),
        row("1", "acct1", &at("2026-11-01"), "Compute", "{\"k\":\"v\\u200b\"}"),
        row("5", "acct1", &at("2026-11-01"), "Compute", ""),
        row("1", "acct1", &at("2026-11-01"), "Compute", "").replace("USD", "EUR"),
    ];
    let limits = Limits {
        max_field_bytes: FIELD_CAP,
        ..Limits::default()
    };
    let table = read(&rows, &limits)?;
    assert_eq!(table.accepted, 1);
    assert_eq!(skipped(&table, SkipReason::Oversized), 1);
    assert_eq!(skipped(&table, SkipReason::Malformed), MALFORMED_ROWS);
    assert_eq!(skipped(&table, SkipReason::BadAmount), MALFORMED_ROWS);
    assert_eq!(skipped(&table, SkipReason::BadDate), 1);
    assert_eq!(skipped(&table, SkipReason::BadTags), BAD_TAG_ROWS);
    assert_eq!(skipped(&table, SkipReason::MixedCurrency), 1);
    assert_eq!(table.day_totals.get(&day(1)?), Some(&dec("5")?));
    assert_eq!(table.currency.as_deref(), Some("USD"));
    Ok(())
}


#[test]
fn invalid_utf8_row_is_malformed() -> Result<(), Box<dyn Error>> {
    let mut bytes = export(&[]).into_bytes();
    bytes.extend_from_slice(b"\n1,USD,acct1,2026-11-01T00:00:00Z,\xff,{},x\n");
    let table = read_focus(bytes.as_slice(), &Limits::default(), TENANT)?;
    assert_eq!(skipped(&table, SkipReason::Malformed), 1);
    Ok(())
}


#[test]
fn missing_required_columns_are_named() -> Result<(), Box<dyn Error>> {
    let all = ["BilledCost", "BillingCurrency", "BillingAccountId", "ChargePeriodStart", "ServiceName"];
    all.iter().try_for_each(|missing| -> Result<(), Box<dyn Error>> {
        let header = all.iter().filter(|name| *name != missing).copied().collect::<Vec<_>>().join(",");
        let outcome = read_focus(header.as_bytes(), &Limits::default(), TENANT);
        assert!(matches!(outcome, Err(CostError::MissingColumn { column }) if column == *missing));
        Ok(())
    })?;
    let empty = read_focus("".as_bytes(), &Limits::default(), TENANT);
    assert!(matches!(empty, Err(CostError::MissingColumn { .. })));
    Ok(())
}


#[test]
fn input_bytes_are_capped_at_exactly_the_limit() -> Result<(), Box<dyn Error>> {
    let text = export(&sample());
    let exact = Limits {
        max_bytes: text.len() as u64,
        ..Limits::default()
    };
    assert!(read_focus(text.as_bytes(), &exact, TENANT).is_ok());
    let below = Limits {
        max_bytes: exact.max_bytes - 1,
        ..Limits::default()
    };
    let outcome = read_focus(text.as_bytes(), &below, TENANT);
    assert!(matches!(outcome, Err(CostError::TooLarge { limit }) if limit == below.max_bytes));
    Ok(())
}


#[test]
fn rows_are_capped_at_exactly_the_limit() -> Result<(), Box<dyn Error>> {
    let exact = Limits {
        max_rows: ROW_COUNT,
        ..Limits::default()
    };
    assert!(read(&sample(), &exact).is_ok());
    let below = Limits {
        max_rows: ROW_COUNT - 1,
        ..Limits::default()
    };
    assert!(matches!(read(&sample(), &below), Err(CostError::TooManyRows { limit }) if limit == below.max_rows));
    Ok(())
}


#[test]
fn field_length_is_capped_at_exactly_the_limit() -> Result<(), Box<dyn Error>> {
    let rows = vec![row("1", "acct1", &at("2026-11-01"), "Compute", "")];
    let longest = rows.iter().flat_map(|line| line.split(',')).map(str::len).max().unwrap_or(0);
    let exact = Limits {
        max_field_bytes: longest,
        ..Limits::default()
    };
    assert_eq!(read(&rows, &exact)?.accepted, 1);
    let below = Limits {
        max_field_bytes: longest - 1,
        ..Limits::default()
    };
    assert_eq!(skipped(&read(&rows, &below)?, SkipReason::Oversized), 1);
    Ok(())
}


#[test]
fn tag_pairs_per_row_are_capped_at_exactly_the_limit() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_tags_per_row: TAG_CAP,
        ..Limits::default()
    };
    let rows = vec![
        row("1", "acct1", &at("2026-11-01"), "Compute", r#"{"a":"1","b":"2"}"#),
        row("1", "acct1", &at("2026-11-01"), "Compute", r#"{"a":"1","b":"2","c":"3"}"#),
    ];
    let table = read(&rows, &limits)?;
    assert_eq!(table.accepted, 1);
    assert_eq!(skipped(&table, SkipReason::BadTags), 1);
    Ok(())
}


#[test]
fn series_beyond_the_cap_go_to_the_other_bucket() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_series: SERIES_CAP,
        ..Limits::default()
    };
    let rows = vec![
        row("1", "acct1", &at("2026-11-01"), "svc1", r#"{"t1":"v"}"#),
        row("2", "acct2", &at("2026-11-01"), "svc2", r#"{"t2":"v"}"#),
        row("4", "acct3", &at("2026-11-01"), "svc1", r#"{"t3":"v","t1":"v"}"#),
        row("8", "acct1", &at("2026-11-01"), "svc3", ""),
    ];
    let table = read(&rows, &limits)?;
    assert_eq!(table.other.count, OTHER_ROWS);
    assert_eq!(table.other.cost, dec("12")?);
    assert_eq!(table.tag_other.count, 1);
    assert_eq!(table.tag_other.cost, dec("4")?);
    assert_eq!(table.day_totals.get(&day(1)?), Some(&dec("15")?));
    assert_eq!(table.by_account_service.len(), SERIES_CAP);
    assert_eq!(table.by_tag.get(&key(day(1)?, "t1", "v")), Some(&dec("5")?));
    Ok(())
}


#[test]
fn series_at_exactly_the_cap_are_all_kept() -> Result<(), Box<dyn Error>> {
    let limits = Limits {
        max_series: SERIES_CAP,
        ..Limits::default()
    };
    let rows = vec![
        row("1", "acct1", &at("2026-11-01"), "svc1", ""),
        row("2", "acct2", &at("2026-11-01"), "svc2", ""),
    ];
    let table = read(&rows, &limits)?;
    assert_eq!(table.other.count, 0);
    assert_eq!(table.by_account_service.len(), SERIES_CAP);
    Ok(())
}


#[test]
fn tenant_grammar_is_core_pgs() -> Result<(), Box<dyn Error>> {
    let outcome = read_focus(Broken, &Limits::default(), "-x");
    assert!(matches!(outcome, Err(CostError::Tenant(_))));
    Ok(())
}


#[test]
fn read_failures_surface() -> Result<(), Box<dyn Error>> {
    let broken = read_focus(Broken, &Limits::default(), TENANT);
    assert!(matches!(broken, Err(CostError::Read(_))));
    let mut bytes = b"\xff\xfe,BilledCost\n".to_vec();
    bytes.extend_from_slice(b"1,2\n");
    let header = read_focus(bytes.as_slice(), &Limits::default(), TENANT);
    assert!(matches!(header, Err(CostError::Read(_))));
    let text = export(&sample());
    let chained = text.as_bytes().chain(Broken);
    assert!(matches!(read_focus(chained, &Limits::default(), TENANT), Err(CostError::Read(_))));
    Ok(())
}


#[test]
fn totals_that_overflow_are_refused() -> Result<(), Box<dyn Error>> {
    let same_day = vec![
        row(DECIMAL_MAX, "a1", &at("2026-11-01"), "s1", ""),
        row(DECIMAL_MAX, "a2", &at("2026-11-01"), "s2", ""),
    ];
    assert!(matches!(read(&same_day, &Limits::default()), Err(CostError::Overflow)));
    let series = vec![
        row(DECIMAL_MAX, "a1", &at("2026-11-01"), "s1", ""),
        row(DECIMAL_MIN, "a2", &at("2026-11-01"), "s2", ""),
        row(DECIMAL_MAX, "a1", &at("2026-11-01"), "s1", ""),
    ];
    assert!(matches!(read(&series, &Limits::default()), Err(CostError::Overflow)));
    let one = Limits {
        max_series: 1,
        ..Limits::default()
    };
    let other = vec![
        row(DECIMAL_MIN, "a1", &at("2026-11-01"), "s1", ""),
        row(DECIMAL_MAX, "a2", &at("2026-11-01"), "s2", ""),
        row(DECIMAL_MAX, "a3", &at("2026-11-01"), "s3", ""),
    ];
    assert!(matches!(read(&other, &one), Err(CostError::Overflow)));
    let tag = vec![
        row(DECIMAL_MAX, "a1", &at("2026-11-01"), "s1", r#"{"k":"v"}"#),
        row(DECIMAL_MIN, "a2", &at("2026-11-01"), "s2", ""),
        row(DECIMAL_MAX, "a3", &at("2026-11-01"), "s3", r#"{"k":"v"}"#),
    ];
    assert!(matches!(read(&tag, &Limits::default()), Err(CostError::Overflow)));
    let tag_other = vec![
        row(DECIMAL_MIN, "a1", &at("2026-11-01"), "s1", r#"{"p1":"v"}"#),
        row(DECIMAL_MAX, "a1", &at("2026-11-01"), "s1", r#"{"p2":"v"}"#),
        row(DECIMAL_MAX, "a1", &at("2026-11-01"), "s1", r#"{"p3":"v"}"#),
    ];
    assert!(matches!(read(&tag_other, &one), Err(CostError::Overflow)));
    Ok(())
}


#[test]
fn amounts_are_plain_decimals() -> Result<(), Box<dyn Error>> {
    assert_eq!(parse_amount("12.50"), Some(dec("12.5")?));
    assert_eq!(parse_amount("-0.001"), Some(dec("-0.001")?));
    assert_eq!(parse_amount("1E3"), None);
    assert_eq!(parse_amount("1e3"), None);
    assert_eq!(parse_amount(""), None);
    assert_eq!(parse_amount("1.2.3"), None);
    let mut total = dec(DECIMAL_MAX)?;
    assert!(matches!(add_cost(&mut total, dec("1")?), Err(CostError::Overflow)));
    assert_eq!(total, dec(DECIMAL_MAX)?);
    Ok(())
}


#[test]
fn only_valid_short_account_labels_are_seen_for_the_replace() -> Result<(), Box<dyn Error>> {
    let rows = vec![
        row("1", "", &at("2026-11-01"), "Compute", ""),
        row("1", "evil\u{202e}", &at("2026-11-01"), "Compute", ""),
        row("1", &"a".repeat(FIELD_CAP + 1), &at("2026-11-01"), "Compute", ""),
        row("x", "skipped", &at("2026-11-01"), "Compute", ""),
        row("1", "kept", &at("2026-11-01"), "Compute", ""),
    ];
    let limits = Limits {
        max_field_bytes: FIELD_CAP,
        ..Limits::default()
    };
    let table = read(&rows, &limits)?;
    assert_eq!(table.seen_accounts, ["kept".to_owned(), "skipped".to_owned()].into_iter().collect());
    Ok(())
}


#[test]
fn default_limits_are_bounded() -> Result<(), Box<dyn Error>> {
    let limits = Limits::default();
    assert!(limits.max_bytes > 0 && limits.max_rows > 0 && limits.max_field_bytes > 0);
    assert!(limits.max_tags_per_row > 0 && limits.max_series > 0);
    Ok(())
}
