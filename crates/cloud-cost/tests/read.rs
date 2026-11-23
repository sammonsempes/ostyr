#[path = "common/accept.rs"]
mod accept;
#[path = "common/reply.rs"]
mod reply;
#[path = "common/types.rs"]
mod types;


use cloud_cost::load::{plain, request_url_len, Statement, MAX_URL_BYTES};
use cloud_cost::read::{
    check_account, check_profile, check_span, collect_rows, dimension_name, escape_param, parse_day_text, parse_dimension, parse_generation,
    parse_row, parse_state, plan_read, printable, read_daily, read_daily_capped, read_daily_timed, read_state, read_statement, state_statement,
    DailyQuery, Dimension, ReadCaps, ReadError, Session, MAX_READ_DAYS, MAX_STATE_BYTES, STATE_MAX_ROWS,
};
use cloud_cost::settings::CostLoadConfig;
use reply::{cut, failing, ok, serve_replies, Canned};
use rust_decimal::Decimal;
use siem_ingest::clickhouse::new_agent;
use siem_ingest::error::InsertClass;
use siem_ingest::reader_profile::{changed_statement, pin_clause, pins, CHECK_MAX_ROWS};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, BufReader};
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use time::{Date, Month};
use types::TestResult;


const PASSWORD: &str = "READPW-71c9a2e4";


const TENANT: &str = "acme";


const OTHER_TENANT: &str = "evil";


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


const TIMEOUT_MS: u64 = 30_000;


const YEAR: i32 = 2026;


const SMALL_ROWS: usize = 2;


const SMALL_BYTES: u64 = 100;


const ROW_BYTES: u64 = 4096;


const LONG_ACCOUNT: usize = 1025;


const FULL_ACCOUNT: usize = 1024;


const URL_FILLER: usize = 70_000;


const URL_FILLER_MAX: usize = 2000;


const FIRST_DAY: u8 = 5;


const LAST_DAY: u8 = 7;


const OVER_SPAN_DAYS: i64 = 366;


const TOO_LATE_YEAR: i32 = 2149;


const TOO_EARLY_YEAR: i32 = 1969;


const TWICE: usize = 2;


const STATEMENT_ROWS: u64 = 5;


const LAST_YEAR_DAY: u8 = 31;


const MILLION_DAYS: i32 = 1_000_000;


const COST_UNITS: i64 = 12_340_000_000;


const DECIMAL_SCALE: u32 = 9;


const INVALID_FIRST: u8 = 0xff;


const INVALID_SECOND: u8 = 0xfe;


const ZERO_CALLS: usize = 0;


const GENERATION: &str = "1700000000000";


const OTHER_GENERATION: &str = "1700000000001";


const SEVENTEEN: u64 = 17;


const GENERATION_VALUE: u64 = 1_700_000_000_000;


const TWO_GENERATIONS: &str = "3400000000000";


struct Served {
    config: CostLoadConfig,
    _dir: TempDir,
    server: JoinHandle<io::Result<Vec<String>>>,
}


struct Rig {
    dir: TempDir,
    config: CostLoadConfig,
    listener: TcpListener,
}


fn rig() -> Result<Rig, Box<dyn Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let password = dir.path().join("password");
    write_secret(&password, format!("{PASSWORD}\n"))?;
    let config = CostLoadConfig {
        url: format!("http://127.0.0.1:{port}"),
        user: "reader".to_owned(),
        password_file: password,
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "cloud_cost_daily".to_owned(),
        timeout_ms: TIMEOUT_MS,
        ttl_days: 1,
        tenant: TENANT.to_owned(),
    };
    Ok(Rig { dir, config, listener })
}


fn day(month: Month, number: u8) -> Result<Date, Box<dyn Error>> {
    Ok(Date::from_calendar_date(YEAR, month, number)?)
}


fn query() -> Result<DailyQuery, Box<dyn Error>> {
    Ok(DailyQuery {
        from: day(Month::January, FIRST_DAY)?,
        to: day(Month::January, LAST_DAY)?,
        dimension: Dimension::Total,
        account: None,
    })
}


fn with_account(account: &str) -> Result<DailyQuery, Box<dyn Error>> {
    Ok(DailyQuery {
        account: Some(account.to_owned()),
        ..query()?
    })
}


fn caps(rows: usize, bytes: u64) -> ReadCaps {
    ReadCaps { rows, bytes }
}


fn big_caps() -> ReadCaps {
    caps(ROW_BYTES as usize, ROW_BYTES * ROW_BYTES)
}


fn row_line(tenant: &str, day_text: &str, account: &str, dimension: &str, cost: &str) -> String {
    format!(
        "{{\"day_text\":\"{day_text}\",\"account\":\"{account}\",\"source\":\"abc\",\"dimension\":\"{dimension}\",\"key1\":\"\",\"key2\":\"\",\"cost_text\":\"{cost}\",\"currency\":\"USD\",\"tenant\":\"{tenant}\"}}"
    )
}


fn good_row() -> String {
    row_line(TENANT, "2026-01-05", "acct", "total", "12.340000000")
}


fn clean_check() -> String {
    let names: Vec<&str> = pins(&[], CHECK_MAX_ROWS).iter().map(|(name, _)| *name).chain(["readonly"]).collect();
    format!("{}\n", names.join("\n"))
}


fn state_line(count: &str, sum: &str, pending: &str) -> String {
    format!("{{\"count_text\":\"{count}\",\"sum_text\":\"{sum}\",\"pending_text\":\"{pending}\"}}\n")
}


fn done() -> String {
    state_line("1", GENERATION, "0")
}


fn done_b() -> String {
    state_line("2", TWO_GENERATIONS, "0")
}


fn untouched(listener: &TcpListener) -> Result<bool, Box<dyn Error>> {
    listener.set_nonblocking(true)?;
    Ok(listener.accept().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock))
}


fn joined(handle: JoinHandle<io::Result<Vec<String>>>) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(handle.join().map_err(|_| "server thread panicked")??)
}


fn serve(rig: Rig, replies: Vec<Canned>) -> Result<Served, Box<dyn Error>> {
    let Rig { dir, config, listener } = rig;
    Ok(Served {
        config,
        _dir: dir,
        server: serve_replies(listener, replies),
    })
}


fn pairs_of(head: &str) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let target = head.split_whitespace().nth(1).ok_or("no target")?;
    Ok(url::Url::parse(&format!("http://host{target}"))?
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect())
}


#[test]
fn the_statement_is_final_parameterised_and_pinned() -> TestResult {
    let rig = rig()?;
    let pins_text = pin_clause(&[], STATEMENT_ROWS + 1);
    let expected = format!(
        "SELECT toString(`day`) AS `day_text`, `account`, `source`, `dimension`, `key1`, `key2`, toString(`cost`) AS `cost_text`, `currency`, `tenant` \
         FROM `ostyr`.`cloud_cost_daily` FINAL WHERE `tenant` = {{tenant:String}} AND `day` >= {{from:Date}} AND `day` <= {{to:Date}} \
         AND `dimension` = {{dimension:String}} ORDER BY `day`, `account`, `source`, `dimension`, `key1`, `key2` LIMIT {{limit:UInt64}}{pins_text} FORMAT JSONEachRow"
    );
    assert_eq!(read_statement(&rig.config, false, STATEMENT_ROWS as usize)?, expected);
    assert!(expected.contains("max_result_rows = 6"));
    assert!(expected.contains("filter = ''"));
    assert!(expected.contains("additional_table_filters = {}"));
    assert!(expected.contains("limit = 0"));
    assert!(expected.contains("sort_overflow_mode = 'throw'"));
    assert!(read_statement(&rig.config, true, STATEMENT_ROWS as usize)?
        .contains("AND `dimension` = {dimension:String} AND `account` = {account:String} ORDER BY"));
    Ok(())
}


#[test]
fn a_bad_identifier_is_a_statement_error() -> TestResult {
    let mut rig = rig()?;
    rig.config.database = "a`b".to_owned();
    assert!(matches!(read_statement(&rig.config, false, 1), Err(ReadError::Statement(_))));
    Ok(())
}


#[test]
fn the_plan_binds_every_value_and_escapes_the_account() -> TestResult {
    let rig = rig()?;
    let plan = plan_read(&rig.config, TENANT, &with_account("a'b\\c")?, big_caps())?;
    let params: BTreeMap<&str, &str> = plan.params.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
    assert_eq!(params.get("tenant"), Some(&TENANT));
    assert_eq!(params.get("from"), Some(&"2026-01-05"));
    assert_eq!(params.get("to"), Some(&"2026-01-07"));
    assert_eq!(params.get("dimension"), Some(&"total"));
    assert_eq!(params.get("account"), Some(&"a'b\\\\c"));
    assert_eq!(params.get("limit"), Some(&"4097"));
    assert!(!plan.statement.contains("a'b"));
    Ok(())
}


#[test]
fn the_worst_case_request_url_stays_under_the_cap() -> TestResult {
    let mut rig = rig()?;
    rig.config.url = format!("http://127.0.0.1:{}/{}", rig.listener.local_addr()?.port(), "p".repeat(URL_FILLER_MAX));
    let plan = plan_read(
        &rig.config,
        TENANT,
        &with_account(&"\\".repeat(FULL_ACCOUNT))?,
        caps(cloud_cost::read::MAX_READ_ROWS, 1),
    )?;
    let read = Statement {
        text: plan.statement,
        params: plan.params,
        body: String::new(),
    };
    assert!(request_url_len(&rig.config, &read) < MAX_URL_BYTES);
    assert!(request_url_len(&rig.config, &plain(changed_statement())) < MAX_URL_BYTES);
    Ok(())
}


#[test]
fn a_full_length_account_is_accepted_and_one_byte_more_is_not() -> TestResult {
    let rig = rig()?;
    plan_read(&rig.config, TENANT, &with_account(&"a".repeat(FULL_ACCOUNT))?, big_caps())?;
    assert!(matches!(check_account(Some(&"a".repeat(LONG_ACCOUNT))), Err(ReadError::BadAccount)));
    assert!(matches!(check_account(Some("")), Err(ReadError::BadAccount)));
    assert!(matches!(check_account(Some("a\u{202e}b")), Err(ReadError::BadAccount)));
    assert!(check_account(None).is_ok());
    Ok(())
}


#[test]
fn every_refusal_comes_before_any_request() -> TestResult {
    let rig = rig()?;
    let refused = |tenant: &str, asked: &DailyQuery| read_daily_capped(&rig.config, tenant, asked, big_caps());
    fs::remove_file(&rig.config.password_file)?;
    assert!(matches!(refused(OTHER_TENANT, &query()?), Err(ReadError::TenantMismatch)));
    assert!(matches!(refused("-x", &query()?), Err(ReadError::TenantMismatch)));
    let reversed = DailyQuery {
        from: day(Month::January, LAST_DAY)?,
        to: day(Month::January, FIRST_DAY)?,
        ..query()?
    };
    assert!(matches!(refused(TENANT, &reversed), Err(ReadError::SpanOrder)));
    let long = DailyQuery {
        to: Date::from_calendar_date(YEAR + 1, Month::January, LAST_DAY)?,
        ..query()?
    };
    assert!(matches!(refused(TENANT, &long), Err(ReadError::SpanTooLong)));
    let early = DailyQuery {
        from: Date::from_calendar_date(TOO_EARLY_YEAR, Month::December, LAST_YEAR_DAY)?,
        ..query()?
    };
    assert!(matches!(refused(TENANT, &early), Err(ReadError::DayOutOfRange)));
    let late = DailyQuery {
        to: Date::from_calendar_date(TOO_LATE_YEAR, Month::June, LAST_DAY)?,
        ..query()?
    };
    assert!(matches!(refused(TENANT, &late), Err(ReadError::DayOutOfRange)));
    assert!(matches!(
        refused(TENANT, &with_account(&"a".repeat(LONG_ACCOUNT))?),
        Err(ReadError::BadAccount)
    ));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_span_of_one_million_days_is_refused() -> TestResult {
    let from = Date::from_calendar_date(YEAR, Month::January, 1)?;
    let far = Date::from_julian_day(from.to_julian_day() + MILLION_DAYS)?;
    assert!(matches!(check_span(from, far), Err(ReadError::DayOutOfRange)));
    let edge = Date::from_julian_day(from.to_julian_day() + i32::try_from(MAX_READ_DAYS)?)?;
    assert!(matches!(check_span(from, edge), Err(ReadError::SpanTooLong)));
    let last = Date::from_julian_day(from.to_julian_day() + i32::try_from(OVER_SPAN_DAYS - 1)?)?;
    assert!(check_span(from, last).is_ok());
    assert!(check_span(from, from).is_ok());
    Ok(())
}


#[test]
fn bad_settings_are_refused_before_any_request() -> TestResult {
    let mut rig = rig()?;
    rig.config.user = String::new();
    assert!(matches!(read_daily(&rig.config, TENANT, &query()?), Err(ReadError::Settings(_))));
    rig.config.user = "reader".to_owned();
    rig.config.url = format!("{}/{}", rig.config.url, "p".repeat(URL_FILLER));
    assert!(matches!(read_daily(&rig.config, TENANT, &query()?), Err(ReadError::Settings(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_clean_profile_then_the_read_returns_the_rows() -> TestResult {
    let rig = rig()?;
    let body = format!("{}\n{}\n", good_row(), row_line(TENANT, "2026-01-06", "acct", "total", "3"));
    let Served { config, _dir, server } = serve(rig, vec![ok(&clean_check()), ok(&done()), ok(&body), ok(&done())])?;
    let found = read_daily(&config, TENANT, &query()?)?;
    let heads = joined(server)?;
    assert_eq!(found.len(), TWICE);
    let first = found.first().ok_or("no row")?;
    assert_eq!(first.day, day(Month::January, FIRST_DAY)?);
    assert_eq!(first.account, "acct");
    assert_eq!(first.cost, Decimal::new(COST_UNITS, DECIMAL_SCALE));
    assert_eq!(first.currency, "USD");
    assert_eq!(first.source, "abc");
    assert_eq!(heads.len(), TWICE * TWICE);
    let check = pairs_of(heads.first().ok_or("no check")?)?;
    assert_eq!(check.get("query"), Some(&changed_statement()));
    assert_eq!(check.get("readonly").map(String::as_str), Some("2"));
    let read = pairs_of(heads.get(TWICE).ok_or("no read")?)?;
    assert_eq!(read.get("query"), Some(&read_statement(&config, false, cloud_cost::read::MAX_READ_ROWS)?));
    assert_eq!(read.get("param_tenant").map(String::as_str), Some(TENANT));
    assert_eq!(read.get("param_from").map(String::as_str), Some("2026-01-05"));
    assert_eq!(read.get("param_to").map(String::as_str), Some("2026-01-07"));
    assert_eq!(read.get("param_dimension").map(String::as_str), Some("total"));
    assert_eq!(read.get("param_limit").map(String::as_str), Some("50001"));
    assert!(heads.iter().all(|head| head.contains(PASSWORD)));
    let expected = state_statement(&config)?;
    assert!(expected.contains("FROM `ostyr`.`cloud_cost_daily_load_state` FINAL WHERE `tenant` = {tenant:String} SETTINGS max_result_rows = 2"));
    assert!(expected.ends_with(" FORMAT JSONEachRow"));
    [1, TWICE + 1].iter().try_for_each(|index| -> TestResult {
        let state = pairs_of(heads.get(*index).ok_or("no state")?)?;
        assert_eq!(state.get("query"), Some(&expected));
        assert_eq!(state.get("param_tenant").map(String::as_str), Some(TENANT));
        assert_eq!(state.get("readonly").map(String::as_str), Some("2"));
        Ok(())
    })?;
    Ok(())
}


#[test]
fn an_empty_reply_is_an_empty_result() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), ok(""), ok(&done())])?;
    assert!(read_daily_capped(&config, TENANT, &query()?, big_caps())?.is_empty());
    joined(server)?;
    Ok(())
}


#[test]
fn a_profile_with_a_changed_setting_is_refused_before_the_read() -> TestResult {
    let body = format!("{}skip_unavailable_shards\n", clean_check());
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&body)])?;
    let outcome = read_daily_capped(&config, TENANT, &query()?, big_caps());
    assert!(matches!(outcome, Err(ReadError::ReaderProfileChanged(1))));
    assert_eq!(joined(server)?.len(), 1);
    Ok(())
}


#[test]
fn a_cut_or_empty_check_reply_is_refused() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![ok("")])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::ReaderProfileChanged(_))
    ));
    assert_eq!(joined(server)?.len(), 1);
    Ok(())
}


#[test]
fn a_profile_refusal_code_is_reader_profile_changed() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![failing("500 Internal Server Error", Some("164"))])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::ReaderProfileChanged(1))
    ));
    assert_eq!(joined(server)?.len(), 1);
    Ok(())
}


#[test]
fn another_refusal_of_the_check_is_a_class() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![failing("503 Service Unavailable", None)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::Refused(InsertClass::Unavailable))
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn a_refused_read_is_a_class() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), failing("401 Unauthorized", None)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::Refused(InsertClass::Unauthorized))
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn a_check_body_cut_short_is_a_body_error() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![cut("readonly\n")])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::Body(_))
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn a_read_body_cut_short_is_a_body_error() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), cut(&format!("{}\n", good_row()))])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::Body(_))
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn a_foreign_tenant_row_is_a_named_error() -> TestResult {
    let body = format!("{}\n{}\n", good_row(), row_line(OTHER_TENANT, "2026-01-05", "acct", "total", "1"));
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), ok(&body)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::ForeignTenant)
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn rows_outside_the_request_are_named_errors() -> TestResult {
    let asked = with_account("acct")?;
    let outside = [
        row_line(TENANT, "2026-01-04", "acct", "total", "1"),
        row_line(TENANT, "2026-01-08", "acct", "total", "1"),
        row_line(TENANT, "2026-01-06", "acct", "tag", "1"),
        row_line(TENANT, "2026-01-06", "other", "total", "1"),
    ];
    assert!(outside
        .iter()
        .all(|line| matches!(parse_row(line, TENANT, &asked), Err(ReadError::OutOfScope))));
    assert!(parse_row(&row_line(TENANT, "2026-01-06", "acct", "total", "1"), TENANT, &asked).is_ok());
    assert!(parse_row(&row_line(TENANT, "2026-01-06", "any", "total", "1"), TENANT, &query()?).is_ok());
    Ok(())
}


#[test]
fn a_malformed_or_exception_line_is_a_named_error() -> TestResult {
    let asked = query()?;
    let malformed = [
        "not json".to_owned(),
        String::new(),
        "{}".to_owned(),
        format!("{},\"extra\":1}}", good_row().trim_end_matches('}')),
        row_line(TENANT, "2026-1-5", "acct", "total", "1"),
        row_line(TENANT, "2026-01-05", "acct", "total", "1e5"),
        row_line(TENANT, "2026-01-05", "acct", "total", "x"),
    ];
    assert!(malformed
        .iter()
        .all(|line| matches!(parse_row(line, TENANT, &asked), Err(ReadError::MalformedReply))));
    assert!(matches!(
        parse_row("{\"exception\": \"Code: 241. DB::Exception: memory\"}", TENANT, &asked),
        Err(ReadError::ExceptionInBody)
    ));
    Ok(())
}


#[test]
fn an_exception_line_after_good_rows_fails_the_whole_read() -> TestResult {
    let body = format!("{}\n{{\"exception\": \"Code: 241\"}}\n", good_row());
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), ok(&body)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::ExceptionInBody)
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn a_reply_over_the_row_cap_is_an_error_never_a_cut_list() -> TestResult {
    let body = format!("{}\n{}\n{}\n", good_row(), good_row(), good_row());
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), ok(&body)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, caps(SMALL_ROWS, ROW_BYTES * ROW_BYTES)),
        Err(ReadError::TooManyRows(SMALL_ROWS))
    ));
    joined(server)?;
    let exact = format!("{}\n{}\n", good_row(), good_row());
    let Served {
        config: config_again,
        _dir: _dir_again,
        server: server_again,
    } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), ok(&exact), ok(&done())])?;
    assert_eq!(
        read_daily_capped(&config_again, TENANT, &query()?, caps(SMALL_ROWS, ROW_BYTES * ROW_BYTES))?.len(),
        SMALL_ROWS
    );
    joined(server_again)?;
    Ok(())
}


#[test]
fn a_reply_over_the_byte_cap_is_an_error() -> TestResult {
    let body = format!("{}\n{}\n", good_row(), good_row());
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check()), ok(&done()), ok(&body)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, caps(ROW_BYTES as usize, SMALL_BYTES)),
        Err(ReadError::TooManyBytes(SMALL_BYTES))
    ));
    joined(server)?;
    Ok(())
}


#[test]
fn collect_rows_reads_invalid_utf8_as_a_body_error() -> TestResult {
    let mut reader = BufReader::new(&[INVALID_FIRST, INVALID_SECOND, b'\n'][..]);
    assert!(matches!(
        collect_rows(&mut reader, TENANT, &query()?, SMALL_ROWS),
        Err(ReadError::Body(_))
    ));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing() -> TestResult {
    let rig = rig()?;
    let spent = || Duration::from_millis(TIMEOUT_MS);
    assert!(matches!(
        read_daily_timed(&rig.config, TENANT, &query()?, big_caps(), &spent),
        Err(ReadError::Refused(InsertClass::Timeout))
    ));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn a_deadline_spent_after_the_check_sends_no_read() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check())])?;
    let calls = Cell::new(ZERO_CALLS);
    let elapsed = || {
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            Duration::from_millis(TIMEOUT_MS)
        } else {
            Duration::ZERO
        }
    };
    assert!(matches!(
        read_daily_timed(&config, TENANT, &query()?, big_caps(), &elapsed),
        Err(ReadError::Refused(InsertClass::Timeout))
    ));
    assert_eq!(joined(server)?.len(), 1);
    Ok(())
}


#[test]
fn a_server_that_hangs_up_is_a_class() -> TestResult {
    let Rig { config, listener, dir: _dir } = rig()?;
    let hangup = std::thread::spawn(move || accept::accept_bounded(&listener).map(drop));
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::Refused(InsertClass::Unavailable))
    ));
    hangup.join().map_err(|_| "server thread panicked")??;
    Ok(())
}


#[test]
fn a_bad_password_file_or_ca_is_a_setup_error() -> TestResult {
    let mut rig = rig()?;
    fs::write(&rig.config.password_file, [INVALID_FIRST, INVALID_SECOND])?;
    assert!(matches!(read_daily(&rig.config, TENANT, &query()?), Err(ReadError::Setup(_))));
    fs::remove_file(&rig.config.password_file)?;
    assert!(matches!(read_daily(&rig.config, TENANT, &query()?), Err(ReadError::Setup(_))));
    write_secret(&rig.config.password_file, format!("{PASSWORD}\n"))?;
    rig.config.ca_file = Some(rig.dir.path().join("absent.pem"));
    assert!(matches!(read_daily(&rig.config, TENANT, &query()?), Err(ReadError::Setup(_))));
    assert!(untouched(&rig.listener)?);
    Ok(())
}


#[test]
fn check_profile_alone_accepts_a_clean_reply() -> TestResult {
    let Served { config, _dir, server } = serve(rig()?, vec![ok(&clean_check())])?;
    let agent = new_agent(None, false)?;
    check_profile(&agent, &config, PASSWORD, Duration::from_secs(TWICE as u64))?;
    joined(server)?;
    Ok(())
}


#[test]
fn small_helpers() -> TestResult {
    assert_eq!(parse_dimension("total"), Some(Dimension::Total));
    assert_eq!(parse_dimension("account_service"), Some(Dimension::AccountService));
    assert_eq!(parse_dimension("tag"), Some(Dimension::Tag));
    assert_eq!(parse_dimension("other"), None);
    assert_eq!(parse_dimension("tag_other"), None);
    assert_eq!(dimension_name(Dimension::AccountService), "account_service");
    assert_eq!(parse_day_text("2026-01-05"), Some(day(Month::January, FIRST_DAY)?));
    assert_eq!(parse_day_text("2026-1-5"), None);
    assert_eq!(parse_day_text("2026-01-05T00:00:00Z"), None);
    assert_eq!(escape_param("a\\b'c"), "a\\\\b'c");
    assert_eq!(printable("ok name"), "ok name");
    assert_eq!(printable("a\\b"), "a\\u{5c}b");
    assert_eq!(printable("\u{1b}[31m\u{202e}é"), "\\u{1b}[31m\\u{202e}\\u{e9}");
    Ok(())
}


#[cfg(unix)]
fn write_secret(path: &std::path::Path, content: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, content: impl AsRef<[u8]>) -> io::Result<()> {
    fs::write(path, content)
}


fn served_states(replies: Vec<Canned>) -> Result<Served, Box<dyn Error>> {
    let mut all = vec![ok(&clean_check())];
    all.extend(replies);
    serve(rig()?, all)
}


fn pending(first: &str, second: &str, rows: &str) -> Result<Result<usize, ReadError>, Box<dyn Error>> {
    let Served { config, _dir, server } = served_states(vec![ok(first), ok(rows), ok(second)])?;
    let outcome = read_daily_capped(&config, TENANT, &query()?, big_caps()).map(|found| found.len());
    joined(server)?;
    Ok(outcome)
}


fn rows_body() -> String {
    format!("{}\n", good_row())
}


#[test]
fn the_state_statement_is_one_pinned_aggregate_of_the_tenant() -> TestResult {
    let rig = rig()?;
    let statement = state_statement(&rig.config)?;
    assert!(statement.starts_with(
        "SELECT toString(count()) AS `count_text`, toString(sum(`generation`)) AS `sum_text`, \
         toString(countIf(`state` = 'in_progress')) AS `pending_text` FROM `ostyr`.`cloud_cost_daily_load_state` FINAL WHERE `tenant` = {tenant:String}"
    ));
    assert!(statement.ends_with(&format!("{} FORMAT JSONEachRow", pin_clause(&[], STATE_MAX_ROWS))));
    assert!(!statement.contains("LIMIT"));
    Ok(())
}


#[test]
fn a_load_in_progress_before_the_read_is_a_named_error_and_no_row_is_requested() -> TestResult {
    let Served { config, _dir, server } = served_states(vec![ok(&state_line("1", GENERATION, "1"))])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::LoadInProgress)
    ));
    assert_eq!(joined(server)?.len(), TWICE);
    Ok(())
}


#[test]
fn a_load_in_progress_after_the_read_is_a_named_error() -> TestResult {
    let outcome = pending(&done(), &state_line("1", OTHER_GENERATION, "1"), &rows_body())?;
    assert!(matches!(outcome, Err(ReadError::LoadInProgress)));
    Ok(())
}


#[test]
fn a_change_of_the_sum_or_the_count_during_the_read_is_a_named_error() -> TestResult {
    let moved_sum = state_line("1", OTHER_GENERATION, "0");
    assert!(matches!(pending(&done(), &moved_sum, &rows_body())?, Err(ReadError::LoadInProgress)));
    assert!(matches!(pending(&moved_sum, &done(), &rows_body())?, Err(ReadError::LoadInProgress)));
    assert!(matches!(pending(&done(), &done_b(), &rows_body())?, Err(ReadError::LoadInProgress)));
    assert!(matches!(pending(&done_b(), &done(), &rows_body())?, Err(ReadError::LoadInProgress)));
    let same_sum_other_count = state_line("2", GENERATION, "0");
    assert!(matches!(
        pending(&done(), &same_sum_other_count, &rows_body())?,
        Err(ReadError::LoadInProgress)
    ));
    assert!(matches!(pending(&done(), &done(), &rows_body())?, Ok(1)));
    assert!(matches!(pending(&done_b(), &done_b(), &rows_body())?, Ok(1)));
    Ok(())
}


#[test]
fn a_killed_load_of_one_export_blocks_the_read_even_when_another_export_is_done() -> TestResult {
    let killed_a_then_done_b = state_line("2", TWO_GENERATIONS, "1");
    let Served { config, _dir, server } = served_states(vec![ok(&killed_a_then_done_b)])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::LoadInProgress)
    ));
    assert_eq!(joined(server)?.len(), TWICE);
    assert!(matches!(
        pending(&done(), &killed_a_then_done_b, &rows_body())?,
        Err(ReadError::LoadInProgress)
    ));
    Ok(())
}


#[test]
fn no_state_row_reads_as_before_and_a_first_load_during_the_read_is_a_named_error() -> TestResult {
    let none = state_line("0", "0", "0");
    assert!(matches!(pending(&none, &none, &rows_body())?, Ok(1)));
    assert!(matches!(pending(&none, &done(), &rows_body())?, Err(ReadError::LoadInProgress)));
    assert!(matches!(pending(&done(), &none, &rows_body())?, Err(ReadError::LoadInProgress)));
    Ok(())
}


#[test]
fn a_missing_state_table_refuses_the_read_with_a_named_error() -> TestResult {
    let Served { config, _dir, server } = served_states(vec![failing("404 Not Found", Some("60"))])?;
    assert!(matches!(
        read_daily_capped(&config, TENANT, &query()?, big_caps()),
        Err(ReadError::Refused(_))
    ));
    assert_eq!(joined(server)?.len(), TWICE);
    Ok(())
}


#[test]
fn a_bad_state_reply_is_a_named_error() -> TestResult {
    let long = format!("{}{}\n", done().trim_end(), " ".repeat(MAX_STATE_BYTES as usize));
    let two_lines = format!("{}{}", done(), done());
    let bad = [
        ("not json\n".to_owned(), "malformed"),
        ("{}\n".to_owned(), "malformed"),
        (String::new(), "malformed"),
        (two_lines, "malformed"),
        (long, "malformed"),
        (state_line("+5", GENERATION, "0"), "malformed"),
        (state_line("1", "x", "0"), "malformed"),
        (state_line("1", GENERATION, "-1"), "malformed"),
        ("{\"exception\": \"Code: 241\"}\n".to_owned(), "exception"),
    ];
    bad.iter().try_for_each(|(reply, kind)| -> TestResult {
        let Served { config, _dir, server } = served_states(vec![ok(reply)])?;
        let outcome = read_daily_capped(&config, TENANT, &query()?, big_caps());
        joined(server)?;
        let named = match *kind {
            "malformed" => matches!(outcome, Err(ReadError::MalformedReply)),
            _ => matches!(outcome, Err(ReadError::ExceptionInBody)),
        };
        assert!(named, "{reply}");
        Ok(())
    })
}


#[test]
fn a_cut_state_read_is_an_error() -> TestResult {
    let Served { config, _dir, server } = served_states(vec![cut(&done())])?;
    let outcome = read_daily_capped(&config, TENANT, &query()?, big_caps());
    joined(server)?;
    assert!(matches!(outcome, Err(ReadError::Body(_))));
    Ok(())
}


#[test]
fn state_helpers() -> TestResult {
    assert_eq!(parse_generation("17"), Some(SEVENTEEN));
    assert_eq!(parse_generation("017"), None);
    assert_eq!(parse_generation("-1"), None);
    assert_eq!(parse_generation(""), None);
    assert!(matches!(parse_state(done().trim_end()), Ok((1, GENERATION_VALUE))));
    assert!(matches!(
        parse_state(state_line("1", "5", "2").trim_end()),
        Err(ReadError::LoadInProgress)
    ));
    let rig = rig()?;
    let plan = plan_read(&rig.config, TENANT, &query()?, big_caps())?;
    assert_eq!(plan.state_params, vec![("tenant".to_owned(), TENANT.to_owned())]);
    let agent = new_agent(None, false)?;
    let session = Session {
        agent: &agent,
        config: &rig.config,
        password: PASSWORD,
    };
    assert!(matches!(read_state(session, &plan, Duration::from_millis(1)), Err(ReadError::Refused(_))));
    Ok(())
}


#[test]
fn a_body_error_keeps_only_a_kind() -> TestResult {
    let error = ReadError::Body(io::ErrorKind::UnexpectedEof);
    assert!(error.source().is_none());
    assert!(format!("{error:?}").contains("UnexpectedEof"));
    Ok(())
}


#[test]
fn a_deadline_spent_after_the_state_sends_no_read() -> TestResult {
    let Served { config, _dir, server } = served_states(vec![ok(&done())])?;
    let calls = Cell::new(ZERO_CALLS);
    let elapsed = || {
        calls.set(calls.get() + 1);
        if calls.get() > TWICE {
            Duration::from_millis(TIMEOUT_MS)
        } else {
            Duration::ZERO
        }
    };
    assert!(matches!(
        read_daily_timed(&config, TENANT, &query()?, big_caps(), &elapsed),
        Err(ReadError::Refused(InsertClass::Timeout))
    ));
    assert_eq!(joined(server)?.len(), TWICE);
    Ok(())
}
