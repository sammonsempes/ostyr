#[path = "common/types.rs"]
mod types;


use intel_feeds::config::{ClickhouseConfig, ClickhouseError};
use intel_feeds::limits::{MAX_RETRO_BYTES, MAX_RETRO_MATCHES, MAX_RETRO_ROWS_TO_GROUP, MAX_RETRO_ROWS_TO_READ, MAX_RETRO_SECONDS};
use intel_feeds::load::LoadError;
use intel_feeds::retro::{
    absorb, body_failure, gap_of, parse_scalar, refusal, retro_run, statements, time_of, validate_retro, window_epochs, Collected, Direction, Gap,
    MatchGroup, RetroError, RetroReply, RetroRequest, RetroRun, RetroSettings,
};
use serde_json::json;
use siem_ingest::error::InsertClass;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::{self, Cursor, Read};
use std::time::Duration;
use time::macros::{date, datetime};
use time::{Date, OffsetDateTime};
use types::TestResult;
use ureq::http::StatusCode;


const START: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const END: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const START_EPOCH: u32 = 1_793_664_000;


const END_EPOCH: u32 = 1_793_707_200;


const TIMEOUT_MS: u64 = 5_000;


const THREE: usize = 3;


const FOUR: usize = 4;


const FIVE: usize = 5;


const RESULT_ROWS_OF_A_COUNT: &str = "1";


const MATCH_FIELDS: usize = 10;


const DICTIONARY_PORT: u16 = 9440;


const EXEC_SECONDS: u32 = 30;


const READ_ROWS: u64 = 1_000_000;


const GROUP_ROWS: u64 = 10_000;


const MATCH_COUNT: u32 = 2;


const LAST_OFFSET: u32 = 60;


const PAIR: usize = 2;


const NOT_AN_IP: u64 = 7;


const LONG_LINE: usize = 20_000;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const SCALAR_VALUE: u64 = 42;


const LONG_SCALAR: usize = 100;


const WIDE_HOST: usize = 15_000;


const WIDE_ROWS: usize = 300;


const CODE_TIMEOUT: u32 = 159;


const CODE_TOO_SLOW: u32 = 160;


const CODE_ROWS: u32 = 158;


const CODE_RESULT: u32 = 396;


const CODE_BAD_ARGUMENTS: u32 = 36;


const STEP_MS: u64 = 1_000;


const FIRST_LEFT_MS: u64 = 4_000;


const SECOND_LEFT_MS: u64 = 3_000;


const THIRD_LEFT_MS: u64 = 2_000;


const HOST_CHARS: usize = 256;


const LAST_TIME: OffsetDateTime = datetime!(2026-11-03 00:01:00 UTC);


const DAY: Date = date!(2026 - 11 - 03);


const GAP_FROM: OffsetDateTime = datetime!(2026-11-02 20:00:00 UTC);


const BEFORE_EPOCH: OffsetDateTime = datetime!(1969-12-31 00:00:00 UTC);


const AFTER_U32: OffsetDateTime = datetime!(2200-01-01 00:00:00 UTC);


struct Failing(io::ErrorKind);


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.0))
    }
}


fn reader() -> ClickhouseConfig {
    ClickhouseConfig {
        url: "http://127.0.0.1:8123".to_owned(),
        user: "retro_reader".to_owned(),
        password_file: "/nonexistent/password".into(),
        ca_file: None,
        database: "ostyr".to_owned(),
        table: "iocs".to_owned(),
        dictionary: "ioc_trie".to_owned(),
        dictionary_user: "ostyr_dict".to_owned(),
        dictionary_port: DICTIONARY_PORT,
        timeout_ms: TIMEOUT_MS,
        tenant: "tenant-a".to_owned(),
    }
}


fn settings() -> RetroSettings {
    RetroSettings {
        reader: reader(),
        events_database: "ostyr".to_owned(),
        events_table: "events".to_owned(),
        max_matches: THREE,
        max_execution_seconds: EXEC_SECONDS,
        max_rows_to_read: READ_ROWS,
        max_rows_to_group_by: GROUP_ROWS,
    }
}


fn reply(status: StatusCode, code: Option<u32>, body: Box<dyn Read>) -> RetroReply {
    RetroReply { status, code, body }
}


fn text(body: &str) -> Result<RetroReply, InsertClass> {
    Ok(reply(StatusCode::OK, None, Box::new(Cursor::new(body.as_bytes().to_vec()))))
}


fn failing(code: u32, status: StatusCode) -> Result<RetroReply, InsertClass> {
    Ok(reply(status, Some(code), Box::new(Cursor::new(b"Code: not read".to_vec()))))
}


fn row_json(indicator: &str, ip: &str, host: &str, foreign: u8, first: u32) -> String {
    json!({
        "indicator": indicator,
        "matched_ip": ip,
        "direction": "source",
        "host": host,
        "host_was_cut": 0,
        "event_day": "2026-11-03",
        "foreign": foreign,
        "matches": MATCH_COUNT,
        "first_time": first,
        "last_time": first + LAST_OFFSET,
    })
    .to_string()
}


fn rows(count: usize) -> String {
    (0..count)
        .map(|index| {
            format!(
                "{}\n",
                row_json("203.0.113.0/24", &format!("2001:db8::{index:x}"), "web-1", 0, START_EPOCH + index as u32)
            )
        })
        .collect()
}


fn run_with(
    settings: &RetroSettings,
    start: OffsetDateTime,
    end: OffsetDateTime,
    previous_end: Option<OffsetDateTime>,
    script: Vec<Result<RetroReply, InsertClass>>,
) -> (Result<RetroRun, RetroError>, Vec<RetroRequest>) {
    let replies = RefCell::new(VecDeque::from(script));
    let seen = RefCell::new(Vec::new());
    let result = retro_run(settings, start, end, previous_end, &|| Duration::ZERO, &|request| {
        seen.borrow_mut().push(request.clone());
        replies.borrow_mut().pop_front().unwrap_or(Err(InsertClass::Rejected))
    });
    (result, seen.into_inner())
}


fn run_ok(script: Vec<Result<RetroReply, InsertClass>>) -> (Result<RetroRun, RetroError>, Vec<RetroRequest>) {
    run_with(&settings(), START, END, None, script)
}


fn three_replies(not_an_ip: &str, body: &str) -> Vec<Result<RetroReply, InsertClass>> {
    vec![text("0\n"), text(not_an_ip), text(body)]
}


fn error_of(script: Vec<Result<RetroReply, InsertClass>>) -> Result<RetroError, Box<dyn std::error::Error>> {
    run_ok(script).0.err().ok_or_else(|| "the run succeeded".into())
}


#[test]
fn the_statements_are_exact_and_carry_no_tenant_or_time_text() -> TestResult {
    let found = statements(&settings())?;
    let window =
        "`tenant` = {tenant:String} AND `@timestamp` >= toDateTime({start:UInt32}, 'UTC') AND `@timestamp` < toDateTime({end:UInt32}, 'UTC')";
    assert_eq!(
        found.foreign,
        "SELECT count() FROM (SELECT 1 FROM `ostyr`.`iocs` WHERE `tenant` != {tenant:String} AND `checked` = 1 LIMIT 1) FORMAT TabSeparated"
    );
    assert_eq!(
        found.not_an_ip,
        format!(
            "SELECT countIf(`source.ip` != '' AND isNull(toIPv6OrNull(`source.ip`))) + \
             countIf(`destination.ip` != '' AND isNull(toIPv6OrNull(`destination.ip`))) \
             FROM `ostyr`.`events` WHERE {window} FORMAT TabSeparated"
        )
    );
    let direction = |name: &str, column: &str| {
        format!(
            "SELECT '{name}' AS `direction`, assumeNotNull(toIPv6OrNull(`{column}`)) AS `key`, `host.name` AS `event_host`, `@timestamp` AS `ts` \
             FROM `ostyr`.`events` WHERE {window} AND isNotNull(toIPv6OrNull(`{column}`))"
        )
    };
    assert_eq!(
        found.matches,
        format!(
            "SELECT dictGet('ostyr.ioc_trie', 'indicator', `key`) AS `indicator`, IPv6NumToString(`key`) AS `matched_ip`, `direction`, \
             substringUTF8(`event_host`, 1, 256) AS `host`, toUInt8(lengthUTF8(`event_host`) > 256) AS `host_was_cut`, \
             toString(toDate(`ts`, 'UTC')) AS `event_day`, toUInt8(dictGet('ostyr.ioc_trie', 'tenant', `key`) != {{tenant:String}}) AS `foreign`, \
             toUInt32(count()) AS `matches`, toUInt32(toUnixTimestamp(min(`ts`))) AS `first_time`, toUInt32(toUnixTimestamp(max(`ts`))) AS `last_time` \
             FROM ({} UNION ALL {}) WHERE dictHas('ostyr.ioc_trie', `key`) \
             GROUP BY `indicator`, `matched_ip`, `direction`, `host`, `host_was_cut`, `event_day`, `foreign` \
             ORDER BY `foreign` DESC, `first_time`, `indicator`, `matched_ip`, `direction`, `host` LIMIT {{limit:UInt64}} FORMAT JSONEachRow",
            direction("source", "source.ip"),
            direction("destination", "destination.ip")
        )
    );
    [&found.foreign, &found.not_an_ip, &found.matches].iter().for_each(|statement| {
        assert!(!statement.contains("tenant-a"));
        assert!(!statement.contains("OrDefault"));
        assert!(!statement.contains("toIPv6(`"));
        assert!(!statement.contains("now()"));
    });
    Ok(())
}


#[test]
fn the_requests_carry_the_parameters_and_every_setting_with_throw_overflow_modes() -> TestResult {
    let (result, seen) = run_ok(three_replies(&format!("{NOT_AN_IP}\n"), &rows(PAIR)));
    let run = result?;
    assert_eq!(run.summary.not_an_ip, NOT_AN_IP);
    assert_eq!(seen.len(), THREE);
    let tenant = ("tenant", "tenant-a".to_owned());
    let window = [tenant.clone(), ("start", START_EPOCH.to_string()), ("end", END_EPOCH.to_string())];
    assert_eq!(seen.first().map(|request| request.params.clone()), Some(vec![tenant.clone()]));
    assert_eq!(seen.get(1).map(|request| request.params.clone()), Some(window.to_vec()));
    let match_params = seen.get(PAIR).map(|request| request.params.clone());
    let mut with_limit = window.to_vec();
    with_limit.push(("limit", "4".to_owned()));
    assert_eq!(match_params, Some(with_limit));
    let match_settings = seen.get(PAIR).map(|request| request.settings.clone()).ok_or("no match request")?;
    assert_eq!(
        match_settings,
        vec![
            ("readonly", "1".to_owned()),
            ("max_execution_time", "30".to_owned()),
            ("timeout_overflow_mode", "throw".to_owned()),
            ("max_rows_to_read", "1000000".to_owned()),
            ("read_overflow_mode", "throw".to_owned()),
            ("max_rows_to_group_by", "10000".to_owned()),
            ("group_by_overflow_mode", "throw".to_owned()),
            ("max_result_rows", "4".to_owned()),
            ("result_overflow_mode", "throw".to_owned()),
            ("http_write_exception_in_output_format", "0".to_owned()),
        ]
    );
    assert_eq!(match_settings.len(), MATCH_FIELDS);
    seen.iter().for_each(|request| {
        assert!(request
            .settings
            .iter()
            .all(|(name, value)| !name.contains("break") && !value.contains("break")));
        assert!(request
            .settings
            .iter()
            .filter(|(name, _)| name.ends_with("_mode"))
            .all(|(_, value)| value == "throw"));
        assert_eq!(request.remaining, Duration::from_millis(TIMEOUT_MS));
    });
    let scalar_rows = seen
        .first()
        .and_then(|request| request.settings.iter().find(|(name, _)| *name == "max_result_rows"))
        .map(|(_, value)| value.as_str());
    assert_eq!(scalar_rows, Some(RESULT_ROWS_OF_A_COUNT));
    Ok(())
}


#[test]
fn matches_become_groups_with_the_summary() -> TestResult {
    let body = format!(
        "{}\n{}\n",
        row_json("203.0.113.0/24", "::ffff:203.0.113.9", "web-1", 0, START_EPOCH),
        row_json("2001:db8::/32", "2001:db8::1", "", 0, END_EPOCH)
    );
    let (result, _) = run_ok(three_replies("0\n", &body));
    let run = result?;
    assert_eq!(
        run.groups.first(),
        Some(&MatchGroup {
            tenant: "tenant-a".to_owned(),
            indicator: "203.0.113.0/24".to_owned(),
            matched_ip: "::ffff:203.0.113.9".to_owned(),
            direction: Direction::Source,
            host: "web-1".to_owned(),
            host_cut: false,
            event_day: DAY,
            matches: MATCH_COUNT,
            first_time: START,
            last_time: LAST_TIME,
        })
    );
    assert_eq!(run.groups.len(), PAIR);
    assert_eq!(run.summary.groups, PAIR);
    assert_eq!(run.summary.more_than, None);
    assert!(!run.summary.truncated);
    assert_eq!(run.summary.tenant, "tenant-a");
    assert_eq!((run.summary.window_start, run.summary.window_end), (START, END));
    assert_eq!(run.summary.gap, None);
    Ok(())
}


#[test]
fn more_groups_than_max_matches_is_truncated_and_named_with_the_group_count() -> TestResult {
    let (result, _) = run_ok(three_replies("0\n", &rows(FOUR)));
    let run = result?;
    assert!(run.summary.truncated);
    assert_eq!(run.summary.groups, THREE);
    assert_eq!(run.summary.more_than, Some(THREE));
    assert_eq!(run.groups.len(), THREE);
    let exact = run_ok(three_replies("0\n", &rows(THREE))).0?;
    assert!(!exact.summary.truncated);
    Ok(())
}


#[test]
fn a_reply_with_more_rows_than_the_limit_is_an_error() -> TestResult {
    let found = error_of(three_replies("0\n", &rows(FIVE)))?;
    assert!(matches!(found, RetroError::TooManyRows(FOUR)));
    Ok(())
}


#[test]
fn a_foreign_row_in_the_match_reply_is_a_foreign_dictionary_error() -> TestResult {
    let body = format!(
        "{}\n{}\n",
        row_json("a", "::1", "h", 0, START_EPOCH),
        row_json("b", "::2", "h", 1, START_EPOCH)
    );
    assert!(matches!(error_of(three_replies("0\n", &body))?, RetroError::ForeignDictionary));
    Ok(())
}


#[test]
fn a_foreign_row_in_the_source_table_stops_the_run_before_any_event_query() -> TestResult {
    let (result, seen) = run_ok(vec![text("1\n"), text("0\n"), text(&rows(1))]);
    assert!(matches!(result, Err(RetroError::ForeignDictionary)));
    assert_eq!(seen.len(), 1);
    Ok(())
}


#[test]
fn any_line_that_does_not_parse_is_a_malformed_reply_and_nothing_is_returned() -> TestResult {
    let long = format!("{}\n", "x".repeat(LONG_LINE));
    let good = rows(1);
    let bad_day = row_json("a", "::1", "h", 0, START_EPOCH).replace("2026-11-03", "yesterday");
    let bad_ip = row_json("a", "not an ip", "h", 0, START_EPOCH);
    let bad_direction = row_json("a", "::1", "h", 0, START_EPOCH).replace("source", "sideways");
    let exception = "{\"exception\": \"Code: 159. DB::Exception: Timeout exceeded\"}\n";
    let mut not_utf8 = NOT_UTF8.to_vec();
    not_utf8.push(b'\n');
    let bodies: Vec<Vec<u8>> = vec![
        format!("garbage\n{good}").into_bytes(),
        format!("{good}{long}").into_bytes(),
        format!("{bad_day}\n").into_bytes(),
        format!("{bad_ip}\n").into_bytes(),
        format!("{bad_direction}\n").into_bytes(),
        not_utf8,
        format!("{good}{exception}").into_bytes(),
    ];
    bodies.into_iter().try_for_each(|body| -> TestResult {
        let script = vec![text("0\n"), text("0\n"), Ok(reply(StatusCode::OK, None, Box::new(Cursor::new(body))))];
        let (result, _) = run_with(
            &RetroSettings {
                max_matches: MAX_RETRO_MATCHES,
                ..settings()
            },
            START,
            END,
            None,
            script,
        );
        assert!(matches!(result, Err(RetroError::MalformedReply)));
        Ok(())
    })
}


#[test]
fn a_row_collector_counts_rows_and_foreign() -> TestResult {
    let next = absorb(Collected::default(), Ok(row_json("a", "::1", "h", 1, START_EPOCH)), "tenant-a")?;
    assert!(next.foreign);
    assert_eq!((next.rows, next.groups.len()), (1, 1));
    let after = absorb(next, Ok(row_json("b", "::2", "h", 0, START_EPOCH)), "tenant-a")?;
    assert!(after.foreign);
    assert_eq!((after.rows, after.groups.len()), (PAIR, PAIR));
    Ok(())
}


#[test]
fn the_count_replies_are_parsed_strictly() -> TestResult {
    assert_eq!(parse_scalar(b"42\n")?, SCALAR_VALUE);
    assert_eq!(parse_scalar(b"0")?, 0);
    [&b""[..], b"\n", b"x", b"-1", b"1 2", &NOT_UTF8, b"99999999999999999999999"]
        .iter()
        .for_each(|bytes| assert!(matches!(parse_scalar(bytes), Err(RetroError::Malformed))));
    let long = Ok(reply(StatusCode::OK, None, Box::new(Cursor::new(vec![b'1'; LONG_SCALAR]))));
    assert!(matches!(error_of(vec![long])?, RetroError::Malformed));
    assert!(matches!(error_of(vec![text("abc")])?, RetroError::Malformed));
    assert!(matches!(error_of(vec![text("0\n"), text("")])?, RetroError::Malformed));
    Ok(())
}


#[test]
fn a_body_that_fails_maps_to_a_fixed_variant() -> TestResult {
    let scalar = Ok(reply(StatusCode::OK, None, Box::new(Failing(io::ErrorKind::ConnectionReset))));
    assert!(matches!(error_of(vec![scalar])?, RetroError::Body(io::ErrorKind::ConnectionReset)));
    let timed = Ok(reply(StatusCode::OK, None, Box::new(Failing(io::ErrorKind::TimedOut))));
    assert!(matches!(error_of(vec![text("0\n"), text("0\n"), timed])?, RetroError::Timeout));
    assert!(matches!(
        body_failure(&io::Error::other("secret text")),
        RetroError::Body(io::ErrorKind::Other)
    ));
    Ok(())
}


#[test]
fn a_reply_over_the_byte_cap_is_an_error() -> TestResult {
    let line = format!("{}\n", row_json("a", "::1", &"x".repeat(WIDE_HOST), 0, START_EPOCH));
    let body = line.repeat(WIDE_ROWS).into_bytes();
    assert!(body.len() as u64 > MAX_RETRO_BYTES);
    let huge = Ok(reply(StatusCode::OK, None, Box::new(Cursor::new(body))));
    let wide = RetroSettings {
        max_matches: MAX_RETRO_MATCHES,
        ..settings()
    };
    let script = vec![text("0\n"), text("0\n"), huge];
    let (result, _) = run_with(&wide, START, END, None, script);
    assert!(matches!(result, Err(RetroError::TooManyBytes(MAX_RETRO_BYTES))));
    Ok(())
}


#[test]
fn exception_codes_map_to_fixed_errors_and_the_text_is_never_read() -> TestResult {
    let cases = [
        (CODE_TIMEOUT, StatusCode::INTERNAL_SERVER_ERROR, "timeout"),
        (CODE_TOO_SLOW, StatusCode::INTERNAL_SERVER_ERROR, "timeout"),
        (CODE_ROWS, StatusCode::INTERNAL_SERVER_ERROR, "too_many_rows_or_groups"),
        (CODE_RESULT, StatusCode::INTERNAL_SERVER_ERROR, "too_many_rows_or_groups"),
        (CODE_BAD_ARGUMENTS, StatusCode::INTERNAL_SERVER_ERROR, "dictionary_outdated_or_bad_query"),
    ];
    cases.iter().try_for_each(|(code, status, name)| -> TestResult {
        assert_eq!(error_of(vec![failing(*code, *status)])?.to_string(), *name);
        assert_eq!(error_of(vec![text("0\n"), failing(*code, *status)])?.to_string(), *name);
        assert_eq!(error_of(vec![text("0\n"), text("0\n"), failing(*code, *status)])?.to_string(), *name);
        Ok(())
    })?;
    assert!(matches!(
        error_of(vec![failing(1, StatusCode::INTERNAL_SERVER_ERROR)])?,
        RetroError::Refused(InsertClass::Unavailable)
    ));
    assert!(matches!(
        error_of(vec![Ok(reply(StatusCode::UNAUTHORIZED, None, Box::new(Cursor::new(Vec::new()))))])?,
        RetroError::Refused(InsertClass::Unauthorized)
    ));
    assert!(refusal(StatusCode::OK, Some(CODE_TIMEOUT)).is_none());
    assert!(matches!(
        error_of(vec![Err(InsertClass::Timeout)])?,
        RetroError::Refused(InsertClass::Timeout)
    ));
    Ok(())
}


#[test]
fn a_spent_deadline_sends_nothing_and_each_request_gets_what_is_left() -> TestResult {
    let sent = Cell::new(0);
    let spent = retro_run(&settings(), START, END, None, &|| Duration::from_millis(TIMEOUT_MS), &|_| {
        sent.set(sent.get() + 1);
        Err(InsertClass::Rejected)
    });
    assert!(matches!(spent, Err(RetroError::Timeout)));
    assert_eq!(sent.get(), 0);
    let calls = Cell::new(0);
    let remaining = RefCell::new(Vec::new());
    let replies = RefCell::new(VecDeque::from(three_replies("0\n", "")));
    let later = retro_run(
        &settings(),
        START,
        END,
        None,
        &|| {
            calls.set(calls.get() + 1);
            Duration::from_millis(calls.get() * STEP_MS)
        },
        &|request| {
            remaining.borrow_mut().push(request.remaining);
            replies.borrow_mut().pop_front().unwrap_or(Err(InsertClass::Rejected))
        },
    );
    assert!(later.is_ok());
    assert_eq!(
        remaining.into_inner(),
        vec![
            Duration::from_millis(FIRST_LEFT_MS),
            Duration::from_millis(SECOND_LEFT_MS),
            Duration::from_millis(THIRD_LEFT_MS)
        ]
    );
    let exhausted = Cell::new(0);
    let sent_before_exhaustion = Cell::new(0);
    let result = retro_run(
        &settings(),
        START,
        END,
        None,
        &|| {
            exhausted.set(exhausted.get() + 1);
            Duration::from_millis(if exhausted.get() > 1 { TIMEOUT_MS } else { 0 })
        },
        &|_| {
            sent_before_exhaustion.set(sent_before_exhaustion.get() + 1);
            text("0\n")
        },
    );
    assert!(matches!(result, Err(RetroError::Timeout)));
    assert_eq!(sent_before_exhaustion.get(), 1);
    Ok(())
}


#[test]
fn a_bad_window_is_refused_before_any_request() -> TestResult {
    [
        (END, START),
        (START, START),
        (BEFORE_EPOCH, START),
        (START, AFTER_U32),
        (AFTER_U32, AFTER_U32),
    ]
    .iter()
    .try_for_each(|(start, end)| -> TestResult {
        let (result, seen) = run_with(&settings(), *start, *end, None, three_replies("0\n", ""));
        assert!(matches!(result, Err(RetroError::Window)));
        assert!(seen.is_empty());
        Ok(())
    })?;
    assert_eq!(window_epochs(START, END)?, (START_EPOCH, END_EPOCH));
    Ok(())
}


#[test]
fn settings_out_of_range_are_refused_before_any_request() -> TestResult {
    let base = settings();
    let cases = [
        (
            RetroSettings {
                max_matches: 0,
                ..base.clone()
            },
            "max_matches",
        ),
        (
            RetroSettings {
                max_matches: MAX_RETRO_MATCHES + 1,
                ..base.clone()
            },
            "max_matches",
        ),
        (
            RetroSettings {
                max_execution_seconds: 0,
                ..base.clone()
            },
            "max_execution_seconds",
        ),
        (
            RetroSettings {
                max_execution_seconds: MAX_RETRO_SECONDS + 1,
                ..base.clone()
            },
            "max_execution_seconds",
        ),
        (
            RetroSettings {
                max_rows_to_read: 0,
                ..base.clone()
            },
            "max_rows_to_read",
        ),
        (
            RetroSettings {
                max_rows_to_read: MAX_RETRO_ROWS_TO_READ + 1,
                ..base.clone()
            },
            "max_rows_to_read",
        ),
        (
            RetroSettings {
                max_rows_to_group_by: 0,
                ..base.clone()
            },
            "max_rows_to_group_by",
        ),
        (
            RetroSettings {
                max_rows_to_group_by: MAX_RETRO_ROWS_TO_GROUP + 1,
                ..base.clone()
            },
            "max_rows_to_group_by",
        ),
    ];
    cases.iter().try_for_each(|(case, name)| -> TestResult {
        let (result, seen) = run_with(case, START, END, None, three_replies("0\n", ""));
        assert!(matches!(result, Err(RetroError::Settings(found)) if found == *name));
        assert!(seen.is_empty());
        Ok(())
    })?;
    let edge = RetroSettings {
        max_matches: MAX_RETRO_MATCHES,
        max_execution_seconds: MAX_RETRO_SECONDS,
        max_rows_to_read: MAX_RETRO_ROWS_TO_READ,
        max_rows_to_group_by: MAX_RETRO_ROWS_TO_GROUP,
        ..base
    };
    validate_retro(&edge)?;
    Ok(())
}


#[test]
fn a_bad_tenant_or_identifier_is_refused_before_any_request() -> TestResult {
    let bad_tenant = RetroSettings {
        reader: ClickhouseConfig {
            tenant: "-x".to_owned(),
            ..reader()
        },
        ..settings()
    };
    let (result, seen) = run_with(&bad_tenant, START, END, None, Vec::new());
    assert!(matches!(result, Err(RetroError::Setup(LoadError::Settings(ClickhouseError::Tenant(_))))));
    assert!(seen.is_empty());
    let bad_events = RetroSettings {
        events_database: "ev`il".to_owned(),
        ..settings()
    };
    assert!(matches!(validate_retro(&bad_events), Err(RetroError::Statement(_))));
    let bad_table = RetroSettings {
        events_table: "1x".to_owned(),
        ..settings()
    };
    assert!(matches!(validate_retro(&bad_table), Err(RetroError::Statement(_))));
    let bad_dictionary = RetroSettings {
        reader: ClickhouseConfig {
            dictionary: "d`x".to_owned(),
            ..reader()
        },
        ..settings()
    };
    assert!(statements(&bad_dictionary).is_err());
    let bad_source = RetroSettings {
        reader: ClickhouseConfig {
            table: "t`x".to_owned(),
            ..reader()
        },
        ..settings()
    };
    assert!(statements(&bad_source).is_err());
    let bad_events_database = RetroSettings {
        events_database: "d`x".to_owned(),
        ..settings()
    };
    assert!(statements(&bad_events_database).is_err());
    Ok(())
}


#[test]
fn the_gap_names_the_uncovered_span_only() -> TestResult {
    let before = GAP_FROM;
    assert_eq!(gap_of(Some(before), START), Some(Gap { from: before, to: START }));
    assert_eq!(gap_of(Some(START), START), None);
    assert_eq!(gap_of(Some(END), START), None);
    assert_eq!(gap_of(None, START), None);
    let (result, _) = run_with(&settings(), START, END, Some(before), three_replies("0\n", ""));
    assert_eq!(result?.summary.gap, Some(Gap { from: before, to: START }));
    assert_eq!(time_of(START_EPOCH), START);
    Ok(())
}


#[test]
fn the_default_ceiling_keeps_499_groups_and_names_a_500th() -> TestResult {
    let wide = RetroSettings {
        max_matches: MAX_RETRO_MATCHES,
        ..settings()
    };
    let full = run_with(&wide, START, END, None, three_replies("0\n", &rows(MAX_RETRO_MATCHES))).0?;
    assert_eq!(
        (full.summary.groups, full.summary.more_than, full.summary.truncated),
        (MAX_RETRO_MATCHES, None, false)
    );
    let over = run_with(&wide, START, END, None, three_replies("0\n", &rows(MAX_RETRO_MATCHES + 1))).0?;
    assert_eq!(
        (over.summary.groups, over.summary.more_than, over.summary.truncated),
        (MAX_RETRO_MATCHES, Some(MAX_RETRO_MATCHES), true)
    );
    Ok(())
}


#[test]
fn a_host_with_a_nul_or_a_long_text_is_kept_as_the_server_gave_it() -> TestResult {
    let nul = row_json("a", "::1", "x\u{0}y", 0, START_EPOCH);
    let run = run_ok(three_replies("0\n", &format!("{nul}\n"))).0?;
    assert_eq!(run.groups.first().map(|group| group.host.as_str()), Some("x\u{0}y"));
    let long = row_json("a", "::1", &"h".repeat(HOST_CHARS), 0, START_EPOCH);
    let cut = run_ok(three_replies("0\n", &format!("{long}\n"))).0?;
    assert_eq!(cut.groups.first().map(|group| group.host.chars().count()), Some(HOST_CHARS));
    Ok(())
}
