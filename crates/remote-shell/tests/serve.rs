mod common;


use common::types::TestResult;
use core_pg::scope::{tenant_scope, TenantScope};
use remote_shell::error::StoreError;
use remote_shell::grammar::{valid_reference, valid_subject};
use remote_shell::serve::{get_session, list_page, parse_cursor, raw_cursor, serve_row, writable_time, MAX_CURSOR_BYTES};
use remote_shell::store::{LIST_AFTER_SQL, LIST_SQL, MAX_PAGE, MIGRATIONS, SESSION_SQL};
use remote_shell::store_model::{Cell, ListFilter, Param, Statement};
use remote_shell::types::Row;
use std::cell::RefCell;
use std::future::{ready, Ready};
use std::rc::Rc;


const OPENED: i64 = 1_800_000_000;


const CLOSED: i64 = 1_800_000_600;


const YEAR_10000: i64 = 253_402_300_800;


const LAST_YEAR_9999: i64 = 253_402_300_799;


const YEAR_ZERO: i64 = -62_167_219_200;


const BEFORE_YEAR_ZERO: i64 = -62_167_219_201;


const HASH_BYTES: usize = 32;


const SHORT_HASH: usize = 31;


const FRAMES: i64 = 3;


const TWO_ROWS: u32 = 2;


const THREE_ROWS: u32 = 3;


const IDX_LIMIT_PARAM: usize = 3;


const IDX_CURSOR_AT: usize = 4;


const IDX_CURSOR_ID: usize = 5;


const FOURTH: usize = 3;


const FOUR: usize = 4;


const TWO: usize = 2;


const CURSOR_CAP: usize = 149;


const HASH_FILL: u8 = 7;


const OVER_REFERENCE: usize = 129;


const MAX_REFERENCE: usize = 128;


const MAX_SUBJECT: usize = 255;


const OVER_SUBJECT: usize = 256;


const NEGATIVE_FIVE: i64 = -5;


const IDX_SESSION: usize = 0;


const IDX_REQUESTER: usize = 1;


const IDX_ASSET: usize = 2;


const IDX_TICKET: usize = 3;


const IDX_OPENED: usize = 4;


const IDX_CLOSED: usize = 5;


const IDX_REASON: usize = 6;


const IDX_FRAMES: usize = 7;


const IDX_HASH: usize = 8;


const IDX_BYTES: usize = 9;


const MARKER_REQUESTER: &str = "ev\u{1b}il\u{202e}MARK";


const MARKER_TICKET: &str = "T-1\nMARK";


fn open_row(session: &str, opened_at: i64) -> Row {
    vec![
        Cell::Text(session.to_owned()),
        Cell::Text("alice".to_owned()),
        Cell::Text("host-7".to_owned()),
        Cell::Text("INC-1".to_owned()),
        Cell::Int(opened_at),
        Cell::Null,
        Cell::Null,
        Cell::Null,
        Cell::Null,
        Cell::Null,
    ]
}


fn closed_row(session: &str) -> Row {
    let mut row = open_row(session, OPENED);
    set(&mut row, IDX_CLOSED, Cell::Int(CLOSED));
    set(&mut row, IDX_REASON, Cell::Text("user_close".to_owned()));
    set(&mut row, IDX_FRAMES, Cell::Int(FRAMES));
    set(&mut row, IDX_HASH, Cell::Bytes(vec![HASH_FILL; HASH_BYTES]));
    set(&mut row, IDX_BYTES, Cell::Int(0));
    row
}


fn set(row: &mut Row, index: usize, value: Cell) {
    if let Some(slot) = row.get_mut(index) {
        *slot = value;
    }
}


fn with(mut row: Row, index: usize, value: Cell) -> Row {
    set(&mut row, index, value);
    row
}


fn text(value: &str) -> Cell {
    Cell::Text(value.to_owned())
}


fn scope() -> Result<TenantScope, Box<dyn std::error::Error>> {
    Ok(tenant_scope("acme")?)
}


fn canned(rows: Vec<Row>, log: &Rc<RefCell<Vec<Statement>>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Rc::clone(log);
    move |_scope: &TenantScope, statement: Statement| {
        shared.borrow_mut().push(statement);
        ready(Ok(rows.clone()))
    }
}


fn failing(_scope: &TenantScope, _statement: Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    ready(Err(StoreError::BadRow { column: "executor" }))
}


fn new_log() -> Rc<RefCell<Vec<Statement>>> {
    Rc::new(RefCell::new(Vec::new()))
}


fn field_of(error: Option<StoreError>) -> Option<&'static str> {
    match error {
        Some(StoreError::StoredValue { field }) => Some(field),
        _ => None,
    }
}


#[test]
fn a_good_open_and_a_good_closed_row_are_served() -> TestResult {
    assert_eq!(serve_row(&open_row("s-1", OPENED))?.session_id, "s-1");
    let closed = serve_row(&closed_row("s-2"))?;
    assert_eq!(closed.close_reason.as_deref(), Some("user_close"));
    assert_eq!(closed.recording_frames, Some(FRAMES));
    let closed_without_recording = with(
        with(open_row("s-3", OPENED), IDX_CLOSED, Cell::Int(OPENED)),
        IDX_REASON,
        text("clock_skew"),
    );
    assert!(serve_row(&closed_without_recording).is_ok());
    Ok(())
}


#[test]
fn each_unservable_row_names_only_its_field() -> TestResult {
    let long_reference = "a".repeat(OVER_REFERENCE);
    let cases: Vec<(Row, &str)> = vec![
        (with(open_row("s-1", OPENED), IDX_SESSION, text("-x")), "session_id"),
        (with(open_row("s-1", OPENED), IDX_SESSION, text(&long_reference)), "session_id"),
        (with(open_row("s-1", OPENED), IDX_REQUESTER, text(MARKER_REQUESTER)), "requester"),
        (with(open_row("s-1", OPENED), IDX_REQUESTER, text("alice\u{3164}")), "requester"),
        (with(open_row("s-1", OPENED), IDX_ASSET, text("host 7")), "asset"),
        (with(open_row("s-1", OPENED), IDX_TICKET, text(MARKER_TICKET)), "ticket"),
        (with(closed_row("s-1"), IDX_REASON, text("bogus")), "close_reason"),
        (with(open_row("s-1", OPENED), IDX_REASON, text("user_close")), "close_reason"),
        (with(closed_row("s-1"), IDX_REASON, Cell::Null), "close_reason"),
        (with(closed_row("s-1"), IDX_FRAMES, Cell::Null), "recording_hash"),
        (with(closed_row("s-1"), IDX_HASH, Cell::Null), "recording_hash"),
        (with(closed_row("s-1"), IDX_BYTES, Cell::Null), "recording_bytes"),
        (
            with(closed_row("s-1"), IDX_HASH, Cell::Bytes(vec![HASH_FILL; SHORT_HASH])),
            "recording_hash",
        ),
        (with(closed_row("s-1"), IDX_FRAMES, Cell::Int(1)), "recording_frames"),
        (with(closed_row("s-1"), IDX_BYTES, Cell::Int(-1)), "recording_bytes"),
        (with(closed_row("s-1"), IDX_CLOSED, Cell::Int(OPENED - 1)), "closed_at"),
        (with(open_row("s-1", YEAR_10000), IDX_OPENED, Cell::Int(YEAR_10000)), "opened_at"),
        (
            with(open_row("s-1", BEFORE_YEAR_ZERO), IDX_OPENED, Cell::Int(BEFORE_YEAR_ZERO)),
            "opened_at",
        ),
        (with(closed_row("s-1"), IDX_CLOSED, Cell::Int(YEAR_10000)), "closed_at"),
    ];
    let mut open_with_recording = closed_row("s-1");
    set(&mut open_with_recording, IDX_CLOSED, Cell::Null);
    set(&mut open_with_recording, IDX_REASON, Cell::Null);
    let all: Vec<(Row, &str)> = cases.into_iter().chain([(open_with_recording, "recording_hash")]).collect();
    all.iter().try_for_each(|(row, field)| -> TestResult {
        let error = serve_row(row).err();
        let shown = format!("{error:?}");
        assert_eq!(field_of(error), Some(*field), "{shown}");
        assert!(!shown.contains("MARK"));
        Ok(())
    })
}


#[test]
fn year_bounds_are_exact() -> TestResult {
    assert!(writable_time(YEAR_ZERO));
    assert!(writable_time(LAST_YEAR_9999));
    assert!(!writable_time(YEAR_10000));
    assert!(!writable_time(BEFORE_YEAR_ZERO));
    assert!(!writable_time(i64::MAX));
    Ok(())
}


#[test]
fn a_row_of_the_wrong_shape_is_a_bad_row() -> TestResult {
    assert!(matches!(serve_row(&vec![Cell::Int(1)]), Err(StoreError::BadRow { .. })));
    Ok(())
}


#[tokio::test]
async fn a_lookup_names_absent_present_and_unservable() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    assert_eq!(get_session(&mut canned(Vec::new(), &log), &scope, "s-1").await?, None);
    let found = get_session(&mut canned(vec![open_row("s-1", OPENED)], &log), &scope, "s-1").await?;
    assert_eq!(found.map(|row| row.session_id), Some("s-1".to_owned()));
    let hostile = with(open_row("s-1", OPENED), IDX_REQUESTER, text(MARKER_REQUESTER));
    let refused = get_session(&mut canned(vec![hostile], &log), &scope, "s-1").await;
    assert_eq!(field_of(refused.err()), Some("requester"));
    let late = get_session(&mut canned(vec![open_row("s-1", YEAR_10000)], &log), &scope, "s-1").await;
    assert_eq!(field_of(late.err()), Some("opened_at"));
    let statements = log.borrow();
    assert!(statements.iter().all(|statement| statement.sql == SESSION_SQL));
    assert!(SESSION_SQL.contains("tenant = $1 AND session_id = $2"));
    assert_eq!(
        statements.first().map(|statement| statement.params.clone()),
        Some(vec![Param::Text("s-1".to_owned())])
    );
    Ok(())
}


#[tokio::test]
async fn a_lookup_refuses_a_bad_id_before_any_statement_and_passes_executor_errors() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let refused = get_session(&mut canned(vec![open_row("s-1", OPENED)], &log), &scope, "-s").await;
    assert!(matches!(refused, Err(StoreError::Invalid { field: "session_id" })));
    assert!(log.borrow().is_empty());
    assert!(matches!(
        get_session(&mut failing, &scope, "s-1").await,
        Err(StoreError::BadRow { column: "executor" })
    ));
    Ok(())
}


#[tokio::test]
async fn a_page_serves_skips_and_counts() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let hostile = with(
        with(open_row("s-2", OPENED), IDX_REQUESTER, text(MARKER_REQUESTER)),
        IDX_TICKET,
        text(MARKER_TICKET),
    );
    let rows = vec![open_row("s-3", OPENED), vec![Cell::Int(1)], hostile, open_row("s-0", YEAR_10000)];
    let page = list_page(&mut canned(rows, &log), &scope, &ListFilter::default(), None, THREE_ROWS).await?;
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.skipped, TWO);
    assert_eq!(page.next_cursor, Some(format!("{OPENED}.s-2")));
    Ok(())
}


#[tokio::test]
async fn the_cursor_is_the_last_row_read_even_when_skipped() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let hostile = with(open_row("s-2", OPENED), IDX_REQUESTER, text(MARKER_REQUESTER));
    let rows = vec![open_row("s-3", OPENED), hostile, open_row("s-1", OPENED)];
    let page = list_page(&mut canned(rows, &log), &scope, &ListFilter::default(), None, TWO_ROWS).await?;
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.skipped, 1);
    assert_eq!(page.next_cursor, Some(format!("{OPENED}.s-2")));
    let statement = log.borrow().first().cloned().ok_or("no statement")?;
    assert_eq!(statement.sql, LIST_SQL);
    assert_eq!(statement.params.get(IDX_LIMIT_PARAM), Some(&Param::Int(i64::from(THREE_ROWS))));
    Ok(())
}


#[tokio::test]
async fn a_year_10000_row_is_skipped_and_the_walk_continues() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let rows = vec![open_row("s-2", YEAR_10000), open_row("s-1", OPENED)];
    let page = list_page(&mut canned(rows, &log), &scope, &ListFilter::default(), None, 1).await?;
    assert_eq!((page.rows.len(), page.skipped), (0, 1));
    assert_eq!(page.next_cursor, Some(format!("{YEAR_10000}.s-2")));
    let next = list_page(
        &mut canned(Vec::new(), &log),
        &scope,
        &ListFilter::default(),
        page.next_cursor.as_deref(),
        1,
    )
    .await?;
    assert_eq!(next.next_cursor, None);
    let statement = log.borrow().last().cloned().ok_or("no statement")?;
    assert_eq!(statement.sql, LIST_AFTER_SQL);
    assert_eq!(statement.params.get(IDX_CURSOR_AT), Some(&Param::Int(YEAR_10000)));
    assert_eq!(statement.params.get(IDX_CURSOR_ID), Some(&Param::Text("s-2".to_owned())));
    Ok(())
}


#[tokio::test]
async fn a_full_page_without_a_next_row_has_no_cursor() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let rows = vec![open_row("s-2", OPENED), open_row("s-1", OPENED)];
    let page = list_page(&mut canned(rows, &log), &scope, &ListFilter::default(), None, TWO_ROWS).await?;
    assert_eq!((page.rows.len(), page.skipped, page.next_cursor), (TWO, 0, None));
    Ok(())
}


#[tokio::test]
async fn a_hostile_session_id_at_the_end_of_a_page_is_an_error_and_no_cursor() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let hostile = with(open_row("s-2", OPENED), IDX_SESSION, text("bad\u{1b}MARK"));
    let rows = vec![hostile, open_row("s-1", OPENED)];
    let outcome = list_page(&mut canned(rows, &log), &scope, &ListFilter::default(), None, 1).await;
    let shown = format!("{outcome:?}");
    assert!(!shown.contains("MARK"));
    assert_eq!(field_of(outcome.err()), Some("session_id"));
    let short = vec![vec![Cell::Int(1)], open_row("s-1", OPENED)];
    let broken = list_page(&mut canned(short, &log), &scope, &ListFilter::default(), None, 1).await;
    assert!(matches!(broken, Err(StoreError::BadRow { .. })));
    Ok(())
}


#[tokio::test]
async fn the_page_refuses_bad_limits_cursors_and_filters_before_any_statement() -> TestResult {
    let scope = scope()?;
    let log = new_log();
    let rows = vec![open_row("s-2", OPENED), open_row("s-1", OPENED)];
    let none = ListFilter::default();
    assert!(matches!(
        list_page(&mut canned(rows.clone(), &log), &scope, &none, None, 0).await,
        Err(StoreError::LimitOutOfRange { .. })
    ));
    assert!(matches!(
        list_page(&mut canned(rows.clone(), &log), &scope, &none, None, MAX_PAGE + 1).await,
        Err(StoreError::LimitOutOfRange { .. })
    ));
    assert!(matches!(
        list_page(&mut canned(rows.clone(), &log), &scope, &none, Some("nope"), 1).await,
        Err(StoreError::BadCursor)
    ));
    let bad_filter = ListFilter {
        asset: Some("-x".to_owned()),
        ..ListFilter::default()
    };
    assert!(matches!(
        list_page(&mut canned(rows.clone(), &log), &scope, &bad_filter, None, 1).await,
        Err(StoreError::Invalid { .. })
    ));
    assert!(log.borrow().is_empty());
    assert!(matches!(
        list_page(&mut failing, &scope, &none, None, 1).await,
        Err(StoreError::BadRow { column: "executor" })
    ));
    let full = list_page(&mut canned(rows, &log), &scope, &none, None, MAX_PAGE).await?;
    assert_eq!(full.rows.len(), TWO);
    assert_eq!(
        log.borrow().first().and_then(|statement| statement.params.get(IDX_LIMIT_PARAM).cloned()),
        Some(Param::Int(i64::from(MAX_PAGE) + 1))
    );
    Ok(())
}


#[test]
fn the_cursor_grammar_is_strict() -> TestResult {
    let parsed = parse_cursor("-5.a.b-c")?;
    assert_eq!((parsed.opened_at, parsed.session_id.as_str()), (NEGATIVE_FIVE, "a.b-c"));
    assert_eq!(parse_cursor(&format!("{}.s-1", i64::MIN))?.opened_at, i64::MIN);
    let max_id = "a".repeat(MAX_REFERENCE);
    assert!(parse_cursor(&format!("{}.{max_id}", i64::MIN)).is_ok());
    assert_eq!(MAX_CURSOR_BYTES, CURSOR_CAP);
    let too_long = format!("{}.{}", i64::MIN, "a".repeat(OVER_REFERENCE));
    let hostile = [
        "",
        ".",
        "5",
        "5.",
        ".s-1",
        "+5.s-1",
        "05.s-1",
        "-0.s-1",
        " 5.s-1",
        "5 .s-1",
        "x.s-1",
        "5.-x",
        "5.s\n1",
        "5.s\u{3164}",
        "99999999999999999999.s-1",
        too_long.as_str(),
    ];
    hostile.iter().try_for_each(|text| -> TestResult {
        assert!(matches!(parse_cursor(text), Err(StoreError::BadCursor)), "{text:?}");
        Ok(())
    })
}


#[test]
fn a_raw_cursor_needs_its_two_columns() -> TestResult {
    assert!(matches!(raw_cursor(&vec![Cell::Null]), Err(StoreError::BadRow { .. })));
    assert!(matches!(raw_cursor(&vec![text("s-1"), Cell::Null]), Err(StoreError::BadRow { .. })));
    assert!(matches!(
        raw_cursor(&vec![text("s-1"), Cell::Null, Cell::Null, Cell::Null, Cell::Text("x".to_owned())]),
        Err(StoreError::BadRow { .. })
    ));
    Ok(())
}


fn migration_text() -> Result<&'static str, Box<dyn std::error::Error>> {
    Ok(MIGRATIONS.get(FOURTH).ok_or("no fourth migration")?.sql)
}


fn regex_of(column: &str) -> Result<regex::Regex, Box<dyn std::error::Error>> {
    let marker = format!("{column} ~ '");
    let literal = migration_text()?
        .split(&marker)
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .ok_or("no regex")?;
    Ok(regex::Regex::new(literal)?)
}


#[test]
fn the_check_regexes_match_the_rust_grammar_on_edge_inputs() -> TestResult {
    let max_reference = "a".repeat(MAX_REFERENCE);
    let over_reference = "a".repeat(OVER_REFERENCE);
    let max_subject = "a".repeat(MAX_SUBJECT);
    let over_subject = "a".repeat(OVER_SUBJECT);
    let inputs = [
        "",
        "a",
        "A9",
        "-a",
        "a-",
        "_a",
        ".a",
        "a_b.c:d/e-f",
        "a@b",
        "a+b=c|d",
        "auth0|123",
        "a b",
        "a\n",
        "\na",
        "a\u{1b}",
        "a\u{3164}",
        "\u{3164}",
        "\u{202e}",
        "é",
        "a|",
        "|a",
        "-",
        max_reference.as_str(),
        over_reference.as_str(),
        max_subject.as_str(),
        over_subject.as_str(),
    ];
    let reference = ["session_id", "asset", "ticket"];
    reference.iter().try_for_each(|column| -> TestResult {
        let pattern = regex_of(column)?;
        inputs
            .iter()
            .for_each(|input| assert_eq!(pattern.is_match(input), valid_reference(input), "{column} {input:?}"));
        Ok(())
    })?;
    let subject = regex_of("requester")?;
    inputs
        .iter()
        .for_each(|input| assert_eq!(subject.is_match(input), valid_subject(input), "requester {input:?}"));
    Ok(())
}


#[test]
fn the_fourth_migration_pins_ascii_and_the_grammars() -> TestResult {
    let sql = migration_text()?;
    ["session_id", "requester", "asset", "ticket"]
        .iter()
        .for_each(|column| assert!(sql.contains(&format!("octet_length({column}) = char_length({column})"))));
    assert_eq!(sql.matches("ADD CONSTRAINT").count(), FOUR);
    Ok(())
}
