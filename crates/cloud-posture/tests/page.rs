#[path = "common/types.rs"]
mod types;


use cloud_posture::error::StoreError;
use cloud_posture::model::{Finding, PageCursor, RunHeader, Severity, Status};
use cloud_posture::page::{
    check_cursor, check_read, cursor_text, finding_of, header_of, is_identity_hex, micros_of, next_cursor, page_of, page_params, parse_cursor,
    rank_of, read_findings, refusal_pending, served_of, COL_BAD_FIELD, COL_CHECK, COL_DETAIL, COL_DETAIL_CUT, COL_DUPLICATE, COL_FINISHED,
    COL_FOREIGN, COL_IDENTITY, COL_ITEMS, COL_PROVIDER, COL_RANK, COL_REFUSED_FAIL, COL_REFUSED_ITEMS, COL_REFUSED_MANUAL, COL_REFUSED_MICROS,
    COL_REFUSED_MUTED, COL_REFUSED_PASS, COL_REGION, COL_RESOURCE_TYPE, COL_RESOURCE_UID, COL_RUN_ID, COL_SEVERITY, COL_STATUS, COL_STORE_REFUSED,
    COL_TIME, COL_TITLE, COL_TITLE_CUT, COL_UID, COL_UNPARSABLE, CURSOR_FIELDS, MAX_CURSOR_BYTES, MAX_PAGE_LIMIT, PAGE_SQL, RANK_BEFORE_FIRST,
    ROW_COLUMNS,
};
use cloud_posture::prowler::identity_of;
use cloud_posture::store::MIGRATIONS;
use cloud_posture::text::{severity_rank, severity_text, status_text};
use cloud_posture::types::RowFuture;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use std::future::ready;
use std::sync::Mutex;
use types::TestResult;


#[derive(Clone)]
pub struct Call {
    pub tenant: String,
    pub sql: &'static str,
    pub params: Vec<String>,
}


pub struct Double {
    pub calls: Mutex<Vec<Call>>,
    pub reply: Vec<Vec<String>>,
    pub fail: bool,
}


const RUN: &str = "run1";


const FINISHED: &str = "1700000000000000";


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


const FIVE: usize = 5;


const SEVEN: i16 = 7;


const NINE: i16 = 9;


const OVER_MAX: usize = 501;


const HEX: usize = 64;


const STORED: i64 = 100;


const NEWER: i64 = STORED + 1;


const COALESCED: usize = 18;


const LATER: i64 = 1_700_000_000_000_001;


fn double(reply: Vec<Vec<String>>) -> Double {
    Double {
        calls: Mutex::new(Vec::new()),
        reply,
        fail: false,
    }
}


fn executor<'a>(fake: &'a Double) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        let answer = if fake.fail {
            Err(PgError::InvalidTenant)
        } else {
            match fake.calls.lock() {
                Ok(mut calls) => {
                    calls.push(Call {
                        tenant: tenant_of(&scope).to_owned(),
                        sql,
                        params,
                    });
                    Ok(fake.reply.clone())
                }
                Err(_poisoned) => Err(PgError::InvalidTenant),
            }
        };
        Box::pin(ready(answer))
    }
}


fn calls_of(fake: &Double) -> Result<Vec<Call>, Box<dyn std::error::Error>> {
    Ok(fake.calls.lock().map_err(|_poisoned| "poisoned")?.clone())
}


fn finding(uid: &str, severity: Severity) -> Finding {
    Finding {
        uid: uid.to_owned(),
        check_id: "check_one".to_owned(),
        status: Status::Fail,
        severity,
        provider: "aws".to_owned(),
        account: "acc".to_owned(),
        region: "eu-west-1".to_owned(),
        resource_uid: format!("res-{uid}"),
        resource_type: "AwsResource".to_owned(),
        time_unix: 1,
        title: "title".to_owned(),
        title_cut: 0,
        detail: "detail".to_owned(),
        detail_cut: 0,
    }
}


fn row_of(run: &str, finished: &str, found: Option<&Finding>) -> Vec<String> {
    let header = [run, finished, "3", "0", "0", "0", "0", "0", "0", "0", "0", "0", "", "0"];
    let finding_columns: Vec<String> = found.map_or_else(
        || vec![String::new(); ROW_COLUMNS - header.len()],
        |item| {
            vec![
                format!("{:x}", identity_of(item)),
                severity_rank(item.severity).to_string(),
                item.uid.clone(),
                item.check_id.clone(),
                status_text(item.status).to_owned(),
                severity_text(item.severity).to_owned(),
                item.provider.clone(),
                item.region.clone(),
                item.resource_uid.clone(),
                item.resource_type.clone(),
                item.time_unix.to_string(),
                item.title.clone(),
                item.title_cut.to_string(),
                item.detail.clone(),
                item.detail_cut.to_string(),
            ]
        },
    );
    header.iter().map(|text| (*text).to_owned()).chain(finding_columns).collect()
}


fn row(uid: &str, severity: Severity) -> Vec<String> {
    row_of(RUN, FINISHED, Some(&finding(uid, severity)))
}


fn with_column(mut source: Vec<String>, index: usize, value: &str) -> Vec<String> {
    source.iter_mut().skip(index).take(1).for_each(|cell| value.clone_into(cell));
    source
}


fn refused<Value: std::fmt::Debug>(result: Result<Value, StoreError>) -> Result<StoreError, Box<dyn std::error::Error>> {
    match result {
        Err(error) => Ok(error),
        Ok(value) => Err(format!("expected a refusal, got {value:?}").into()),
    }
}


fn cursor_of_row(source: &[String]) -> Result<PageCursor, Box<dyn std::error::Error>> {
    Ok(parse_cursor(&cursor_text(
        RUN,
        FINISHED.parse()?,
        source.get(COL_RANK).ok_or("no rank")?,
        source.get(COL_IDENTITY).ok_or("no identity")?,
    ))?)
}


#[test]
fn the_row_layout_matches_the_columns_of_the_statement() -> TestResult {
    let sample = row("u1", Severity::High);
    assert_eq!(sample.len(), ROW_COLUMNS);
    assert_eq!(sample.get(COL_IDENTITY).ok_or("none")?.len(), HEX);
    assert_eq!(PAGE_SQL.matches("tenant = $1").count(), 1);
    assert!(PAGE_SQL.contains("LEFT JOIN posture_page($1, $2, $3::text::integer, $4::text, $5::text::bigint) p ON true"));
    assert!(PAGE_SQL.contains("WHERE r.tenant = $1 AND r.account = $2 ORDER BY p.page_key NULLS LAST"));
    let function = MIGRATIONS.get(TWO).ok_or("no third migration")?.sql;
    assert!(function.contains(
        "WHERE f.tenant = tenant_name AND f.account = account_name AND f.page_key > (int4send(32767 - rank_value) || decode(identity_hex, 'hex'))"
    ));
    assert!(function.contains("ORDER BY f.page_key LIMIT row_limit"));
    assert_eq!(PAGE_SQL.matches("coalesce(").count(), COALESCED);
    assert_eq!(RANK_BEFORE_FIRST, i16::MAX);
    assert_eq!(CURSOR_FIELDS, FOUR);
    Ok(())
}


#[test]
fn a_cursor_prints_and_parses_back_and_every_malformed_one_is_refused() -> TestResult {
    let sample = row("u1", Severity::High);
    let parsed = cursor_of_row(&sample)?;
    assert_eq!(parsed.run_id, RUN);
    assert_eq!(parsed.finished_micros, FINISHED.parse::<i64>()?);
    assert_eq!(parsed.rank, i16::from(severity_rank(Severity::High)));
    let identity = sample.get(COL_IDENTITY).ok_or("none")?.clone();
    let good = format!("{RUN} {FINISHED} 5 {identity}");
    assert!(parse_cursor(&good).is_ok());
    let upper = identity.to_ascii_uppercase();
    let short = identity.chars().take(HEX - 1).collect::<String>();
    let long_run = "r".repeat(MAX_CURSOR_BYTES);
    [
        String::new(),
        format!("{RUN} {FINISHED} 5"),
        format!("{good} extra"),
        format!("{RUN}  {FINISHED} 5 {identity}"),
        format!("-{RUN} {FINISHED} 5 {identity}"),
        format!("{RUN} -1 5 {identity}"),
        format!("{RUN} 01 5 {identity}"),
        format!("{RUN} x 5 {identity}"),
        format!("{RUN} {FINISHED} 32768 {identity}"),
        format!("{RUN} {FINISHED} -32769 {identity}"),
        format!("{RUN} {FINISHED} +5 {identity}"),
        format!("{RUN} {FINISHED} 05 {identity}"),
        format!("{RUN} {FINISHED} -0 {identity}"),
        format!("{RUN} {FINISHED} 5 {upper}"),
        format!("{RUN} {FINISHED} 5 {short}"),
        format!("{RUN} {FINISHED} 5 {identity}\n"),
        format!("{long_run} {FINISHED} 5 {identity}"),
        format!("{RUN}\u{3164} {FINISHED} 5 {identity}"),
    ]
    .iter()
    .try_for_each(|bad| {
        assert!(matches!(parse_cursor(bad), Err(StoreError::BadCursor)), "{bad:?}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(rank_of("7"), Some(SEVEN));
    assert_eq!(rank_of("9"), Some(NINE));
    assert_eq!(rank_of("-1"), Some(-1));
    assert_eq!(rank_of("32767"), Some(i16::MAX));
    assert_eq!(rank_of("-32768"), Some(i16::MIN));
    assert!(rank_of("32768").is_none());
    assert!(rank_of("+5").is_none());
    assert!(parse_cursor(&format!("{RUN} {FINISHED} 9 {identity}")).is_ok());
    assert!(parse_cursor(&format!("{RUN} {FINISHED} -1 {identity}")).is_ok());
    assert!(micros_of("0").is_some());
    assert!(micros_of("+5").is_none());
    assert!(is_identity_hex(&identity));
    assert!(!is_identity_hex(&format!("{identity}0")));
    Ok(())
}


#[tokio::test]
async fn account_limit_and_cursor_are_refused_before_any_io() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(vec![row("u1", Severity::High)]);
    let exec = executor(&fake);
    assert!(matches!(
        refused(read_findings(&exec, &scope, "-acc", None, 1).await)?,
        StoreError::BadAccount
    ));
    assert!(matches!(
        refused(read_findings(&exec, &scope, "", None, 1).await)?,
        StoreError::BadAccount
    ));
    assert!(matches!(
        refused(read_findings(&exec, &scope, "acc", None, 0).await)?,
        StoreError::BadLimit { max: MAX_PAGE_LIMIT }
    ));
    assert!(matches!(
        refused(read_findings(&exec, &scope, "acc", None, OVER_MAX).await)?,
        StoreError::BadLimit { .. }
    ));
    assert!(matches!(
        refused(read_findings(&exec, &scope, "acc", Some("junk"), 1).await)?,
        StoreError::BadCursor
    ));
    assert!(calls_of(&fake)?.is_empty());
    assert!(check_read("acc", None, MAX_PAGE_LIMIT)?.is_none());
    Ok(())
}


#[tokio::test]
async fn the_statement_runs_once_under_the_scope_with_the_cursor_key_and_one_row_more() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(vec![row("u1", Severity::High)]);
    let exec = executor(&fake);
    read_findings(&exec, &scope, "acc", None, TWO).await?;
    let sample = row("u0", Severity::Medium);
    let text = cursor_text(
        RUN,
        FINISHED.parse()?,
        sample.get(COL_RANK).ok_or("none")?,
        sample.get(COL_IDENTITY).ok_or("none")?,
    );
    read_findings(&exec, &scope, "acc", Some(&text), FIVE).await?;
    let calls = calls_of(&fake)?;
    assert_eq!(calls.len(), TWO);
    calls.iter().for_each(|call| {
        assert_eq!(call.tenant, "a");
        assert_eq!(call.sql, PAGE_SQL);
    });
    let first = calls.first().ok_or("none")?;
    assert_eq!(first.params, vec!["acc".to_owned(), "32767".to_owned(), String::new(), "3".to_owned()]);
    let second = calls.get(1).ok_or("none")?;
    assert_eq!(
        second.params,
        vec![
            "acc".to_owned(),
            "4".to_owned(),
            sample.get(COL_IDENTITY).ok_or("none")?.clone(),
            "6".to_owned()
        ]
    );
    assert_eq!(
        page_params("acc", None, 1),
        vec!["acc".to_owned(), "32767".to_owned(), String::new(), "2".to_owned()]
    );
    Ok(())
}


#[test]
fn a_page_has_the_first_limit_rows_and_the_cursor_of_the_last_of_them() -> TestResult {
    let rows = vec![row("u1", Severity::Critical), row("u2", Severity::High), row("u3", Severity::Low)];
    let page = page_of("acc", &rows, TWO, None)?;
    assert_eq!(page.items.len(), TWO);
    assert_eq!(page.unservable, 0);
    let second = rows.get(1).ok_or("none")?;
    let expected = cursor_text(
        RUN,
        FINISHED.parse()?,
        second.get(COL_RANK).ok_or("none")?,
        second.get(COL_IDENTITY).ok_or("none")?,
    );
    assert_eq!(page.next, Some(expected));
    let run = page.run.ok_or("no run")?;
    assert_eq!(run.run_id.as_deref(), Some(RUN));
    assert_eq!(run.finished_micros, Some(FINISHED.parse()?));
    assert_eq!(run.items, u64::try_from(THREE)?);
    let last = page_of("acc", &rows, THREE, None)?;
    assert_eq!(last.items.len(), THREE);
    assert!(last.next.is_none());
    let wide = page_of("acc", &rows, FIVE, None)?;
    assert!(wide.next.is_none());
    Ok(())
}


#[test]
fn a_skipped_last_row_still_gives_the_next_cursor_its_raw_key() -> TestResult {
    let bad = with_column(row("u2", Severity::High), COL_TIME, "253402300800");
    let rows = vec![row("u1", Severity::Critical), bad.clone(), row("u3", Severity::Low)];
    let page = page_of("acc", &rows, TWO, None)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.unservable, 1);
    let expected = cursor_text(
        RUN,
        FINISHED.parse()?,
        bad.get(COL_RANK).ok_or("none")?,
        bad.get(COL_IDENTITY).ok_or("none")?,
    );
    assert_eq!(page.next, Some(expected));
    Ok(())
}


#[test]
fn a_row_failing_the_serving_check_is_skipped_and_counted_never_served() -> TestResult {
    let base = row("u1", Severity::High);
    let other_identity = format!("{:x}", identity_of(&finding("u2", Severity::High)));
    let long_title = "t".repeat(MAX_CURSOR_BYTES * THREE);
    let mutations: Vec<(usize, String)> = vec![
        (COL_UID, "\0".to_owned()),
        (COL_UID, String::new()),
        (COL_CHECK, "-check".to_owned()),
        (COL_CHECK, "chéck".to_owned()),
        (COL_STATUS, "BAD".to_owned()),
        (COL_SEVERITY, "BAD".to_owned()),
        (COL_PROVIDER, "AWS".to_owned()),
        (COL_REGION, "eu west".to_owned()),
        (COL_RESOURCE_UID, "a  b".to_owned()),
        (COL_RESOURCE_UID, "<svg/onload=alert(1)>".to_owned()),
        (COL_RESOURCE_TYPE, "ty\u{3164}pe".to_owned()),
        (COL_TIME, "x".to_owned()),
        (COL_TIME, "-62167219201".to_owned()),
        (COL_TITLE, "bad\0title".to_owned()),
        (COL_TITLE, long_title.clone()),
        (COL_TITLE_CUT, "x".to_owned()),
        (COL_TITLE_CUT, "99999999999999999999999".to_owned()),
        (COL_DETAIL, "bad\0detail".to_owned()),
        (COL_DETAIL, long_title),
        (COL_DETAIL_CUT, "-1".to_owned()),
        (COL_RANK, "6".to_owned()),
        (COL_RANK, String::new()),
        (COL_IDENTITY, other_identity),
    ];
    mutations.iter().try_for_each(|(index, value)| {
        let hostile = with_column(base.clone(), *index, value);
        assert!(served_of(&hostile, "acc").is_none(), "column {index} {value:?}");
        let page = page_of("acc", std::slice::from_ref(&hostile), 1, None);
        let only_skipped = page.is_ok_and(|served| served.items.is_empty() && served.unservable == 1 && served.next.is_none());
        assert!(only_skipped, "column {index} {value:?}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(served_of(&base, "acc").is_some());
    assert!(served_of(&base, "other").is_none());
    Ok(())
}


#[test]
fn a_truncated_or_unparsable_row_has_no_finding() -> TestResult {
    let base = row("u1", Severity::High);
    (0..ROW_COLUMNS).try_for_each(|length| {
        let prefix: Vec<String> = base.iter().take(length).cloned().collect();
        let parsed = finding_of(&prefix, "acc");
        assert_eq!(parsed.is_some(), length >= ROW_COLUMNS);
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(finding_of(&base, "acc").is_some());
    Ok(())
}


#[test]
fn a_hostile_title_row_is_skipped_by_the_walk_and_counted_on_the_page() -> TestResult {
    let hostile = with_column(row("u2", Severity::High), COL_TITLE, "x\0y");
    let rows = vec![row("u1", Severity::Critical), hostile];
    let page = page_of("acc", &rows, THREE, None)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.unservable, 1);
    assert!(page.items.iter().all(|item| !item.title.contains('\0')));
    Ok(())
}


#[tokio::test]
async fn a_served_page_carries_the_run_header_and_logs_skips() -> TestResult {
    let scope = tenant_scope("a")?;
    let fake = double(vec![
        row("u1", Severity::Critical),
        with_column(row("u2", Severity::High), COL_STATUS, "BAD"),
    ]);
    let exec = executor(&fake);
    let page = read_findings(&exec, &scope, "acc", None, TWO).await?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.unservable, 1);
    assert!(page.run.is_some());
    let clean = double(vec![row("u1", Severity::Critical)]);
    let clean_exec = executor(&clean);
    assert_eq!(read_findings(&clean_exec, &scope, "acc", None, TWO).await?.unservable, 0);
    Ok(())
}


#[test]
fn an_unprintable_next_key_or_run_is_a_stored_value_error() -> TestResult {
    let rows = |second: Vec<String>| vec![row("u1", Severity::Critical), second, row("u3", Severity::Low)];
    let bad_rank = with_column(row("u2", Severity::High), COL_RANK, "99999");
    let bad_identity = with_column(row("u2", Severity::High), COL_IDENTITY, "ZZ");
    [bad_rank, bad_identity].iter().try_for_each(|second| {
        assert!(matches!(page_of("acc", &rows(second.clone()), TWO, None), Err(StoreError::StoredValue)));
        let ends_there = vec![row("u1", Severity::Critical), second.clone()];
        let page = page_of("acc", &ends_there, TWO, None)?;
        assert!(page.next.is_none());
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let never_stored = vec![
        with_column(with_column(row("u1", Severity::Critical), COL_RUN_ID, ""), COL_FINISHED, ""),
        row("u2", Severity::High),
    ];
    assert!(matches!(page_of("acc", &never_stored, 1, None), Err(StoreError::StoredValue)));
    let header = header_of(&row("u1", Severity::High))?;
    assert!(matches!(next_cursor(&header, &[]), Err(StoreError::BadAnswer)));
    assert!(matches!(next_cursor(&header, &vec![String::new(); FIVE]), Err(StoreError::BadAnswer)));
    assert!(matches!(
        next_cursor(&header, &with_column(row("u1", Severity::High), COL_RANK, "99999")),
        Err(StoreError::StoredValue)
    ));
    assert!(next_cursor(&header, &with_column(row("u1", Severity::High), COL_RANK, "9")).is_ok());
    Ok(())
}


#[test]
fn a_row_of_a_rank_outside_the_severity_map_is_counted_and_the_walk_goes_on() -> TestResult {
    let rows = vec![
        row("u1", Severity::Critical),
        with_column(row("u2", Severity::High), COL_RANK, "9"),
        with_column(row("u3", Severity::High), COL_RANK, "-4"),
    ];
    let page = page_of("acc", &rows, TWO, None)?;
    assert_eq!((page.items.len(), page.unservable), (1, 1));
    let next = page.next.ok_or("no next cursor")?;
    assert!(next.contains(" 9 "));
    let resumed = parse_cursor(&next)?;
    assert_eq!(resumed.rank, NINE);
    Ok(())
}


#[test]
fn a_cursor_of_another_run_or_a_vanished_run_is_run_changed() -> TestResult {
    let rows = vec![row("u1", Severity::Critical), row("u2", Severity::High)];
    let sample = rows.first().ok_or("none")?;
    let identity = sample.get(COL_IDENTITY).ok_or("none")?;
    let rank = sample.get(COL_RANK).ok_or("none")?;
    let same = parse_cursor(&cursor_text(RUN, FINISHED.parse()?, rank, identity))?;
    assert!(page_of("acc", &rows, 1, Some(&same)).is_ok());
    let other_run = parse_cursor(&cursor_text("run2", FINISHED.parse()?, rank, identity))?;
    assert!(matches!(page_of("acc", &rows, 1, Some(&other_run)), Err(StoreError::RunChanged)));
    let reused_id = parse_cursor(&cursor_text(RUN, 1, rank, identity))?;
    assert!(matches!(page_of("acc", &rows, 1, Some(&reused_id)), Err(StoreError::RunChanged)));
    assert!(matches!(page_of("acc", &[], 1, Some(&same)), Err(StoreError::RunChanged)));
    let nothing = page_of("acc", &[], 1, None)?;
    assert!(nothing.run.is_none() && nothing.items.is_empty() && nothing.next.is_none());
    let refused_only = row_of("", "", None);
    assert!(matches!(page_of("acc", &[refused_only], 1, Some(&same)), Err(StoreError::RunChanged)));
    let header = header_of(&row("u1", Severity::High))?;
    assert!(check_cursor(&header, None).is_ok());
    assert!(check_cursor(&header, Some(&same)).is_ok());
    assert!(matches!(check_cursor(&header, Some(&other_run)), Err(StoreError::RunChanged)));
    Ok(())
}


#[test]
fn a_run_header_without_findings_is_a_page_with_the_header_only() -> TestResult {
    let empty = row_of(RUN, FINISHED, None);
    let page = page_of("acc", &[empty], 1, None)?;
    assert!(page.items.is_empty() && page.next.is_none() && page.unservable == 0);
    assert_eq!(page.run.ok_or("no run")?.run_id.as_deref(), Some(RUN));
    let never = row_of("", "", None);
    let header = header_of(&never)?;
    assert!(header.run_id.is_none() && header.finished_micros.is_none());
    Ok(())
}


#[test]
fn the_header_reads_every_count_and_refuses_a_bad_cell() -> TestResult {
    let base = row_of(RUN, FINISHED, None);
    let counts = [
        COL_ITEMS,
        COL_UNPARSABLE,
        COL_BAD_FIELD,
        COL_DUPLICATE,
        COL_FOREIGN,
        COL_REFUSED_PASS,
        COL_REFUSED_MUTED,
        COL_REFUSED_MANUAL,
        COL_REFUSED_FAIL,
        COL_STORE_REFUSED,
        COL_REFUSED_ITEMS,
    ];
    counts.iter().try_for_each(|index| {
        assert!(matches!(header_of(&with_column(base.clone(), *index, "x")), Err(StoreError::BadAnswer)));
        assert!(matches!(header_of(&with_column(base.clone(), *index, "-1")), Err(StoreError::BadAnswer)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(matches!(
        header_of(&with_column(base.clone(), COL_FINISHED, "-1")),
        Err(StoreError::BadAnswer)
    ));
    assert!(matches!(
        header_of(&with_column(base.clone(), COL_REFUSED_MICROS, "x")),
        Err(StoreError::BadAnswer)
    ));
    assert!(matches!(
        header_of(&with_column(base.clone(), COL_RUN_ID, "-bad")),
        Err(StoreError::StoredValue)
    ));
    assert!(matches!(header_of(&[]), Err(StoreError::BadAnswer)));
    let full = header_of(&with_column(base, COL_REFUSED_MICROS, &LATER.to_string()))?;
    assert_eq!(full.refused_micros, Some(LATER));
    assert_eq!(full.refused_items, 0);
    Ok(())
}


#[test]
fn a_row_of_another_width_is_a_bad_answer() -> TestResult {
    let short: Vec<String> = row("u1", Severity::High).into_iter().take(ROW_COLUMNS - 1).collect();
    assert!(matches!(page_of("acc", &[short], 1, None), Err(StoreError::BadAnswer)));
    let mut wide = row("u1", Severity::High);
    wide.push(String::new());
    assert!(matches!(page_of("acc", &[wide], 1, None), Err(StoreError::BadAnswer)));
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_a_database_error() -> TestResult {
    let scope = tenant_scope("a")?;
    let failing = Double {
        fail: true,
        ..double(Vec::new())
    };
    let exec = executor(&failing);
    assert!(matches!(refused(read_findings(&exec, &scope, "acc", None, 1).await)?, StoreError::Pg(_)));
    Ok(())
}


#[test]
fn a_refused_run_newer_than_the_stored_one_is_pending() -> TestResult {
    let stored = header_of(&row_of(RUN, &STORED.to_string(), None))?;
    let pending = |refused: Option<i64>, finished: Option<i64>| {
        refusal_pending(&RunHeader {
            refused_micros: refused,
            finished_micros: finished,
            ..stored.clone()
        })
    };
    assert!(!pending(None, Some(STORED)));
    assert!(!pending(Some(STORED), Some(STORED)));
    assert!(!pending(Some(1), Some(STORED)));
    assert!(pending(Some(NEWER), Some(STORED)));
    assert!(pending(Some(1), None));
    assert!(!pending(None, None));
    Ok(())
}
