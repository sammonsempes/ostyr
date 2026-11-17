mod types;


use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::packs::MAX_ID_CHARS;
use hunt_packs::schedule::RunWindow;
use hunt_packs::store::{
    count_oversized, format_cursor, is_permanent, list_findings, parse_cursor, record_finding, CursorError, FindingPage, FindingRow, Param,
    StateError, FINDING_SQL, ID_BYTE_CAP, LIST_SQL, MAX_FINDINGS_PAGE, MIGRATIONS, OVERSIZED_REPORT_CAP, OVERSIZED_SQL,
};
use hunt_packs::types::ListResult;
use std::cell::RefCell;
use std::error::Error;
use std::future::{ready, Ready};
use std::rc::Rc;
use types::{Rows, Seen, TestResult};


const PACK: &str = "lateral-movement";


const START: i64 = 1_000;


const END: i64 = 2_000;


const LATER: i64 = 3_000;


const THREE: i64 = 3;


const ID_CAP: usize = 64;


const SECOND: i64 = 2;


const SECOND_USIZE: usize = 2;


const LIMIT_PARAM: usize = 2;


const YEAR_10000: i64 = 253_402_300_800;


const OVER_LIMIT: i64 = MAX_FINDINGS_PAGE + 1;


fn window() -> RunWindow {
    RunWindow { start: START, end: END }
}


fn row(pack: &str, end: i64) -> FindingRow {
    FindingRow {
        pack_id: pack.to_owned(),
        window_start: end - 1,
        window_end: end,
        matches: 1,
        max_matches: 0,
    }
}


fn insert_exec(store: &Rows, seen: &Seen) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> {
    let rows = Rc::clone(store);
    let log = Rc::clone(seen);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params.clone()));
        let answer = match params.as_slice() {
            [Param::Text(pack), Param::Int(_), Param::Int(end), Param::Int(matches), Param::Int(baseline)] => {
                let mut held = rows.borrow_mut();
                let tenant = tenant_of(scope).to_owned();
                let known = held
                    .iter()
                    .any(|(owner, stored)| *owner == tenant && stored.pack_id == *pack && stored.window_end == *end);
                if !known {
                    held.push((
                        tenant,
                        FindingRow {
                            pack_id: pack.clone(),
                            window_start: START,
                            window_end: *end,
                            matches: *matches,
                            max_matches: *baseline,
                        },
                    ));
                }
                Ok(if known { Vec::new() } else { vec![*end] })
            }
            _ => Err(PgError::InvalidTenant),
        };
        ready(answer)
    }
}


fn list_exec(store: &Rows, seen: &Seen) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<ListResult> {
    let rows = Rc::clone(store);
    let log = Rc::clone(seen);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params.clone()));
        let answer = match params.as_slice() {
            [Param::Int(end), Param::Text(pack), Param::Int(limit), Param::Int(cap)] => {
                let mut matching: Vec<FindingRow> = rows
                    .borrow()
                    .iter()
                    .filter(|(owner, stored)| {
                        owner == tenant_of(scope)
                            && (stored.window_end, &stored.pack_id) > (*end, pack)
                            && i64::try_from(stored.pack_id.len()).is_ok_and(|length| length <= *cap)
                    })
                    .map(|(_, stored)| stored.clone())
                    .collect();
                matching.sort_by(|left, right| (left.window_end, &left.pack_id).cmp(&(right.window_end, &right.pack_id)));
                matching.truncate(usize::try_from(*limit).unwrap_or(0));
                Ok(matching)
            }
            _ => Err(PgError::InvalidTenant),
        };
        ready(answer)
    }
}


fn fresh() -> (Rows, Seen) {
    (Rc::new(RefCell::new(Vec::new())), Rc::new(RefCell::new(Vec::new())))
}


#[test]
fn sql_binds_the_tenant_first_and_orders_by_the_cursor_key() -> TestResult {
    assert!(FINDING_SQL.contains("VALUES ($1, $2, $3, $4, $5, $6, now())"));
    assert!(FINDING_SQL.contains("ON CONFLICT (tenant, pack_id, window_end) DO NOTHING RETURNING window_end"));
    assert!(LIST_SQL.contains(
        "WHERE tenant = $1 AND (window_end, pack_id) > ($2, $3) AND octet_length(pack_id) <= $5::bigint ORDER BY window_end, pack_id LIMIT $4"
    ));
    assert!(!LIST_SQL.contains("OFFSET"));
    assert!(OVERSIZED_SQL.contains("WHERE tenant = $1 AND octet_length(pack_id) > 64 LIMIT $2::bigint"));
    assert!(OVERSIZED_SQL.contains(&format!("octet_length(pack_id) > {ID_BYTE_CAP} ")));
    assert_eq!(usize::try_from(ID_BYTE_CAP)?, ID_CAP);
    assert_eq!(ID_BYTE_CAP, i64::try_from(MAX_ID_CHARS)?);
    let constraint = MIGRATIONS
        .iter()
        .find(|migration| migration.version == "hunt_packs_0003")
        .ok_or("no 0003")?
        .sql;
    assert!(constraint.contains(&format!("CHECK (octet_length(pack_id) BETWEEN 1 AND {ID_BYTE_CAP}) NOT VALID")));
    let partial = MIGRATIONS.last().ok_or("no migration")?;
    assert_eq!(partial.version, "hunt_packs_0004");
    assert!(partial.sql.contains(&format!("(tenant) WHERE octet_length(pack_id) > {ID_BYTE_CAP};")));
    assert!(MIGRATIONS
        .iter()
        .any(|migration| migration.sql.contains("ON hunt_pack_findings (tenant, window_end, pack_id)")));
    Ok(())
}


#[tokio::test]
async fn a_finding_binds_every_value_after_the_tenant_and_a_replay_inserts_nothing() -> TestResult {
    let (store, seen) = fresh();
    let mut exec = insert_exec(&store, &seen);
    assert!(record_finding(&mut exec, "acme", PACK, &window(), THREE as u64, 0).await?);
    assert!(!record_finding(&mut exec, "acme", PACK, &window(), THREE as u64, 0).await?);
    assert_eq!(store.borrow().len(), 1);
    let first = seen.borrow().first().cloned().ok_or("no call")?;
    assert_eq!(
        first,
        (
            "acme".to_owned(),
            FINDING_SQL,
            vec![
                Param::Text(PACK.to_owned()),
                Param::Int(START),
                Param::Int(END),
                Param::Int(THREE),
                Param::Int(0)
            ]
        )
    );
    Ok(())
}


#[tokio::test]
async fn a_refused_finding_sends_nothing() -> TestResult {
    let (store, seen) = fresh();
    let mut exec = insert_exec(&store, &seen);
    let too_big = u64::try_from(i64::MAX)? + 1;
    assert!(matches!(
        record_finding(&mut exec, "acme", PACK, &window(), too_big, 0).await,
        Err(StateError::CountOutOfRange(_))
    ));
    assert!(matches!(
        record_finding(&mut exec, "acme", PACK, &window(), 1, too_big).await,
        Err(StateError::CountOutOfRange(_))
    ));
    assert!(matches!(
        record_finding(&mut exec, "acme", "-x", &window(), 1, 0).await,
        Err(StateError::InvalidPackId)
    ));
    assert!(matches!(
        record_finding(&mut exec, "-x", PACK, &window(), 1, 0).await,
        Err(StateError::Pg(_))
    ));
    let wild_end = RunWindow {
        start: START,
        end: YEAR_10000,
    };
    assert!(matches!(
        record_finding(&mut exec, "acme", PACK, &wild_end, 1, 0).await,
        Err(StateError::OutOfRange(_))
    ));
    let wild_start = RunWindow { start: YEAR_10000, end: END };
    assert!(matches!(
        record_finding(&mut exec, "acme", PACK, &wild_start, 1, 0).await,
        Err(StateError::OutOfRange(_))
    ));
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[tokio::test]
async fn an_odd_insert_reply_is_an_error() -> TestResult {
    let mut two = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Ok::<Vec<i64>, PgError>(vec![1, SECOND]));
    assert!(matches!(
        record_finding(&mut two, "acme", PACK, &window(), 1, 0).await,
        Err(StateError::BadReply)
    ));
    let mut failing = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Err::<Vec<i64>, PgError>(PgError::LegacyRecords));
    assert!(matches!(
        record_finding(&mut failing, "acme", PACK, &window(), 1, 0).await,
        Err(StateError::Pg(_))
    ));
    Ok(())
}


#[tokio::test]
async fn the_list_is_ordered_and_the_cursor_is_strict() -> TestResult {
    let (store, seen) = fresh();
    store.borrow_mut().extend([
        ("a".to_owned(), row("zeta", END)),
        ("a".to_owned(), row("alpha", END)),
        ("a".to_owned(), row("alpha", LATER)),
    ]);
    let mut exec = list_exec(&store, &seen);
    let all = list_findings(&mut exec, "a", 0, "", MAX_FINDINGS_PAGE).await?;
    let order: Vec<(i64, &str)> = all.rows.iter().map(|found| (found.window_end, found.pack_id.as_str())).collect();
    assert_eq!(order, vec![(END, "alpha"), (END, "zeta"), (LATER, "alpha")]);
    let after = list_findings(&mut exec, "a", END, "alpha", MAX_FINDINGS_PAGE).await?;
    assert_eq!(after.rows.len(), SECOND_USIZE);
    let none = list_findings(&mut exec, "a", LATER, "alpha", MAX_FINDINGS_PAGE).await?;
    assert_eq!(none, FindingPage::default());
    Ok(())
}


#[tokio::test]
async fn the_limit_is_capped_before_the_statement() -> TestResult {
    let (store, seen) = fresh();
    let mut exec = list_exec(&store, &seen);
    list_findings(&mut exec, "a", 0, "", MAX_FINDINGS_PAGE).await?;
    list_findings(&mut exec, "a", 0, "", OVER_LIMIT).await?;
    list_findings(&mut exec, "a", 0, "", i64::MAX).await?;
    list_findings(&mut exec, "a", 0, "", -1).await?;
    list_findings(&mut exec, "a", 0, "", 0).await?;
    let limits: Vec<Param> = seen
        .borrow()
        .iter()
        .filter_map(|(_, _, params)| params.get(LIMIT_PARAM).cloned())
        .collect();
    assert_eq!(
        limits,
        vec![
            Param::Int(MAX_FINDINGS_PAGE),
            Param::Int(MAX_FINDINGS_PAGE),
            Param::Int(MAX_FINDINGS_PAGE),
            Param::Int(1),
            Param::Int(1)
        ]
    );
    Ok(())
}


#[tokio::test]
async fn a_tenant_never_lists_another_tenants_findings() -> TestResult {
    let (store, seen) = fresh();
    let mut insert = insert_exec(&store, &seen);
    record_finding(&mut insert, "a", PACK, &window(), 1, 0).await?;
    let mut exec = list_exec(&store, &seen);
    assert_eq!(list_findings(&mut exec, "a", 0, "", MAX_FINDINGS_PAGE).await?.rows.len(), 1);
    assert!(list_findings(&mut exec, "b", 0, "", MAX_FINDINGS_PAGE).await?.rows.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_hostile_tenant_or_cursor_is_refused_before_any_statement() -> TestResult {
    let (store, seen) = fresh();
    let mut exec = list_exec(&store, &seen);
    for tenant in ["-x", "a' OR '1'='1", "a\0b", ""] {
        assert!(matches!(list_findings(&mut exec, tenant, 0, "", 1).await, Err(StateError::Pg(_))));
    }
    assert!(matches!(
        list_findings(&mut exec, "a", YEAR_10000, "", 1).await,
        Err(StateError::OutOfRange(_))
    ));
    assert!(seen.borrow().is_empty());
    Ok(())
}


#[tokio::test]
async fn a_row_with_an_invalid_pack_id_is_skipped_and_counted() -> TestResult {
    let (store, seen) = fresh();
    store
        .borrow_mut()
        .extend([("a".to_owned(), row("Bad Id", END)), ("a".to_owned(), row("fine", END))]);
    let mut exec = list_exec(&store, &seen);
    let page = list_findings(&mut exec, "a", 0, "", MAX_FINDINGS_PAGE).await?;
    assert_eq!((page.rows.len(), page.skipped), (1, 1));
    let mut failing = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Err::<Vec<FindingRow>, PgError>(PgError::LegacyRecords));
    assert!(matches!(list_findings(&mut failing, "a", 0, "", 1).await, Err(StateError::Pg(_))));
    Ok(())
}


#[tokio::test]
async fn the_count_error_keeps_its_cause_and_is_permanent() -> TestResult {
    let (store, seen) = fresh();
    let mut exec = insert_exec(&store, &seen);
    let too_big = u64::try_from(i64::MAX)? + 1;
    let error = record_finding(&mut exec, "acme", PACK, &window(), too_big, 0)
        .await
        .err()
        .ok_or("accepted")?;
    assert!(error.source().is_some());
    assert!(is_permanent(&error));
    assert!(is_permanent(&StateError::InvalidPackId));
    assert!(!is_permanent(&StateError::BadReply));
    Ok(())
}


#[tokio::test]
async fn a_full_page_of_skipped_rows_still_gives_the_next_cursor() -> TestResult {
    let (store, seen) = fresh();
    store.borrow_mut().extend([
        ("a".to_owned(), row("Bad Id", END)),
        ("a".to_owned(), row("Bad Two", LATER)),
        ("a".to_owned(), row("fine", LATER + 1)),
    ]);
    let mut exec = list_exec(&store, &seen);
    let page = list_findings(&mut exec, "a", 0, "", SECOND).await?;
    assert_eq!((page.rows.len(), page.skipped), (0, SECOND_USIZE));
    assert_eq!(page.next, Some((LATER, "Bad Two".to_owned())));
    let following = list_findings(&mut exec, "a", LATER, "Bad Two", SECOND).await?;
    assert_eq!((following.rows.len(), following.skipped, following.next), (1, 0, None));
    Ok(())
}


#[tokio::test]
async fn the_printed_cursor_of_an_escaped_id_round_trips_and_lists_the_row_between() -> TestResult {
    let (store, seen) = fresh();
    store.borrow_mut().extend([
        ("a".to_owned(), row("Bad Id", END)),
        ("a".to_owned(), row("beta", END)),
        ("a".to_owned(), row("x\u{1b}[31mred", END)),
        ("a".to_owned(), row("x-hidden", END)),
    ]);
    let mut exec = list_exec(&store, &seen);
    let first = list_findings(&mut exec, "a", 0, "", THREE).await?;
    let (end, pack) = first.next.ok_or("no cursor")?;
    let printed = format_cursor(end, &pack);
    assert!(printed.is_ascii() && !printed.chars().any(char::is_control));
    let (parsed_end, parsed_pack) = parse_cursor(&printed)?;
    assert_eq!((parsed_end, parsed_pack.as_str()), (END, pack.as_str()));
    let second = list_findings(&mut exec, "a", parsed_end, &parsed_pack, THREE).await?;
    let listed: Vec<&str> = second.rows.iter().map(|found| found.pack_id.as_str()).collect();
    assert_eq!(listed, ["x-hidden"]);
    Ok(())
}


#[test]
fn a_cursor_other_than_the_printed_form_is_refused() -> TestResult {
    assert_eq!(parse_cursor("1")?, (1, String::new()));
    let too_long = format!("1:{}", "61".repeat(ID_CAP + 1));
    let refused = ["x", "1:6", "1:6G", "1:4A", "1:zz", "1:ff", "1:é", too_long.as_str()];
    assert!(refused.iter().all(|text| parse_cursor(text) == Err(CursorError::Malformed)));
    assert_eq!(parse_cursor(&format!("1:{}", "61".repeat(ID_CAP)))?.1.len(), ID_CAP);
    Ok(())
}


#[test]
fn the_error_texts_are_fixed() -> TestResult {
    assert!(CursorError::Malformed.to_string().contains("lowercase hex"));
    assert!(StateError::InvalidPackId.to_string().contains("invalid pack id"));
    assert!(StateError::BadReply.to_string().contains("unexpected number of rows"));
    let conversion = i64::try_from(u64::MAX).err().ok_or("fits")?;
    assert!(StateError::CountOutOfRange(conversion).to_string().contains("match count"));
    let range = hunt_packs::schedule::checked_time(YEAR_10000).err().ok_or("in range")?;
    assert!(StateError::OutOfRange(range).to_string().contains("years 0 to 9999"));
    Ok(())
}


#[tokio::test]
async fn an_id_of_exactly_the_cap_lists_and_round_trips_while_one_byte_more_is_never_read() -> TestResult {
    let (store, seen) = fresh();
    let exact = "y".repeat(ID_CAP);
    let over = "y".repeat(ID_CAP + 1);
    let wide = "é".repeat(ID_CAP / SECOND_USIZE + 1);
    store.borrow_mut().extend([
        ("a".to_owned(), row(&exact, END)),
        ("a".to_owned(), row(&over, END)),
        ("a".to_owned(), row(&wide, END)),
        ("a".to_owned(), row("zz", LATER)),
    ]);
    let mut exec = list_exec(&store, &seen);
    let first = list_findings(&mut exec, "a", 0, "", 1).await?;
    let (end, pack) = first.next.ok_or("no cursor")?;
    assert_eq!(pack, exact);
    let printed = format_cursor(end, &pack);
    assert_eq!(parse_cursor(&printed)?, (END, exact.clone()));
    let second = list_findings(&mut exec, "a", END, &exact, MAX_FINDINGS_PAGE).await?;
    let listed: Vec<&str> = second.rows.iter().map(|found| found.pack_id.as_str()).collect();
    assert_eq!(listed, ["zz"]);
    Ok(())
}


#[tokio::test]
async fn a_page_of_only_short_invalid_rows_is_still_paged_past_with_oversized_rows_present() -> TestResult {
    let (store, seen) = fresh();
    store.borrow_mut().extend([
        ("a".to_owned(), row("Bad Id", END)),
        ("a".to_owned(), row(&"Y".repeat(ID_CAP + SECOND_USIZE), END)),
        ("a".to_owned(), row("Bad Two", LATER)),
        ("a".to_owned(), row("fine", LATER + 1)),
    ]);
    let mut exec = list_exec(&store, &seen);
    let page = list_findings(&mut exec, "a", 0, "", SECOND).await?;
    assert_eq!((page.rows.len(), page.skipped), (0, SECOND_USIZE));
    let (end, pack) = page.next.ok_or("no cursor")?;
    let following = list_findings(&mut exec, "a", end, &pack, SECOND).await?;
    assert_eq!(following.rows.len(), 1);
    Ok(())
}


#[tokio::test]
async fn the_oversized_count_is_bound_under_the_tenant_and_a_bad_reply_is_refused() -> TestResult {
    let (_, seen) = fresh();
    assert_eq!(count_oversized(&mut count_exec(&seen, one_row), "a").await?, THREE);
    let call = seen.borrow().first().cloned().ok_or("no call")?;
    assert_eq!((call.0.as_str(), call.1), ("a", OVERSIZED_SQL));
    assert_eq!(call.2, vec![Param::Int(OVERSIZED_REPORT_CAP + 1)]);
    assert!(matches!(
        count_oversized(&mut count_exec(&seen, no_row), "a").await,
        Err(StateError::BadReply)
    ));
    assert!(matches!(
        count_oversized(&mut count_exec(&seen, no_row), "-x").await,
        Err(StateError::Pg(_))
    ));
    assert!(matches!(
        count_oversized(&mut count_exec(&seen, store_down), "a").await,
        Err(StateError::Pg(_))
    ));
    Ok(())
}


fn count_exec(
    seen: &Seen,
    answer: fn() -> Result<Vec<i64>, PgError>,
) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> {
    let log = Rc::clone(seen);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params));
        ready(answer())
    }
}


fn one_row() -> Result<Vec<i64>, PgError> {
    Ok(vec![THREE])
}


fn no_row() -> Result<Vec<i64>, PgError> {
    Ok(Vec::new())
}


fn store_down() -> Result<Vec<i64>, PgError> {
    Err(PgError::LegacyRecords)
}
