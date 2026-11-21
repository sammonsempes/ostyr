mod common;


use common::types::TestResult;
use core_pg::migrate::check_embedded;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use remote_shell::error::StoreError;
use remote_shell::recording::{DataFrame, Direction, Header, Recording, Trailer};
use remote_shell::session::CloseReason;
use remote_shell::store::{
    bytes_of, check_asset, close_of, decode_session, int_of, list_sessions, reason_token, register_close, register_open, text_of, to_i64, CLOSE_SQL,
    COL_BYTES, COL_HASH, COL_OPENED_AT, LIST_AFTER_SQL, LIST_SQL, MAX_PAGE, MIGRATIONS, MIGRATION_NAMESPACE, OPEN_SQL, STATE_SQL,
};
use remote_shell::store_model::{Cell, CloseRecord, Cursor, ListFilter, Param, Statement};
use remote_shell::types::{ChainHash, Row, HASH_LEN};
use std::cell::RefCell;
use std::future::{ready, Future, Ready};
use std::rc::Rc;


const ACME: &str = "acme";


const GLOBEX: &str = "globex";


const OPENED: i64 = 1_800_000_000;


const CLOSED: i64 = 1_800_000_600;


const HASH_BYTE: u8 = 7;


const SEEDED: usize = 15;


const TIE_GROUP: usize = 3;


const SMALL_PAGE: u32 = 1;


const MEDIUM_PAGE: u32 = 7;


const MAX_ROUNDS: usize = 40;


const COLUMNS: usize = 10;


const FIRST_OPTIONAL_COLUMN: usize = 5;


const LONG_TICKET: usize = 129;


const LONG_SUBJECT: usize = 256;


const FRAMES_IN_RECORDING: usize = 3;


const TOKENS: usize = 6;


const IDX2: usize = 2;


const IDX3: usize = 3;


const IDX4: usize = 4;


const IDX5: usize = 5;


const IDX6: usize = 6;


const IDX7: usize = 7;


const IDX8: usize = 8;


const IDX9: usize = 9;


const STATE_COLUMNS: usize = 5;


const FIELDS: usize = 4;


const SKIPPED: usize = 2;


const SECOND_SEQ: u64 = 2;


const LATER: i64 = 100;


const SECOND_ASSET: &str = "host-8";


const BYTES_LEN: u64 = 4096;


struct Stored {
    tenant: String,
    session_id: String,
    requester: String,
    asset: String,
    ticket: String,
    opened_at: i64,
    closed_at: Option<i64>,
    reason: Option<String>,
    frames: Option<i64>,
    hash: Option<Vec<u8>>,
    bytes: Option<i64>,
}


#[derive(Default)]
struct Db {
    rows: Vec<Stored>,
    log: Vec<&'static str>,
}


fn bad(column: &'static str) -> StoreError {
    StoreError::BadRow { column }
}


fn int_param(params: &[Param], index: usize) -> Result<i64, StoreError> {
    match params.get(index) {
        Some(Param::Int(value)) => Ok(*value),
        _ => Err(bad("fake int")),
    }
}


fn text_param(params: &[Param], index: usize) -> Result<String, StoreError> {
    match params.get(index) {
        Some(Param::Text(value)) => Ok(value.clone()),
        _ => Err(bad("fake text")),
    }
}


fn bool_param(params: &[Param], index: usize) -> Result<bool, StoreError> {
    match params.get(index) {
        Some(Param::Bool(value)) => Ok(*value),
        _ => Err(bad("fake bool")),
    }
}


fn bytes_param(params: &[Param], index: usize) -> Result<Vec<u8>, StoreError> {
    match params.get(index) {
        Some(Param::Bytes(value)) => Ok(value.clone()),
        _ => Err(bad("fake bytes")),
    }
}


fn optional_int_cell(value: Option<i64>) -> Cell {
    value.map_or(Cell::Null, Cell::Int)
}


fn fake_open(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let session_id = text_param(params, 0)?;
    if db.rows.iter().any(|row| row.tenant == tenant && row.session_id == session_id) {
        Ok(Vec::new())
    } else {
        db.rows.push(Stored {
            tenant: tenant.to_owned(),
            session_id: session_id.clone(),
            requester: text_param(params, 1)?,
            asset: text_param(params, IDX2)?,
            ticket: text_param(params, IDX3)?,
            opened_at: int_param(params, IDX4)?,
            closed_at: None,
            reason: None,
            frames: None,
            hash: None,
            bytes: None,
        });
        Ok(vec![vec![Cell::Text(session_id)]])
    }
}


fn fake_close(db: &mut Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let scoped = CLOSE_SQL.contains("tenant = $1");
    let guarded = CLOSE_SQL.contains("closed_at IS NULL");
    let headed = CLOSE_SQL.contains("requester = $8 AND asset = $9 AND ticket = $10 AND opened_at = $11");
    let session_id = text_param(params, 0)?;
    let at = int_param(params, 1)?;
    let requester = text_param(params, IDX6)?;
    let asset = text_param(params, IDX7)?;
    let ticket = text_param(params, IDX8)?;
    let opened_at = int_param(params, IDX9)?;
    let found = db.rows.iter_mut().find(|row| {
        (!scoped || row.tenant == tenant)
            && row.session_id == session_id
            && (!guarded || row.closed_at.is_none())
            && row.opened_at <= at
            && (!headed || (row.requester == requester && row.asset == asset && row.ticket == ticket && row.opened_at == opened_at))
    });
    match found {
        Some(row) => {
            row.closed_at = Some(at);
            row.reason = Some(text_param(params, IDX2)?);
            row.frames = Some(int_param(params, IDX3)?);
            row.hash = Some(bytes_param(params, IDX4)?);
            row.bytes = Some(int_param(params, IDX5)?);
            Ok(vec![vec![Cell::Text(session_id)]])
        }
        None => Ok(Vec::new()),
    }
}


fn fake_state(db: &Db, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let scoped = STATE_SQL.contains("tenant = $1");
    let session_id = text_param(params, 0)?;
    Ok(db
        .rows
        .iter()
        .filter(|row| (!scoped || row.tenant == tenant) && row.session_id == session_id)
        .map(|row| {
            vec![
                optional_int_cell(row.closed_at),
                Cell::Int(row.opened_at),
                Cell::Text(row.requester.clone()),
                Cell::Text(row.asset.clone()),
                Cell::Text(row.ticket.clone()),
            ]
        })
        .collect())
}


fn session_cells(row: &Stored) -> Row {
    vec![
        Cell::Text(row.session_id.clone()),
        Cell::Text(row.requester.clone()),
        Cell::Text(row.asset.clone()),
        Cell::Text(row.ticket.clone()),
        Cell::Int(row.opened_at),
        optional_int_cell(row.closed_at),
        row.reason.clone().map_or(Cell::Null, Cell::Text),
        optional_int_cell(row.frames),
        row.hash.clone().map_or(Cell::Null, Cell::Bytes),
        optional_int_cell(row.bytes),
    ]
}


fn fake_list(db: &Db, sql: &'static str, tenant: &str, params: &[Param]) -> Result<Vec<Row>, StoreError> {
    let scoped = sql.contains("tenant = $1");
    let asset = text_param(params, 0)?;
    let requester = text_param(params, 1)?;
    let open_only = bool_param(params, IDX2)?;
    let limit = usize::try_from(int_param(params, IDX3)?).map_err(|_overflow| bad("fake limit"))?;
    let cursor = match params.get(IDX4) {
        Some(_) => Some((int_param(params, IDX4)?, text_param(params, IDX5)?)),
        None => None,
    };
    let mut shown: Vec<&Stored> = db
        .rows
        .iter()
        .filter(|row| (!scoped || row.tenant == tenant) && (asset.is_empty() || row.asset == asset))
        .filter(|row| requester.is_empty() || row.requester == requester)
        .filter(|row| !open_only || row.closed_at.is_none())
        .filter(|row| {
            cursor
                .as_ref()
                .is_none_or(|(at, id)| (row.opened_at, row.session_id.as_str()) < (*at, id.as_str()))
        })
        .collect();
    shown.sort_by(|left, right| (right.opened_at, &right.session_id).cmp(&(left.opened_at, &left.session_id)));
    shown.truncate(limit);
    Ok(shown.into_iter().map(session_cells).collect())
}


fn fake(db: &mut Db, tenant: &str, statement: Statement) -> Result<Vec<Row>, StoreError> {
    db.log.push(statement.sql);
    match statement.sql {
        OPEN_SQL => fake_open(db, tenant, &statement.params),
        CLOSE_SQL => fake_close(db, tenant, &statement.params),
        STATE_SQL => fake_state(db, tenant, &statement.params),
        LIST_SQL | LIST_AFTER_SQL => fake_list(db, statement.sql, tenant, &statement.params),
        _ => Err(bad("fake sql")),
    }
}


fn executor(db: &Rc<RefCell<Db>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Rc::clone(db);
    move |scope: &TenantScope, statement: Statement| ready(fake(&mut shared.borrow_mut(), tenant_of(scope), statement))
}


fn header(tenant: &str, session_id: &str, opened_at: i64) -> Header {
    Header {
        session_id: session_id.to_owned(),
        tenant: tenant.to_owned(),
        requester: "alice".to_owned(),
        asset: "host-7".to_owned(),
        ticket: "INC-1".to_owned(),
        opened_at,
    }
}


fn hash() -> ChainHash {
    [HASH_BYTE; HASH_LEN]
}


fn close_record(at: i64) -> CloseRecord {
    close_record_for(header(ACME, "s-1", OPENED), at)
}


fn close_record_for(header: Header, at: i64) -> CloseRecord {
    CloseRecord {
        header,
        reason: CloseReason::UserClose,
        trailer: Trailer {
            seq: 1,
            at,
            reason: "user_close".to_owned(),
        },
        final_hash: hash(),
        frames: FRAMES_IN_RECORDING as u64,
        bytes: BYTES_LEN,
    }
}


fn new_db() -> Rc<RefCell<Db>> {
    Rc::new(RefCell::new(Db::default()))
}


async fn collect_ids<Executor, Pending>(exec: &mut Executor, scope: &TenantScope, filter: &ListFilter, limit: u32) -> Result<Vec<String>, StoreError>
where
    Executor: FnMut(&TenantScope, Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, StoreError>>,
{
    let mut ids = Vec::new();
    let mut cursor: Option<Cursor> = None;
    let mut rounds = 0;
    let mut done = false;
    while !done && rounds < MAX_ROUNDS {
        let page = list_sessions(exec, scope, filter, cursor.as_ref(), limit).await?;
        cursor = page.last().map(|row| Cursor {
            opened_at: row.opened_at,
            session_id: row.session_id.clone(),
        });
        done = page.is_empty();
        ids.extend(page.into_iter().map(|row| row.session_id));
        rounds += 1;
    }
    Ok(ids)
}


async fn seed(exec: &mut impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>>, scope: &TenantScope) -> TestResult {
    for index in 0..SEEDED {
        let at = OPENED + i64::try_from(index / TIE_GROUP)?;
        register_open(exec, scope, &header(tenant_of(scope), &format!("s-{index:02}"), at)).await?;
    }
    Ok(())
}


#[tokio::test]
async fn two_tenants_with_one_session_id_stay_apart() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    let globex = tenant_scope(GLOBEX)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    register_open(&mut exec, &globex, &header(GLOBEX, "s-1", OPENED)).await?;
    register_close(&mut exec, &acme, "s-1", &close_record(CLOSED)).await?;
    let acme_rows = list_sessions(&mut exec, &acme, &ListFilter::default(), None, MAX_PAGE).await?;
    let globex_rows = list_sessions(&mut exec, &globex, &ListFilter::default(), None, MAX_PAGE).await?;
    assert_eq!(acme_rows.len(), 1);
    assert_eq!(acme_rows.first().and_then(|row| row.closed_at), Some(CLOSED));
    assert_eq!(globex_rows.len(), 1);
    assert_eq!(globex_rows.first().and_then(|row| row.closed_at), None);
    Ok(())
}


#[tokio::test]
async fn a_close_row_carries_the_recording_identity() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    register_close(&mut exec, &acme, "s-1", &close_record(CLOSED)).await?;
    let rows = list_sessions(&mut exec, &acme, &ListFilter::default(), None, 1).await?;
    let row = rows.first().ok_or("no row")?;
    assert_eq!(row.close_reason.as_deref(), Some("user_close"));
    assert_eq!(row.recording_frames, Some(i64::try_from(FRAMES_IN_RECORDING)?));
    assert_eq!(row.recording_hash.as_deref(), Some(hash().as_slice()));
    assert_eq!(row.recording_bytes, Some(i64::try_from(BYTES_LEN)?));
    assert_eq!(
        (row.requester.as_str(), row.asset.as_str(), row.ticket.as_str()),
        ("alice", "host-7", "INC-1")
    );
    Ok(())
}


#[tokio::test]
async fn a_repeated_open_is_a_duplicate_and_changes_nothing() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    let mut other = header(ACME, "s-1", OPENED + 1);
    other.requester = "mallory".to_owned();
    let result = register_open(&mut exec, &acme, &other).await;
    assert!(matches!(result, Err(StoreError::Duplicate { ref session_id }) if session_id == "s-1"));
    let rows = list_sessions(&mut exec, &acme, &ListFilter::default(), None, MAX_PAGE).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.first().map(|row| row.requester.as_str()), Some("alice"));
    Ok(())
}


#[tokio::test]
async fn a_second_close_is_refused_and_the_first_stays() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    register_close(&mut exec, &acme, "s-1", &close_record(CLOSED)).await?;
    let result = register_close(&mut exec, &acme, "s-1", &close_record(CLOSED + 1)).await;
    assert!(matches!(result, Err(StoreError::AlreadyClosed { .. })));
    let rows = list_sessions(&mut exec, &acme, &ListFilter::default(), None, MAX_PAGE).await?;
    assert_eq!(rows.first().and_then(|row| row.closed_at), Some(CLOSED));
    Ok(())
}


#[tokio::test]
async fn a_close_before_the_open_time_is_refused() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    let result = register_close(&mut exec, &acme, "s-1", &close_record(OPENED - 1)).await;
    assert!(matches!(result, Err(StoreError::CloseBeforeOpen { .. })));
    let still_open = list_sessions(
        &mut exec,
        &acme,
        &ListFilter {
            open_only: true,
            ..ListFilter::default()
        },
        None,
        MAX_PAGE,
    )
    .await?;
    assert_eq!(still_open.len(), 1);
    register_close(&mut exec, &acme, "s-1", &close_record(OPENED)).await?;
    Ok(())
}


#[tokio::test]
async fn an_unknown_id_and_another_tenant_are_unknown() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    let globex = tenant_scope(GLOBEX)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    let missing = register_close(&mut exec, &acme, "s-2", &close_record_for(header(ACME, "s-2", OPENED), CLOSED)).await;
    assert!(matches!(missing, Err(StoreError::Unknown { .. })));
    let foreign = register_close(&mut exec, &globex, "s-1", &close_record_for(header(GLOBEX, "s-1", OPENED), CLOSED)).await;
    assert!(matches!(foreign, Err(StoreError::Unknown { ref session_id }) if session_id == "s-1"));
    register_close(&mut exec, &acme, "s-1", &close_record(CLOSED)).await?;
    let closed_foreign = register_close(&mut exec, &globex, "s-1", &close_record_for(header(GLOBEX, "s-1", OPENED), CLOSED)).await;
    assert!(matches!(closed_foreign, Err(StoreError::Unknown { .. })));
    let rows = list_sessions(&mut exec, &acme, &ListFilter::default(), None, MAX_PAGE).await?;
    assert_eq!(rows.first().and_then(|row| row.closed_at), Some(CLOSED));
    assert!(list_sessions(&mut exec, &globex, &ListFilter::default(), None, MAX_PAGE)
        .await?
        .is_empty());
    Ok(())
}


#[tokio::test]
async fn a_header_of_another_tenant_is_refused_before_any_statement() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let globex = tenant_scope(GLOBEX)?;
    let result = register_open(&mut exec, &globex, &header(ACME, "s-1", OPENED)).await;
    assert!(matches!(result, Err(StoreError::TenantMismatch)));
    assert!(db.borrow().log.is_empty());
    Ok(())
}


#[tokio::test]
async fn pages_of_any_size_give_the_same_rows_in_order() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    seed(&mut exec, &acme).await?;
    register_open(&mut exec, &tenant_scope(GLOBEX)?, &header(GLOBEX, "g-1", OPENED + LATER)).await?;
    let filter = ListFilter::default();
    let one = collect_ids(&mut exec, &acme, &filter, SMALL_PAGE).await?;
    let seven = collect_ids(&mut exec, &acme, &filter, MEDIUM_PAGE).await?;
    let all = collect_ids(&mut exec, &acme, &filter, MAX_PAGE).await?;
    assert_eq!(one.len(), SEEDED);
    assert_eq!(one, seven);
    assert_eq!(one, all);
    assert_eq!(one.first().map(String::as_str), Some("s-14"));
    assert_eq!(one.last().map(String::as_str), Some("s-00"));
    assert!(!one.iter().any(|id| id == "g-1"));
    Ok(())
}


#[tokio::test]
async fn the_page_bound_is_checked_before_any_statement() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    let zero = list_sessions(&mut exec, &acme, &ListFilter::default(), None, 0).await;
    let over = list_sessions(&mut exec, &acme, &ListFilter::default(), None, MAX_PAGE + 1).await;
    assert!(matches!(zero, Err(StoreError::LimitOutOfRange { limit: 0, .. })));
    assert!(matches!(over, Err(StoreError::LimitOutOfRange { max: MAX_PAGE, .. })));
    assert!(db.borrow().log.is_empty());
    Ok(())
}


#[tokio::test]
async fn filters_narrow_the_list() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    let mut second = header(ACME, "s-2", OPENED + 1);
    second.asset = SECOND_ASSET.to_owned();
    second.requester = "bob".to_owned();
    register_open(&mut exec, &acme, &second).await?;
    register_close(&mut exec, &acme, "s-1", &close_record(CLOSED)).await?;
    let by_asset = ListFilter {
        asset: Some(SECOND_ASSET.to_owned()),
        ..ListFilter::default()
    };
    let by_requester = ListFilter {
        requester: Some("alice".to_owned()),
        ..ListFilter::default()
    };
    let open_only = ListFilter {
        open_only: true,
        ..ListFilter::default()
    };
    assert_eq!(collect_ids(&mut exec, &acme, &by_asset, MAX_PAGE).await?, vec!["s-2".to_owned()]);
    assert_eq!(collect_ids(&mut exec, &acme, &by_requester, MAX_PAGE).await?, vec!["s-1".to_owned()]);
    assert_eq!(collect_ids(&mut exec, &acme, &open_only, MAX_PAGE).await?, vec!["s-2".to_owned()]);
    Ok(())
}


fn hostile_values() -> Result<Vec<String>, std::num::TryFromIntError> {
    Ok(vec![
        "-x".to_owned(),
        "a\u{3164}".to_owned(),
        "a\u{202e}b".to_owned(),
        "a\0b".to_owned(),
        "a'; DROP TABLE remote_shell_sessions; --".to_owned(),
        "a\nb".to_owned(),
        String::new(),
        "a".repeat(LONG_TICKET),
    ])
}


#[tokio::test]
async fn every_text_field_is_checked_before_any_statement() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    let mut refused = 0;
    for value in hostile_values()? {
        let mut by_id = header(ACME, &value, OPENED);
        by_id.session_id = value.clone();
        let mut by_requester = header(ACME, "s-1", OPENED);
        by_requester.requester = value.clone();
        let mut by_asset = header(ACME, "s-1", OPENED);
        by_asset.asset = value.clone();
        let mut by_ticket = header(ACME, "s-1", OPENED);
        by_ticket.ticket = value.clone();
        let subject_ok = value == "-x" || value.len() == LONG_TICKET;
        for (candidate, is_requester) in [(by_id, false), (by_requester, true), (by_asset, false), (by_ticket, false)] {
            if !(is_requester && subject_ok) {
                let result = register_open(&mut exec, &acme, &candidate).await;
                assert!(matches!(result, Err(StoreError::Invalid { .. })));
                refused += 1;
            }
        }
        let close = register_close(&mut exec, &acme, &value, &close_record(CLOSED)).await;
        assert!(matches!(close, Err(StoreError::Invalid { field: "session_id" })));
        let asset_filter = ListFilter {
            asset: Some(value.clone()),
            ..ListFilter::default()
        };
        let requester_filter = ListFilter {
            requester: Some(if subject_ok { "a".repeat(LONG_SUBJECT) } else { value.clone() }),
            ..ListFilter::default()
        };
        let cursor = Cursor {
            opened_at: OPENED,
            session_id: value.clone(),
        };
        assert!(matches!(
            list_sessions(&mut exec, &acme, &asset_filter, None, 1).await,
            Err(StoreError::Invalid { field: "asset" })
        ));
        assert!(matches!(
            list_sessions(&mut exec, &acme, &requester_filter, None, 1).await,
            Err(StoreError::Invalid { field: "requester" })
        ));
        assert!(matches!(
            list_sessions(&mut exec, &acme, &ListFilter::default(), Some(&cursor), 1).await,
            Err(StoreError::Invalid { field: "cursor" })
        ));
    }
    assert_eq!(refused, hostile_values()?.len() * FIELDS - SKIPPED);
    assert!(db.borrow().log.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_requester_may_hold_subject_punctuation_but_an_asset_may_not_start_with_it() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    let mut allowed = header(ACME, "s-1", OPENED);
    allowed.requester = "auth0|123@example.org".to_owned();
    register_open(&mut exec, &acme, &allowed).await?;
    assert!(check_asset("-host").is_err());
    assert!(check_asset("host-1").is_ok());
    Ok(())
}


#[test]
fn the_migration_is_embedded_and_named() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    assert_eq!(MIGRATION_NAMESPACE, "remote_shell");
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("PRIMARY KEY (tenant, session_id)"));
    assert!(sql.contains("closed_at >= opened_at"));
    assert!(sql.contains("(tenant, asset, opened_at DESC, session_id DESC)"));
    assert!(sql.contains("(tenant, requester, opened_at DESC, session_id DESC)"));
    assert!(sql.contains("BEFORE DELETE ON remote_shell_sessions"));
    Ok(())
}


#[test]
fn the_second_migration_refuses_truncate_and_pins_the_reason_tokens() -> TestResult {
    let second = MIGRATIONS.get(1).ok_or("no second migration")?;
    assert_eq!(second.version, "rshell_0002");
    assert!(second.sql.contains("BEFORE TRUNCATE ON remote_shell_sessions"));
    assert!(second.sql.contains("FOR EACH STATEMENT"));
    let listed = second
        .sql
        .split("IN (")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .ok_or("no reason list")?;
    let mut in_sql: Vec<String> = listed.split(',').map(|token| token.trim().trim_matches('\'').to_owned()).collect();
    let mut in_rust: Vec<String> = [
        CloseReason::IdleTimeout,
        CloseReason::MaxDuration,
        CloseReason::RecordingFailed,
        CloseReason::ChannelDead,
        CloseReason::UserClose,
        CloseReason::ClockSkew,
    ]
    .iter()
    .map(|reason| reason_token(*reason).to_owned())
    .collect();
    in_sql.sort();
    in_rust.sort();
    assert_eq!(in_sql, in_rust);
    Ok(())
}


const THIRD_MIGRATION: usize = 2;


#[test]
fn the_third_migration_is_registered_last() -> TestResult {
    let versions: Vec<&str> = MIGRATIONS.iter().map(|migration| migration.version).collect();
    assert_eq!(versions, vec!["rshell_0001", "rshell_0002", "rshell_0003"]);
    assert!(!MIGRATIONS.get(THIRD_MIGRATION).ok_or("no third migration")?.sql.is_empty());
    Ok(())
}


fn recording(tenant: &str, session_id: &str) -> Recording {
    Recording {
        header: header(tenant, session_id, OPENED),
        frames: vec![DataFrame {
            seq: 1,
            at: OPENED,
            direction: Direction::In,
            bytes: Vec::new(),
        }],
        trailer: Trailer {
            seq: SECOND_SEQ,
            at: CLOSED,
            reason: "user_close".to_owned(),
        },
        final_hash: hash(),
    }
}


#[test]
fn close_of_reads_the_recording_and_refuses_a_foreign_one() -> TestResult {
    let acme = tenant_scope(ACME)?;
    let record = close_of(&acme, "s-1", &recording(ACME, "s-1"), CloseReason::MaxDuration, BYTES_LEN)?;
    assert_eq!(record.header, header(ACME, "s-1", OPENED));
    assert_eq!(record.frames, FRAMES_IN_RECORDING as u64);
    assert_eq!(record.trailer.at, CLOSED);
    assert_eq!(record.final_hash, hash());
    assert_eq!(record.bytes, BYTES_LEN);
    let foreign_tenant = close_of(&acme, "s-1", &recording(GLOBEX, "s-1"), CloseReason::MaxDuration, BYTES_LEN);
    assert!(matches!(foreign_tenant, Err(StoreError::TenantMismatch)));
    let foreign_session = close_of(&acme, "s-2", &recording(ACME, "s-1"), CloseReason::MaxDuration, BYTES_LEN);
    assert!(matches!(foreign_session, Err(StoreError::RecordingMismatch { ref session_id }) if session_id == "s-2"));
    Ok(())
}


#[test]
fn each_close_reason_has_its_own_lowercase_token() -> TestResult {
    let tokens = [
        reason_token(CloseReason::IdleTimeout),
        reason_token(CloseReason::MaxDuration),
        reason_token(CloseReason::RecordingFailed),
        reason_token(CloseReason::ChannelDead),
        reason_token(CloseReason::UserClose),
        reason_token(CloseReason::ClockSkew),
    ];
    let distinct: std::collections::BTreeSet<&str> = tokens.iter().copied().collect();
    assert_eq!(distinct.len(), TOKENS);
    assert!(tokens
        .iter()
        .all(|token| token.chars().all(|character| character.is_ascii_lowercase() || character == '_')));
    Ok(())
}


#[tokio::test]
async fn a_value_that_does_not_fit_the_store_is_refused() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    let mut huge_frames = close_record(CLOSED);
    huge_frames.frames = u64::MAX;
    let mut huge_bytes = close_record(CLOSED);
    huge_bytes.bytes = u64::MAX;
    assert!(matches!(
        register_close(&mut exec, &acme, "s-1", &huge_frames).await,
        Err(StoreError::OutOfRange { field: "frames" })
    ));
    assert!(matches!(
        register_close(&mut exec, &acme, "s-1", &huge_bytes).await,
        Err(StoreError::OutOfRange { field: "bytes" })
    ));
    assert!(matches!(to_i64("x", u64::MAX), Err(StoreError::OutOfRange { field: "x" })));
    Ok(())
}


fn good_row() -> Row {
    vec![
        Cell::Text("s-1".to_owned()),
        Cell::Text("alice".to_owned()),
        Cell::Text("host-7".to_owned()),
        Cell::Text("INC-1".to_owned()),
        Cell::Int(OPENED),
        Cell::Null,
        Cell::Null,
        Cell::Null,
        Cell::Null,
        Cell::Null,
    ]
}


fn replaced(index: usize, cell: Cell) -> Row {
    let mut row = good_row();
    if let Some(slot) = row.get_mut(index) {
        *slot = cell;
    }
    row
}


#[test]
fn a_row_of_the_wrong_shape_is_a_bad_row() -> TestResult {
    assert!(decode_session(&good_row()).is_ok());
    assert!(matches!(decode_session(&Vec::new()), Err(StoreError::BadRow { .. })));
    for index in 0..COLUMNS {
        let wrong = if index == COL_HASH { Cell::Int(1) } else { Cell::Bytes(Vec::new()) };
        assert!(matches!(decode_session(&replaced(index, wrong)), Err(StoreError::BadRow { .. })));
        let nulled = decode_session(&replaced(index, Cell::Null));
        assert_eq!(nulled.is_err(), index < FIRST_OPTIONAL_COLUMN);
    }
    assert!(matches!(
        decode_session(&replaced(COL_OPENED_AT, Cell::Text(String::new()))),
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(
        decode_session(&replaced(COL_BYTES, Cell::Text(String::new()))),
        Err(StoreError::BadRow { .. })
    ));
    assert!(matches!(int_of(Cell::Null, "c"), Err(StoreError::BadRow { column: "c" })));
    assert!(matches!(text_of(Cell::Null, "c"), Err(StoreError::BadRow { column: "c" })));
    assert!(matches!(bytes_of(Cell::Null, "c"), Err(StoreError::BadRow { column: "c" })));
    Ok(())
}


#[tokio::test]
async fn a_list_of_bad_rows_and_a_failing_executor_are_errors() -> TestResult {
    let acme = tenant_scope(ACME)?;
    let mut short = |_scope: &TenantScope, _statement: Statement| ready(Ok(vec![Vec::new()]));
    assert!(matches!(
        list_sessions(&mut short, &acme, &ListFilter::default(), None, 1).await,
        Err(StoreError::BadRow { .. })
    ));
    let mut failing = |_scope: &TenantScope, _statement: Statement| ready(Err::<Vec<Row>, StoreError>(bad("boom")));
    assert!(matches!(
        list_sessions(&mut failing, &acme, &ListFilter::default(), None, 1).await,
        Err(StoreError::BadRow { column: "boom" })
    ));
    assert!(matches!(
        register_open(&mut failing, &acme, &header(ACME, "s-1", OPENED)).await,
        Err(StoreError::BadRow { column: "boom" })
    ));
    assert!(matches!(
        register_close(&mut failing, &acme, "s-1", &close_record(CLOSED)).await,
        Err(StoreError::BadRow { column: "boom" })
    ));
    Ok(())
}


#[tokio::test]
async fn a_failing_state_read_after_a_refused_close_is_an_error() -> TestResult {
    let acme = tenant_scope(ACME)?;
    let mut state_fails =
        |_scope: &TenantScope, statement: Statement| ready(if statement.sql == CLOSE_SQL { Ok(Vec::new()) } else { Err(bad("state")) });
    assert!(matches!(
        register_close(&mut state_fails, &acme, "s-1", &close_record(CLOSED)).await,
        Err(StoreError::BadRow { column: "state" })
    ));
    let mut state_garbled = |_scope: &TenantScope, statement: Statement| {
        ready(Ok(if statement.sql == CLOSE_SQL {
            Vec::new()
        } else {
            vec![vec![Cell::Text("x".to_owned())]]
        }))
    };
    assert!(matches!(
        register_close(&mut state_garbled, &acme, "s-1", &close_record(CLOSED)).await,
        Err(StoreError::BadRow { column: "closed_at" })
    ));
    Ok(())
}


#[tokio::test]
async fn an_error_names_only_the_escaped_session_id() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    let duplicate = register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED))
        .await
        .err()
        .ok_or("no error")?;
    assert_eq!(duplicate.to_string(), "session `s-1` is already registered");
    let invalid = register_close(&mut exec, &acme, "a\u{202e}b", &close_record(CLOSED))
        .await
        .err()
        .ok_or("no error")?;
    assert_eq!(invalid.to_string(), "field `session_id` is outside its grammar");
    Ok(())
}


fn altered_headers() -> Vec<Header> {
    let base = header(ACME, "s-1", OPENED);
    vec![
        Header {
            requester: "mallory".to_owned(),
            ..base.clone()
        },
        Header {
            asset: SECOND_ASSET.to_owned(),
            ..base.clone()
        },
        Header {
            ticket: "INC-2".to_owned(),
            ..base.clone()
        },
        Header {
            opened_at: OPENED + 1,
            ..base
        },
    ]
}


#[tokio::test]
async fn a_recording_header_that_is_not_the_rows_is_refused_and_nothing_is_written() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    register_open(&mut exec, &acme, &header(ACME, "s-1", OPENED)).await?;
    for altered in altered_headers() {
        let result = register_close(&mut exec, &acme, "s-1", &close_record_for(altered, CLOSED)).await;
        assert!(matches!(result, Err(StoreError::RecordingMismatch { ref session_id }) if session_id == "s-1"));
    }
    let still_open = list_sessions(&mut exec, &acme, &ListFilter::default(), None, 1).await?;
    assert_eq!(still_open.first().and_then(|row| row.closed_at), None);
    register_close(&mut exec, &acme, "s-1", &close_record(CLOSED)).await?;
    let late = register_close(&mut exec, &acme, "s-1", &close_record_for(header(ACME, "s-1", OPENED + 1), CLOSED)).await;
    assert!(matches!(late, Err(StoreError::RecordingMismatch { .. })));
    Ok(())
}


#[tokio::test]
async fn a_header_of_another_tenant_or_session_is_refused_before_any_close_statement() -> TestResult {
    let db = new_db();
    let mut exec = executor(&db);
    let acme = tenant_scope(ACME)?;
    let foreign_tenant = register_close(&mut exec, &acme, "s-1", &close_record_for(header(GLOBEX, "s-1", OPENED), CLOSED)).await;
    assert!(matches!(foreign_tenant, Err(StoreError::TenantMismatch)));
    let foreign_session = register_close(&mut exec, &acme, "s-1", &close_record_for(header(ACME, "s-2", OPENED), CLOSED)).await;
    assert!(matches!(foreign_session, Err(StoreError::RecordingMismatch { .. })));
    assert!(db.borrow().log.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_state_row_of_the_wrong_shape_is_a_bad_row() -> TestResult {
    let acme = tenant_scope(ACME)?;
    let expected = ["closed_at", "opened_at", "requester", "asset", "ticket"];
    for index in 0..STATE_COLUMNS {
        let mut cells = vec![
            Cell::Null,
            Cell::Int(OPENED),
            Cell::Text("a".to_owned()),
            Cell::Text("b".to_owned()),
            Cell::Text("c".to_owned()),
        ];
        if let Some(slot) = cells.get_mut(index) {
            *slot = Cell::Bytes(Vec::new());
        }
        let mut garbled =
            |_scope: &TenantScope, statement: Statement| ready(Ok(if statement.sql == CLOSE_SQL { Vec::new() } else { vec![cells.clone()] }));
        let result = register_close(&mut garbled, &acme, "s-1", &close_record(CLOSED)).await;
        assert!(matches!(result, Err(StoreError::BadRow { column }) if Some(&column) == expected.get(index)));
    }
    let mut short = |_scope: &TenantScope, statement: Statement| {
        ready(Ok(if statement.sql == CLOSE_SQL {
            Vec::new()
        } else {
            vec![vec![Cell::Null]]
        }))
    };
    assert!(matches!(
        register_close(&mut short, &acme, "s-1", &close_record(CLOSED)).await,
        Err(StoreError::BadRow { column: "opened_at" })
    ));
    Ok(())
}


#[test]
fn every_statement_is_scoped_by_the_tenant() -> TestResult {
    for sql in [CLOSE_SQL, STATE_SQL, LIST_SQL, LIST_AFTER_SQL] {
        assert!(sql.contains("WHERE tenant = $1 AND"), "{sql}");
    }
    assert!(OPEN_SQL.contains("VALUES ($1,"));
    Ok(())
}
