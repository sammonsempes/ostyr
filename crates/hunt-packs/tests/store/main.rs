mod types;


use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_of, TenantScope};
use hunt_packs::store::{
    last_done, record_done, single_end, Param, StateError, GET_SQL, MIGRATIONS, MIGRATION_NAMESPACE, SET_SQL, STATEMENT_DEADLINE,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::future::{ready, Ready};
use std::rc::Rc;
use types::{Calls, Store, TestResult};


const PACK: &str = "lateral-movement";


const OLD: i64 = 500;


const SECOND: i64 = 2;


const NEWER: i64 = 1_000;


const NEWEST: i64 = 2_000;


const YEAR_10000: i64 = 253_402_300_800;


const LONG_ID_BYTES: usize = 10_000;


fn answer(store: &Store, scope: &TenantScope, sql: &'static str, params: &[Param]) -> Result<Vec<i64>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    let mut map = store.borrow_mut();
    match (sql, params) {
        (GET_SQL, [Param::Text(pack)]) => Ok(map.get(&(tenant, pack.clone())).copied().into_iter().collect()),
        (SET_SQL, [Param::Text(pack), Param::Int(end)]) => {
            let stored = map.entry((tenant, pack.clone())).or_insert(*end);
            *stored = (*stored).max(*end);
            Ok(vec![*stored])
        }
        _ => Err(PgError::InvalidTenant),
    }
}


fn fake(store: &Store, calls: &Calls) -> impl FnMut(&TenantScope, &'static str, Vec<Param>) -> Ready<Result<Vec<i64>, PgError>> {
    let shared = Rc::clone(store);
    let log = Rc::clone(calls);
    move |scope, sql, params| {
        log.borrow_mut().push((tenant_of(scope).to_owned(), sql, params.clone()));
        ready(answer(&shared, scope, sql, &params))
    }
}


fn fresh() -> (Store, Calls) {
    (Rc::new(RefCell::new(HashMap::new())), Rc::new(RefCell::new(Vec::new())))
}


#[test]
fn sql_binds_the_tenant_first_and_every_value_as_a_parameter() -> TestResult {
    assert!(GET_SQL.contains("WHERE tenant = $1 AND pack_id = $2"));
    assert!(SET_SQL.contains("VALUES ($1, $2, $3, now())"));
    assert!(SET_SQL
        .contains("ON CONFLICT (tenant, pack_id) DO UPDATE SET last_done_end = GREATEST(hunt_pack_runs.last_done_end, EXCLUDED.last_done_end)"));
    assert!(SET_SQL.ends_with("RETURNING last_done_end"));
    Ok(())
}


#[tokio::test]
async fn a_write_binds_pack_and_end_after_the_tenant() -> Result<(), Box<dyn Error>> {
    let (store, calls) = fresh();
    let mut exec = fake(&store, &calls);
    record_done(&mut exec, "acme", PACK, NEWER).await?;
    last_done(&mut exec, "acme", PACK).await?;
    let seen = calls.borrow().clone();
    assert_eq!(
        seen,
        vec![
            ("acme".to_owned(), SET_SQL, vec![Param::Text(PACK.to_owned()), Param::Int(NEWER)]),
            ("acme".to_owned(), GET_SQL, vec![Param::Text(PACK.to_owned())]),
        ]
    );
    Ok(())
}


#[tokio::test]
async fn an_older_end_never_moves_the_state_back() -> Result<(), Box<dyn Error>> {
    let (store, calls) = fresh();
    let mut exec = fake(&store, &calls);
    assert_eq!(last_done(&mut exec, "acme", PACK).await?, None);
    assert_eq!(record_done(&mut exec, "acme", PACK, NEWER).await?, NEWER);
    assert_eq!(record_done(&mut exec, "acme", PACK, OLD).await?, NEWER);
    assert_eq!(last_done(&mut exec, "acme", PACK).await?, Some(NEWER));
    assert_eq!(record_done(&mut exec, "acme", PACK, NEWEST).await?, NEWEST);
    Ok(())
}


#[tokio::test]
async fn a_tenant_never_sees_another_tenants_state() -> Result<(), Box<dyn Error>> {
    let (store, calls) = fresh();
    let mut exec = fake(&store, &calls);
    record_done(&mut exec, "a", PACK, NEWEST).await?;
    assert_eq!(last_done(&mut exec, "b", PACK).await?, None);
    assert_eq!(record_done(&mut exec, "b", PACK, 1).await?, 1);
    assert_eq!(last_done(&mut exec, "a", PACK).await?, Some(NEWEST));
    assert_eq!(last_done(&mut exec, "b", PACK).await?, Some(1));
    Ok(())
}


#[tokio::test]
async fn bad_keys_and_ends_are_refused_before_any_statement() -> Result<(), Box<dyn Error>> {
    let (store, calls) = fresh();
    let mut exec = fake(&store, &calls);
    let long = "a".repeat(LONG_ID_BYTES);
    assert!(matches!(
        record_done(&mut exec, "-x", PACK, NEWER).await,
        Err(StateError::Pg(PgError::InvalidTenant))
    ));
    assert!(matches!(
        last_done(&mut exec, "-x", PACK).await,
        Err(StateError::Pg(PgError::InvalidTenant))
    ));
    for pack in ["-p", "p\u{3164}", long.as_str(), "'; DROP TABLE hunt_pack_runs; --", "", "UPPER"] {
        assert!(matches!(
            record_done(&mut exec, "acme", pack, NEWER).await,
            Err(StateError::InvalidPackId)
        ));
        assert!(matches!(last_done(&mut exec, "acme", pack).await, Err(StateError::InvalidPackId)));
    }
    assert!(matches!(
        record_done(&mut exec, "acme", PACK, YEAR_10000).await,
        Err(StateError::OutOfRange(_))
    ));
    assert!(matches!(
        record_done(&mut exec, "acme", PACK, i64::MIN).await,
        Err(StateError::OutOfRange(_))
    ));
    assert!(calls.borrow().is_empty());
    Ok(())
}


#[tokio::test]
async fn an_executor_error_is_returned() -> Result<(), Box<dyn Error>> {
    let mut failing = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Err::<Vec<i64>, PgError>(PgError::LegacyRecords));
    assert!(matches!(
        last_done(&mut failing, "acme", PACK).await,
        Err(StateError::Pg(PgError::LegacyRecords))
    ));
    assert!(matches!(
        record_done(&mut failing, "acme", PACK, NEWER).await,
        Err(StateError::Pg(PgError::LegacyRecords))
    ));
    Ok(())
}


#[tokio::test]
async fn an_odd_reply_is_an_error() -> Result<(), Box<dyn Error>> {
    let mut empty = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Ok::<Vec<i64>, PgError>(Vec::new()));
    assert!(matches!(record_done(&mut empty, "acme", PACK, NEWER).await, Err(StateError::BadReply)));
    let mut two = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Ok::<Vec<i64>, PgError>(vec![1, SECOND]));
    assert!(matches!(last_done(&mut two, "acme", PACK).await, Err(StateError::BadReply)));
    let mut wild = |_scope: &TenantScope, _sql: &'static str, _params: Vec<Param>| ready(Ok::<Vec<i64>, PgError>(vec![YEAR_10000]));
    assert!(matches!(last_done(&mut wild, "acme", PACK).await, Err(StateError::OutOfRange(_))));
    Ok(())
}


#[test]
fn single_end_reads_none_one_or_refuses() -> TestResult {
    assert_eq!(single_end(&[]).ok(), Some(None));
    assert_eq!(single_end(&[NEWER]).ok(), Some(Some(NEWER)));
    assert!(single_end(&[1, SECOND]).is_err());
    Ok(())
}


#[test]
fn the_migration_is_embedded_and_its_namespace_valid() -> Result<(), Box<dyn Error>> {
    check_embedded(&MIGRATIONS)?;
    check_namespace(MIGRATION_NAMESPACE)?;
    assert!(MIGRATIONS.iter().all(|migration| migration.sql.contains("PRIMARY KEY (tenant, pack_id)")));
    assert!(!STATEMENT_DEADLINE.is_zero());
    Ok(())
}
