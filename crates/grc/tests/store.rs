#[path = "common/types.rs"]
mod types;


use core_pg::error::PgError;
use core_pg::migrate::plan_migrations;
use core_pg::scope::{tenant_of, TenantScope};
use grc::error::StoreError;
use grc::export::to_json;
use grc::report::{ComplianceReport, ControlRow, StatusCounts};
use grc::store::{
    decode_meta, decode_store_row, decode_stored, digest_hex, get_report, list_reports, render_body, store_report, store_report_with_cap,
    StoreOutcome, GET_SQL, LIST_FRAMEWORK_SQL, LIST_SQL, MAX_FRAMEWORK_BYTES, MAX_LIST_LIMIT, MAX_REPORTS_PER_TENANT, MAX_REPORT_BYTES, MIGRATIONS,
    MIGRATION_NAMESPACE, STORE_SQL,
};
use grc::types::{Row, RowFuture};
use std::future::ready;
use std::sync::{Mutex, PoisonError};
use types::TestResult;


const BIG_TITLE_BYTES: usize = 10_000_000;


const SMALL_CAP: i64 = 3;


const STORED_ID: i64 = 7;


const VERSION: u32 = 2;


const PAGE: usize = 2;


const LISTED_ID: i64 = 9;


const LISTED_BYTES: u64 = 1200;


const LISTED_EPOCH: i64 = 1_700_000_000;


#[derive(Clone)]
struct Call {
    tenant: String,
    sql: &'static str,
    params: Vec<String>,
}


#[derive(Default)]
struct Calls {
    seen: Mutex<Vec<Call>>,
}


fn cells(items: &[&str]) -> Row {
    items.iter().map(|item| (*item).to_owned()).collect()
}


fn report(tenant: &str, title: &str) -> ComplianceReport {
    ComplianceReport {
        tenant: tenant.to_owned(),
        framework: "nis2".to_owned(),
        version: VERSION,
        generated: "2026-11-23".to_owned(),
        counts: StatusCounts {
            compliant: 1,
            partially_compliant: 0,
            non_compliant: 0,
            not_assessable: 0,
        },
        controls: vec![ControlRow {
            id: "c1".to_owned(),
            title: title.to_owned(),
            status: "compliant".to_owned(),
            evidence_digest: None,
            evidence_time: None,
            risks: Vec::new(),
            open_actions: Vec::new(),
            reason: None,
        }],
        gaps: Vec::new(),
        plan: Vec::new(),
    }
}


fn answering<'a>(
    calls: &'a Calls,
    answer: Result<Vec<Row>, PgError>,
) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    let shared = Mutex::new(Some(answer));
    move |scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'a> {
        calls.seen.lock().unwrap_or_else(PoisonError::into_inner).push(Call {
            tenant: tenant_of(&scope).to_owned(),
            sql,
            params,
        });
        let next = shared.lock().unwrap_or_else(PoisonError::into_inner).take().unwrap_or(Ok(Vec::new()));
        Box::pin(ready(next))
    }
}


fn recorded(calls: &Calls) -> Vec<Call> {
    calls.seen.lock().unwrap_or_else(PoisonError::into_inner).clone()
}


#[test]
fn the_migration_is_one_file_with_the_lock_and_the_pinned_search_path() -> TestResult {
    assert_eq!(MIGRATION_NAMESPACE, "grc");
    assert_eq!(MIGRATIONS.len(), 1);
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("pg_advisory_xact_lock(hashtextextended('grc_report/' || p_tenant, 0))"));
    assert!(sql.contains("SET search_path = pg_catalog, public, pg_temp"));
    assert!(sql.contains("UNIQUE (tenant, framework, generated, digest)"));
    assert!(sql.contains("PRIMARY KEY (tenant, id)"));
    assert!(sql.contains("octet_length(body) <= 1048576"));
    assert!(sql.contains("held >= p_cap"));
    assert_eq!(plan_migrations(&[], &MIGRATIONS).map(|plan| plan.len())?, 1);
    Ok(())
}


#[test]
fn every_statement_is_keyed_by_the_tenant_first() -> TestResult {
    [LIST_SQL, LIST_FRAMEWORK_SQL, GET_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("WHERE tenant = $1"), "{sql}"));
    assert!(STORE_SQL.contains("grc_report_store($1,"));
    [LIST_SQL, LIST_FRAMEWORK_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("ORDER BY grc_report.id DESC"), "{sql}"));
    Ok(())
}


#[tokio::test]
async fn a_report_is_stored_with_the_digest_of_its_json_bytes() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["stored", "7"])]));
    let compliance = report("acme", "Title");
    let outcome = store_report(&exec, "acme", &compliance).await?;
    assert_eq!(outcome, StoreOutcome::Stored { id: STORED_ID });
    let mut expected = Vec::new();
    to_json(&compliance, &mut expected)?;
    let body = String::from_utf8(expected)?;
    assert_eq!(render_body(&compliance)?, body);
    let seen = recorded(&calls);
    let Call { tenant, sql, params } = seen.first().ok_or("no call")?;
    assert_eq!((tenant.as_str(), *sql), ("acme", STORE_SQL));
    assert_eq!(
        params,
        &vec![
            "nis2".to_owned(),
            "2".to_owned(),
            "2026-11-23".to_owned(),
            digest_hex(&body),
            body,
            MAX_REPORTS_PER_TENANT.to_string()
        ]
    );
    Ok(())
}


#[tokio::test]
async fn the_same_inputs_answer_already_stored() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["already_stored", "7"])]));
    assert_eq!(
        store_report(&exec, "acme", &report("acme", "Title")).await?,
        StoreOutcome::AlreadyStored { id: STORED_ID }
    );
    Ok(())
}


#[tokio::test]
async fn a_tenant_over_the_cap_is_refused_by_name_and_the_cap_is_lowered_to_the_maximum() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["refused", ""])]));
    let refused = store_report_with_cap(&exec, "acme", &report("acme", "Title"), SMALL_CAP).await;
    assert!(matches!(refused, Err(StoreError::CapReached { max: SMALL_CAP })));
    let high = answering(&calls, Ok(vec![cells(&["refused", ""])]));
    let lowered = store_report_with_cap(&high, "acme", &report("acme", "Title"), i64::MAX).await;
    assert!(matches!(lowered, Err(StoreError::CapReached { max: MAX_REPORTS_PER_TENANT })));
    let seen = recorded(&calls);
    assert_eq!(seen.first().and_then(|call| call.params.last()), Some(&SMALL_CAP.to_string()));
    assert_eq!(seen.last().and_then(|call| call.params.last()), Some(&MAX_REPORTS_PER_TENANT.to_string()));
    Ok(())
}


#[tokio::test]
async fn inputs_refused_before_any_io() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["stored", "1"])]));
    let foreign = store_report(&exec, "acme", &report("other", "Title")).await;
    assert!(matches!(foreign, Err(StoreError::TenantMismatch)));
    let bad_tenant = store_report(&exec, "-x", &report("-x", "Title")).await;
    assert!(matches!(bad_tenant, Err(StoreError::Tenant(_))));
    let mut long = report("acme", "Title");
    long.framework = "f".repeat(MAX_FRAMEWORK_BYTES + 1);
    let named = store_report(&exec, "acme", &long).await;
    assert!(matches!(named, Err(StoreError::FrameworkTooLong { .. })));
    let huge = store_report(&exec, "acme", &report("acme", &"x".repeat(BIG_TITLE_BYTES))).await;
    assert!(matches!(huge, Err(StoreError::TooLarge { max: MAX_REPORT_BYTES, .. })));
    assert!(recorded(&calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_a_store_error_and_a_bad_row_is_refused() -> TestResult {
    let calls = Calls::default();
    let failing = answering(&calls, Err(PgError::InvalidTenant));
    let failed = store_report(&failing, "acme", &report("acme", "Title")).await;
    assert!(matches!(failed, Err(StoreError::Store(_))));
    [
        vec![],
        vec![cells(&["stored", "1"]), cells(&["stored", "2"])],
        vec![cells(&["stored"])],
        vec![cells(&["stored", "x"])],
        vec![cells(&["already_stored", "x"])],
        vec![cells(&["unknown", "1"])],
    ]
    .iter()
    .for_each(|rows| assert!(matches!(decode_store_row(rows, 1), Err(StoreError::BadRow))));
    Ok(())
}


#[tokio::test]
async fn a_list_is_bounded_and_scoped() -> TestResult {
    let calls = Calls::default();
    let row = cells(&["9", "nis2", "2", "2026-11-23", "abc", "1200", "1700000000"]);
    let exec = answering(&calls, Ok(vec![row.clone()]));
    let metas = list_reports(&exec, "acme", None, PAGE).await?;
    assert_eq!(metas.len(), 1);
    assert_eq!(
        metas.first().map(|meta| (meta.id, meta.bytes, meta.stored_epoch, meta.version)),
        Some((LISTED_ID, LISTED_BYTES, LISTED_EPOCH, VERSION))
    );
    let named = answering(&calls, Ok(vec![row]));
    list_reports(&named, "acme", Some("nis2"), 1).await?;
    let seen = recorded(&calls);
    assert_eq!(
        seen.first().map(|call| (call.tenant.as_str(), call.sql, call.params.clone())),
        Some(("acme", LIST_SQL, vec![PAGE.to_string()]))
    );
    assert_eq!(
        seen.last().map(|call| (call.sql, call.params.clone())),
        Some((LIST_FRAMEWORK_SQL, vec!["nis2".to_owned(), "1".to_owned()]))
    );
    Ok(())
}


#[tokio::test]
async fn a_list_refuses_bad_limits_tenants_failures_and_overlong_answers() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(Vec::new()));
    assert!(matches!(list_reports(&exec, "acme", None, 0).await, Err(StoreError::BadLimit { .. })));
    assert!(matches!(
        list_reports(&exec, "acme", None, MAX_LIST_LIMIT + 1).await,
        Err(StoreError::BadLimit { max: MAX_LIST_LIMIT })
    ));
    assert!(matches!(list_reports(&exec, "-x", None, 1).await, Err(StoreError::Tenant(_))));
    assert!(recorded(&calls).is_empty());
    let failing = answering(&calls, Err(PgError::InvalidTenant));
    assert!(matches!(list_reports(&failing, "acme", None, 1).await, Err(StoreError::Store(_))));
    let row = cells(&["9", "nis2", "2", "2026-11-23", "abc", "1200", "1700000000"]);
    let overlong = answering(&calls, Ok(vec![row.clone(), row]));
    assert!(matches!(list_reports(&overlong, "acme", None, 1).await, Err(StoreError::BadRow)));
    Ok(())
}


#[test]
fn a_meta_row_must_have_seven_readable_cells() -> TestResult {
    assert!(matches!(decode_meta(&cells(&["1"])), Err(StoreError::BadRow)));
    [
        cells(&["x", "nis2", "2", "2026-11-23", "abc", "1200", "1700000000"]),
        cells(&["9", "nis2", "x", "2026-11-23", "abc", "1200", "1700000000"]),
        cells(&["9", "nis2", "2", "2026-11-23", "abc", "-1", "1700000000"]),
        cells(&["9", "nis2", "2", "2026-11-23", "abc", "1200", "x"]),
    ]
    .iter()
    .for_each(|row| assert!(matches!(decode_meta(row), Err(StoreError::BadRow))));
    Ok(())
}


#[tokio::test]
async fn a_get_returns_the_body_of_the_tenant_only() -> TestResult {
    let calls = Calls::default();
    let body = render_body(&report("acme", "Title"))?;
    let row = cells(&["nis2", "2", "2026-11-23", &digest_hex(&body), &body]);
    let exec = answering(&calls, Ok(vec![row]));
    let found = get_report(&exec, "acme", STORED_ID).await?.ok_or("missing")?;
    assert_eq!((found.id, found.version, found.body.as_str()), (STORED_ID, VERSION, body.as_str()));
    let other = answering(&calls, Ok(Vec::new()));
    assert_eq!(get_report(&other, "other", STORED_ID).await?, None);
    let seen = recorded(&calls);
    assert_eq!(
        seen.first().map(|call| (call.tenant.as_str(), call.sql, call.params.clone())),
        Some(("acme", GET_SQL, vec!["7".to_owned()]))
    );
    assert_eq!(seen.last().map(|call| call.tenant.as_str()), Some("other"));
    Ok(())
}


#[tokio::test]
async fn an_edited_body_is_a_named_digest_mismatch() -> TestResult {
    let calls = Calls::default();
    let body = render_body(&report("acme", "Title"))?;
    let edited = body.replace("compliant", "tampered");
    let row = cells(&["nis2", "2", "2026-11-23", &digest_hex(&body), &edited]);
    let exec = answering(&calls, Ok(vec![row.clone()]));
    assert!(matches!(get_report(&exec, "acme", 1).await, Err(StoreError::DigestMismatch)));
    assert!(matches!(decode_stored(1, &row), Err(StoreError::DigestMismatch)));
    Ok(())
}


#[tokio::test]
async fn a_get_refuses_a_bad_tenant_a_failure_and_unreadable_rows() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(Vec::new()));
    assert!(matches!(get_report(&exec, "-x", 1).await, Err(StoreError::Tenant(_))));
    assert!(recorded(&calls).is_empty());
    let failing = answering(&calls, Err(PgError::InvalidTenant));
    assert!(matches!(get_report(&failing, "acme", 1).await, Err(StoreError::Store(_))));
    let two = answering(&calls, Ok(vec![cells(&["a"]), cells(&["b"])]));
    assert!(matches!(get_report(&two, "acme", 1).await, Err(StoreError::BadRow)));
    let short = answering(&calls, Ok(vec![cells(&["a"])]));
    assert!(matches!(get_report(&short, "acme", 1).await, Err(StoreError::BadRow)));
    let body = "{}";
    let bad_version = cells(&["nis2", "x", "2026-11-23", &digest_hex(body), body]);
    assert!(matches!(decode_stored(1, &bad_version), Err(StoreError::BadRow)));
    Ok(())
}
