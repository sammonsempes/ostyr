#[path = "support/types.rs"]
mod types;


use attack_paths::error::StoreError;
use attack_paths::model::{Edge, Graph, Node, NodeKind, Path, PathSet, Relation, StopReason, Unsearched};
use attack_paths::store::{
    build_body, decode_meta, decode_store_row, decode_stored, digest_hex, generated_text, get_report, graph_digest, list_reports, paths_lower_bound,
    render_body, store_report, store_report_with_cap, ReportBody, StoreOutcome, GET_SQL, LIST_SQL, MAX_LIST_LIMIT, MAX_REPORTS_PER_TENANT,
    MAX_REPORT_BYTES, MIGRATIONS, MIGRATION_NAMESPACE, STORE_SQL,
};
use attack_paths::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::migrate::plan_migrations;
use core_pg::scope::{tenant_of, TenantScope};
use std::future::ready;
use std::sync::{Mutex, PoisonError};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};
use types::TestResult;


const SMALL_CAP: i64 = 3;


const STORED_ID: i64 = 7;


const PAGE: usize = 2;


const LISTED_ID: i64 = 9;


const LISTED_BYTES: u64 = 1200;


const LISTED_EPOCH: i64 = 1_700_000_000;


const HUGE_NODE_BYTES: usize = 2_000_000;


const MANY_PATHS: usize = 20_000;


const TWO_UNSEARCHED: usize = 2;


const LISTED_UNSEARCHED: u64 = 2;


const META_CELLS: [usize; 6] = [0, 4, 5, 6, 7, 8];


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


fn graph() -> Graph {
    Graph {
        nodes: vec![
            Node {
                id: "a".to_owned(),
                kind: NodeKind::User,
                critical: false,
                entry_point: true,
            },
            Node {
                id: "b".to_owned(),
                kind: NodeKind::DomainController,
                critical: true,
                entry_point: false,
            },
        ],
        edges: vec![Edge {
            from: "a".to_owned(),
            to: "b".to_owned(),
            relation: Relation::AdminTo,
        }],
    }
}


fn route(ids: &[&str]) -> Path {
    Path {
        nodes: ids.iter().map(|id| (*id).to_owned()).collect(),
    }
}


fn found(truncated: bool, budget_reached: bool) -> PathSet {
    PathSet {
        paths: vec![route(&["a", "m", "b"]), route(&["c", "m", "b"])],
        truncated,
        budget_reached,
        unsearched: vec![
            Unsearched {
                id: "c".to_owned(),
                reason: StopReason::PathCap,
            },
            Unsearched {
                id: "d".to_owned(),
                reason: StopReason::StepBudget,
            },
        ],
    }
}


fn moment(text: &str) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    Ok(OffsetDateTime::parse(text, &Rfc3339)?)
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


fn stored_row(body: &str, truncated: &str, budget: &str, unsearched: &str, graph_text: &str) -> Row {
    cells(&[graph_text, "2026-11-23T10:00:00Z", &digest_hex(body), truncated, budget, unsearched, body])
}


fn good_body(truncated: bool) -> Result<(String, String), Box<dyn std::error::Error>> {
    let digest = graph_digest(&graph())?;
    Ok((render_body(&build_body(digest.clone(), &found(truncated, false)))?, digest))
}


#[test]
fn the_migration_is_one_file_with_the_lock_and_the_pinned_search_path() -> TestResult {
    assert_eq!(MIGRATION_NAMESPACE, "attack_paths");
    assert_eq!(MIGRATIONS.len(), 1);
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("pg_advisory_xact_lock(hashtextextended('attack_paths/' || p_tenant, 0))"));
    assert!(sql.contains("SET search_path = pg_catalog, public, pg_temp"));
    assert!(sql.contains("UNIQUE (tenant, graph_digest, digest)"));
    assert!(sql.contains("PRIMARY KEY (tenant, id)"));
    assert!(sql.contains("octet_length(body) <= 1048576"));
    assert!(sql.contains("held >= p_cap"));
    assert!(sql.contains("truncated boolean NOT NULL"));
    assert!(sql.contains("budget_reached boolean NOT NULL"));
    assert!(sql.contains("unsearched_count bigint NOT NULL"));
    assert_eq!(plan_migrations(&[], &MIGRATIONS).map(|plan| plan.len())?, 1);
    Ok(())
}


#[test]
fn every_statement_is_keyed_by_the_tenant_first() -> TestResult {
    [LIST_SQL, GET_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("WHERE tenant = $1"), "{sql}"));
    assert!(STORE_SQL.contains("attack_path_report_store($1,"));
    assert!(LIST_SQL.contains("ORDER BY attack_path_report.id DESC"));
    Ok(())
}


#[tokio::test]
async fn a_report_is_stored_with_the_digest_of_its_json_bytes_and_the_incompleteness_fields() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["stored", "7"])]));
    let outcome = store_report(&exec, "acme", &graph(), &found(true, true), moment("2026-11-23T12:34:56.789+02:00")?).await?;
    assert_eq!(outcome, StoreOutcome::Stored { id: STORED_ID });
    let digest = graph_digest(&graph())?;
    let body = render_body(&build_body(digest.clone(), &found(true, true)))?;
    let seen = recorded(&calls);
    let Call { tenant, sql, params } = seen.first().ok_or("no call")?;
    assert_eq!((tenant.as_str(), *sql), ("acme", STORE_SQL));
    assert_eq!(
        params,
        &vec![
            digest,
            "2026-11-23T10:34:56Z".to_owned(),
            digest_hex(&body),
            body.clone(),
            "true".to_owned(),
            "true".to_owned(),
            TWO_UNSEARCHED.to_string(),
            MAX_REPORTS_PER_TENANT.to_string()
        ]
    );
    assert!(body.contains("\"truncated\":true"));
    assert!(body.contains("\"budget_reached\":true"));
    assert!(body.contains("\"unsearched\":[{\"id\":\"c\",\"reason\":\"path_cap\"},{\"id\":\"d\",\"reason\":\"step_budget\"}]"));
    assert!(body.contains("\"choke_points\":[{\"node\":\"m\",\"paths_through\":2}]"));
    assert!(body.contains("\"recommendations\":["));
    Ok(())
}


#[test]
fn the_incompleteness_fields_are_in_the_body_even_when_nothing_is_cut() -> TestResult {
    let (body, _) = good_body(false)?;
    assert!(body.contains("\"truncated\":false"));
    assert!(body.contains("\"budget_reached\":false"));
    assert!(body.contains("\"unsearched\":["));
    let empty = render_body(&build_body(
        "x".to_owned(),
        &PathSet {
            paths: Vec::new(),
            truncated: false,
            budget_reached: false,
            unsearched: Vec::new(),
        },
    ))?;
    assert!(empty.contains("\"unsearched\":[]"));
    Ok(())
}


#[tokio::test]
async fn the_same_inputs_answer_already_stored() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["already_stored", "7"])]));
    let outcome = store_report(&exec, "acme", &graph(), &found(false, false), moment("2026-11-23T10:00:00Z")?).await?;
    assert_eq!(outcome, StoreOutcome::AlreadyStored { id: STORED_ID });
    Ok(())
}


#[tokio::test]
async fn a_tenant_over_the_cap_is_refused_by_name_and_the_cap_is_lowered_to_the_maximum() -> TestResult {
    let calls = Calls::default();
    let when = moment("2026-11-23T10:00:00Z")?;
    let exec = answering(&calls, Ok(vec![cells(&["refused", ""])]));
    let refused = store_report_with_cap(&exec, "acme", &graph(), &found(false, false), when, SMALL_CAP).await;
    assert!(matches!(refused, Err(StoreError::CapReached { max: SMALL_CAP })));
    let high = answering(&calls, Ok(vec![cells(&["refused", ""])]));
    let lowered = store_report_with_cap(&high, "acme", &graph(), &found(false, false), when, i64::MAX).await;
    assert!(matches!(lowered, Err(StoreError::CapReached { max: MAX_REPORTS_PER_TENANT })));
    let seen = recorded(&calls);
    assert_eq!(seen.first().and_then(|call| call.params.last()), Some(&SMALL_CAP.to_string()));
    assert_eq!(seen.last().and_then(|call| call.params.last()), Some(&MAX_REPORTS_PER_TENANT.to_string()));
    Ok(())
}


#[test]
fn the_generation_time_is_written_in_utc_and_refused_outside_years_1_to_9999() -> TestResult {
    assert_eq!(generated_text(moment("2026-11-23T12:34:56.789+02:00")?)?, "2026-11-23T10:34:56Z");
    assert_eq!(generated_text(moment("9999-12-31T23:59:59Z")?)?, "9999-12-31T23:59:59Z");
    assert_eq!(generated_text(moment("0001-01-01T00:00:00Z")?)?, "0001-01-01T00:00:00Z");
    assert_eq!(generated_text(moment("0001-01-01T01:00:00+01:00")?)?, "0001-01-01T00:00:00Z");
    assert!(matches!(generated_text(moment("0000-12-31T23:59:59Z")?), Err(StoreError::BadGenerated)));
    assert!(matches!(
        generated_text(moment("0001-01-01T00:30:00+01:00")?),
        Err(StoreError::BadGenerated)
    ));
    let before_year_one = Date::from_calendar_date(-1, Month::January, 1)?.midnight().assume_utc();
    assert!(matches!(generated_text(before_year_one), Err(StoreError::BadGenerated)));
    let past_the_end = OffsetDateTime::parse("9999-12-31T23:00:00-02:00", &Rfc3339);
    assert!(past_the_end.is_err() || matches!(generated_text(past_the_end?), Err(StoreError::BadGenerated)));
    Ok(())
}


#[tokio::test]
async fn inputs_refused_before_any_io() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(vec![cells(&["stored", "1"])]));
    let when = moment("2026-11-23T10:00:00Z")?;
    let bad_tenant = store_report(&exec, "-x", &graph(), &found(false, false), when).await;
    assert!(matches!(bad_tenant, Err(StoreError::Tenant(_))));
    let mut broken = graph();
    broken.nodes.push(broken.nodes.first().ok_or("no node")?.clone());
    let duplicate = store_report(&exec, "acme", &broken, &found(false, false), when).await;
    assert!(matches!(duplicate, Err(StoreError::Graph(_))));
    let before_year_one = moment("0000-12-31T23:59:59Z")?;
    let early = store_report(&exec, "acme", &graph(), &found(false, false), before_year_one).await;
    assert!(matches!(early, Err(StoreError::BadGenerated)));
    let mut huge = found(false, false);
    huge.paths.push(route(&["a", &"x".repeat(HUGE_NODE_BYTES), "b"]));
    let large = store_report(&exec, "acme", &graph(), &huge, when).await;
    assert!(matches!(large, Err(StoreError::TooLarge { max: MAX_REPORT_BYTES, .. })));
    let mut wide = found(false, false);
    wide.paths = (0..MANY_PATHS)
        .map(|index| route(&[&format!("n{index}"), &format!("m{index}"), "b"]))
        .collect();
    assert!(paths_lower_bound(&wide) <= MAX_REPORT_BYTES);
    let exact = store_report(&exec, "acme", &graph(), &wide, when).await;
    assert!(matches!(exact, Err(StoreError::TooLarge { max: MAX_REPORT_BYTES, .. })));
    assert!(recorded(&calls).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_a_store_error_and_a_bad_row_is_refused() -> TestResult {
    let calls = Calls::default();
    let failing = answering(&calls, Err(PgError::InvalidTenant));
    let failed = store_report(&failing, "acme", &graph(), &found(false, false), moment("2026-11-23T10:00:00Z")?).await;
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
async fn a_list_is_bounded_scoped_and_carries_the_incompleteness_fields() -> TestResult {
    let calls = Calls::default();
    let row = cells(&["9", "gd", "2026-11-23T10:00:00Z", "abc", "1200", "true", "false", "2", "1700000000"]);
    let exec = answering(&calls, Ok(vec![row]));
    let metas = list_reports(&exec, "acme", PAGE).await?;
    let meta = metas.first().ok_or("no meta")?;
    assert_eq!(
        (
            meta.id,
            meta.bytes,
            meta.stored_epoch,
            meta.truncated,
            meta.budget_reached,
            meta.unsearched_count
        ),
        (LISTED_ID, LISTED_BYTES, LISTED_EPOCH, true, false, LISTED_UNSEARCHED)
    );
    let seen = recorded(&calls);
    assert_eq!(
        seen.first().map(|call| (call.tenant.as_str(), call.sql, call.params.clone())),
        Some(("acme", LIST_SQL, vec![PAGE.to_string()]))
    );
    Ok(())
}


#[tokio::test]
async fn a_list_refuses_bad_limits_tenants_failures_and_overlong_answers() -> TestResult {
    let calls = Calls::default();
    let exec = answering(&calls, Ok(Vec::new()));
    assert!(matches!(list_reports(&exec, "acme", 0).await, Err(StoreError::BadLimit { .. })));
    assert!(matches!(
        list_reports(&exec, "acme", MAX_LIST_LIMIT + 1).await,
        Err(StoreError::BadLimit { max: MAX_LIST_LIMIT })
    ));
    assert!(matches!(list_reports(&exec, "-x", 1).await, Err(StoreError::Tenant(_))));
    assert!(recorded(&calls).is_empty());
    let failing = answering(&calls, Err(PgError::InvalidTenant));
    assert!(matches!(list_reports(&failing, "acme", 1).await, Err(StoreError::Store(_))));
    let row = cells(&["9", "gd", "2026-11-23T10:00:00Z", "abc", "1200", "true", "false", "2", "1700000000"]);
    let overlong = answering(&calls, Ok(vec![row.clone(), row]));
    assert!(matches!(list_reports(&overlong, "acme", 1).await, Err(StoreError::BadRow)));
    Ok(())
}


#[test]
fn a_meta_row_must_have_nine_readable_cells() -> TestResult {
    assert!(matches!(decode_meta(&cells(&["1"])), Err(StoreError::BadRow)));
    let good = ["9", "gd", "2026-11-23T10:00:00Z", "abc", "1200", "true", "false", "2", "1700000000"];
    META_CELLS.iter().try_for_each(|index| -> TestResult {
        let mut bad = good;
        *bad.get_mut(*index).ok_or("no cell")? = "x";
        assert!(matches!(decode_meta(&cells(&bad)), Err(StoreError::BadRow)), "cell {index}");
        Ok(())
    })?;
    assert!(decode_meta(&cells(&good)).is_ok());
    Ok(())
}


#[tokio::test]
async fn a_get_returns_the_body_of_the_tenant_only_and_keeps_the_truncated_flag() -> TestResult {
    let calls = Calls::default();
    let (body, digest) = good_body(true)?;
    let exec = answering(&calls, Ok(vec![stored_row(&body, "true", "false", "2", &digest)]));
    let stored = get_report(&exec, "acme", STORED_ID).await?.ok_or("missing")?;
    assert_eq!((stored.id, stored.body.as_str()), (STORED_ID, body.as_str()));
    assert!(stored.report.truncated);
    assert!(!stored.report.budget_reached);
    assert_eq!(stored.report.unsearched.len(), TWO_UNSEARCHED);
    assert_eq!(stored.report, serde_json::from_str::<ReportBody>(&body)?);
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
    let (body, digest) = good_body(true)?;
    let edited = body.replace("\"truncated\":true", "\"truncated\":false");
    let row = cells(&[&digest, "2026-11-23T10:00:00Z", &digest_hex(&body), "true", "false", "2", &edited]);
    let exec = answering(&calls, Ok(vec![row.clone()]));
    assert!(matches!(get_report(&exec, "acme", 1).await, Err(StoreError::DigestMismatch)));
    assert!(matches!(decode_stored(1, &row), Err(StoreError::DigestMismatch)));
    Ok(())
}


#[test]
fn columns_that_disagree_with_the_body_are_refused() -> TestResult {
    let (body, digest) = good_body(true)?;
    assert!(decode_stored(1, &stored_row(&body, "true", "false", "2", &digest)).is_ok());
    [
        stored_row(&body, "false", "false", "2", &digest),
        stored_row(&body, "true", "true", "2", &digest),
        stored_row(&body, "true", "false", "1", &digest),
        stored_row(&body, "true", "false", "2", "other"),
    ]
    .iter()
    .for_each(|row| assert!(matches!(decode_stored(1, row), Err(StoreError::MetadataMismatch))));
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
    let not_json = "not json";
    let bad_body = cells(&["g", "t", &digest_hex(not_json), "true", "false", "2", not_json]);
    assert!(matches!(decode_stored(1, &bad_body), Err(StoreError::BadBody)));
    let (body, digest) = good_body(true)?;
    assert!(matches!(
        decode_stored(1, &stored_row(&body, "x", "false", "2", &digest)),
        Err(StoreError::BadRow)
    ));
    assert!(matches!(
        decode_stored(1, &stored_row(&body, "true", "x", "2", &digest)),
        Err(StoreError::BadRow)
    ));
    assert!(matches!(
        decode_stored(1, &stored_row(&body, "true", "false", "x", &digest)),
        Err(StoreError::BadRow)
    ));
    Ok(())
}


#[test]
fn the_graph_digest_follows_the_graph() -> TestResult {
    let mut other = graph();
    other.edges.clear();
    assert_ne!(graph_digest(&graph())?, graph_digest(&other)?);
    assert_eq!(graph_digest(&graph())?, graph_digest(&graph())?);
    Ok(())
}
