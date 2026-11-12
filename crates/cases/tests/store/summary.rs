use crate::memory::{detail_row_of, summary_row_of, Db, Entry, Forced};
use crate::types::TestResult;
use crate::{case, comment, executor, force, know_alert, observable, sent, ALERT, NOW, OTHER_ALERT, THREE, TWO};
use alerts::types::Row;
use cases::error::CaseStoreError;
use cases::model::{CaseStatus, ObservableKind, Resolution, Severity};
use cases::store::{
    add_comment, add_observable, attach_alert, create_case, format_cursor, parse_cursor, DETAIL_RESOLUTION_COLUMN, DETAIL_SQL, DETAIL_TASKS_COLUMN,
    FIRST_SUMMARY_SQL, MAX_ID_CHARS, NEXT_SUMMARY_SQL, SUMMARY_ALERTS_COLUMN, SUMMARY_CREATED_COLUMN, SUMMARY_SEVERITY_COLUMN,
};
use cases::stored::{CaseCursor, CasePage};
use cases::summary::{detail_from_row, get_case_detail, list_case_summaries, summary_from_row};
use core_pg::scope::tenant_scope;
use std::collections::{BTreeMap, BTreeSet};


const TOTAL: usize = 120;


const PAGE_SIZES: [usize; 3] = [1, 7, 50];


const CASE_COUNT_BASE: i64 = 10_000;


pub fn entry() -> Entry {
    Entry {
        case: case("acme", "c1", NOW),
        version: 1,
        alerts: BTreeMap::new(),
    }
}


pub fn replaced(row: Result<Row, impl std::fmt::Debug>, column: usize, value: &str) -> Result<Row, Box<dyn std::error::Error>> {
    let mut found = row.map_err(|error| format!("{error:?}"))?;
    *found.get_mut(column).ok_or("column")? = value.to_owned();
    Ok(found)
}


#[test]
fn summary_statements_read_no_list_column_and_keep_the_keyset_order() -> TestResult {
    [FIRST_SUMMARY_SQL, NEXT_SUMMARY_SQL, DETAIL_SQL].iter().for_each(|sql| {
        assert!(sql.contains("tenant = $1"), "{sql}");
        ["comments::text", "observables::text", "history::text", "description"]
            .iter()
            .filter(|forbidden| **forbidden != "description" || *sql != DETAIL_SQL)
            .for_each(|forbidden| assert!(!sql.contains(forbidden), "{sql} {forbidden}"));
        assert!(sql.contains("jsonb_array_length(comments)"), "{sql}");
        assert!(
            sql.contains("case_alerts.tenant = cases.tenant AND case_alerts.case_id = cases.id"),
            "{sql}"
        );
    });
    [FIRST_SUMMARY_SQL, NEXT_SUMMARY_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("ORDER BY cases.created_at DESC, cases.id DESC") && sql.contains("LIMIT")));
    assert!(NEXT_SUMMARY_SQL.contains("(created_at, id) < ($2::text::bigint, $3::text)"));
    assert!(DETAIL_SQL.contains("id = $2::text"));
    Ok(())
}


#[tokio::test]
async fn summaries_page_newest_first_and_list_every_case_once() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    for index in 0..TOTAL {
        let created = CASE_COUNT_BASE + i64::try_from(index % (TOTAL / THREE))?;
        create_case(&exec, &scope, &case("acme", &format!("case-{index:03}"), created)).await?;
    }
    create_case(&exec, &other, &case("other", "foreign", CASE_COUNT_BASE * TWO as i64)).await?;
    for size in PAGE_SIZES {
        let ids = collect_ids(&db, size).await?;
        let distinct: BTreeSet<&String> = ids.iter().collect();
        assert_eq!(ids.len(), TOTAL, "size {size}");
        assert_eq!(distinct.len(), TOTAL, "size {size}");
        assert!(!ids.iter().any(|id| id == "foreign"));
    }
    Ok(())
}


pub async fn collect_ids(db: &Db, size: usize) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let exec = executor(db);
    let scope = tenant_scope("acme")?;
    let mut ids = Vec::new();
    let mut after = None;
    let mut done = false;
    let mut attempts = 0;
    while !done && attempts <= TOTAL {
        let page = CasePage { after: after.clone(), size };
        let found = list_case_summaries(&exec, &scope, &page).await?;
        assert!(found.summaries.len() <= size);
        ids.extend(found.summaries.iter().map(|summary| summary.id.clone()));
        done = found.next.is_none();
        after = found.next;
        attempts += 1;
    }
    Ok(ids)
}


#[tokio::test]
async fn a_summary_carries_counts_and_never_the_lists() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    add_comment(&exec, &scope, "c1", &comment("one")).await?;
    add_comment(&exec, &scope, "c1", &comment("two")).await?;
    add_observable(&exec, &scope, "c1", &observable(ObservableKind::Ip, "10.0.0.1")).await?;
    know_alert(&db, "acme", ALERT);
    know_alert(&db, "acme", OTHER_ALERT);
    attach_alert(&exec, &scope, "c1", ALERT, ("tester", NOW)).await?;
    attach_alert(&exec, &scope, "c1", OTHER_ALERT, ("tester", NOW)).await?;
    let page = CasePage { after: None, size: 1 };
    let found = list_case_summaries(&exec, &scope, &page).await?;
    let summary = found.summaries.first().ok_or("empty")?;
    assert_eq!((summary.counts.tasks, summary.counts.comments, summary.counts.observables), (1, TWO, 1));
    assert_eq!((summary.counts.history, summary.counts.alerts), (0, TWO));
    assert_eq!((summary.severity, summary.status, summary.version), (Severity::High, CaseStatus::New, 1));
    assert_eq!(summary.assignee.as_deref(), Some("alice"));
    assert!(found.next.is_none());
    let detail = get_case_detail(&exec, &scope, "c1").await?.ok_or("missing")?;
    assert_eq!(&detail.summary, summary);
    assert_eq!(
        (detail.description.as_deref(), detail.template.as_deref()),
        (Some("details"), Some("incident"))
    );
    assert_eq!(detail.tasks.len(), 1);
    let rendered = serde_json::to_value(&detail)?;
    assert!(rendered.get("comments").is_none() && rendered.get("history").is_none() && rendered.get("observables").is_none());
    assert_eq!(rendered.get("id").and_then(serde_json::Value::as_str), Some("c1"));
    assert_eq!(
        rendered.get("counts").and_then(|counts| counts.get("comments")),
        Some(&serde_json::json!(TWO))
    );
    Ok(())
}


#[tokio::test]
async fn detail_is_tenant_scoped_and_refuses_a_malformed_id_before_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    assert!(get_case_detail(&exec, &tenant_scope("other")?, "c1").await?.is_none());
    assert!(get_case_detail(&exec, &scope, "c2").await?.is_none());
    let before = sent(&db);
    for bad in ["", "a\0b", &"x".repeat(MAX_ID_CHARS + 1)] {
        assert!(get_case_detail(&exec, &scope, bad).await.is_err(), "{bad:?}");
    }
    assert_eq!(sent(&db), before);
    Ok(())
}


#[tokio::test]
async fn the_resolution_of_a_closed_case_is_decoded() -> TestResult {
    let row = replaced(detail_row_of(&entry()), DETAIL_RESOLUTION_COLUMN, "false_positive")?;
    assert_eq!(detail_from_row(&row)?.resolution, Some(Resolution::FalsePositive));
    assert_eq!(
        detail_from_row(&replaced(detail_row_of(&entry()), DETAIL_RESOLUTION_COLUMN, "")?)?.resolution,
        None
    );
    Ok(())
}


#[tokio::test]
async fn malformed_summary_and_detail_rows_are_typed_errors() -> TestResult {
    let short: Row = summary_row_of(&entry())?.into_iter().take(SUMMARY_ALERTS_COLUMN).collect();
    assert!(matches!(summary_from_row(&short), Err(CaseStoreError::BadRow { .. })));
    let number = replaced(summary_row_of(&entry()), SUMMARY_CREATED_COLUMN, "x")?;
    assert!(matches!(summary_from_row(&number), Err(CaseStoreError::BadNumber { .. })));
    let label = replaced(summary_row_of(&entry()), SUMMARY_SEVERITY_COLUMN, "bogus")?;
    assert!(matches!(summary_from_row(&label), Err(CaseStoreError::BadLabels(_))));
    let resolution = replaced(detail_row_of(&entry()), DETAIL_RESOLUTION_COLUMN, "bogus")?;
    assert!(matches!(detail_from_row(&resolution), Err(CaseStoreError::BadLabels(_))));
    let tasks = replaced(detail_row_of(&entry()), DETAIL_TASKS_COLUMN, "oops")?;
    assert!(matches!(detail_from_row(&tasks), Err(CaseStoreError::BadDocument(_))));
    let no_tasks: Row = detail_row_of(&entry())?.into_iter().take(DETAIL_TASKS_COLUMN).collect();
    assert!(matches!(detail_from_row(&no_tasks), Err(CaseStoreError::BadRow { .. })));
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    force(&db, Forced::Rows(vec![short]));
    let page = CasePage { after: None, size: 1 };
    assert!(list_case_summaries(&exec, &scope, &page).await.is_err());
    force(&db, Forced::Fail);
    assert!(matches!(list_case_summaries(&exec, &scope, &page).await, Err(CaseStoreError::Pg(_))));
    force(&db, Forced::Fail);
    assert!(matches!(get_case_detail(&exec, &scope, "c1").await, Err(CaseStoreError::Pg(_))));
    Ok(())
}


#[tokio::test]
async fn a_bad_page_is_refused_before_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    create_case(&exec, &scope, &case("acme", "c1", NOW)).await?;
    let before = sent(&db);
    for size in [0, MAX_ID_CHARS] {
        let page = CasePage { after: None, size };
        assert!(matches!(
            list_case_summaries(&exec, &scope, &page).await,
            Err(CaseStoreError::BadPageSize { .. })
        ));
    }
    let forged = CaseCursor {
        created_at: -1,
        id: "c".to_owned(),
    };
    let page = CasePage {
        after: Some(forged),
        size: 1,
    };
    assert!(list_case_summaries(&exec, &scope, &page).await.is_err());
    assert_eq!(sent(&db), before);
    Ok(())
}


#[test]
fn cursors_round_trip_and_refuse_anything_else() -> TestResult {
    let cursor = CaseCursor {
        created_at: NOW,
        id: "a.b.c".to_owned(),
    };
    assert_eq!(parse_cursor(&format_cursor(&cursor))?, cursor);
    let long = format!("1.{}", "x".repeat(MAX_ID_CHARS + 1));
    let overflow = format!("{}0.id", i64::MAX);
    for bad in ["", "no-dot", ".id", "1.", "-1.id", "+1.id", "1 .id", "1.a\0b", &long, &overflow] {
        assert!(matches!(parse_cursor(bad), Err(CaseStoreError::BadCursor)), "{bad:?}");
    }
    Ok(())
}
