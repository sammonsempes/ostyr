use crate::memory::{lock, Db, Forced};
use crate::types::TestResult;
use crate::{alert, executor, sent};
use alerts::error::StoreError;
use alerts::model::Alert;
use alerts::store::{ack_playbook_feed, read_playbook_feed, MAX_PAGE_SIZE, PLAYBOOK_ACK_SQL, PLAYBOOK_FEED_SQL};
use alerts::types::Row;
use core_pg::scope::tenant_scope;


const SEQ_ONE: u64 = 41;


const CREATED_TWO: u64 = 2;


const CREATED_THREE: u64 = 3;


const CREATED_FOUR: u64 = 4;


const FOUR: usize = 4;


const AGE_SECONDS: u64 = 7;


const ALERT_COLUMNS: usize = 11;


const TWO: usize = 2;


const THREE: usize = 3;


pub fn feed_row_of(alert: &Alert, seq: &str, age: &str) -> Row {
    vec![
        alert.id.clone(),
        alert.rule_id.clone(),
        alert.rule_title.clone(),
        alert.severity.to_string(),
        alert.event_time.clone(),
        alert.created_micros.to_string(),
        alert.host_name.as_ref().map_or_else(String::new, Clone::clone),
        alert.user_name.as_ref().map_or_else(String::new, Clone::clone),
        serde_json::json!(alert.event_ids).to_string(),
        alert.summary.text.clone(),
        alert.summary.truncated.to_string(),
        alert.summary.original_bytes.to_string(),
        seq.to_owned(),
        age.to_owned(),
    ]
}


pub fn force(db: &Db, rows: Vec<Row>) {
    lock(&db.forced).push_back(Forced::Rows(rows));
}


#[tokio::test]
async fn the_feed_keeps_every_row_and_the_cause_of_each_that_does_not_decode() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let good = alert("acme", "rule", &["e1"], 1);
    let missing = alert("acme", "rule", &["e2"], CREATED_TWO);
    let mut missing_row = feed_row_of(&missing, "42", "0");
    missing_row.iter_mut().skip(1).take(ALERT_COLUMNS).for_each(String::clear);
    let mut bad_id = feed_row_of(&alert("acme", "rule", &["e3"], CREATED_THREE), "43", "0");
    bad_id.first_mut().ok_or("no id")?.push_str("-not-an-id");
    let bad_seq = feed_row_of(&alert("acme", "rule", &["e4"], CREATED_FOUR), "x", "0");
    force(&db, vec![feed_row_of(&good, "41", "7"), missing_row, bad_id, bad_seq]);
    let items = read_playbook_feed(&exec, &scope, MAX_PAGE_SIZE).await?;
    assert_eq!(items.len(), FOUR);
    let first = items.first().ok_or("no item")?;
    let decoded = first.row.as_ref().map_err(|error| error.to_string())?;
    assert_eq!((decoded.seq, decoded.age_seconds), (SEQ_ONE, AGE_SECONDS));
    assert_eq!(decoded.alert, good);
    assert_eq!(first.id, good.id);
    assert!(matches!(items.get(1).ok_or("no item")?.row, Err(StoreError::BadRow { .. })));
    assert!(items.get(1).ok_or("no item")?.id == missing.id);
    assert!(matches!(items.get(TWO).ok_or("no item")?.row, Err(StoreError::BadId)));
    assert!(matches!(items.get(THREE).ok_or("no item")?.row, Err(StoreError::BadNumber { .. })));
    let statements = lock(&db.statements);
    assert_eq!(statements.as_slice(), [("acme".to_owned(), PLAYBOOK_FEED_SQL)]);
    Ok(())
}


#[tokio::test]
async fn the_feed_page_is_bounded_before_and_after_the_query() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    assert!(matches!(read_playbook_feed(&exec, &scope, 0).await, Err(StoreError::BadPageSize { .. })));
    assert!(matches!(
        read_playbook_feed(&exec, &scope, MAX_PAGE_SIZE + 1).await,
        Err(StoreError::BadPageSize { .. })
    ));
    assert_eq!(sent(&db), 0);
    let rows: Vec<Row> = (0..THREE)
        .map(|index| feed_row_of(&alert("acme", "rule", &[&format!("e{index}")], 1), "1", "0"))
        .collect();
    force(&db, rows);
    assert_eq!(read_playbook_feed(&exec, &scope, TWO).await?.len(), TWO);
    Ok(())
}


#[tokio::test]
async fn a_failing_store_or_a_headless_row_fails_the_read() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    lock(&db.forced).push_back(Forced::Fail);
    assert!(matches!(read_playbook_feed(&exec, &scope, 1).await, Err(StoreError::Pg(_))));
    force(&db, vec![Vec::new()]);
    assert!(matches!(
        read_playbook_feed(&exec, &scope, 1).await,
        Err(StoreError::BadRow { column: 0 })
    ));
    Ok(())
}


#[tokio::test]
async fn the_feed_statements_are_tenant_scoped_and_ordered() -> TestResult {
    assert!(PLAYBOOK_FEED_SQL.contains("WHERE tenant = $1 ORDER BY seq LIMIT $2::text::bigint) o") && PLAYBOOK_FEED_SQL.ends_with("ORDER BY o.seq"));
    assert!(PLAYBOOK_FEED_SQL.contains("LEFT JOIN LATERAL (SELECT * FROM alerts WHERE tenant = o.tenant AND id = o.id) a ON true"));
    assert!(PLAYBOOK_ACK_SQL.contains("DELETE FROM playbook_outbox WHERE tenant = $1 AND id IN"));
    Ok(())
}


#[tokio::test]
async fn acknowledging_deletes_by_id_and_checks_the_answer() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    assert_eq!(ack_playbook_feed(&exec, &scope, &[]).await?, 0);
    assert_eq!(sent(&db), 0);
    let too_many: Vec<String> = vec!["a".to_owned(); MAX_PAGE_SIZE + 1];
    assert!(matches!(
        ack_playbook_feed(&exec, &scope, &too_many).await,
        Err(StoreError::BadPageSize { .. })
    ));
    assert_eq!(sent(&db), 0);
    let ids = vec!["a".to_owned(), "b".to_owned()];
    force(&db, vec![vec!["2".to_owned()]]);
    assert_eq!(ack_playbook_feed(&exec, &scope, &ids).await?, TWO);
    force(&db, Vec::new());
    assert!(matches!(ack_playbook_feed(&exec, &scope, &ids).await, Err(StoreError::BadRow { .. })));
    force(&db, vec![vec!["x".to_owned()]]);
    assert!(matches!(ack_playbook_feed(&exec, &scope, &ids).await, Err(StoreError::BadNumber { .. })));
    lock(&db.forced).push_back(Forced::Fail);
    assert!(matches!(ack_playbook_feed(&exec, &scope, &ids).await, Err(StoreError::Pg(_))));
    Ok(())
}
