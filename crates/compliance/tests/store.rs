#[path = "common/types.rs"]
mod types;


use alerts::types::{Row, RowFuture};
use compliance::error::StateError;
use compliance::model::{FailedAt, RecordOutcome, Verdict};
use compliance::store::{
    apply_row, decode_rows, entries_json, plan_run, record_verdicts, record_verdicts_with_cap, row_cells, verdict_name, MAX_RUN_ENTRIES,
    MAX_STATE_ROWS_PER_TENANT, MIGRATIONS, MIGRATION_NAMESPACE, RECORD_SQL,
};
use compliance::types::{PlannedEntry, RunEntry};
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::migrate::plan_migrations;
use core_pg::query::{column_text, scoped_query};
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use core_pg::types::SqlParameter;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::future::ready;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio_postgres::Client;
use types::TestResult;


const NOW: u64 = 1_700_000_000_000_000;


const DEADLINE: Duration = Duration::from_secs(30);


const DRAIN_LIMIT: usize = 100;


const SMALL_CAP: i64 = 2;


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


const TWO: usize = 2;


const THREE: usize = 3;


const BAD_ROWS: usize = 7;


const FIRST_FAILED: u64 = 1600;


fn fail() -> Verdict {
    Verdict::Fail {
        offending: Vec::new(),
        total: 1,
    }
}


fn planned(verdict: &'static str) -> Vec<PlannedEntry> {
    vec![(("anssi".to_owned(), "ssh-01".to_owned(), "web-1".to_owned()), verdict)]
}


fn row(cells: &[&str]) -> Row {
    cells.iter().map(|cell| (*cell).to_owned()).collect()
}


fn answering(rows: Vec<Row>) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'static> {
    move |_scope, _sql, _params| -> RowFuture<'static> { Box::pin(ready(Ok(rows.clone()))) }
}


fn failing(_scope: TenantScope, _sql: &'static str, _params: Vec<String>) -> RowFuture<'static> {
    Box::pin(ready(Err(PgError::InvalidTenant)))
}


async fn pg_rows(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Row>, PgError> {
    let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
    let rows = scoped_query(client, &scope, sql, &bound, DEADLINE).await?;
    rows.iter()
        .map(|one| (0..one.len()).map(|index| column_text(one, index)).collect())
        .collect()
}


async fn client_with(handler: Handler) -> Result<(Client, Fake, TempDir), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&password_file, "p")?;
    #[cfg(unix)]
    std::fs::set_permissions(&password_file, std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        fake.port,
        password_file.display(),
        ca_file.display()
    );
    let client = connect(&parse_settings(&text, "pg.yaml")?).await?;
    Ok((client, fake, dir))
}


fn drain(fake: &mut Fake) -> Vec<String> {
    std::iter::repeat_with(|| fake.statements.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


#[test]
fn the_migration_is_registered_under_its_namespace() -> TestResult {
    assert_eq!(MIGRATION_NAMESPACE, "compliance");
    assert_eq!(plan_migrations(&[], &MIGRATIONS)?.len(), MIGRATIONS.len());
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("PRIMARY KEY (tenant, baseline, control, asset)"));
    assert!(sql.contains("verdict IN ('pass', 'fail', 'error', 'excepted')"));
    assert!(sql.contains("pg_advisory_xact_lock"));
    Ok(())
}


#[test]
fn the_statement_binds_the_tenant_first_and_every_query_filters_on_it() -> TestResult {
    assert!(RECORD_SQL.contains("compliance_record($1, $2::text::jsonb, $3::text::bigint, $4::text::bigint)"));
    let sql = MIGRATIONS.first().ok_or("no migration")?.sql;
    assert!(sql.contains("WHERE tenant = p_tenant"));
    assert!(sql.contains("s.tenant = p_tenant"));
    assert!(sql.contains("SELECT p_tenant, n.baseline"));
    assert!(sql.contains("WHEN EXCLUDED.verdict <> 'fail' THEN NULL"));
    assert!(sql.contains("WHEN st.verdict = 'fail' THEN st.first_failed_micros"));
    Ok(())
}


#[test]
fn verdicts_are_named_for_the_table() -> TestResult {
    assert_eq!(verdict_name(&Verdict::Pass), "pass");
    assert_eq!(verdict_name(&fail()), "fail");
    assert_eq!(verdict_name(&Verdict::Error { reason: "x".to_owned() }), "error");
    assert_eq!(
        verdict_name(&Verdict::Excepted {
            owner: "o".to_owned(),
            reason: "r".to_owned()
        }),
        "excepted"
    );
    Ok(())
}


#[test]
fn a_run_is_planned_sorted_deduplicated_and_skips_a_refused_entry_alone() -> TestResult {
    let pass = Verdict::Pass;
    let failed = fail();
    let run: Vec<RunEntry<'_>> = vec![
        ("b", "c", "web-2", &pass),
        ("a", "c", "web-1", &pass),
        ("a", "c", "web-1", &failed),
        ("-bad", "c", "web-1", &pass),
        ("a", "c;", "web-1", &pass),
        ("a", "c", "-web", &pass),
    ];
    let (entries, skipped) = plan_run(&run)?;
    assert_eq!(skipped, THREE);
    assert_eq!(entries.len(), TWO);
    assert_eq!(entries.first().map(|(key, verdict)| (key.0.as_str(), *verdict)), Some(("a", "fail")));
    let text = entries_json(&entries);
    assert!(text.starts_with("[{\"asset\":\"web-1\""), "{text}");
    Ok(())
}


#[test]
fn a_run_over_the_limit_is_refused_before_any_io() -> TestResult {
    let pass = Verdict::Pass;
    let run: Vec<RunEntry<'_>> = std::iter::repeat_n(("a", "c", "web-1", &pass), MAX_RUN_ENTRIES + 1).collect();
    assert!(matches!(plan_run(&run), Err(StateError::RunTooLarge { entries, max }) if entries == MAX_RUN_ENTRIES + 1 && max == MAX_RUN_ENTRIES));
    let scope = tenant_scope("acme")?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let refused = runtime.block_on(record_verdicts(&failing, &scope, &run, NOW));
    assert!(matches!(refused, Err(StateError::RunTooLarge { .. })), "{refused:?}");
    Ok(())
}


#[test]
fn a_row_is_decoded_into_the_outcome() -> TestResult {
    let entries = planned("fail");
    let stored = apply_row(&entries, RecordOutcome::default(), &row(&["1", "stored", "1600"]))?;
    assert_eq!(
        stored.failed,
        vec![FailedAt {
            baseline: "anssi".to_owned(),
            control: "ssh-01".to_owned(),
            asset: "web-1".to_owned(),
            first_failed_micros: FIRST_FAILED
        }]
    );
    let refused = apply_row(&entries, RecordOutcome::default(), &row(&["1", "refused", ""]))?;
    assert_eq!((refused.failed.len(), refused.refused_no_room), (0, 1));
    let passed = apply_row(&planned("pass"), RecordOutcome::default(), &row(&["1", "stored", ""]))?;
    assert_eq!(passed, RecordOutcome::default());
    assert_eq!(
        decode_rows(&entries, &[row(&["1", "stored", "5"]), row(&["1", "refused", ""])])?.refused_no_room,
        1
    );
    assert!(row_cells(&row(&["1", "stored"])).is_none());
    Ok(())
}


#[test]
fn an_unreadable_row_is_refused_without_its_text() -> TestResult {
    let entries = planned("fail");
    let hostile = "secret-marker";
    let bad: [Vec<&str>; BAD_ROWS] = [
        vec!["1", "stored"],
        vec![hostile, "stored", "1"],
        vec!["0", "stored", "1"],
        vec!["2", "stored", "1"],
        vec!["1", hostile, "1"],
        vec!["1", "stored", hostile],
        vec!["1", "stored", ""],
    ];
    for cells in bad {
        let error = apply_row(&entries, RecordOutcome::default(), &row(&cells)).err().ok_or("accepted")?;
        assert!(matches!(error, StateError::BadRow), "{error:?}");
        assert!(!format!("{error} {error:?}").contains(hostile));
    }
    Ok(())
}


#[tokio::test]
async fn a_run_of_only_refused_entries_does_no_io() -> TestResult {
    let scope = tenant_scope("acme")?;
    let pass = Verdict::Pass;
    let run: Vec<RunEntry<'_>> = vec![("-bad", "c", "web-1", &pass)];
    let outcome = record_verdicts(&failing, &scope, &run, NOW).await?;
    assert_eq!((outcome.skipped_invalid, outcome.failed.len()), (1, 0));
    Ok(())
}


#[tokio::test]
async fn a_time_past_the_store_range_is_refused_before_any_io() -> TestResult {
    let scope = tenant_scope("acme")?;
    let pass = Verdict::Pass;
    let run: Vec<RunEntry<'_>> = vec![("a", "c", "web-1", &pass)];
    let refused = record_verdicts(&failing, &scope, &run, u64::MAX).await;
    assert!(matches!(refused, Err(StateError::TimeOutOfRange)), "{refused:?}");
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_reported() -> TestResult {
    let scope = tenant_scope("acme")?;
    let pass = Verdict::Pass;
    let run: Vec<RunEntry<'_>> = vec![("a", "c", "web-1", &pass)];
    let refused = record_verdicts(&failing, &scope, &run, NOW).await;
    assert!(matches!(refused, Err(StateError::Store(PgError::InvalidTenant))), "{refused:?}");
    Ok(())
}


#[tokio::test]
async fn a_store_answering_garbage_is_reported() -> TestResult {
    let scope = tenant_scope("acme")?;
    let pass = Verdict::Pass;
    let run: Vec<RunEntry<'_>> = vec![("a", "c", "web-1", &pass)];
    let exec = answering(vec![row(&["9", "stored", ""])]);
    let refused = record_verdicts(&exec, &scope, &run, NOW).await;
    assert!(matches!(refused, Err(StateError::BadRow)), "{refused:?}");
    Ok(())
}


#[tokio::test]
async fn refused_entries_and_skipped_entries_are_counted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let failed = fail();
    let pass = Verdict::Pass;
    let run: Vec<RunEntry<'_>> = vec![("a", "c", "web-1", &failed), ("a", "c", "web-2", &failed), ("-x", "c", "web-3", &pass)];
    let exec = answering(vec![row(&["1", "stored", "77"]), row(&["2", "refused", ""])]);
    let outcome = record_verdicts_with_cap(&exec, &scope, &run, NOW, SMALL_CAP).await?;
    assert_eq!((outcome.failed.len(), outcome.refused_no_room, outcome.skipped_invalid), (1, 1, 1));
    Ok(())
}


#[tokio::test]
async fn a_refusal_for_room_alone_is_counted_without_a_skipped_entry() -> TestResult {
    let scope = tenant_scope("acme")?;
    let failed = fail();
    let run: Vec<RunEntry<'_>> = vec![("a", "c", "web-1", &failed)];
    let exec = answering(vec![row(&["1", "refused", ""])]);
    let outcome = record_verdicts_with_cap(&exec, &scope, &run, NOW, SMALL_CAP).await?;
    assert_eq!((outcome.failed.len(), outcome.refused_no_room, outcome.skipped_invalid), (0, 1, 0));
    Ok(())
}


#[tokio::test]
async fn the_real_client_path_binds_the_tenant_first() -> TestResult {
    let handler: Handler = Arc::new(|sql| {
        if sql.contains("compliance_record") {
            Reply::Rows(vec![vec!["1".to_owned(), "stored".to_owned(), "1600".to_owned()]])
        } else {
            Reply::Done
        }
    });
    let (client, mut fake, _dir) = client_with(handler).await?;
    let scope = tenant_scope("acme")?;
    let failed = fail();
    let run: Vec<RunEntry<'_>> = vec![("anssi", "ssh-01", "web-1", &failed)];
    let exec = |tenant: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, tenant, sql, params)) };
    let outcome = record_verdicts(&exec, &scope, &run, NOW).await?;
    assert_eq!(outcome.failed.first().map(|found| found.first_failed_micros), Some(FIRST_FAILED));
    let statements = drain(&mut fake);
    let params: Vec<&String> = statements.iter().filter(|entry| entry.starts_with("PARAMS")).collect();
    let expected_tail = format!("|{NOW}|{MAX_STATE_ROWS_PER_TENANT}");
    assert_eq!(params.len(), 1, "{statements:?}");
    assert!(
        params
            .iter()
            .all(|entry| entry.starts_with("PARAMS acme|[{") && entry.ends_with(&expected_tail)),
        "{params:?}"
    );
    Ok(())
}
