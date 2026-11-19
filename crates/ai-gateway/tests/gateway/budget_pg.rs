use crate::types::TestResult;
use ai_gateway::budget::{give_back, read_settled, reserve, Param, RESERVE_SQL, SETTLED_SQL, SETTLE_SQL, STATEMENT_DEADLINE};
use ai_gateway::limits::HELD_EXPIRY_SECONDS;
use ai_gateway::pg::{pg_budget_executor, pg_budget_rows};
use ai_gateway::types::BudgetExecutor;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_postgres::Client;


const SECRET_MODE: u32 = 0o600;


const DRAIN_LIMIT: usize = 100;


const CALLS: i64 = 3;


const TOKENS: i64 = 900;


const RESERVATION: i64 = 600;


const GIVE_BACK: i64 = 100;


const SETTLED_CALLS: i64 = 2;


const SETTLED_TOKENS: i64 = 300;


const DAY: &str = "2023-11-14";


pub async fn client_with(handler: Handler) -> Result<(Client, Fake, TempDir), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&password_file, "p")?;
    std::fs::set_permissions(&password_file, PermissionsExt::from_mode(SECRET_MODE))?;
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


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn handler() -> Handler {
    Arc::new(|sql| {
        if sql.starts_with("INSERT INTO ai_budget_day") {
            Reply::Typed {
                parameters: vec![TEXT_OID, TEXT_OID, INT8_OID, INT8_OID, INT8_OID, INT8_OID],
                columns: vec![INT8_OID, INT8_OID],
                rows: vec![vec![int8_cell(CALLS), int8_cell(TOKENS)]],
            }
        } else if sql.starts_with("SELECT calls, tokens - CASE") {
            Reply::Typed {
                parameters: vec![TEXT_OID, TEXT_OID, INT8_OID],
                columns: vec![INT8_OID, INT8_OID],
                rows: vec![vec![int8_cell(SETTLED_CALLS), int8_cell(SETTLED_TOKENS)]],
            }
        } else if sql.starts_with("UPDATE ai_budget_day") {
            Reply::Typed {
                parameters: vec![TEXT_OID, TEXT_OID, INT8_OID, INT8_OID],
                columns: vec![INT8_OID, INT8_OID],
                rows: vec![],
            }
        } else if sql.contains("BADCOLUMNS") {
            Reply::Typed {
                parameters: vec![TEXT_OID],
                columns: vec![TEXT_OID, TEXT_OID],
                rows: vec![vec![Some(b"a".to_vec()), Some(b"b".to_vec())]],
            }
        } else if sql.contains("SYNTAX") {
            Reply::Error("42601")
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn the_real_executor_binds_the_tenant_first_and_reads_two_bigint_columns() -> TestResult {
    let (client, mut fake, _dir) = client_with(handler()).await?;
    let scope = tenant_scope("acme")?;
    let exec = pg_budget_executor(&client, STATEMENT_DEADLINE);
    let borrowed: BudgetExecutor<'_, '_> = &exec;
    let settings = crate::common::settings("ok");
    let reserved = reserve(borrowed, &scope, &settings, DAY, RESERVATION).await?;
    assert_eq!(reserved, Some((CALLS, TOKENS)));
    let statements = drain(&mut fake.statements);
    let expected = format!(
        "PARAMS acme|{DAY}|{RESERVATION}|{}|{}|{HELD_EXPIRY_SECONDS}",
        settings.max_calls_per_day, settings.max_tokens_per_day
    );
    assert!(statements.iter().any(|entry| entry == &expected), "{statements:?}");
    assert!(
        statements.iter().any(|entry| entry.starts_with("SET statement_timeout")),
        "{statements:?}"
    );
    assert!(statements.iter().any(|entry| entry.as_str() == RESERVE_SQL), "{statements:?}");
    Ok(())
}


#[tokio::test]
async fn an_update_that_matches_no_row_is_an_empty_answer() -> TestResult {
    let (client, mut fake, _dir) = client_with(handler()).await?;
    let scope = tenant_scope("acme")?;
    let exec = pg_budget_executor(&client, STATEMENT_DEADLINE);
    let settled = give_back(&exec, &scope, DAY, GIVE_BACK, RESERVATION).await?;
    assert_eq!(settled, None);
    let statements = drain(&mut fake.statements);
    assert!(
        statements
            .iter()
            .any(|entry| entry == &format!("PARAMS acme|{DAY}|{GIVE_BACK}|{RESERVATION}")),
        "{statements:?}"
    );
    assert!(statements.iter().any(|entry| entry.as_str() == SETTLE_SQL), "{statements:?}");
    Ok(())
}


#[tokio::test]
async fn a_server_error_and_a_wrong_column_type_are_reduced() -> TestResult {
    let (client, _fake, _dir) = client_with(handler()).await?;
    let scope = tenant_scope("acme")?;
    let syntax = pg_budget_rows(&client, STATEMENT_DEADLINE, scope.clone(), "SELECT SYNTAX $1", vec![]).await;
    assert!(matches!(syntax, Err(PgError::Server { .. })), "{syntax:?}");
    let columns = pg_budget_rows(&client, STATEMENT_DEADLINE, scope, "SELECT BADCOLUMNS $1", vec![]).await;
    assert!(columns.is_err());
    let text = Param::Text("x".to_owned());
    assert_eq!(text, Param::Text("x".to_owned()));
    Ok(())
}


#[tokio::test]
async fn the_settled_read_binds_the_tenant_and_the_expiry_and_reads_two_bigint_columns() -> TestResult {
    let (client, mut fake, _dir) = client_with(handler()).await?;
    let scope = tenant_scope("acme")?;
    let exec = pg_budget_executor(&client, STATEMENT_DEADLINE);
    let settled = read_settled(&exec, &scope, DAY).await?;
    assert_eq!(settled, (SETTLED_CALLS, SETTLED_TOKENS));
    let statements = drain(&mut fake.statements);
    assert!(
        statements
            .iter()
            .any(|entry| entry == &format!("PARAMS acme|{DAY}|{HELD_EXPIRY_SECONDS}")),
        "{statements:?}"
    );
    assert!(statements.iter().any(|entry| entry.as_str() == SETTLED_SQL), "{statements:?}");
    Ok(())
}
