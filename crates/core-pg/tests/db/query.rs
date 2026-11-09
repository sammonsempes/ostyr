use crate::certs::{loopback, make_pki};
use crate::drain;
use crate::fake::{Fake, Mode, Reply};
use crate::settings_for;
use crate::types::Handler;
use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::query::{column_text, execute_script, global_query, scoped_query};
use core_pg::scope::tenant_scope;
use rcgen::SanType;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio_postgres::Client;


const DEADLINE: Duration = Duration::from_secs(30);


const SEVEN: i32 = 7;


const TWO_TENANTS: usize = 2;


const SHORT: Duration = Duration::from_secs(2);


pub async fn client_with(handler: Handler) -> Result<(Client, Fake, TempDir), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = crate::fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem, "p", DEADLINE.as_secs())?;
    let client = connect(&settings).await?;
    Ok((client, fake, dir))
}


pub fn by_sql() -> Handler {
    Arc::new(|sql| {
        if sql.contains("HANG") {
            Reply::Hang
        } else if sql.contains("SYNTAX") {
            Reply::Error("42601")
        } else if sql.contains("TENANTS") {
            Reply::Rows(vec![vec!["acme".to_owned()], vec!["other".to_owned()]])
        } else if sql.contains("INTS") {
            Reply::IntRows(vec![SEVEN])
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn a_server_error_keeps_its_sqlstate_and_drops_its_text() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(by_sql()).await?;
    let error = execute_script(&client, "SYNTAX", DEADLINE).await.err().ok_or("accepted")?;
    assert!(matches!(&error, PgError::Server { code, class } if code == "42601" && *class == "syntax error or access rule violation"));
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains("secret-parameter-text"), "{shown}");
    let query_error = global_query(&client, "SELECT SYNTAX", DEADLINE).await.err().ok_or("accepted")?;
    assert!(matches!(query_error, PgError::Server { .. }));
    Ok(())
}


#[tokio::test]
async fn scoped_query_binds_the_tenant_first() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(by_sql()).await?;
    let scope = tenant_scope("acme")?;
    let note = "n";
    let rows = scoped_query(&client, &scope, "SELECT TENANTS WHERE tenant = $1 AND note = $2", &[&note], DEADLINE).await?;
    assert_eq!(rows.len(), TWO_TENANTS);
    assert_eq!(column_text(rows.first().ok_or("no row")?, 0)?, "acme");
    let statements = drain(&mut fake.statements);
    assert!(statements.iter().any(|sql| sql.contains("tenant = $1 AND note = $2")), "{statements:?}");
    Ok(())
}


#[tokio::test]
async fn a_column_of_the_wrong_type_is_an_error() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(by_sql()).await?;
    let rows = global_query(&client, "SELECT INTS", DEADLINE).await?;
    assert!(matches!(column_text(rows.first().ok_or("no row")?, 0), Err(PgError::Client(_))));
    Ok(())
}


#[tokio::test]
async fn a_hung_script_hits_the_statement_deadline() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(by_sql()).await?;
    tokio::time::pause();
    let error = execute_script(&client, "HANG", SHORT).await.err().ok_or("accepted")?;
    assert!(
        matches!(error, PgError::StatementTimeout { seconds } if seconds == SHORT.as_secs()),
        "{error}"
    );
    Ok(())
}


#[tokio::test]
async fn a_hung_query_hits_the_statement_deadline() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(by_sql()).await?;
    tokio::time::pause();
    let error = global_query(&client, "SELECT HANG", SHORT).await.err().ok_or("accepted")?;
    assert!(matches!(error, PgError::StatementTimeout { .. }), "{error}");
    Ok(())
}
