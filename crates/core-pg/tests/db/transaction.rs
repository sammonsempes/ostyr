use crate::drain;
use crate::fake::Reply;
use crate::query::client_with;
use crate::types::Handler;
use core_pg::error::PgError;
use core_pg::transaction::{begin, commit, cross, rollback, Boundary};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;


const DEADLINE: Duration = Duration::from_secs(30);


const SHORT: Duration = Duration::from_secs(2);


#[tokio::test]
async fn begin_commit_and_rollback_send_the_bare_statements() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|_sql| Reply::Done);
    let (client, mut fake, _dir) = client_with(handler).await?;
    begin(&client, DEADLINE).await?;
    commit(&client, DEADLINE).await?;
    rollback(&client, DEADLINE).await?;
    let statements = drain(&mut fake.statements);
    assert_eq!(statements, vec!["BEGIN".to_owned(), "COMMIT".to_owned(), "ROLLBACK".to_owned()]);
    Ok(())
}


#[tokio::test]
async fn cross_sends_the_statement_of_its_boundary() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|_sql| Reply::Done);
    let (client, mut fake, _dir) = client_with(handler).await?;
    cross(&client, Boundary::Begin, DEADLINE).await?;
    cross(&client, Boundary::Commit, DEADLINE).await?;
    cross(&client, Boundary::Rollback, DEADLINE).await?;
    assert_eq!(
        drain(&mut fake.statements),
        vec!["BEGIN".to_owned(), "COMMIT".to_owned(), "ROLLBACK".to_owned()]
    );
    Ok(())
}


#[tokio::test]
async fn a_refused_commit_is_a_server_error_with_its_sqlstate() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|sql| if sql == "COMMIT" { Reply::Error("40001") } else { Reply::Done });
    let (client, _fake, _dir) = client_with(handler).await?;
    let error = commit(&client, DEADLINE).await.err().ok_or("accepted")?;
    assert!(matches!(&error, PgError::Server { code, .. } if code == "40001"), "{error}");
    Ok(())
}


#[tokio::test]
async fn a_hung_control_statement_hits_the_client_deadline() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|_sql| Reply::Hang);
    let (client, _fake, _dir) = client_with(handler).await?;
    tokio::time::pause();
    let error = begin(&client, SHORT).await.err().ok_or("accepted")?;
    assert!(
        matches!(error, PgError::ClientDeadline { seconds } if seconds == SHORT.as_secs()),
        "{error}"
    );
    Ok(())
}


#[tokio::test]
async fn a_deadline_that_overflows_is_refused_by_name() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|_sql| Reply::Done);
    let (client, _fake, _dir) = client_with(handler).await?;
    let error = rollback(&client, Duration::MAX).await.err().ok_or("accepted")?;
    assert!(matches!(error, PgError::DeadlineOverflow), "{error}");
    Ok(())
}
