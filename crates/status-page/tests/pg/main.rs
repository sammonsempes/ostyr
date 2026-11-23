#[path = "../common/types.rs"]
mod types;


use core_pg::connect::connect;
use core_pg::error::PgError;
use core_pg::scope::{tenant_scope, TenantScope};
use core_pg::settings::parse_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT4_OID, INT8_OID, TEXT_OID};
use pg_fake::types::Handler;
use rcgen::SanType;
use status_page::error::StoreError;
use status_page::pg::execute;
use status_page::store::{
    add_update, create_incident, published_incidents, resolve_incident, CREATE_SQL, MAX_PUBLISHED, PUBLISHED_SQL, RESOLVE_SQL, UPDATES_SQL,
    UPDATE_SQL,
};
use status_page::store_model::{Cell, IncidentRef, NewIncident, Param, Statement};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_postgres::Client;
use types::TestResult;


const READ_STATEMENTS: usize = 2;


const BOOL_OID: i32 = 16;


const TEXT_ARRAY_OID: i32 = 1009;


const DRAIN_LIMIT: usize = 100;


const TENANT: &str = "acme";


const OTHER_TENANT: &str = "globex";


const SERVICE: &str = "svc-web";


const STARTED: i64 = 1_700_000_000;


const ID: i64 = 42;


const VERSION: i64 = 3;


const SHORT_SECONDS: u64 = 7;


const SHORT_DEADLINE: Duration = Duration::from_secs(SHORT_SECONDS);


const LONG_DEADLINE: Duration = Duration::from_secs(30);


const ONE_DIMENSION: u32 = 1;


const SELECT_ONE: &str = "SELECT $1";


const SELECT_ALL: &str = "SELECT $1, $2, $3, $4, $5";


pub struct Served {
    pub client: Client,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn text(value: &str) -> Option<Vec<u8>> {
    Some(value.as_bytes().to_vec())
}


pub async fn served(handler: Handler) -> Result<Served, Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    write_secret(&password_file, "p")?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let yaml = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        fake.port,
        password_file.display(),
        ca_file.display()
    );
    let settings = parse_settings(&yaml, "pg.yaml")?;
    let client = connect(&settings).await?;
    Ok(Served { client, fake, _dir: dir })
}


pub fn replying(sql: &'static str, reply: Reply) -> Handler {
    Arc::new(move |received| if received == sql { reply.clone() } else { Reply::Done })
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn bound(served: &mut Served) -> Vec<String> {
    drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect()
}


pub fn pair_reply(parameters: Vec<i32>) -> Reply {
    Reply::Typed {
        parameters,
        columns: vec![INT8_OID, INT8_OID],
        rows: vec![vec![int8_cell(ID), int8_cell(VERSION)]],
    }
}


pub fn incident() -> NewIncident {
    NewIncident {
        service: SERVICE.to_owned(),
        title: "Down".to_owned(),
        published: true,
        started_at: STARTED,
        internal_note: "note".to_owned(),
    }
}


pub fn reference() -> IncidentRef {
    IncidentRef { id: ID, version: VERSION }
}


pub fn text_array(items: &[&str]) -> Result<String, Box<dyn Error>> {
    let header = [ONE_DIMENSION, 0, TEXT_OID.unsigned_abs(), u32::try_from(items.len())?, ONE_DIMENSION];
    let mut bytes: Vec<u8> = header.iter().flat_map(|word| word.to_be_bytes()).collect();
    items.iter().try_for_each(|item| {
        bytes.extend_from_slice(&u32::try_from(item.len())?.to_be_bytes());
        bytes.extend_from_slice(item.as_bytes());
        Ok::<(), Box<dyn Error>>(())
    })?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("oid{TEXT_ARRAY_OID}:{hex}"))
}


pub fn scope(tenant: &str) -> Result<TenantScope, Box<dyn Error>> {
    Ok(tenant_scope(tenant)?)
}


pub fn statement(sql: &'static str) -> Statement {
    Statement { sql, params: Vec::new() }
}


pub fn single(columns: Vec<i32>, row: Vec<Option<Vec<u8>>>) -> Reply {
    Reply::Typed {
        parameters: vec![TEXT_OID],
        columns,
        rows: vec![row],
    }
}


pub fn store_error<Value: std::fmt::Debug>(outcome: Result<Value, StoreError>) -> Result<StoreError, Box<dyn Error>> {
    match outcome {
        Err(error) => Ok(error),
        Ok(value) => Err(format!("expected an error, got {value:?}").into()),
    }
}


#[tokio::test]
async fn create_incident_binds_the_tenant_first() -> TestResult {
    let reply = pair_reply(vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID, TEXT_OID]);
    let mut served = served(replying(CREATE_SQL, reply)).await?;
    let bound_scope = scope(TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    let created = create_incident(&mut exec, &bound_scope, &incident()).await?;
    assert_eq!(created, reference());
    let params = bound(&mut served);
    assert_eq!(params, vec![format!("PARAMS acme|svc-web|Down|oid16:01|{STARTED}|note")]);
    Ok(())
}


#[tokio::test]
async fn an_unpublished_incident_binds_a_false_bool() -> TestResult {
    let reply = pair_reply(vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID, TEXT_OID]);
    let mut served = served(replying(CREATE_SQL, reply)).await?;
    let bound_scope = scope(TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    let hidden = NewIncident {
        published: false,
        ..incident()
    };
    create_incident(&mut exec, &bound_scope, &hidden).await?;
    let params = bound(&mut served);
    assert_eq!(params, vec![format!("PARAMS acme|svc-web|Down|oid16:00|{STARTED}|note")]);
    Ok(())
}


#[tokio::test]
async fn another_scope_binds_another_tenant() -> TestResult {
    let reply = pair_reply(vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID, TEXT_OID]);
    let mut served = served(replying(CREATE_SQL, reply)).await?;
    let other = scope(OTHER_TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    create_incident(&mut exec, &other, &incident()).await?;
    let params = bound(&mut served);
    assert!(params.iter().all(|entry| entry.starts_with("PARAMS globex|svc-web|")), "{params:?}");
    Ok(())
}


#[tokio::test]
async fn add_update_binds_the_tenant_first() -> TestResult {
    let reply = pair_reply(vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID, TEXT_OID, TEXT_OID, INT8_OID]);
    let mut served = served(replying(UPDATE_SQL, reply)).await?;
    let bound_scope = scope(TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    let updated = add_update(&mut exec, &bound_scope, reference(), STARTED, "msg", "private").await?;
    assert_eq!(updated, reference());
    let params = bound(&mut served);
    let expected = format!("PARAMS acme|{ID}|{VERSION}|{STARTED}|msg|private|100");
    assert_eq!(params, vec![expected]);
    Ok(())
}


#[tokio::test]
async fn resolve_incident_binds_the_tenant_first() -> TestResult {
    let reply = pair_reply(vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID]);
    let mut served = served(replying(RESOLVE_SQL, reply)).await?;
    let bound_scope = scope(TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    resolve_incident(&mut exec, &bound_scope, reference(), STARTED).await?;
    let params = bound(&mut served);
    assert_eq!(params, vec![format!("PARAMS acme|{ID}|{VERSION}|{STARTED}")]);
    Ok(())
}


#[tokio::test]
async fn published_incidents_are_read_with_the_tenant_first() -> TestResult {
    let incidents = Reply::Typed {
        parameters: vec![TEXT_OID, INT8_OID, TEXT_ARRAY_OID],
        columns: vec![INT8_OID, TEXT_OID, TEXT_OID, INT8_OID, INT8_OID, INT8_OID],
        rows: vec![vec![int8_cell(ID), text(SERVICE), text("Down"), int8_cell(STARTED), None, int8_cell(0)]],
    };
    let handler: Handler = Arc::new(move |sql| {
        if sql == PUBLISHED_SQL {
            incidents.clone()
        } else if sql == UPDATES_SQL {
            Reply::Typed {
                parameters: vec![TEXT_OID, INT8_OID, INT8_OID, INT8_OID, TEXT_ARRAY_OID],
                columns: vec![INT8_OID, INT8_OID, TEXT_OID],
                rows: Vec::new(),
            }
        } else {
            Reply::Done
        }
    });
    let mut served = served(handler).await?;
    let bound_scope = scope(TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    let services = vec![SERVICE.to_owned()];
    let read = published_incidents(&mut exec, &bound_scope, &services, MAX_PUBLISHED).await?;
    assert_eq!(read.len(), 1);
    assert_eq!(read.first().map(|item| item.resolved_at), Some(None));
    assert_eq!(read.first().map(|item| item.tenant.as_str()), Some(TENANT));
    let params = bound(&mut served);
    assert_eq!(params.len(), READ_STATEMENTS, "{params:?}");
    let array = text_array(&[SERVICE])?;
    assert!(params.contains(&format!("PARAMS acme|500|{array}")), "{params:?}");
    assert!(
        params.iter().all(|entry| entry.starts_with("PARAMS acme|") && entry.ends_with(&array)),
        "{params:?}"
    );
    Ok(())
}


#[tokio::test]
async fn a_server_error_is_a_store_error() -> TestResult {
    let served = served(replying(SELECT_ONE, Reply::Error("42601"))).await?;
    let error = store_error(execute(&served.client, scope(TENANT)?, statement(SELECT_ONE), LONG_DEADLINE).await)?;
    assert!(matches!(error, StoreError::Pg(PgError::Server { .. })), "{error}");
    Ok(())
}


#[tokio::test]
async fn a_dropped_connection_is_a_store_error() -> TestResult {
    let dropping: Handler = Arc::new(|sql| {
        if sql.starts_with("SET statement_timeout") {
            Reply::Drop
        } else {
            Reply::Done
        }
    });
    let served = served(dropping).await?;
    let error = store_error(execute(&served.client, scope(TENANT)?, statement(SELECT_ONE), LONG_DEADLINE).await)?;
    assert!(matches!(error, StoreError::Pg(_)), "{error}");
    Ok(())
}


#[tokio::test]
async fn a_hanging_statement_times_out_at_the_passed_deadline() -> TestResult {
    let pausing: Handler = Arc::new(|sql| {
        if sql == SELECT_ONE {
            tokio::time::pause();
            Reply::Hang
        } else {
            Reply::Done
        }
    });
    let served = served(pausing).await?;
    let error = store_error(execute(&served.client, scope(TENANT)?, statement(SELECT_ONE), SHORT_DEADLINE).await)?;
    assert!(
        matches!(error, StoreError::Pg(PgError::ClientDeadline { seconds: SHORT_SECONDS })),
        "{error}"
    );
    Ok(())
}


#[tokio::test]
async fn cells_decode_as_int_null_and_text() -> TestResult {
    let reply = single(vec![INT8_OID, INT8_OID, TEXT_OID], vec![int8_cell(ID), None, text("hello")]);
    let served = served(replying(SELECT_ONE, reply)).await?;
    let rows = execute(&served.client, scope(TENANT)?, statement(SELECT_ONE), LONG_DEADLINE).await?;
    assert_eq!(rows, vec![vec![Cell::Int(ID), Cell::Null, Cell::Text("hello".to_owned())]]);
    Ok(())
}


#[tokio::test]
async fn a_column_of_another_type_refuses_the_row() -> TestResult {
    let int4 = single(vec![INT4_OID], vec![Some(vec![0, 0, 0, 1])]);
    let boolean = single(vec![BOOL_OID], vec![Some(vec![1])]);
    for reply in [int4, boolean] {
        let served = served(replying(SELECT_ONE, reply)).await?;
        let error = store_error(execute(&served.client, scope(TENANT)?, statement(SELECT_ONE), LONG_DEADLINE).await)?;
        assert!(matches!(error, StoreError::BadRow { column: "cell" }), "{error}");
    }
    Ok(())
}


#[tokio::test]
async fn a_null_text_refuses_the_row() -> TestResult {
    let served = served(replying(SELECT_ONE, single(vec![TEXT_OID], vec![None]))).await?;
    let error = store_error(execute(&served.client, scope(TENANT)?, statement(SELECT_ONE), LONG_DEADLINE).await)?;
    assert!(matches!(error, StoreError::BadRow { column: "cell" }), "{error}");
    Ok(())
}


#[tokio::test]
async fn a_text_where_an_integer_is_read_is_refused() -> TestResult {
    let reply = Reply::Typed {
        parameters: vec![TEXT_OID, TEXT_OID, TEXT_OID, BOOL_OID, INT8_OID, TEXT_OID],
        columns: vec![TEXT_OID, INT8_OID],
        rows: vec![vec![text("x"), int8_cell(VERSION)]],
    };
    let served = served(replying(CREATE_SQL, reply)).await?;
    let bound_scope = scope(TENANT)?;
    let mut exec = |query_scope: &TenantScope, statement: Statement| execute(&served.client, query_scope.clone(), statement, LONG_DEADLINE);
    let error = store_error(create_incident(&mut exec, &bound_scope, &incident()).await)?;
    assert!(matches!(error, StoreError::BadRow { column: "id" }), "{error}");
    Ok(())
}


#[tokio::test]
async fn every_param_kind_is_bound() -> TestResult {
    let reply = Reply::Typed {
        parameters: vec![TEXT_OID, INT8_OID, TEXT_OID, BOOL_OID, TEXT_ARRAY_OID],
        columns: Vec::new(),
        rows: Vec::new(),
    };
    let mut served = served(replying(SELECT_ALL, reply)).await?;
    let all = Statement {
        sql: SELECT_ALL,
        params: vec![
            Param::Int(ID),
            Param::Text("t".to_owned()),
            Param::Bool(true),
            Param::Texts(vec!["a".to_owned(), "bc".to_owned()]),
        ],
    };
    execute(&served.client, scope(TENANT)?, all, LONG_DEADLINE).await?;
    let params = bound(&mut served);
    let array = text_array(&["a", "bc"])?;
    assert_eq!(params, vec![format!("PARAMS acme|{ID}|t|oid16:01|{array}")]);
    Ok(())
}


#[cfg(unix)]
const SECRET_MODE: u32 = 0o600;


#[cfg(unix)]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)?;
    std::fs::set_permissions(path.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(SECRET_MODE))
}


#[cfg(not(unix))]
fn write_secret(path: impl AsRef<std::path::Path>, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path.as_ref(), content)
}
