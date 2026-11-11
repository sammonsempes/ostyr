#[path = "../../../alerts/tests/pg/certs.rs"]
mod certs;
#[path = "../../../alerts/tests/pg/fake.rs"]
mod fake;
mod types;


use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::error::StoreError;
use cases::backend::pg_backend;
use cases::error::CaseStoreError;
use cases::model::{Comment, Resolution};
use cases::store::{APPLY_SQL, COMMENT_SQL, DETAIL_SQL, GET_SQL};
use cases::stored::CasePage;
use cases::transition::CaseAction;
use certs::{loopback, make_pki};
use core_audit::log::{append, genesis_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_pg::scope::tenant_scope;
use core_pg::settings::{open_settings, PgSettings};
use fake::{Fake, Mode, Reply};
use rcgen::SanType;
use std::error::Error;
use std::io::sink;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use types::Handler;


const DRAIN_LIMIT: usize = 100;


const PAGE_SIZE: usize = 10;


const WRITE_TIME: i64 = 1_700_000_100;


const FIRST_TIME: i64 = 1_700_000_000;


const WRITTEN_VERSION: i64 = 2;


const VERSION_COLUMN: usize = 8;


const STATEMENTS: usize = 2;


const SUMMARY_COLUMNS: usize = 14;


pub struct Served {
    pub engine: Arc<ReloadEngine<PgSettings>>,
    pub fake: Fake,
    pub _dir: TempDir,
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn summary_row() -> Vec<String> {
    let columns = [
        "c1",
        "Case c1",
        "high",
        "new",
        "alice",
        "malware",
        "1700000000",
        "1700000000",
        "1",
        "1",
        "0",
        "2",
        "0",
        "0",
    ];
    assert_eq!(columns.len(), SUMMARY_COLUMNS);
    columns.iter().map(|column| (*column).to_owned()).collect()
}


pub fn detail_row() -> Vec<String> {
    let mut row = summary_row();
    row.extend(["details", "", "incident", "[]"].iter().map(|column| (*column).to_owned()));
    row
}


pub fn case_handler() -> Handler {
    Arc::new(|sql| {
        if sql.contains("FROM cases WHERE tenant = $1 AND id = $2") {
            Reply::Rows(vec![detail_row()])
        } else if sql.contains("FROM cases") {
            Reply::Rows(vec![summary_row()])
        } else {
            Reply::Done
        }
    })
}


pub async fn served(handler: Handler) -> Result<Served, Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", handler).await?;
    let dir = tempdir()?;
    let password_file = dir.path().join("pg.pass");
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&password_file, "p")?;
    std::fs::write(&ca_file, &pki.ca_pem)?;
    let settings_text = format!(
        "host: 127.0.0.1\nport: {}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        fake.port,
        password_file.display(),
        ca_file.display()
    );
    let settings_file = dir.path().join("pg.yaml");
    std::fs::write(&settings_file, settings_text)?;
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "acme".to_owned(),
        module: "cases".to_owned(),
        target: settings_file.display().to_string(),
        request_id: "test".to_owned(),
    };
    let engine = Arc::new(open_settings(settings_file, Box::new(move |entry| append(&log, entry)), context)?);
    Ok(Served { engine, fake, _dir: dir })
}


#[tokio::test]
async fn the_pg_backend_lists_and_gets_through_a_leased_connection_scoped_to_the_tenant() -> Result<(), Box<dyn Error>> {
    let mut served = served(case_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let page = CasePage {
        after: None,
        size: PAGE_SIZE,
    };
    let listed = (backend.list)(scope.clone(), page).await?;
    assert_eq!(listed.summaries.len(), 1);
    let found = (backend.get)(scope, "c1".to_owned()).await?;
    assert_eq!(found.map(|detail| detail.summary.id), Some("c1".to_owned()));
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert_eq!(bound.len(), STATEMENTS, "{bound:?}");
    assert!(bound.iter().all(|entry| entry.starts_with("PARAMS acme|")), "{bound:?}");
    Ok(())
}


#[tokio::test]
async fn a_full_pool_is_busy_before_any_connection() -> Result<(), Box<dyn Error>> {
    let served = served(case_handler()).await?;
    let permits = Arc::new(Semaphore::new(0));
    let refused = lease(&served.engine, &permits).await.err().ok_or("leased")?;
    assert!(matches!(refused, StoreError::Busy));
    let backend = pg_backend(Arc::clone(&served.engine), permits);
    let scope = tenant_scope("acme")?;
    let page = CasePage {
        after: None,
        size: PAGE_SIZE,
    };
    assert!(matches!(
        (backend.list)(scope.clone(), page).await,
        Err(CaseStoreError::Lease(StoreError::Busy))
    ));
    assert!(matches!(
        (backend.get)(scope, "c1".to_owned()).await,
        Err(CaseStoreError::Lease(StoreError::Busy))
    ));
    Ok(())
}


pub fn get_row() -> Vec<String> {
    [
        "c1",
        "Case c1",
        "details",
        "high",
        "new",
        "",
        "alice",
        "incident",
        "malware",
        "1700000000",
        "1700000000",
        "1",
        "[]",
        "[]",
        "[]",
        "[]",
    ]
    .iter()
    .map(|column| (*column).to_owned())
    .collect()
}


pub fn write_handler() -> Handler {
    Arc::new(|sql| {
        if sql == GET_SQL {
            Reply::Rows(vec![get_row()])
        } else if sql == APPLY_SQL {
            Reply::Rows(vec![vec!["2".to_owned()]])
        } else if sql == DETAIL_SQL {
            let mut row = detail_row();
            row.iter_mut().for_each(|cell| {
                if cell == "new" {
                    "in_progress".clone_into(cell);
                }
            });
            row.get_mut(VERSION_COLUMN)
                .into_iter()
                .for_each(|cell| WRITTEN_VERSION.to_string().clone_into(cell));
            Reply::Rows(vec![row])
        } else if sql == COMMENT_SQL {
            Reply::Rows(vec![vec!["1".to_owned(), "1".to_owned(), "0".to_owned()]])
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn the_pg_backend_acts_and_comments_through_a_leased_connection_scoped_to_the_tenant() -> Result<(), Box<dyn Error>> {
    let mut served = served(write_handler()).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let backend = pg_backend(Arc::clone(&served.engine), Arc::clone(&permits));
    let scope = tenant_scope("acme")?;
    let detail = (backend.act)(scope.clone(), "c1".to_owned(), CaseAction::Start, "alice".to_owned(), WRITE_TIME).await?;
    assert_eq!(detail.summary.version, WRITTEN_VERSION);
    let comment = Comment {
        author: "alice".to_owned(),
        at: WRITE_TIME,
        text: "hello".to_owned(),
    };
    (backend.comment)(scope.clone(), "c1".to_owned(), comment).await?;
    assert!((backend.clock)() > FIRST_TIME);
    assert_eq!(permits.available_permits(), MAX_CONNECTIONS);
    let bound: Vec<String> = drain(&mut served.fake.statements)
        .into_iter()
        .filter(|entry| entry.starts_with("PARAMS"))
        .collect();
    assert!(
        !bound.is_empty() && bound.iter().all(|entry| entry.starts_with("PARAMS acme|")),
        "{bound:?}"
    );
    let busy = pg_backend(Arc::clone(&served.engine), Arc::new(Semaphore::new(0)));
    let closing = CaseAction::Close(Some(Resolution::Benign));
    assert!(matches!(
        (busy.act)(scope.clone(), "c1".to_owned(), closing, "alice".to_owned(), 1).await,
        Err(CaseStoreError::Lease(StoreError::Busy))
    ));
    let again = Comment {
        author: "alice".to_owned(),
        at: 1,
        text: "x".to_owned(),
    };
    assert!(matches!(
        (busy.comment)(scope, "c1".to_owned(), again).await,
        Err(CaseStoreError::Lease(StoreError::Busy))
    ));
    Ok(())
}
