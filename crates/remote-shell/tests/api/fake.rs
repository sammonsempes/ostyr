use core_pg::scope::{tenant_of, TenantScope};
use remote_shell::api_model::SessionsBackend;
use remote_shell::error::StoreError;
use remote_shell::serve::{get_session, list_page};
use remote_shell::store::{LIST_AFTER_SQL, SESSION_SQL};
use remote_shell::store_model::{Cell, Param, Statement};
use remote_shell::types::Row;
use std::future::ready;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;


pub const OPENED: i64 = 1_800_000_000;


pub const CLOSED: i64 = 1_800_000_600;


pub const FRAMES: i64 = 5;


pub const HASH_FILL: u8 = 171;


pub const HASH_BYTES: usize = 32;


pub const BYTES: i64 = 2_048;


pub const IDX_OPEN: usize = 2;


pub const IDX_LIMIT: usize = 3;


pub const IDX_AFTER_AT: usize = 4;


pub const IDX_AFTER_ID: usize = 5;


pub struct Entry {
    pub tenant: String,
    pub session: String,
    pub requester: String,
    pub asset: String,
    pub opened: i64,
    pub closed: bool,
    pub row: Row,
}


#[derive(Default)]
pub struct Fake {
    pub entries: Mutex<Vec<Entry>>,
    pub statements: Mutex<Vec<&'static str>>,
}


pub fn row_of(session: &str, requester: &str, asset: &str, opened: i64, closed: bool) -> Row {
    let text = |value: &str| Cell::Text(value.to_owned());
    let (closed_at, reason, frames, hash, bytes) = if closed {
        (
            Cell::Int(CLOSED),
            text("user_close"),
            Cell::Int(FRAMES),
            Cell::Bytes(vec![HASH_FILL; HASH_BYTES]),
            Cell::Int(BYTES),
        )
    } else {
        (Cell::Null, Cell::Null, Cell::Null, Cell::Null, Cell::Null)
    };
    vec![
        text(session),
        text(requester),
        text(asset),
        text("INC-1"),
        Cell::Int(opened),
        closed_at,
        reason,
        frames,
        hash,
        bytes,
    ]
}


pub fn put(fake: &Fake, tenant: &str, session: &str, requester: &str, asset: &str, opened: i64, closed: bool) {
    if let Ok(mut entries) = fake.entries.lock() {
        entries.push(Entry {
            tenant: tenant.to_owned(),
            session: session.to_owned(),
            requester: requester.to_owned(),
            asset: asset.to_owned(),
            opened,
            closed,
            row: row_of(session, requester, asset, opened, closed),
        });
    }
}


pub fn read_count(fake: &Fake) -> usize {
    fake.statements.lock().map_or(0, |statements| statements.len())
}


fn text_param(params: &[Param], index: usize) -> String {
    match params.get(index) {
        Some(Param::Text(value)) => value.clone(),
        _ => String::new(),
    }
}


fn int_param(params: &[Param], index: usize) -> i64 {
    match params.get(index) {
        Some(Param::Int(value)) => *value,
        _ => 0,
    }
}


pub fn answer(fake: &Fake, scope: &TenantScope, statement: &Statement) -> Result<Vec<Row>, StoreError> {
    if let Ok(mut statements) = fake.statements.lock() {
        statements.push(statement.sql);
    }
    let entries = fake.entries.lock().map_err(|_poisoned| StoreError::BadRow { column: "lock" })?;
    let mut mine: Vec<&Entry> = entries.iter().filter(|entry| entry.tenant == tenant_of(scope)).collect();
    let params = &statement.params;
    Ok(if statement.sql == SESSION_SQL {
        let wanted = text_param(params, 0);
        mine.into_iter()
            .filter(|entry| entry.session == wanted)
            .map(|entry| entry.row.clone())
            .collect()
    } else {
        let asset = text_param(params, 0);
        let requester = text_param(params, 1);
        let open_only = matches!(params.get(IDX_OPEN), Some(Param::Bool(true)));
        let limit = usize::try_from(int_param(params, IDX_LIMIT)).unwrap_or(0);
        let after = (statement.sql == LIST_AFTER_SQL).then(|| (int_param(params, IDX_AFTER_AT), text_param(params, IDX_AFTER_ID)));
        mine.sort_by(|left, right| (right.opened, &right.session).cmp(&(left.opened, &left.session)));
        mine.into_iter()
            .filter(|entry| asset.is_empty() || entry.asset == asset)
            .filter(|entry| requester.is_empty() || entry.requester == requester)
            .filter(|entry| !open_only || !entry.closed)
            .filter(|entry| {
                after
                    .as_ref()
                    .is_none_or(|(at, id)| (entry.opened, entry.session.clone()) < (*at, id.clone()))
            })
            .take(limit)
            .map(|entry| entry.row.clone())
            .collect()
    })
}


pub fn memory_backend(fake: &Arc<Fake>) -> SessionsBackend {
    let list_fake = Arc::clone(fake);
    let get_fake = Arc::clone(fake);
    SessionsBackend {
        list: Arc::new(move |scope, filter, after, limit| {
            let held = Arc::clone(&list_fake);
            Box::pin(async move {
                let mut exec = |bound: &TenantScope, statement: Statement| ready(answer(&held, bound, &statement));
                list_page(&mut exec, &scope, &filter, after.as_deref(), limit).await
            })
        }),
        get: Arc::new(move |scope, session_id| {
            let held = Arc::clone(&get_fake);
            Box::pin(async move {
                let mut exec = |bound: &TenantScope, statement: Statement| ready(answer(&held, bound, &statement));
                get_session(&mut exec, &scope, &session_id).await
            })
        }),
    }
}


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[derive(Clone, Default)]
pub struct Capture {
    pub bytes: Arc<Mutex<Vec<u8>>>,
}


impl std::io::Write for Capture {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let mut bytes = self.bytes.lock().map_err(|_poisoned| std::io::Error::other("poisoned"))?;
        bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


pub fn capture_dispatch(capture: &Capture) -> Dispatch {
    LazyLock::force(&ANCHOR);
    let writer = capture.clone();
    Dispatch::new(tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish())
}


pub fn captured(capture: &Capture) -> String {
    String::from_utf8_lossy(&capture.bytes.lock().unwrap_or_else(std::sync::PoisonError::into_inner)).into_owned()
}
