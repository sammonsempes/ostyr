use alerts::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use std::cmp::Reverse;
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use vuln_match::store::{ASSET_SQL, FIRST_SQL, NEXT_SQL};


pub const SEEN: &str = "1700000000000000";


pub const COL_PRIORITY: usize = 9;


pub const COL_CVSS: usize = 6;


pub const KEY_COLUMNS: usize = 4;


pub const NEXT_PARAMS: usize = 6;


#[derive(Default)]
pub struct State {
    pub rows: Vec<(String, Row)>,
    pub reads: Vec<(String, &'static str)>,
    pub forced: Option<Vec<Row>>,
}


#[derive(Default)]
pub struct Fake {
    pub state: Mutex<State>,
}


pub fn bad<Cause>(_error: Cause) -> PgError {
    PgError::InvalidTenant
}


pub fn priority_of(row: &Row) -> u64 {
    row.get(COL_PRIORITY).and_then(|text| text.parse().ok()).unwrap_or(0)
}


pub fn key_of(row: &Row) -> Vec<String> {
    row.iter().take(KEY_COLUMNS).cloned().collect()
}


pub fn cells_of(key: (&str, &str, &str, &str), priority: u32) -> Row {
    [
        key.0,
        key.1,
        key.2,
        key.3,
        "1.0-1",
        "1.2",
        "7.5",
        "0.5",
        "false",
        &priority.to_string(),
        SEEN,
        SEEN,
    ]
    .map(str::to_owned)
    .to_vec()
}


pub fn put(fake: &Fake, tenant: &str, cells: Row) {
    let mut state = fake.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.rows.push((tenant.to_owned(), cells));
}


pub fn recorded(fake: &Fake) -> Vec<(String, &'static str)> {
    fake.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).reads.clone()
}


pub fn ordered(state: &State, tenant: &str, keep: impl Fn(&Row) -> bool) -> Vec<Row> {
    let mut rows: Vec<Row> = state
        .rows
        .iter()
        .filter(|(owner, row)| owner == tenant && keep(row))
        .map(|(_owner, row)| row.clone())
        .collect();
    rows.sort_by_key(|row| (Reverse(priority_of(row)), key_of(row)));
    rows
}


pub fn limit_of(params: &[String], index: usize) -> Result<usize, PgError> {
    params.get(index).ok_or(PgError::InvalidTenant)?.parse().map_err(bad)
}


pub fn next_rows(state: &State, tenant: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let priority: u64 = params.first().ok_or(PgError::InvalidTenant)?.parse().map_err(bad)?;
    let key: Vec<String> = params.iter().skip(1).take(KEY_COLUMNS).cloned().collect();
    let limit = limit_of(params, NEXT_PARAMS - 1)?;
    Ok(ordered(state, tenant, |row| {
        (Reverse(priority_of(row)), key_of(row)) > (Reverse(priority), key.clone())
    })
    .into_iter()
    .take(limit)
    .collect())
}


pub fn answer(fake: &Fake, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    let mut state = fake.state.lock().map_err(bad)?;
    state.reads.push((tenant.clone(), sql));
    if let Some(rows) = state.forced.clone() {
        Ok(rows)
    } else if sql == FIRST_SQL {
        Ok(ordered(&state, &tenant, |_row| true).into_iter().take(limit_of(params, 0)?).collect())
    } else if sql == NEXT_SQL {
        next_rows(&state, &tenant, params)
    } else if sql == ASSET_SQL {
        let asset = params.first().ok_or(PgError::InvalidTenant)?;
        Ok(ordered(&state, &tenant, |row| row.first() == Some(asset))
            .into_iter()
            .take(limit_of(params, 1)?)
            .collect())
    } else {
        Err(PgError::InvalidTenant)
    }
}


pub fn executor<'a>(fake: &'a Fake) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(std::future::ready(answer(fake, &scope, sql, &params))) }
}


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[derive(Clone, Default)]
pub struct Capture {
    pub bytes: Arc<Mutex<Vec<u8>>>,
}


impl Write for Capture {
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
