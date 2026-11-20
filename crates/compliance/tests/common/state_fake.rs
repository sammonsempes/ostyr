use alerts::types::{Row, RowFuture};
use compliance::read::{ASSET_SQL, LIST_ALL_BASELINE_SQL, LIST_ALL_SQL, LIST_VERDICT_BASELINE_SQL, LIST_VERDICT_SQL};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use std::collections::BTreeMap;
use std::io::Write;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;


pub const SECOND: usize = 2;


pub const THIRD: usize = 3;


pub const FOURTH: usize = 4;


#[derive(Debug, Clone)]
pub struct Cells {
    pub verdict: String,
    pub first_failed: String,
    pub last_seen: String,
}


#[derive(Default)]
pub struct State {
    pub rows: BTreeMap<(String, String, String, String), Cells>,
    pub reads: Vec<(String, &'static str)>,
    pub forced: Option<Vec<Row>>,
}


#[derive(Default)]
pub struct Fake {
    pub state: Mutex<State>,
    pub fail: bool,
}


pub fn bad<Cause>(_error: Cause) -> PgError {
    PgError::InvalidTenant
}


pub fn param<Parsed: FromStr>(params: &[String], index: usize) -> Result<Parsed, PgError> {
    params.get(index).ok_or(PgError::InvalidTenant)?.parse().map_err(bad)
}


pub fn row_of(key: &(String, String, String, String), cells: &Cells) -> Row {
    vec![
        key.1.clone(),
        key.2.clone(),
        key.3.clone(),
        cells.verdict.clone(),
        cells.first_failed.clone(),
        cells.last_seen.clone(),
    ]
}


pub fn put(fake: &Fake, tenant: &str, key: (&str, &str, &str), cells: (&str, &str, &str)) {
    let mut state = fake.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.rows.insert(
        (tenant.to_owned(), key.0.to_owned(), key.1.to_owned(), key.2.to_owned()),
        Cells {
            verdict: cells.0.to_owned(),
            first_failed: cells.1.to_owned(),
            last_seen: cells.2.to_owned(),
        },
    );
}


pub fn recorded(fake: &Fake) -> Vec<(String, &'static str)> {
    fake.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).reads.clone()
}


pub fn list_statement(state: &State, tenant: &str, sql: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let by_verdict = sql == LIST_VERDICT_SQL || sql == LIST_VERDICT_BASELINE_SQL;
    let by_baseline = sql == LIST_VERDICT_BASELINE_SQL || sql == LIST_ALL_BASELINE_SQL;
    let offset = usize::from(by_verdict);
    let verdict: Option<String> = if by_verdict { Some(param(params, 0)?) } else { None };
    let after: (String, String, String) = (param(params, offset)?, param(params, offset + 1)?, param(params, offset + SECOND)?);
    let limit: usize = param(params, offset + THIRD)?;
    let baseline: Option<String> = if by_baseline { Some(param(params, offset + FOURTH)?) } else { None };
    Ok(state
        .rows
        .iter()
        .filter(|(key, cells)| {
            key.0 == tenant
                && verdict.as_ref().is_none_or(|wanted| *wanted == cells.verdict)
                && baseline.as_ref().is_none_or(|wanted| *wanted == key.1)
                && (key.1.clone(), key.2.clone(), key.3.clone()) > after
        })
        .take(limit)
        .map(|(key, cells)| row_of(key, cells))
        .collect())
}


pub fn asset_statement(state: &State, tenant: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let asset: String = param(params, 0)?;
    let limit: usize = param(params, 1)?;
    Ok(state
        .rows
        .iter()
        .filter(|(key, _cells)| key.0 == tenant && key.3 == asset)
        .take(limit)
        .map(|(key, cells)| row_of(key, cells))
        .collect())
}


pub fn answer(fake: &Fake, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    let mut state = fake.state.lock().map_err(bad)?;
    state.reads.push((tenant.clone(), sql));
    if fake.fail {
        Err(PgError::InvalidTenant)
    } else if let Some(rows) = state.forced.clone() {
        Ok(rows)
    } else if sql == ASSET_SQL {
        asset_statement(&state, &tenant, params)
    } else if sql == LIST_ALL_SQL || sql == LIST_ALL_BASELINE_SQL || sql == LIST_VERDICT_SQL || sql == LIST_VERDICT_BASELINE_SQL {
        list_statement(&state, &tenant, sql, params)
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
