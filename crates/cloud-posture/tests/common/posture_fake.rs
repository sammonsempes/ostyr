use cloud_posture::model::{Finding, Severity, Status};
use cloud_posture::page::ROW_COLUMNS;
use cloud_posture::prowler::identity_of;
use cloud_posture::text::{severity_rank, severity_text, status_text};
use cloud_posture::types::RowFuture;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use std::cmp::Reverse;
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;


pub const HEADER_COLUMNS: usize = 14;


pub const TIME_UNIX: i64 = 1_700_000_000;


pub const PARAM_ACCOUNT: usize = 0;


pub const PARAM_RANK: usize = 1;


pub const PARAM_IDENTITY: usize = 2;


pub const PARAM_ROWS: usize = 3;


#[derive(Clone)]
pub struct StoredRun {
    pub tenant: String,
    pub account: String,
    pub run_id: String,
    pub finished: i64,
    pub refused_micros: Option<i64>,
    pub findings: Vec<Finding>,
}


#[derive(Default)]
pub struct State {
    pub runs: Vec<StoredRun>,
    pub statements: Vec<(String, Vec<String>)>,
}


#[derive(Default)]
pub struct Fake {
    pub state: Mutex<State>,
}


pub fn finding(account: &str, uid: &str, severity: Severity) -> Finding {
    Finding {
        uid: uid.to_owned(),
        check_id: "check_one".to_owned(),
        status: Status::Fail,
        severity,
        provider: "aws".to_owned(),
        account: account.to_owned(),
        region: "eu-west-1".to_owned(),
        resource_uid: format!("res-{uid}"),
        resource_type: "AwsResource".to_owned(),
        time_unix: TIME_UNIX,
        title: "title".to_owned(),
        title_cut: 0,
        detail: "detail".to_owned(),
        detail_cut: 0,
    }
}


pub fn run_of(tenant: &str, account: &str, run_id: &str, finished: i64, findings: Vec<Finding>) -> StoredRun {
    StoredRun {
        tenant: tenant.to_owned(),
        account: account.to_owned(),
        run_id: run_id.to_owned(),
        finished,
        refused_micros: None,
        findings,
    }
}


pub fn put(fake: &Fake, run: StoredRun) {
    let mut state = fake.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.runs.retain(|held| !(held.tenant == run.tenant && held.account == run.account));
    state.runs.push(run);
}


pub fn statements(fake: &Fake) -> usize {
    fake.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).statements.len()
}


pub fn row_of(run: &StoredRun, item: Option<&Finding>) -> Vec<String> {
    let finished = run.finished.to_string();
    let count = run.findings.len().to_string();
    let refused = run.refused_micros.map_or_else(String::new, |micros| micros.to_string());
    let header = [
        run.run_id.as_str(),
        finished.as_str(),
        count.as_str(),
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        refused.as_str(),
        "0",
    ];
    let finding_columns: Vec<String> = item.map_or_else(
        || vec![String::new(); ROW_COLUMNS - HEADER_COLUMNS],
        |found| {
            vec![
                format!("{:x}", identity_of(found)),
                severity_rank(found.severity).to_string(),
                found.uid.clone(),
                found.check_id.clone(),
                status_text(found.status).to_owned(),
                severity_text(found.severity).to_owned(),
                found.provider.clone(),
                found.region.clone(),
                found.resource_uid.clone(),
                found.resource_type.clone(),
                found.time_unix.to_string(),
                found.title.clone(),
                found.title_cut.to_string(),
                found.detail.clone(),
                found.detail_cut.to_string(),
            ]
        },
    );
    header.iter().map(|text| (*text).to_owned()).chain(finding_columns).collect()
}


pub fn answer(fake: &Fake, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let mut state = fake.state.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    state.statements.push((sql.to_owned(), params.to_vec()));
    let account = params.get(PARAM_ACCOUNT).ok_or(PgError::InvalidTenant)?;
    let rank: i16 = params.get(PARAM_RANK).and_then(|text| text.parse().ok()).ok_or(PgError::InvalidTenant)?;
    let identity = params.get(PARAM_IDENTITY).ok_or(PgError::InvalidTenant)?;
    let wanted: usize = params.get(PARAM_ROWS).and_then(|text| text.parse().ok()).ok_or(PgError::InvalidTenant)?;
    let tenant = tenant_of(scope);
    let found = state.runs.iter().find(|held| held.tenant == tenant && held.account == *account);
    Ok(match found {
        Some(run) => rows_of(run, rank, identity, wanted),
        None => Vec::new(),
    })
}


pub fn rows_of(run: &StoredRun, rank: i16, identity: &str, wanted: usize) -> Vec<Vec<String>> {
    let mut keyed: Vec<(Reverse<i16>, String, &Finding)> = run
        .findings
        .iter()
        .map(|found| {
            (
                Reverse(i16::from(severity_rank(found.severity))),
                format!("{:x}", identity_of(found)),
                found,
            )
        })
        .collect();
    keyed.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    let after: Vec<Vec<String>> = keyed
        .iter()
        .filter(|(key_rank, key_identity, _found)| (key_rank, key_identity.as_str()) > (&Reverse(rank), identity))
        .take(wanted)
        .map(|(_rank, _identity, found)| row_of(run, Some(found)))
        .collect();
    if after.is_empty() {
        vec![row_of(run, None)]
    } else {
        after
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
