use crate::types::Statement;
use alerts::types::RowFuture;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use dhcp_kea::api_model::DhcpBackend;
use dhcp_kea::error::HistoryError;
use dhcp_kea::history::{lease_at, leases_of_mac};
use std::collections::BTreeMap;
use std::future::ready;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};


pub const MARKER: &str = "STORE-SECRET-MARKER";


pub const NULL_CELL: &str = "<SQL NULL>";


const NULLABLE_COLUMNS: [(usize, &str); 2] = [(1, "coalesce(mac, '')"), (2, "coalesce(hostname, '')")];


pub enum Forced {
    Fail,
    Busy,
}


#[derive(Default)]
pub struct Mem {
    pub rows: Mutex<BTreeMap<String, Vec<Vec<String>>>>,
    pub statements: Mutex<Vec<Statement>>,
    pub forced: Mutex<Option<Forced>>,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn row(address: &str, mac: &str, hostname: &str, starts: i64, ends: i64) -> Vec<String> {
    [
        address,
        mac,
        hostname,
        "false",
        &starts.to_string(),
        &ends.to_string(),
        "lease-assigned",
        "7",
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
}


pub fn seed(mem: &Mem, tenant: &str, rows: Vec<Vec<String>>) {
    lock(&mem.rows).insert(tenant.to_owned(), rows);
}


fn read_nulls(sql: &str, row: Vec<String>) -> Result<Vec<String>, PgError> {
    let guarded = |index: usize| {
        NULLABLE_COLUMNS
            .iter()
            .any(|(column, expression)| *column == index && sql.contains(expression))
    };
    row.into_iter()
        .enumerate()
        .map(|(index, cell)| match (cell == NULL_CELL, guarded(index)) {
            (false, _) => Ok(cell),
            (true, true) => Ok(String::new()),
            (true, false) => Err(PgError::InvalidTenant),
        })
        .collect()
}


fn answer(mem: &Mem, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    lock(&mem.statements).push((tenant_of(scope).to_owned(), sql, params.to_vec()));
    let limit = params.last().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
    let failing = matches!(*lock(&mem.forced), Some(Forced::Fail));
    let rows = lock(&mem.rows).get(tenant_of(scope)).cloned().unwrap_or_else(Vec::new);
    if failing {
        Err(PgError::Io {
            file: MARKER.to_owned(),
            source: std::io::Error::other(MARKER),
        })
    } else {
        rows.into_iter().take(limit).map(|row| read_nulls(sql, row)).collect()
    }
}


pub fn executor<'a>(mem: &'a Mem) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(answer(mem, &scope, sql, &params))) }
}


fn busy(mem: &Mem) -> bool {
    matches!(*lock(&mem.forced), Some(Forced::Busy))
}


pub fn lookup_backend(mem: &Arc<Mem>) -> DhcpBackend {
    let at_mem = Arc::clone(mem);
    let mac_mem = Arc::clone(mem);
    DhcpBackend {
        at: Arc::new(move |scope, address, at| {
            let held = Arc::clone(&at_mem);
            Box::pin(async move {
                if busy(&held) {
                    Err(HistoryError::Busy)
                } else {
                    lease_at(&executor(&held), &scope, &address, at).await
                }
            })
        }),
        by_mac: Arc::new(move |scope, mac, from, to| {
            let held = Arc::clone(&mac_mem);
            Box::pin(async move {
                if busy(&held) {
                    Err(HistoryError::Busy)
                } else {
                    leases_of_mac(&executor(&held), &scope, &mac, from, to).await
                }
            })
        }),
    }
}
