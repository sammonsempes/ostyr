use alerts::types::RowFuture;
use cert_inventory::store::{LIST_FIRST_SQL, LIST_NEXT_SQL, SIGHTINGS_SQL, STORE_SQL};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::ready;
use std::io::Write;
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::sync::Barrier;
use tracing::Dispatch;


pub const FIRST_PARAM: usize = 0;


pub const KIND_PARAM: usize = 1;


pub const REF_PARAM: usize = 2;


pub const NOW_PARAM: usize = 3;


pub const MAX_CERTS_PARAM: usize = 4;


pub const MAX_SIGHTINGS_PARAM: usize = 5;


pub const BEFORE_PARAM: usize = 0;


pub const LIMIT_PARAM: usize = 1;


pub const AFTER_PARAM: usize = 2;


pub const FINGERPRINT_PARAM: usize = 3;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub subject: String,
    pub issuer: String,
    pub dns_names: String,
    pub not_before: i64,
    pub not_after: i64,
    pub key_type: String,
    pub key_bits: String,
    pub self_signed: bool,
    pub first_seen: i64,
    pub last_seen: i64,
}


#[derive(Default)]
pub struct State {
    pub certs: BTreeMap<(String, String), Stored>,
    pub sightings: BTreeMap<(String, String, String, String), i64>,
    pub statements: Vec<usize>,
}


#[derive(Default)]
pub struct Fake {
    pub state: Mutex<State>,
    pub gate: Option<Barrier>,
    pub fail: bool,
}


pub fn bad<Cause>(_error: Cause) -> PgError {
    PgError::InvalidTenant
}


pub fn text_of(doc: &Value, key: &str) -> Result<String, PgError> {
    doc.get(key).and_then(Value::as_str).map(str::to_owned).ok_or(PgError::InvalidTenant)
}


pub fn number_of(doc: &Value, key: &str) -> Result<i64, PgError> {
    doc.get(key).and_then(Value::as_i64).ok_or(PgError::InvalidTenant)
}


pub fn param<Parsed: FromStr>(params: &[String], index: usize) -> Result<Parsed, PgError> {
    params.get(index).ok_or(PgError::InvalidTenant)?.parse().map_err(bad)
}


pub fn stored_of(doc: &Value, now: i64) -> Result<Stored, PgError> {
    Ok(Stored {
        subject: text_of(doc, "subject")?,
        issuer: text_of(doc, "issuer")?,
        dns_names: doc.get("dns_names").ok_or(PgError::InvalidTenant)?.to_string(),
        not_before: number_of(doc, "not_before")?,
        not_after: number_of(doc, "not_after")?,
        key_type: text_of(doc, "key_type")?,
        key_bits: doc.get("key_bits").and_then(Value::as_i64).map_or(String::new(), |bits| bits.to_string()),
        self_signed: doc.get("self_signed").and_then(Value::as_bool).ok_or(PgError::InvalidTenant)?,
        first_seen: now,
        last_seen: now,
    })
}


pub fn store_statement(state: &mut State, tenant: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let docs: Vec<Value> = serde_json::from_str(&param::<String>(params, FIRST_PARAM)?).map_err(bad)?;
    let kind: String = param(params, KIND_PARAM)?;
    let reference: String = param(params, REF_PARAM)?;
    let now: i64 = param(params, NOW_PARAM)?;
    let max_certs: usize = param(params, MAX_CERTS_PARAM)?;
    let max_sightings: usize = param(params, MAX_SIGHTINGS_PARAM)?;
    state.statements.push(docs.len());
    let mut unique: BTreeMap<String, &Value> = BTreeMap::new();
    docs.iter().try_for_each(|doc| {
        let fingerprint = text_of(doc, "fingerprint")?;
        unique.entry(fingerprint).or_insert(doc);
        Ok::<(), PgError>(())
    })?;
    let n_certs = state.certs.keys().filter(|(owner, _)| owner == tenant).count();
    let n_sightings = state.sightings.keys().filter(|(owner, ..)| owner == tenant).count();
    let mut cert_room = max_certs.saturating_sub(n_certs);
    let mut sighting_room = max_sightings.saturating_sub(n_sightings);
    let (mut inserted, mut again, mut refused) = (0, 0, 0);
    unique.iter().try_for_each(|(fingerprint, doc)| {
        let cert_key = (tenant.to_owned(), fingerprint.clone());
        let sighting_key = (tenant.to_owned(), fingerprint.clone(), kind.clone(), reference.clone());
        let known = state.certs.contains_key(&cert_key);
        let sighted = state.sightings.contains_key(&sighting_key);
        let cert_ok = known || cert_room > 0;
        cert_room -= usize::from(!known && cert_ok);
        let sighting_ok = sighted || (cert_ok && sighting_room > 0);
        sighting_room -= usize::from(cert_ok && !sighted && sighting_ok);
        if cert_ok && sighting_ok {
            if known {
                again += 1;
                state
                    .certs
                    .entry(cert_key)
                    .and_modify(|stored| stored.last_seen = stored.last_seen.max(now));
            } else {
                inserted += 1;
                state.certs.insert(cert_key, stored_of(doc, now)?);
            }
            let seen = state.sightings.entry(sighting_key).or_insert(now);
            *seen = (*seen).max(now);
        } else {
            refused += 1;
        }
        Ok::<(), PgError>(())
    })?;
    Ok(vec![vec![inserted.to_string(), again.to_string(), refused.to_string()]])
}


pub fn cert_row(fingerprint: &str, stored: &Stored) -> Vec<String> {
    vec![
        fingerprint.to_owned(),
        stored.subject.clone(),
        stored.issuer.clone(),
        stored.dns_names.clone(),
        stored.not_before.to_string(),
        stored.not_after.to_string(),
        stored.key_type.clone(),
        stored.key_bits.clone(),
        stored.self_signed.to_string(),
        stored.first_seen.to_string(),
        stored.last_seen.to_string(),
    ]
}


pub fn list_statement(state: &State, tenant: &str, sql: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let before: i64 = param(params, BEFORE_PARAM)?;
    let limit: usize = param(params, LIMIT_PARAM)?;
    let after: Option<(i64, String)> = if sql == LIST_NEXT_SQL {
        Some((param(params, AFTER_PARAM)?, param(params, FINGERPRINT_PARAM)?))
    } else {
        None
    };
    let mut rows: Vec<(i64, &String, &Stored)> = state
        .certs
        .iter()
        .filter(|((owner, _), stored)| owner == tenant && stored.not_after < before)
        .map(|((_, fingerprint), stored)| (stored.not_after, fingerprint, stored))
        .filter(|(not_after, fingerprint, _)| {
            after
                .as_ref()
                .is_none_or(|(after_na, after_fp)| (*not_after, *fingerprint) > (*after_na, after_fp))
        })
        .collect();
    rows.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    Ok(rows
        .iter()
        .take(limit)
        .map(|(_, fingerprint, stored)| cert_row(fingerprint, stored))
        .collect())
}


pub fn sightings_statement(state: &State, tenant: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let fingerprint: String = param(params, FIRST_PARAM)?;
    let limit: usize = param(params, LIMIT_PARAM)?;
    Ok(state
        .sightings
        .iter()
        .filter(|((owner, found, ..), _)| owner == tenant && *found == fingerprint)
        .take(limit)
        .map(|((_, _, kind, reference), seen)| vec![kind.clone(), reference.clone(), seen.to_string()])
        .collect())
}


pub async fn answer(fake: &Fake, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, PgError> {
    if let Some(gate) = &fake.gate {
        gate.wait().await;
    }
    let tenant = tenant_of(&scope).to_owned();
    let mut state = fake.state.lock().map_err(bad)?;
    if fake.fail {
        Err(PgError::InvalidTenant)
    } else if sql == STORE_SQL {
        store_statement(&mut state, &tenant, &params)
    } else if sql == LIST_FIRST_SQL || sql == LIST_NEXT_SQL {
        list_statement(&state, &tenant, sql, &params)
    } else if sql == SIGHTINGS_SQL {
        sightings_statement(&state, &tenant, &params)
    } else {
        Err(PgError::InvalidTenant)
    }
}


pub fn executor<'a>(fake: &'a Fake) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(answer(fake, scope, sql, params)) }
}


pub fn fixed<'a>(rows: Vec<Vec<String>>) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    move |_scope, _sql, _params| -> RowFuture<'a> { Box::pin(ready(Ok(rows.clone()))) }
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
