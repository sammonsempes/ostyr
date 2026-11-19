#[path = "common/history/types.rs"]
mod history_types;
#[path = "common/types.rs"]
mod types;


use alerts::store::INSERT_SQL;
use alerts::types::{Executor, RowFuture};
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use dhcp_kea::cursor::{MIGRATIONS, MIGRATION_NAMESPACE};
use dhcp_kea::error::HistoryError;
use dhcp_kea::header::parse_header;
use dhcp_kea::history::{
    check_settings, lease_at, lease_doc, leases_of_mac, store_history, HistoryCounts, HistorySettings, AT_SQL, MAC_SQL, MAX_ACTION_CHARS,
    MAX_HISTORY_BATCH, MAX_LOOKUP_ROWS, MAX_RETENTION_DAYS, PRESSURE_RULE_ID, STORE_SQL,
};
use dhcp_kea::row::{convert_row, Converted};
use history_types::Row;
use serde_json::Value;
use std::future::ready;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Barrier, LazyLock, Mutex};
use types::TestResult;


const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


const NOW: i64 = 1_700_000_000;


const DAY: i64 = 86_400;


const SMALL_CAP: u64 = 100;


const MANY: usize = 150;


const PAIR: usize = 2;


const DAYS_PARAM: usize = 2;


const NOW_PARAM: usize = 3;


const EXTRA_ROWS: usize = 5;


const CAP_MULTIPLE: u64 = 20;


const OVER_CAP_BATCH: usize = 10;


const REFUSED_OF_BATCH: u64 = 9;


const CONCURRENT_BATCH: usize = 80;


const CONCURRENT_TOTAL: u64 = 160;


const TINY_CAP: u64 = 5;


const MIXED_NEW: usize = 2;


const MIXED_NEW_COUNT: u64 = 2;


const MIXED_NEW_OFFSET: i64 = 2;


const PAIR_DAYS: i64 = 2;


const OLD_PRESSURE_DAYS: i64 = 8;


const SHORT_RETENTION: u32 = 10;


const OLD_START_DAYS: i64 = 30;


const OLD_END_DAYS: i64 = 20;


const TWO_DAYS: i64 = 172_800;


const REFUSED_LEASES: u64 = 9;


const LOOKUP_WIDTH: usize = 7;


const YEAR_10000: i64 = 253_402_300_800;


const MAC_A: &str = "AA-BB-CC-DD-EE-01";


const MAC_B: &str = "AA-BB-CC-DD-EE-02";


static ANCHOR: LazyLock<tracing::Dispatch> = LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<Vec<Row>>,
    pub fail: bool,
    pub alerts: Mutex<Vec<Value>>,
    pub alert_fail: bool,
    pub shape: Option<Vec<Vec<String>>>,
}


fn text(doc: &Value, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(doc.get(name).and_then(Value::as_str).unwrap_or("").to_string())
}


fn number(doc: &Value, name: &str) -> Result<i64, Box<dyn std::error::Error>> {
    doc.get(name).and_then(Value::as_i64).ok_or_else(|| "missing number".into())
}


fn model_store(store: &Store, tenant: &str, params: &[String]) -> Result<Vec<Vec<String>>, Box<dyn std::error::Error>> {
    let docs: Vec<Value> = serde_json::from_str(params.first().ok_or("params")?)?;
    let cap: usize = params.get(1).ok_or("params")?.parse()?;
    let days: i64 = params.get(DAYS_PARAM).ok_or("params")?.parse()?;
    let now: i64 = params.get(NOW_PARAM).ok_or("params")?.parse()?;
    let cutoff = now - days * DAY;
    let mut rows = store.rows.lock().map_err(|_poisoned| "poisoned")?;
    let before = rows.len();
    rows.retain(|(row_tenant, doc)| row_tenant != tenant || number(doc, "ends").is_ok_and(|ends| ends >= cutoff));
    let expired = before - rows.len();
    let mut seen: Vec<String> = Vec::new();
    let mut stale = 0;
    let mut fresh: Vec<Value> = Vec::new();
    for doc in &docs {
        let identity = text(doc, "identity")?;
        if !seen.contains(&identity) {
            seen.push(identity.clone());
            if number(doc, "ends")? < cutoff {
                stale += 1;
            } else if !rows
                .iter()
                .any(|(row_tenant, row)| row_tenant == tenant && text(row, "identity").is_ok_and(|found| found == identity))
            {
                fresh.push(doc.clone());
            }
        }
    }
    let key_of = |doc: &Value| (number(doc, "ends").unwrap_or(0), number(doc, "starts").unwrap_or(0));
    let held = rows.iter().filter(|(row_tenant, _doc)| row_tenant == tenant).count();
    let need = (fresh.len() + held).saturating_sub(cap);
    let mut ranked: Vec<((i64, i64), bool, usize)> = rows
        .iter()
        .filter(|(row_tenant, _doc)| row_tenant == tenant)
        .map(|(_tenant, doc)| (key_of(doc), true, 0))
        .chain(fresh.iter().enumerate().map(|(index, doc)| (key_of(doc), false, index)))
        .collect();
    ranked.sort();
    let dropped: Vec<((i64, i64), bool, usize)> = ranked.into_iter().take(need).collect();
    let gone: Vec<(i64, i64)> = dropped
        .iter()
        .filter(|(_key, stored, _index)| *stored)
        .map(|(key, _stored, _index)| *key)
        .collect();
    let refused: Vec<usize> = dropped
        .iter()
        .filter(|(_key, stored, _index)| !*stored)
        .map(|(_key, _stored, index)| *index)
        .collect();
    let young_after = now - days * DAY / PAIR_DAYS;
    let pressure = gone.iter().filter(|(ends, _starts)| *ends >= young_after).count();
    let mut to_drop = gone.clone();
    rows.retain(|(row_tenant, doc)| {
        let position = to_drop.iter().position(|found| *found == key_of(doc));
        let drop_it = row_tenant == tenant && position.is_some();
        if let Some(index) = position.filter(|_found| drop_it) {
            to_drop.remove(index);
        }
        !drop_it
    });
    let admitted = fresh.len() - refused.len();
    rows.extend(
        fresh
            .iter()
            .enumerate()
            .filter(|(index, _doc)| !refused.contains(index))
            .map(|(_index, doc)| (tenant.to_string(), doc.clone())),
    );
    let duplicate = docs.len() - stale - fresh.len();
    Ok(vec![vec![
        expired.to_string(),
        admitted.to_string(),
        duplicate.to_string(),
        (fresh.len() - admitted).to_string(),
        stale.to_string(),
        gone.len().to_string(),
        pressure.to_string(),
    ]])
}


fn nullable(doc: &Value, name: &str, sql: &str) -> Result<String, Box<dyn std::error::Error>> {
    let guarded = sql.contains(&format!("coalesce({name}, '')"));
    match doc.get(name).and_then(Value::as_str) {
        Some(found) => Ok(found.to_string()),
        None if guarded => Ok(String::new()),
        None => Err("NULL column read as text".into()),
    }
}


fn lookup_row(doc: &Value, sql: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(vec![
        text(doc, "address")?,
        nullable(doc, "mac", sql)?,
        nullable(doc, "hostname", sql)?,
        number(doc, "starts")?.to_string(),
        number(doc, "ends")?.to_string(),
        text(doc, "action")?,
        number(doc, "subnet_id")?.to_string(),
    ])
}


fn model_lookup(store: &Store, tenant: &str, sql: &str, params: &[String]) -> Result<Vec<Vec<String>>, Box<dyn std::error::Error>> {
    let rows = store.rows.lock().map_err(|_poisoned| "poisoned")?;
    let mut mine: Vec<&Value> = rows
        .iter()
        .filter(|(row_tenant, _doc)| row_tenant == tenant)
        .map(|(_tenant, doc)| doc)
        .collect();
    mine.sort_by_key(|doc| std::cmp::Reverse(number(doc, "starts").unwrap_or(0)));
    let param = |index: usize| params.get(index).cloned().ok_or("params");
    let selected: Vec<&Value> = if sql == AT_SQL {
        let at: i64 = param(1)?.parse()?;
        mine.into_iter()
            .filter(|doc| text(doc, "address").is_ok_and(|found| param(0).is_ok_and(|expected| found == expected)))
            .filter(|doc| number(doc, "starts").is_ok_and(|starts| starts <= at))
            .collect()
    } else {
        let to: i64 = param(1)?.parse()?;
        mine.into_iter()
            .filter(|doc| text(doc, "mac").is_ok_and(|found| param(0).is_ok_and(|expected| found == expected)))
            .filter(|doc| number(doc, "starts").is_ok_and(|starts| starts < to))
            .collect()
    };
    let limit: usize = params.last().ok_or("params")?.parse()?;
    selected.into_iter().take(limit).map(|doc| lookup_row(doc, sql)).collect()
}


fn insert_alert(store: &Store, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let mut alerts = store.alerts.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let documents: Vec<Value> = serde_json::from_str(params.first().ok_or(PgError::InvalidTenant)?).map_err(|_bad| PgError::InvalidTenant)?;
    let document = documents.into_iter().next().ok_or(PgError::InvalidTenant)?;
    let known = alerts.iter().any(|stored| stored.get("id") == document.get("id"));
    let fresh = !store.alert_fail && !known;
    let answer = if store.alert_fail {
        Err(PgError::InvalidTenant)
    } else {
        Ok(vec![vec![usize::from(fresh).to_string()]])
    };
    alerts.extend(fresh.then_some(document));
    answer
}


pub fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        let tenant = tenant_of(&scope).to_string();
        let answer = if store.fail {
            Err(PgError::InvalidTenant)
        } else if let Some(shape) = &store.shape {
            Ok(shape.clone())
        } else if sql == INSERT_SQL {
            insert_alert(store, &params)
        } else if sql == STORE_SQL {
            model_store(store, &tenant, &params).map_err(|_bad| PgError::InvalidTenant)
        } else {
            model_lookup(store, &tenant, sql, &params).map_err(|_bad| PgError::InvalidTenant)
        };
        Box::pin(ready(answer))
    }
}


fn lease(address: &str, mac: &str, cltt: i64, expire: i64, host: &str) -> Result<Converted, Box<dyn std::error::Error>> {
    let columns = parse_header(HEADER)?;
    let row = format!("{address},{mac},,{},{expire},1,0,0,{host},0,", expire - cltt);
    Ok(convert_row(&columns, &row)?)
}


fn settings(max_rows: u64) -> HistorySettings {
    HistorySettings {
        max_rows,
        ..HistorySettings::default()
    }
}


fn distinct(count: usize, base: i64) -> Result<Vec<Converted>, Box<dyn std::error::Error>> {
    (0..count)
        .map(|index| lease("10.0.0.5", "aa:bb:cc:dd:ee:01", base + i64::try_from(index)?, base + DAY + DAY, "pc"))
        .collect()
}


fn capture_dispatch() -> Result<(Arc<std::fs::File>, tracing::Dispatch), Box<dyn std::error::Error>> {
    let capture = Arc::new(tempfile::tempfile()?);
    let writer = Arc::clone(&capture);
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Arc::clone(&writer))
            .finish(),
    );
    Ok((capture, dispatch))
}


fn captured_text(capture: &Arc<std::fs::File>) -> Result<String, Box<dyn std::error::Error>> {
    let mut found = String::new();
    let mut file: &std::fs::File = capture;
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut found)?;
    Ok(found)
}


fn row_count(store: &Store) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(store.rows.lock().map_err(|_poisoned| "poisoned")?.len())
}


#[tokio::test]
async fn two_tenants_with_one_address_and_mac_see_only_their_own_rows() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let first = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "alpha.lan")?;
    let second = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "beta.lan")?;
    store_history(exec, &acme, &settings(SMALL_CAP), NOW, &[first]).await?;
    store_history(exec, &other, &settings(SMALL_CAP), NOW, &[second]).await?;
    let acme_at = lease_at(exec, &acme, "10.0.0.5", NOW + 1).await?;
    let other_at = lease_at(exec, &other, "10.0.0.5", NOW + 1).await?;
    let acme_mac = leases_of_mac(exec, &acme, "aa:bb:cc:dd:ee:01", NOW, NOW + DAY).await?;
    let other_mac = leases_of_mac(exec, &other, MAC_A, NOW, NOW + DAY).await?;
    let nobody = lease_at(exec, &tenant_scope("third")?, "10.0.0.5", NOW + 1).await?;
    assert_eq!(acme_at.intervals.len(), 1);
    assert_eq!(acme_at.intervals.first().and_then(|found| found.hostname.as_deref()), Some("alpha.lan"));
    assert_eq!(other_at.intervals.first().and_then(|found| found.hostname.as_deref()), Some("beta.lan"));
    assert_eq!(acme_at.intervals.first().and_then(|found| found.mac.as_deref()), Some(MAC_A));
    assert_eq!((acme_mac.intervals.len(), other_mac.intervals.len()), (1, 1));
    assert!(nobody.intervals.is_empty() && !nobody.truncated);
    assert!(lease_at(exec, &acme, "10.0.0.5", NOW + DAY).await?.intervals.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_replayed_batch_is_all_duplicate_and_adds_no_row() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let batch = distinct(MAX_HISTORY_BATCH + EXTRA_ROWS, NOW)?;
    let first = store_history(exec, &scope, &settings(SMALL_CAP * CAP_MULTIPLE), NOW, &batch).await?;
    let again = store_history(exec, &scope, &settings(SMALL_CAP * CAP_MULTIPLE), NOW, &batch).await?;
    assert_eq!(first.inserted, u64::try_from(batch.len())?);
    assert_eq!(
        again,
        HistoryCounts {
            duplicate: u64::try_from(batch.len())?,
            ..HistoryCounts::default()
        }
    );
    assert_eq!(row_count(&store)?, batch.len());
    Ok(())
}


#[tokio::test]
async fn a_full_tenant_evicts_its_oldest_rows_and_keeps_the_newest() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    store_history(exec, &scope, &settings(SMALL_CAP), NOW, &distinct(usize::try_from(SMALL_CAP - 1)?, NOW)?).await?;
    let (capture, dispatch) = capture_dispatch()?;
    let guard = tracing::dispatcher::set_default(&dispatch);
    let counts = store_history(exec, &scope, &settings(SMALL_CAP), NOW, &distinct(OVER_CAP_BATCH, NOW + DAY)?).await?;
    let quiet = store_history(exec, &scope, &settings(SMALL_CAP), NOW, &[]).await?;
    drop(guard);
    let logged = captured_text(&capture)?;
    let newest = leases_of_mac(exec, &scope, MAC_A, NOW, NOW + DAY * PAIR_DAYS).await?;
    let newest_start = newest.intervals.first().map(|interval| interval.starts);
    assert_eq!(
        (counts.inserted, counts.refused_full, counts.evicted),
        (REFUSED_OF_BATCH + 1, 0, REFUSED_OF_BATCH)
    );
    assert_eq!(counts.pressure, REFUSED_OF_BATCH);
    assert_eq!(quiet, HistoryCounts::default());
    assert_eq!(logged.matches("oldest rows evicted").count(), 1, "{logged}");
    assert_eq!(newest_start, Some(NOW + DAY + i64::try_from(OVER_CAP_BATCH)? - 1));
    assert_eq!(row_count(&store)?, usize::try_from(SMALL_CAP)?);
    Ok(())
}


#[tokio::test]
async fn an_old_batch_in_a_full_tenant_is_refused_and_evicts_nothing() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let recent = i64::try_from(SMALL_CAP)?;
    store_history(
        exec,
        &scope,
        &settings(SMALL_CAP),
        NOW,
        &distinct(usize::try_from(SMALL_CAP)?, NOW + DAY)?,
    )
    .await?;
    let old = store_history(exec, &scope, &settings(SMALL_CAP), NOW, &distinct(OVER_CAP_BATCH, NOW)?).await?;
    let replay = store_history(exec, &scope, &settings(SMALL_CAP), NOW, &distinct(OVER_CAP_BATCH, NOW)?).await?;
    let mixed = store_history(
        exec,
        &scope,
        &settings(SMALL_CAP),
        NOW,
        &[distinct(OVER_CAP_BATCH, NOW)?, distinct(MIXED_NEW, NOW + DAY + recent)?].concat(),
    )
    .await?;
    let oldest = leases_of_mac(exec, &scope, MAC_A, NOW, NOW + DAY * PAIR_DAYS).await?;
    let oldest_start = oldest.intervals.last().map(|interval| interval.starts);
    assert_eq!(
        (old.inserted, old.refused_full, old.evicted, old.pressure),
        (0, u64::try_from(OVER_CAP_BATCH)?, 0, 0)
    );
    assert_eq!(
        (replay.inserted, replay.refused_full, replay.evicted),
        (0, u64::try_from(OVER_CAP_BATCH)?, 0)
    );
    assert_eq!(
        (mixed.inserted, mixed.refused_full, mixed.evicted),
        (MIXED_NEW_COUNT, u64::try_from(OVER_CAP_BATCH)?, MIXED_NEW_COUNT)
    );
    assert_eq!(oldest_start, Some(NOW + DAY + MIXED_NEW_OFFSET));
    assert_eq!(row_count(&store)?, usize::try_from(SMALL_CAP)?);
    Ok(())
}


#[tokio::test]
async fn a_batch_over_the_whole_cap_keeps_its_newest_rows_and_says_so() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let (capture, dispatch) = capture_dispatch()?;
    let guard = tracing::dispatcher::set_default(&dispatch);
    let counts = store_history(exec, &scope, &settings(TINY_CAP), NOW, &distinct(OVER_CAP_BATCH, NOW)?).await?;
    drop(guard);
    let logged = captured_text(&capture)?;
    assert_eq!((counts.inserted, counts.refused_full, counts.evicted), (TINY_CAP, TINY_CAP, 0));
    assert_eq!(logged.matches("cap reached").count(), 1, "{logged}");
    assert_eq!(row_count(&store)?, usize::try_from(TINY_CAP)?);
    Ok(())
}


#[tokio::test]
async fn old_evictions_raise_no_alert_and_recent_ones_raise_one_per_day() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let cap_rows = usize::try_from(SMALL_CAP)?;
    let fill = |base: i64| distinct(cap_rows, base);
    let short = HistorySettings {
        retention_days: SHORT_RETENTION,
        max_rows: SMALL_CAP,
    };
    store_history(exec, &scope, &short, NOW, &fill(NOW - DAY * OLD_PRESSURE_DAYS)?).await?;
    let quiet = store_history(exec, &scope, &short, NOW, &fill(NOW)?).await?;
    let loud = store_history(exec, &scope, &short, NOW, &fill(NOW + DAY)?).await?;
    let same_day = store_history(exec, &scope, &short, NOW, &fill(NOW + DAY * PAIR_DAYS)?).await?;
    let alerts = store.alerts.lock().map_err(|_poisoned| "poisoned")?.clone();
    assert_eq!((quiet.evicted, quiet.pressure), (SMALL_CAP, 0));
    assert_eq!((loud.evicted, loud.pressure), (SMALL_CAP, SMALL_CAP));
    assert_eq!(same_day.pressure, SMALL_CAP);
    assert_eq!(alerts.len(), 1);
    let rule = alerts.first().and_then(|alert| alert.get("rule_id")).and_then(Value::as_str);
    assert_eq!(rule, Some(PRESSURE_RULE_ID));
    Ok(())
}


#[tokio::test]
async fn a_failed_pressure_alert_is_logged_and_the_counts_still_return() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let store = Store {
        alert_fail: true,
        ..Store::default()
    };
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    store_history(exec, &scope, &settings(SMALL_CAP), NOW, &distinct(usize::try_from(SMALL_CAP)?, NOW)?).await?;
    let (capture, dispatch) = capture_dispatch()?;
    let guard = tracing::dispatcher::set_default(&dispatch);
    let counts = store_history(exec, &scope, &settings(SMALL_CAP), NOW, &distinct(1, NOW + DAY)?).await?;
    drop(guard);
    let logged = captured_text(&capture)?;
    assert_eq!((counts.inserted, counts.pressure), (1, 1));
    assert_eq!(logged.matches("pressure alert not stored").count(), 1, "{logged}");
    Ok(())
}


#[test]
fn concurrent_batches_never_exceed_the_cap() -> TestResult {
    let store = Store::default();
    let barrier = Barrier::new(PAIR);
    let scope = tenant_scope("acme")?;
    let first = distinct(CONCURRENT_BATCH, NOW)?;
    let second = distinct(CONCURRENT_BATCH, NOW + DAY)?;
    let totals: Vec<HistoryCounts> = std::thread::scope(|threads| {
        let handles: Vec<_> = [&first, &second]
            .into_iter()
            .map(|batch| {
                threads.spawn(|| -> Result<HistoryCounts, String> {
                    let runtime = tokio::runtime::Builder::new_current_thread().build().map_err(|error| error.to_string())?;
                    let exec: Executor = &executor(&store);
                    barrier.wait();
                    runtime
                        .block_on(store_history(exec, &scope, &settings(SMALL_CAP), NOW, batch))
                        .map_err(|error| error.to_string())
                })
            })
            .collect();
        handles.into_iter().filter_map(|handle| handle.join().ok().and_then(Result::ok)).collect()
    });
    assert_eq!(totals.len(), PAIR);
    let inserted = totals.iter().map(|counts| counts.inserted).sum::<u64>();
    let refused_full = totals.iter().map(|counts| counts.refused_full).sum::<u64>();
    let evicted = totals.iter().map(|counts| counts.evicted).sum::<u64>();
    assert_eq!(inserted + refused_full, CONCURRENT_TOTAL);
    assert_eq!(inserted - evicted, SMALL_CAP);
    assert_eq!(row_count(&store)?, usize::try_from(SMALL_CAP)?);
    Ok(())
}


#[tokio::test]
async fn retention_deletes_old_rows_and_refuses_stale_ones() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let kept = HistorySettings {
        retention_days: SHORT_RETENTION,
        ..HistorySettings::default()
    };
    let old = lease(
        "10.0.0.5",
        "aa:bb:cc:dd:ee:01",
        NOW - OLD_START_DAYS * DAY,
        NOW - OLD_END_DAYS * DAY,
        "pc",
    )?;
    store_history(exec, &scope, &settings(SMALL_CAP), NOW, std::slice::from_ref(&old)).await?;
    let counts = store_history(
        exec,
        &scope,
        &kept,
        NOW,
        &[old, lease("10.0.0.6", "aa:bb:cc:dd:ee:02", NOW, NOW + DAY, "pc")?],
    )
    .await?;
    assert_eq!((counts.expired, counts.stale, counts.inserted), (1, 1, 1));
    assert_eq!(row_count(&store)?, 1);
    Ok(())
}


#[tokio::test]
async fn a_lookup_returns_at_most_the_bound_and_says_it_truncated() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    store_history(exec, &scope, &HistorySettings::default(), NOW, &distinct(MANY, NOW - DAY)?).await?;
    let found = lease_at(exec, &scope, "10.0.0.5", NOW).await?;
    let by_mac = leases_of_mac(exec, &scope, MAC_A, NOW - DAY, NOW + DAY).await?;
    let newest = found.intervals.first().map(|interval| interval.starts);
    assert_eq!((found.intervals.len(), found.truncated), (MAX_LOOKUP_ROWS, true));
    assert_eq!((by_mac.intervals.len(), by_mac.truncated), (MAX_LOOKUP_ROWS, true));
    assert_eq!(newest, Some(NOW - DAY + i64::try_from(MANY)? - 1));
    Ok(())
}


#[test]
fn a_bad_hostname_is_stored_as_null_and_unstorable_leases_are_refused() -> TestResult {
    let mut hostile = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    hostile.event.host = Some(core_export::ecs::HostFields {
        hostname: Some("x'); DROP TABLE a;--\n".to_string()),
        ..core_export::ecs::HostFields::default()
    });
    let doc = lease_doc(&hostile).ok_or("doc")?;
    let mut late = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    late.key.1 = YEAR_10000;
    let mut backwards = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    backwards.key.0 = NOW + TWO_DAYS;
    let mut negative = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    negative.key.0 = -1;
    let mut no_address = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    no_address.event.source = None;
    let mut bad_address = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    bad_address.event.source = bad_address.event.source.map(|source| core_export::ecs::EndpointFields {
        ip: Some("not an ip".to_string()),
        ..source
    });
    let mut bad_action = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    bad_action.event.event.action = Some("lease'; --".to_string());
    let mut long_action = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    long_action.event.event.action = Some("a".repeat(MAX_ACTION_CHARS + 1));
    let mut no_action = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    no_action.event.event.action = None;
    let mut no_subnet = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW, NOW + DAY, "pc")?;
    no_subnet.event.labels.clear();
    assert_eq!(doc.get("hostname"), Some(&Value::Null));
    assert_eq!(doc.get("mac").and_then(Value::as_str), Some(MAC_A));
    let refused = [
        late,
        backwards,
        negative,
        no_address,
        bad_address,
        bad_action,
        long_action,
        no_action,
        no_subnet,
    ];
    assert!(refused.iter().all(|found| lease_doc(found).is_none()));
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let counts = runtime.block_on(store_history(exec, &tenant_scope("acme")?, &HistorySettings::default(), NOW, &refused))?;
    assert_eq!((counts.refused, counts.inserted), (REFUSED_LEASES, 0));
    Ok(())
}


#[tokio::test]
async fn bad_inputs_and_bad_answers_are_typed_errors() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let batch = distinct(1, NOW)?;
    let failing = Store {
        fail: true,
        ..Store::default()
    };
    let failing_exec: Executor = &executor(&failing);
    let empty = Store {
        shape: Some(Vec::new()),
        ..Store::default()
    };
    let empty_exec: Executor = &executor(&empty);
    let short = Store {
        shape: Some(vec![vec!["1".to_string()]]),
        ..Store::default()
    };
    let short_exec: Executor = &executor(&short);
    let garbled = Store {
        shape: Some(vec![vec!["x".to_string(); LOOKUP_WIDTH]]),
        ..Store::default()
    };
    let garbled_exec: Executor = &executor(&garbled);
    let wide = Store {
        shape: Some(vec![vec!["1".to_string(); PAIR]]),
        ..Store::default()
    };
    let wide_exec: Executor = &executor(&wide);
    let zero_days = HistorySettings {
        retention_days: 0,
        ..HistorySettings::default()
    };
    let long_days = HistorySettings {
        retention_days: MAX_RETENTION_DAYS + 1,
        ..HistorySettings::default()
    };
    let zero_rows = settings(0);
    assert!(matches!(
        store_history(exec, &scope, &zero_days, NOW, &batch).await,
        Err(HistoryError::Settings)
    ));
    assert!(matches!(
        store_history(exec, &scope, &long_days, NOW, &batch).await,
        Err(HistoryError::Settings)
    ));
    assert!(matches!(check_settings(&zero_rows), Err(HistoryError::Settings)));
    assert!(matches!(
        store_history(failing_exec, &scope, &HistorySettings::default(), NOW, &batch).await,
        Err(HistoryError::Pg(_))
    ));
    assert!(matches!(
        store_history(empty_exec, &scope, &HistorySettings::default(), NOW, &batch).await,
        Err(HistoryError::Answer)
    ));
    assert!(matches!(
        store_history(short_exec, &scope, &HistorySettings::default(), NOW, &batch).await,
        Err(HistoryError::Answer)
    ));
    let garbled_found = lease_at(garbled_exec, &scope, "10.0.0.5", NOW).await?;
    let wide_found = lease_at(wide_exec, &scope, "10.0.0.5", NOW).await?;
    assert_eq!((garbled_found.intervals.len(), garbled_found.skipped), (0, 1));
    assert_eq!((wide_found.intervals.len(), wide_found.skipped), (0, 1));
    assert!(matches!(lease_at(exec, &scope, "10.0.0.5 or 1=1", NOW).await, Err(HistoryError::Address)));
    assert!(matches!(
        lease_at(exec, &scope, "10.0.0.5", YEAR_10000).await,
        Err(HistoryError::TimeRange)
    ));
    assert!(matches!(lease_at(exec, &scope, "10.0.0.5", -1).await, Err(HistoryError::TimeRange)));
    assert!(matches!(leases_of_mac(exec, &scope, "zz", NOW, NOW).await, Err(HistoryError::Mac)));
    assert!(matches!(
        leases_of_mac(exec, &scope, MAC_B, NOW, YEAR_10000).await,
        Err(HistoryError::TimeRange)
    ));
    assert!(matches!(
        leases_of_mac(exec, &scope, MAC_B, YEAR_10000, NOW).await,
        Err(HistoryError::TimeRange)
    ));
    assert!(tenant_scope("-x").is_err());
    Ok(())
}


#[test]
fn the_statements_bind_the_tenant_and_the_migrations_are_valid() -> TestResult {
    let migration = MIGRATIONS.get(1).ok_or("second migration")?.sql;
    let eviction = MIGRATIONS.get(PAIR).ok_or("third migration")?.sql;
    assert_eq!(MIGRATIONS.len(), PAIR + 1);
    assert!(eviction.contains("pg_advisory_xact_lock(1145586512, hashtext(tenant_name))") && eviction.contains("UNION ALL"));
    assert!(eviction.contains("ORDER BY ends, starts, lease_key LIMIT (SELECT n_drop FROM need)") && eviction.contains("dhcp_history_rows"));
    assert!(AT_SQL.contains("tenant = $1") && MAC_SQL.contains("tenant = $1") && STORE_SQL.contains("dhcp_history_store($1,"));
    assert!(migration.contains("pg_advisory_xact_lock(1145586512, hashtext(tenant_name))"));
    assert!(migration.contains("ON CONFLICT (tenant, lease_key) DO NOTHING") && migration.contains("h.tenant = tenant_name"));
    assert!(migration.contains("DELETE FROM dhcp_lease_history WHERE tenant = tenant_name"));
    assert!(migration.contains("PRIMARY KEY (tenant, lease_key)") && migration.contains("(tenant, address, starts DESC)"));
    check_namespace(MIGRATION_NAMESPACE)?;
    check_embedded(&MIGRATIONS)?;
    Ok(())
}


fn answer_row(starts: &str, ends: &str, subnet: &str) -> Vec<String> {
    ["a", "", "", starts, ends, "act", subnet].iter().map(ToString::to_string).collect()
}


#[tokio::test]
async fn each_numeric_column_of_a_lookup_row_is_checked_and_empty_columns_are_none() -> TestResult {
    let scope = tenant_scope("acme")?;
    let bad_ends = Store {
        shape: Some(vec![answer_row("1", "x", "1")]),
        ..Store::default()
    };
    let bad_subnet = Store {
        shape: Some(vec![answer_row("1", "2", "x")]),
        ..Store::default()
    };
    let good = Store {
        shape: Some(vec![answer_row("1", &(NOW + DAY).to_string(), "3")]),
        ..Store::default()
    };
    let ends_exec: Executor = &executor(&bad_ends);
    let subnet_exec: Executor = &executor(&bad_subnet);
    let good_exec: Executor = &executor(&good);
    let found = lease_at(good_exec, &scope, "10.0.0.5", NOW).await?;
    let ends_found = lease_at(ends_exec, &scope, "10.0.0.5", NOW).await?;
    let subnet_found = lease_at(subnet_exec, &scope, "10.0.0.5", NOW).await?;
    assert_eq!((ends_found.intervals.len(), ends_found.skipped), (0, 1));
    assert_eq!((subnet_found.intervals.len(), subnet_found.skipped), (0, 1));
    assert_eq!(found.skipped, 0);
    assert_eq!(
        found.intervals.first().map(|interval| (interval.mac.clone(), interval.hostname.clone())),
        Some((None, None))
    );
    Ok(())
}


#[tokio::test]
async fn nullable_columns_are_read_and_leases_without_mac_or_hostname_stay_visible() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let bare = [
        lease("10.0.0.7", MAC_A, NOW, NOW + DAY, "")?,
        lease("10.0.0.7", MAC_A, NOW - DAY, NOW + DAY, "evil host")?,
    ];
    store_history(exec, &scope, &HistorySettings::default(), NOW, &bare).await?;
    let found = lease_at(exec, &scope, "10.0.0.7", NOW + 1).await?;
    assert!(AT_SQL.contains("coalesce(mac, '')") && AT_SQL.contains("coalesce(hostname, '')"));
    assert!(MAC_SQL.contains("coalesce(mac, '')") && MAC_SQL.contains("coalesce(hostname, '')"));
    assert_eq!((found.intervals.len(), found.skipped), (PAIR, 0));
    assert!(found.intervals.iter().all(|interval| interval.hostname.is_none()));
    Ok(())
}


fn counting<'a, 'b>(
    inner: &'b (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync),
    served: &'b Arc<Mutex<Vec<usize>>>,
) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'b {
    move |scope, sql, params| -> RowFuture<'a> {
        let pending = inner(scope, sql, params);
        let tally = Arc::clone(served);
        Box::pin(async move {
            let rows = pending.await?;
            tally.lock().map_err(|_poisoned| PgError::InvalidTenant)?.push(rows.len());
            Ok(rows)
        })
    }
}


fn short_leases(count: usize, base: i64) -> Result<Vec<Converted>, Box<dyn std::error::Error>> {
    (0..count)
        .map(|index| {
            let starts = base + i64::try_from(index)?;
            lease("10.0.0.5", "aa:bb:cc:dd:ee:01", starts, starts + 1, "pc")
        })
        .collect()
}


#[tokio::test]
async fn a_lookup_in_a_gap_reads_at_most_one_more_candidate_than_the_bound_and_says_truncated() -> TestResult {
    let store = Store::default();
    let served = Arc::new(Mutex::new(Vec::new()));
    let plain = executor(&store);
    let inner: Executor = &plain;
    let counted = counting(inner, &served);
    let exec: Executor = &counted;
    let scope = tenant_scope("acme")?;
    store_history(inner, &scope, &HistorySettings::default(), NOW, &short_leases(MANY, NOW)?).await?;
    let gap_at = lease_at(exec, &scope, "10.0.0.5", NOW + DAY).await?;
    let gap_mac = leases_of_mac(exec, &scope, MAC_A, NOW + DAY, NOW + DAY * PAIR_DAYS).await?;
    let rows_read = served.lock().map_err(|_poisoned| "poisoned")?.clone();
    assert_eq!(rows_read, vec![MAX_LOOKUP_ROWS + 1, MAX_LOOKUP_ROWS + 1]);
    assert_eq!((gap_at.intervals.len(), gap_at.truncated), (0, true));
    assert_eq!((gap_mac.intervals.len(), gap_mac.truncated), (0, true));
    assert!(!AT_SQL.contains("ends >") && !MAC_SQL.contains("ends >"));
    Ok(())
}


#[tokio::test]
async fn an_old_long_lease_behind_many_newer_candidates_is_reported_truncated_never_complete() -> TestResult {
    let store = Store::default();
    let exec: Executor = &executor(&store);
    let scope = tenant_scope("acme")?;
    let long = lease("10.0.0.5", "aa:bb:cc:dd:ee:01", NOW - DAY, NOW + DAY, "victim")?;
    let batch = [vec![long], short_leases(MAX_LOOKUP_ROWS + 1, NOW)?].concat();
    store_history(exec, &scope, &HistorySettings::default(), NOW, &batch).await?;
    let found = lease_at(exec, &scope, "10.0.0.5", NOW + DAY - 1).await?;
    let by_mac = leases_of_mac(exec, &scope, MAC_A, NOW + DAY - 1, NOW + DAY).await?;
    assert!(found.truncated && by_mac.truncated);
    assert!(found.intervals.is_empty() && by_mac.intervals.is_empty());
    Ok(())
}


#[tokio::test]
async fn a_time_the_range_cannot_hold_skips_the_row() -> TestResult {
    let scope = tenant_scope("acme")?;
    let sentinel = Store {
        shape: Some(vec![
            answer_row("", "2", "3"),
            answer_row("1", "", "3"),
            answer_row("1", "253402300801", "3"),
            answer_row("-1", "2", "3"),
        ]),
        ..Store::default()
    };
    let exec: Executor = &executor(&sentinel);
    let found = lease_at(exec, &scope, "10.0.0.5", NOW).await?;
    assert_eq!((found.intervals.len(), found.skipped), (0, SENTINEL_ROWS));
    Ok(())
}


const SENTINEL_ROWS: usize = 4;
