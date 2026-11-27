use alerts::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use vuln_match::store::{ASSET_SQL, REBUILD_SQL, SCAN_SQL};


/// Models `vuln_scan_store` (one scan is the whole truth of its asset) and the alert insert.
#[derive(Default)]
pub struct FakeStore {
    pub open: Mutex<BTreeMap<String, BTreeSet<String>>>,
    pub scans: Mutex<Vec<(String, String, usize)>>,
    pub versions: Mutex<BTreeMap<String, String>>,
    pub alerts: Mutex<BTreeSet<String>>,
    pub tenants: Mutex<BTreeSet<String>>,
    pub rebuilds: Mutex<usize>,
    pub missing_counters: AtomicBool,
    pub fail_asset: Option<&'static str>,
    pub no_room_package: Option<&'static str>,
    pub fail_readback: bool,
    pub fail_alerts: AtomicBool,
}


pub const RECORD_PART: usize = 2;


pub fn text_of<'a>(doc: &'a Value, key: &str) -> &'a str {
    doc.get(key).and_then(Value::as_str).map_or("", |text| text)
}


pub fn answer(store: &FakeStore, scope: &TenantScope, sql: &'static str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let first = params.first().map_or("", String::as_str);
    store
        .tenants
        .lock()
        .map_err(|_poisoned| PgError::InvalidTenant)?
        .insert(tenant_of(scope).to_owned());
    if sql == SCAN_SQL {
        if store.fail_asset == Some(first) {
            Err(PgError::InvalidTenant)
        } else if store.missing_counters.swap(false, Ordering::SeqCst) {
            Ok(vec![["0", "0", "0", "0", "0", "0", "1"].map(str::to_owned).to_vec()])
        } else {
            let docs: Vec<Value> = serde_json::from_str(params.get(1).ok_or(PgError::InvalidTenant)?).map_err(|_bad| PgError::InvalidTenant)?;
            let keys: BTreeSet<String> = docs
                .iter()
                .filter(|doc| store.no_room_package != Some(text_of(doc, "package")))
                .map(|doc| format!("{}/{}/{}", text_of(doc, "ecosystem"), text_of(doc, "package"), text_of(doc, "record_id")))
                .collect();
            let admitted: Vec<&Value> = docs.iter().filter(|doc| store.no_room_package != Some(text_of(doc, "package"))).collect();
            let no_room = docs.len() - admitted.len();
            let duplicates = admitted.len() - keys.len();
            let mut versions = store.versions.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
            versions.retain(|key, _| !key.starts_with(&format!("{first}|")));
            admitted.iter().for_each(|doc| {
                let key = format!(
                    "{first}|{}/{}/{}",
                    text_of(doc, "ecosystem"),
                    text_of(doc, "package"),
                    text_of(doc, "record_id")
                );
                let version = text_of(doc, "installed_version").to_owned();
                let kept = versions.get(&key).filter(|held| **held < version).cloned().unwrap_or(version);
                versions.insert(key, kept);
            });
            let mut open = store.open.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
            let resolved = open
                .insert(first.to_owned(), keys.clone())
                .map_or(0, |before| before.difference(&keys).count());
            store
                .scans
                .lock()
                .map_err(|_poisoned| PgError::InvalidTenant)?
                .push((first.to_owned(), tenant_of(scope).to_owned(), keys.len()));
            Ok(vec![[
                keys.len().to_string(),
                "0".to_owned(),
                resolved.to_string(),
                no_room.to_string(),
                "0".into(),
                duplicates.to_string(),
                "0".into(),
            ]
            .to_vec()])
        }
    } else if sql == ASSET_SQL {
        if store.fail_readback {
            Err(PgError::InvalidTenant)
        } else {
            let open = store.open.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
            let versions = store.versions.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
            Ok(open
                .get(first)
                .into_iter()
                .flatten()
                .map(|key| {
                    let parts: Vec<&str> = key.split('/').collect();
                    let text = |index: usize| parts.get(index).map_or(String::new(), |part| (*part).to_owned());
                    let version = versions.get(&format!("{first}|{key}")).map_or("1".to_owned(), Clone::clone);
                    [first.to_owned(), text(0), text(1), text(RECORD_PART), version, String::new()]
                        .into_iter()
                        .chain(["0", "0.5", "true", "1", "1", "1"].map(str::to_owned))
                        .collect()
                })
                .collect())
        }
    } else if sql == REBUILD_SQL {
        *store.rebuilds.lock().map_err(|_poisoned| PgError::InvalidTenant)? += 1;
        Ok(vec![vec!["1".to_owned()]])
    } else if store.fail_alerts.load(Ordering::SeqCst) {
        Err(PgError::InvalidTenant)
    } else {
        let docs: Vec<Value> = serde_json::from_str(first).map_err(|_bad| PgError::InvalidTenant)?;
        let mut alerts = store.alerts.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
        let new = docs
            .iter()
            .filter_map(|doc| doc.get("id").and_then(Value::as_str))
            .filter(|id| alerts.insert((*id).to_owned()))
            .count();
        Ok(vec![vec![new.to_string()]])
    }
}


pub fn executor<'a>(store: &'a FakeStore) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + Sync + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(answer(store, &scope, sql, &params))) }
}
