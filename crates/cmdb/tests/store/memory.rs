use crate::types::StoredAsset;
use cmdb::store::{APPLY_SQL, ASSETS_SQL, KEYS_SQL};
use cmdb::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};


#[derive(Default)]
pub struct Tenant {
    pub assets: BTreeMap<String, StoredAsset>,
    pub keys: BTreeMap<(String, String), String>,
    pub attributes: BTreeMap<(String, String), (String, String)>,
    pub conflicts: Vec<Value>,
    pub events: Vec<Value>,
    pub applies: usize,
    pub raw_assets: Vec<Row>,
    pub raw_keys: Vec<Row>,
    pub raw_attributes: Vec<Row>,
}


#[derive(Clone, Copy)]
pub enum Forced {
    Stale,
    UniqueViolation,
    OtherError,
}


#[derive(Default)]
pub struct Db {
    pub tenants: Mutex<BTreeMap<String, Tenant>>,
    pub forced: Mutex<VecDeque<Forced>>,
    pub apply_calls: Mutex<usize>,
    pub reads: Mutex<Vec<(String, String)>>,
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn text(value: &Value, field: &str) -> String {
    value.get(field).and_then(Value::as_str).map_or_else(String::new, str::to_owned)
}


pub fn items(value: &Value, field: &str) -> Vec<Value> {
    value.get(field).and_then(Value::as_array).map_or_else(Vec::new, Clone::clone)
}


pub fn page(rows: Vec<Row>, params: &[String]) -> Vec<Row> {
    let limit = params.first().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
    let offset = params.get(1).and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
    rows.into_iter().skip(offset).take(limit).collect()
}


pub fn read_rows(tenant: &Tenant, sql: &str) -> Vec<Row> {
    if sql == ASSETS_SQL {
        let mut rows: Vec<Row> = tenant
            .assets
            .iter()
            .map(|(id, (kind, lifecycle, version))| vec![id.clone(), kind.clone(), lifecycle.clone(), version.to_string()])
            .collect();
        rows.extend(tenant.raw_assets.clone());
        rows
    } else if sql == KEYS_SQL {
        let mut rows: Vec<Row> = tenant
            .keys
            .iter()
            .map(|((key, value), asset)| vec![asset.clone(), key.clone(), value.clone()])
            .collect();
        rows.extend(tenant.raw_keys.clone());
        rows
    } else {
        let mut rows: Vec<Row> = tenant
            .attributes
            .iter()
            .map(|((asset, name), (value, source))| vec![asset.clone(), name.clone(), value.clone(), source.clone()])
            .collect();
        rows.extend(tenant.raw_attributes.clone());
        rows
    }
}


pub fn is_stale(tenant: &Tenant, assets: &[Value]) -> bool {
    assets.iter().any(|asset| {
        let version = asset.get("version").and_then(Value::as_i64).unwrap_or(0);
        match tenant.assets.get(&text(asset, "id")) {
            Some((_, _, stored)) => *stored != version,
            None => version != 0,
        }
    })
}


pub fn write_asset(tenant: &mut Tenant, asset: &Value) {
    let id = text(asset, "id");
    let version = asset.get("version").and_then(Value::as_i64).unwrap_or(0);
    tenant
        .assets
        .insert(id.clone(), (text(asset, "kind"), text(asset, "lifecycle"), version + 1));
    items(asset, "keys").iter().for_each(|key| {
        tenant.keys.entry((text(key, "key"), text(key, "value"))).or_insert_with(|| id.clone());
    });
    items(asset, "attributes").iter().for_each(|attribute| {
        tenant.attributes.insert(
            (id.clone(), text(attribute, "name")),
            (text(attribute, "value"), text(attribute, "source")),
        );
    });
}


pub fn apply(tenant: &mut Tenant, document: &Value) -> bool {
    let assets = items(document, "assets");
    let fresh = !is_stale(tenant, &assets);
    if fresh {
        assets.iter().for_each(|asset| write_asset(tenant, asset));
        tenant.conflicts.extend(items(document, "conflicts"));
        tenant.events.extend(items(document, "events"));
        tenant.applies += 1;
    }
    fresh
}


pub fn unique_violation() -> PgError {
    PgError::Server {
        code: "23505".to_owned(),
        class: "integrity constraint violation",
    }
}


pub fn other_error() -> PgError {
    PgError::Server {
        code: "42601".to_owned(),
        class: "syntax error or access rule violation",
    }
}


pub fn handle(db: &Db, scope: &TenantScope, sql: &str, params: &[String]) -> Result<Vec<Row>, PgError> {
    let name = tenant_of(scope).to_owned();
    lock(&db.reads).push((name.clone(), sql.to_owned()));
    let mut tenants = lock(&db.tenants);
    let tenant = tenants.entry(name).or_default();
    if sql == APPLY_SQL {
        *lock(&db.apply_calls) += 1;
        match lock(&db.forced).pop_front() {
            Some(Forced::Stale) => Ok(vec![vec!["false".to_owned()]]),
            Some(Forced::UniqueViolation) => Err(unique_violation()),
            Some(Forced::OtherError) => Err(other_error()),
            None => {
                let document: Value = serde_json::from_str(params.first().map_or("null", String::as_str)).unwrap_or(Value::Null);
                Ok(vec![vec![apply(tenant, &document).to_string()]])
            }
        }
    } else {
        Ok(page(read_rows(tenant, sql), params))
    }
}
