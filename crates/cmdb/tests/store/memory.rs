use crate::types::StoredAsset;
use cmdb::store::{APPLY_SQL, ASSETS_SQL, ASSET_CURSOR, ATTRIBUTE_CURSOR, KEYS_SQL, KEY_CURSOR};
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


pub fn cell_of(row: &Row, column: usize) -> String {
    row.get(column).map_or_else(String::new, Clone::clone)
}


pub fn page(rows: Vec<Row>, sql: &str, params: &[String]) -> Vec<Row> {
    let columns: &[usize] = if sql == ASSETS_SQL {
        &ASSET_CURSOR
    } else if sql == KEYS_SQL {
        &KEY_CURSOR
    } else {
        &ATTRIBUTE_CURSOR
    };
    let first = params.first().is_some_and(|flag| flag == "true");
    let limit = params.last().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
    let cursor: Vec<String> = params.iter().skip(1).take(columns.len()).cloned().collect();
    rows.into_iter()
        .filter(|row| first || columns.iter().map(|column| cell_of(row, *column)).collect::<Vec<String>>() > cursor)
        .take(limit)
        .collect()
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


pub fn owns_foreign_key(tenant: &Tenant, assets: &[Value]) -> bool {
    assets.iter().any(|asset| {
        items(asset, "keys").iter().any(|key| {
            tenant
                .keys
                .get(&(text(key, "key"), text(key, "value")))
                .is_some_and(|owner| *owner != text(asset, "id"))
        })
    })
}


pub fn write_asset(tenant: &mut Tenant, asset: &Value) {
    let id = text(asset, "id");
    let version = asset.get("version").and_then(Value::as_i64).unwrap_or(0);
    tenant
        .assets
        .insert(id.clone(), (text(asset, "kind"), text(asset, "lifecycle"), version + 1));
    items(asset, "keys").iter().for_each(|key| {
        tenant.keys.insert((text(key, "key"), text(key, "value")), id.clone());
    });
    items(asset, "attributes").iter().for_each(|attribute| {
        tenant.attributes.insert(
            (id.clone(), text(attribute, "name")),
            (text(attribute, "value"), text(attribute, "source")),
        );
    });
}


pub fn apply(tenant: &mut Tenant, document: &Value) -> Result<bool, PgError> {
    let assets = items(document, "assets");
    let fresh = !is_stale(tenant, &assets);
    if fresh && owns_foreign_key(tenant, &assets) {
        Err(unique_violation())
    } else {
        if fresh {
            assets.iter().for_each(|asset| write_asset(tenant, asset));
            tenant.conflicts.extend(items(document, "conflicts"));
            tenant.events.extend(items(document, "events"));
            tenant.applies += 1;
        }
        Ok(fresh)
    }
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
                apply(tenant, &document).map(|applied| vec![vec![applied.to_string()]])
            }
        }
    } else {
        Ok(page(read_rows(tenant, sql), sql, params))
    }
}
