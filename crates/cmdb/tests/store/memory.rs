use crate::types::StoredAsset;
use cmdb::store::{APPLY_SQL, ASSETS_SQL, ASSET_CURSOR, ATTRIBUTE_CURSOR, KEYS_SQL, KEY_CURSOR};
use cmdb::types::Row;
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};


const KEY_CAP_PARAM: usize = 2;


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


const CONFLICT_FIELDS: [&str; 6] = [
    "asset",
    "attribute",
    "current_value",
    "current_source",
    "observed_value",
    "observed_source",
];


pub fn set_status(conflict: &mut Value, status: &str) {
    conflict.as_object_mut().into_iter().for_each(|object| {
        object.insert("status".to_owned(), Value::from(status));
    });
}


pub fn is_open(conflict: &Value) -> bool {
    text(conflict, "status") != "resolved"
}


pub fn same_conflict(left: &Value, right: &Value) -> bool {
    is_open(left) && CONFLICT_FIELDS.iter().all(|field| text(left, field) == text(right, field))
}


pub fn is_key(conflict: &Value) -> bool {
    conflict.get("is_key").and_then(Value::as_bool).unwrap_or(false)
}


pub fn open_count(tenant: &Tenant, asset: &str, source: &str, key: bool) -> usize {
    tenant
        .conflicts
        .iter()
        .filter(|conflict| {
            is_open(conflict)
                && text(conflict, "asset") == asset
                && text(conflict, "observed_source") == source
                && text(conflict, "attribute").starts_with("key:") == key
        })
        .count()
}


pub fn is_exempt(conflict: &Value) -> bool {
    conflict.get("exempt").and_then(Value::as_bool).unwrap_or(false)
}


pub fn is_known(tenant: &Tenant, conflict: &Value) -> bool {
    tenant.conflicts.iter().any(|other| same_conflict(other, conflict))
}


pub fn fresh_conflicts(tenant: &Tenant, document: &Value) -> Vec<Value> {
    let mut fresh: Vec<Value> = Vec::new();
    items(document, "conflicts").into_iter().for_each(|conflict| {
        if !is_known(tenant, &conflict) && !fresh.iter().any(|other| same_conflict(other, &conflict)) {
            fresh.push(conflict);
        }
    });
    fresh
}


pub fn duplicate_list(tenant: &Tenant, document: &Value) -> String {
    let mut listed: Vec<(String, String, String)> = items(document, "conflicts")
        .iter()
        .filter(|conflict| is_known(tenant, conflict))
        .map(|conflict| (text(conflict, "asset"), text(conflict, "attribute"), text(conflict, "observed_source")))
        .collect();
    listed.sort();
    listed.dedup();
    Value::Array(
        listed
            .into_iter()
            .map(|(asset, attribute, source)| serde_json::json!({"asset": asset, "attribute": attribute, "observed_source": source}))
            .collect(),
    )
    .to_string()
}


pub fn rank_key(conflict: &Value) -> (String, String, String, String, String, String) {
    (
        text(conflict, "asset"),
        text(conflict, "observed_source"),
        text(conflict, "attribute"),
        text(conflict, "current_value"),
        text(conflict, "current_source"),
        text(conflict, "observed_value"),
    )
}


/// Ranks like `apply.sql`: per (asset, source, key class), by attribute and values, exempt conflicts take no position.
pub fn admitted_conflicts(tenant: &Tenant, fresh: Vec<Value>, cap: usize, key_cap: usize) -> Vec<Value> {
    let mut ranked = fresh;
    ranked.sort_by_key(rank_key);
    let mut taken: BTreeMap<(String, String, bool), usize> = BTreeMap::new();
    ranked
        .into_iter()
        .filter(|conflict| {
            let asset = text(conflict, "asset");
            let source = text(conflict, "observed_source");
            let key = is_key(conflict);
            let exempt = is_exempt(conflict);
            let position = taken.entry((asset.clone(), source.clone(), key)).or_default();
            *position += usize::from(!exempt);
            exempt || open_count(tenant, &asset, &source, key) + *position <= if key { key_cap } else { cap }
        })
        .collect()
}


pub fn refused_list(candidates: &[Value], admitted: &[Value]) -> String {
    let refused: Vec<Value> = candidates
        .iter()
        .filter(|conflict| !admitted.contains(conflict))
        .map(|conflict| {
            serde_json::json!({
                "asset": text(conflict, "asset"),
                "attribute": text(conflict, "attribute"),
                "observed_source": text(conflict, "observed_source"),
            })
        })
        .collect();
    Value::Array(refused).to_string()
}


pub fn apply(tenant: &mut Tenant, document: &Value, caps: (usize, usize)) -> Result<(bool, String, String), PgError> {
    let assets = items(document, "assets");
    let fresh = !is_stale(tenant, &assets);
    if fresh && owns_foreign_key(tenant, &assets) {
        Err(unique_violation())
    } else {
        let mut refused = "[]".to_owned();
        let mut duplicates = "[]".to_owned();
        if fresh {
            let candidates = fresh_conflicts(tenant, document);
            let new_conflicts = admitted_conflicts(tenant, candidates.clone(), caps.0, caps.1);
            refused = refused_list(&candidates, &new_conflicts);
            duplicates = duplicate_list(tenant, document);
            assets
                .iter()
                .filter(|asset| {
                    asset.get("touch").and_then(Value::as_bool).unwrap_or(false)
                        || new_conflicts.iter().any(|conflict| text(conflict, "asset") == text(asset, "id"))
                })
                .for_each(|asset| write_asset(tenant, asset));
            tenant.conflicts.extend(new_conflicts.into_iter().map(|mut conflict| {
                set_status(&mut conflict, "open");
                conflict
            }));
            tenant.events.extend(items(document, "events"));
            tenant.applies += 1;
        }
        Ok((fresh, refused, duplicates))
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
            Some(Forced::Stale) => Ok(vec![vec!["false".to_owned(), "[]".to_owned(), "[]".to_owned()]]),
            Some(Forced::UniqueViolation) => Err(unique_violation()),
            Some(Forced::OtherError) => Err(other_error()),
            None => {
                let document: Value = serde_json::from_str(params.first().map_or("null", String::as_str)).unwrap_or(Value::Null);
                let cap = params.get(1).and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
                let key_cap = params.get(KEY_CAP_PARAM).and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
                apply(tenant, &document, (cap, key_cap)).map(|(applied, refused, duplicates)| vec![vec![applied.to_string(), refused, duplicates]])
            }
        }
    } else {
        Ok(page(read_rows(tenant, sql), sql, params))
    }
}
