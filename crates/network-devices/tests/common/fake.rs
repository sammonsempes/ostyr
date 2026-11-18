use alerts::store::INSERT_SQL;
use cmdb::store::{APPLY_SQL, ASSETS_SQL, KEYS_SQL};
use cmdb::types::{Row, RowFuture};
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::ready;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};


const ASSET_CAP_PARAM: usize = 3;


static LOGGING: OnceLock<Result<(), String>> = OnceLock::new();


/// Installs one global sink subscriber so every `tracing` callsite is enabled whatever the test order.
pub fn init_logging() -> Result<(), String> {
    LOGGING
        .get_or_init(|| {
            tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish()).map_err(|error| error.to_string())
        })
        .clone()
}


#[derive(Default)]
pub struct Tenant {
    pub assets: BTreeMap<String, (String, i64)>,
    pub keys: BTreeMap<(String, String), String>,
    pub attributes: BTreeMap<(String, String), (String, String)>,
    pub retired: Vec<String>,
}


#[derive(Default)]
pub struct Fake {
    pub tenants: Mutex<BTreeMap<String, Tenant>>,
    pub scopes: Mutex<Vec<String>>,
    pub alerts: Mutex<Vec<String>>,
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


pub fn seed_server(fake: &Fake, tenant: &str, id: &str, address: &str) {
    let mut tenants = lock(&fake.tenants);
    let entry = tenants.entry(tenant.to_owned()).or_default();
    entry.assets.insert(id.to_owned(), ("server".to_owned(), 1));
    entry.keys.insert(("name".to_owned(), id.to_owned()), id.to_owned());
    entry
        .attributes
        .insert((id.to_owned(), "discovery.ip".to_owned()), (address.to_owned(), "discovery".to_owned()));
}


pub fn seed_retired_device(fake: &Fake, tenant: &str, name_key: &str) {
    let mut tenants = lock(&fake.tenants);
    let entry = tenants.entry(tenant.to_owned()).or_default();
    let id = format!("name:{name_key}");
    entry.assets.insert(id.clone(), ("iot".to_owned(), 1));
    entry.keys.insert(("name".to_owned(), name_key.to_owned()), id.clone());
    entry.retired.push(id);
}


pub fn read_rows(tenant: &Tenant, sql: &str) -> Vec<Row> {
    if sql == ASSETS_SQL {
        tenant
            .assets
            .iter()
            .map(|(id, (kind, version))| {
                let state = if tenant.retired.contains(id) { "retired" } else { "in_service" };
                vec![id.clone(), kind.clone(), state.to_owned(), version.to_string()]
            })
            .collect()
    } else if sql == KEYS_SQL {
        tenant
            .keys
            .iter()
            .map(|((key, value), asset)| vec![asset.clone(), key.clone(), value.clone()])
            .collect()
    } else {
        tenant
            .attributes
            .iter()
            .map(|((asset, name), (value, source))| vec![asset.clone(), name.clone(), value.clone(), source.clone()])
            .collect()
    }
}


pub fn write_asset(tenant: &mut Tenant, asset: &Value) {
    let id = text(asset, "id");
    let version = asset.get("version").and_then(Value::as_i64).unwrap_or(0);
    tenant.assets.insert(id.clone(), (text(asset, "kind"), version + 1));
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


pub fn apply(tenant: &mut Tenant, params: &[String]) -> Vec<Row> {
    let document: Value = params.first().and_then(|text| serde_json::from_str(text).ok()).unwrap_or(Value::Null);
    let cap: usize = params.get(ASSET_CAP_PARAM).and_then(|text| text.parse().ok()).unwrap_or(0);
    let assets = items(&document, "assets");
    let created = assets.iter().filter(|asset| !tenant.assets.contains_key(&text(asset, "id"))).count();
    let over = tenant.assets.len() + created > cap;
    if !over {
        assets.iter().for_each(|asset| write_asset(tenant, asset));
    }
    let table = if over { "cmdb_assets" } else { "" };
    vec![vec!["true".to_owned(), "[]".to_owned(), "[]".to_owned(), table.to_owned()]]
}


pub fn handle(fake: &Fake, scope: &TenantScope, sql: &'static str, params: &[String]) -> Vec<Row> {
    lock(&fake.scopes).push(tenant_of(scope).to_owned());
    let mut tenants = lock(&fake.tenants);
    let tenant = tenants.entry(tenant_of(scope).to_owned()).or_default();
    let first = params.first().is_some_and(|flag| flag == "true");
    if sql == INSERT_SQL {
        lock(&fake.alerts).push(tenant_of(scope).to_owned());
        vec![vec!["1".to_owned()]]
    } else if sql == APPLY_SQL {
        apply(tenant, params)
    } else if first {
        read_rows(tenant, sql)
    } else {
        Vec::new()
    }
}


pub fn executor(fake: &Fake) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'_> + Sync + '_ {
    move |scope, sql, params| Box::pin(ready(Ok(handle(fake, &scope, sql, &params))))
}
