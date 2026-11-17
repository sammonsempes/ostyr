use crate::error::PlatformError;
use crate::model::Module;
use crate::types::{MigrationPlan, Parts};
use alerts::backend::MAX_CONNECTIONS;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use axum::Router;
use cases::store::{MIGRATIONS as CASE_MIGRATIONS, MIGRATION_NAMESPACE as CASE_NAMESPACE};
use cmdb::store::{MIGRATIONS as CMDB_MIGRATIONS, MIGRATION_NAMESPACE as CMDB_NAMESPACE};
use core_api::routes::core_access;
use core_api::types::{AccessTable, SharedState};
use core_config::reload::ReloadEngine;
use core_config::types::SettingsMap;
use core_pg::migrate::Migration;
use core_pg::settings::PgSettings;
use risk_score::api::{risk_access, risk_document, risk_router};
use risk_score::backend::{pg_backend as risk_backend, system_clock};
use risk_score::cache::risk_state;
use risk_score::model::Weights;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub const SETTING_MODULES: &str = "modules";


pub const SETTING_WEIGHTS_FILE: &str = "risk.weights_file";


pub const MAX_MODULES_CHARS: usize = 64;


pub const ACTOR: &str = "platform";


const ALERT_PLAN: &[Migration] = &ALERT_MIGRATIONS;


const CASE_PLAN: &[Migration] = &CASE_MIGRATIONS;


const CMDB_PLAN: &[Migration] = &CMDB_MIGRATIONS;


pub fn module_of(name: &str) -> Option<Module> {
    match name {
        "alerts" => Some(Module::Alerts),
        "cases" => Some(Module::Cases),
        "cmdb" => Some(Module::Cmdb),
        "risk" => Some(Module::Risk),
        _ => None,
    }
}


/// Strict comma separated list; an error names the entry index, never the text.
pub fn parse_modules(text: &str) -> Result<Vec<Module>, PlatformError> {
    if text.chars().nth(MAX_MODULES_CHARS).is_some() {
        Err(PlatformError::ModulesTooLong { limit: MAX_MODULES_CHARS })
    } else if text.trim().is_empty() {
        Err(PlatformError::EmptyModules)
    } else {
        text.split(',').enumerate().try_fold(Vec::new(), |mut found, (index, entry)| {
            let module = module_of(entry.trim()).ok_or(PlatformError::UnknownModule { index })?;
            if found.contains(&module) {
                Err(PlatformError::DuplicateModule { index })
            } else {
                found.push(module);
                Ok(found)
            }
        })
    }
}


pub fn modules_of(settings: &SettingsMap) -> Result<Vec<Module>, PlatformError> {
    parse_modules(settings.get(SETTING_MODULES).ok_or(PlatformError::MissingModules)?)
}


/// Union of the module tables; a key present twice, or equal to a core key, is refused.
pub fn merge_access(tables: Vec<AccessTable>) -> Result<AccessTable, PlatformError> {
    let core = core_access();
    tables.into_iter().try_fold(AccessTable::new(), |merged, table| {
        table.into_iter().try_fold(merged, |mut acc, (key, rule)| {
            if core.contains_key(&key) || acc.contains_key(&key) {
                Err(PlatformError::DuplicateRoute(key))
            } else {
                acc.insert(key, rule);
                Ok(acc)
            }
        })
    })
}


/// The weights file of the module file, required (and read) only when `risk` is selected.
pub fn weights_file_of(settings: &SettingsMap, modules: &[Module]) -> Result<Option<PathBuf>, PlatformError> {
    if modules.contains(&Module::Risk) {
        settings
            .get(SETTING_WEIGHTS_FILE)
            .map(|path| Some(PathBuf::from(path)))
            .ok_or(PlatformError::MissingWeightsFile)
    } else {
        Ok(None)
    }
}


pub fn shared_permits() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_CONNECTIONS))
}


pub fn module_router(
    module: Module,
    engine: &Arc<ReloadEngine<PgSettings>>,
    permits: &Arc<Semaphore>,
    weights: Option<&Arc<ReloadEngine<Weights>>>,
) -> Result<Router<SharedState>, PlatformError> {
    match module {
        Module::Alerts => Ok(alerts::api::alerts_router(alerts::backend::pg_backend(
            Arc::clone(engine),
            Arc::clone(permits),
        ))),
        Module::Cases => Ok(cases::api::cases_router(cases::backend::pg_backend(
            Arc::clone(engine),
            Arc::clone(permits),
        ))),
        Module::Cmdb => Ok(cmdb::api::cmdb_router(cmdb::backend::pg_backend(Arc::clone(engine), Arc::clone(permits)))),
        Module::Risk => weights.ok_or(PlatformError::MissingWeightsFile).map(|held| {
            risk_router(risk_state(
                risk_backend(Arc::clone(engine), Arc::clone(permits)),
                Arc::clone(held),
                system_clock(),
            ))
        }),
    }
}


pub fn module_access(module: Module) -> AccessTable {
    match module {
        Module::Alerts => alerts::api::alerts_access(),
        Module::Cases => cases::api::cases_access(),
        Module::Cmdb => cmdb::api::cmdb_access(),
        Module::Risk => risk_access(),
    }
}


pub fn module_document(module: Module) -> OpenApiDocument {
    match module {
        Module::Alerts => alerts::api::alerts_document(),
        Module::Cases => cases::api::cases_document(),
        Module::Cmdb => cmdb::api::cmdb_document(),
        Module::Risk => risk_document(),
    }
}


/// Routers, merged access table and documents of the selected modules; the tables merge first, so a clash is an error before any router merge.
pub fn module_parts(
    modules: &[Module],
    engine: &Arc<ReloadEngine<PgSettings>>,
    permits: &Arc<Semaphore>,
    weights: Option<&Arc<ReloadEngine<Weights>>>,
) -> Result<Parts, PlatformError> {
    let access = merge_access(modules.iter().map(|module| module_access(*module)).collect())?;
    let router = modules.iter().try_fold(Router::new(), |merged, module| {
        module_router(*module, engine, permits, weights).map(|part| merged.merge(part))
    })?;
    Ok((router, access, modules.iter().map(|module| module_document(*module)).collect()))
}


/// Namespaces to migrate in dependency order: `cases` needs `alerts` (alert links), and `risk` reads the alerts store.
pub fn migration_plan(modules: &[Module]) -> MigrationPlan {
    let wants = |wanted: &[Module]| modules.iter().any(|module| wanted.contains(module));
    [
        (wants(&[Module::Alerts, Module::Cases, Module::Risk]), ALERT_NAMESPACE, ALERT_PLAN),
        (wants(&[Module::Cases]), CASE_NAMESPACE, CASE_PLAN),
        (wants(&[Module::Cmdb]), CMDB_NAMESPACE, CMDB_PLAN),
    ]
    .into_iter()
    .filter(|(selected, _namespace, _migrations)| *selected)
    .map(|(_selected, namespace, migrations)| (namespace, migrations))
    .collect()
}
