use core_api::reload::current_entry;
use core_api::types::{SharedListener, StartupReloadFn};
use core_audit::error::AuditError;
use core_audit::log::append_declared;
use core_config::error::ConfigError;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use core_config::reload::{open_engine, reload, ReloadContext, ReloadEngine, RELOAD_DECLARED_KEYS};
use core_config::types::{LoaderFn, SharedAuditFn};
use core_pg::settings::{load_settings, settings_state, PgSettings};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;


pub const SETTING_PG: &str = "pg_settings";


pub const STARTUP_REQUEST: &str = "startup";


pub const ACTOR: &str = "alerts";


pub const DEFAULT_TENANT: &str = "default";


pub const NOT_OPEN: &str = "the module audit log is not open yet";


/// The core-pg settings file named by `settings.pg_settings` of the module file.
pub fn pg_file_of(module_file: &Path, module: &ModuleConfig) -> Result<PathBuf, ConfigError> {
    module
        .settings
        .get(SETTING_PG)
        .map(PathBuf::from)
        .ok_or_else(|| ConfigError::WatchedFile {
            file: module_file.display().to_string(),
            reason: format!("settings.{SETTING_PG} is required"),
        })
}


/// The module file is read again at each reload only to refuse a change of `settings.pg_settings`; the file that is parsed is the baseline one.
pub fn check_unchanged(module_file: &Path, baseline: &Path) -> Result<(), ConfigError> {
    let current = pg_file_of(module_file, &load_module(module_file)?)?;
    if current == baseline {
        Ok(())
    } else {
        Err(ConfigError::WatchedFile {
            file: format!("settings.{SETTING_PG}"),
            reason: "read at start only, restart the service to change it".to_owned(),
        })
    }
}


pub fn pg_loader(module_file: PathBuf, baseline: PathBuf) -> Box<LoaderFn<PgSettings>> {
    Box::new(move || {
        check_unchanged(&module_file, &baseline)?;
        load_settings(&baseline)
    })
}


/// Appends to the module audit log once `run_module` has opened it; an entry before that is an error the engine logs.
pub fn module_audit(listener: SharedListener) -> Box<SharedAuditFn> {
    Box::new(move |entry| match listener.state.get() {
        Some(state) => append_declared(&state.audit, current_entry(state, entry), &RELOAD_DECLARED_KEYS),
        None => Err(AuditError::Io(io::Error::other(NOT_OPEN))),
    })
}


/// Reads the module file and the core-pg settings it names; later reloads (file watch, `SIGHUP`) are audited in the module audit log.
pub fn open_pg_engine(module_file: &Path, listener: SharedListener) -> Result<(ReloadEngine<PgSettings>, PathBuf), ConfigError> {
    open_pg_engine_as(module_file, listener, ACTOR)
}


/// As `open_pg_engine`, with the audit actor of the module that embeds the settings (`cases`, not `alerts`).
pub fn open_pg_engine_as(module_file: &Path, listener: SharedListener, actor: &str) -> Result<(ReloadEngine<PgSettings>, PathBuf), ConfigError> {
    let module = load_module(module_file)?;
    open_pg_engine_from(module_file, &module, listener, actor)
}


/// As `open_pg_engine_as` for a module file the caller already read, so the core-pg file named comes from the same read as the rest of the start-up.
pub fn open_pg_engine_from(
    module_file: &Path,
    module: &ModuleConfig,
    listener: SharedListener,
    actor: &str,
) -> Result<(ReloadEngine<PgSettings>, PathBuf), ConfigError> {
    let pg_file = pg_file_of(module_file, module)?;
    let context = ReloadContext {
        actor_id: actor.to_owned(),
        tenant: module.tenant.clone().unwrap_or_else(|| DEFAULT_TENANT.to_owned()),
        module: module.name.clone(),
        target: pg_file.display().to_string(),
        request_id: STARTUP_REQUEST.to_owned(),
    };
    let engine = open_engine(
        pg_loader(module_file.to_path_buf(), pg_file.clone()),
        settings_state,
        Vec::new(),
        module_audit(listener),
        context,
    )?;
    Ok((engine, pg_file))
}


/// The pg engine's reload for `run_loaded`: an edit made before the audit log opened was refused unaudited and left the engine unchanged, so this replays it.
pub fn startup_reload(engine: Arc<ReloadEngine<PgSettings>>) -> StartupReloadFn {
    Box::new(move || reload(&engine))
}


/// The startup reloads every API example hands to `run_loaded`: today the pg engine only.
pub fn api_startup_reloads(engine: Arc<ReloadEngine<PgSettings>>) -> Vec<StartupReloadFn> {
    vec![startup_reload(engine)]
}
