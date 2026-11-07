use crate::config::api_config;
use crate::error::StartupError;
use crate::model::{ApiConfig, ApiSettings};
use crate::oidc::load_oidc;
use crate::server::{check_transport, tls_server_config};
use crate::state::read_compromised;
use crate::types::{LogLevelHandle, SharedState};
use axum_server::tls_rustls::RustlsConfig;
use core_audit::log::append;
use core_auth::rbac::builtin_catalog;
use core_config::error::ConfigError;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use core_config::reload::{module_state, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;


pub const RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);


pub const RELOAD_ACTOR: &str = "core-api";


pub const RELOAD_REQUEST_ID: &str = "reload";


pub const FINGERPRINT_TLS_CERTIFICATE: &str = "file.tls_certificate";


pub const FINGERPRINT_TLS_KEY: &str = "file.tls_key";


pub const FINGERPRINT_COMPROMISED: &str = "file.compromised_list";


pub const FINGERPRINT_OIDC: &str = "file.oidc";


pub fn content_digest(bytes: &[u8]) -> String {
    HEXLOWER.encode(&Sha256::digest(bytes))
}


pub fn file_digest(path: &Path) -> Result<String, io::Error> {
    fs::read(path).map(|bytes| content_digest(&bytes))
}


pub fn file_fingerprints(files: &[(&str, &Path)]) -> Result<BTreeMap<String, String>, io::Error> {
    files
        .iter()
        .map(|(name, path)| file_digest(path).map(|text| ((*name).to_owned(), text)))
        .collect()
}


/// Reads and checks every file the configuration points at, so a swap can no longer fail.
pub fn build_settings(module: ModuleConfig) -> Result<ApiSettings, StartupError> {
    let config = api_config(&module)?;
    check_transport(config.address, config.tls.as_ref())?;
    let tls = config.tls.as_ref().map(|files| tls_server_config(files).map(Arc::new)).transpose()?;
    let oidc = config
        .oidc
        .as_ref()
        .map(|files| load_oidc(files, &builtin_catalog()).map(Arc::new))
        .transpose()?;
    let compromised = Arc::new(read_compromised(&config.compromised_list)?);
    let files = config.tls.iter().flat_map(|tls_files| {
        [
            (FINGERPRINT_TLS_CERTIFICATE, tls_files.certificate.as_path()),
            (FINGERPRINT_TLS_KEY, tls_files.key.as_path()),
        ]
    });
    let all_files: Vec<_> = files.chain([(FINGERPRINT_COMPROMISED, config.compromised_list.as_path())]).collect();
    let mut fingerprints = file_fingerprints(&all_files)?;
    fingerprints.extend(oidc.iter().map(|runtime| (FINGERPRINT_OIDC.to_owned(), runtime.fingerprint.clone())));
    Ok(ApiSettings {
        module,
        config,
        tls,
        oidc,
        compromised,
        fingerprints,
    })
}


/// The loader of the reload engine: any failure becomes a refusal that keeps its cause.
pub fn load_settings(path: &Path) -> Result<ApiSettings, ConfigError> {
    build_settings(load_module(path)?).map_err(|source| ConfigError::Io {
        file: path.display().to_string(),
        source: io::Error::other(source),
    })
}


/// Returns `first` once, so the engine and the running state start from the same configuration, then reads the file.
pub fn first_then_file(first: ApiSettings, path: PathBuf) -> Box<LoaderFn<ApiSettings>> {
    let pending = Mutex::new(Some(first));
    Box::new(move || {
        let taken = pending.lock().unwrap_or_else(PoisonError::into_inner).take();
        taken.map_or_else(|| load_settings(&path), Ok)
    })
}


/// The module state plus one digest per referenced file, so a replaced certificate or list is a change; digests only, never content.
pub fn settings_state(settings: &ApiSettings) -> ConfigState {
    module_state(&settings.module)
        .into_iter()
        .chain(settings.fingerprints.iter().map(|(name, text)| (name.clone(), text.clone())))
        .collect()
}


/// The module file and every file it points at: a change to any of them reloads.
pub fn watched_files(module_file: &Path, config: &ApiConfig) -> Vec<PathBuf> {
    let tls = config.tls.iter().flat_map(|files| [files.certificate.clone(), files.key.clone()]);
    let oidc = config
        .oidc
        .iter()
        .flat_map(|files| [Some(files.config.clone()), files.ca_file.clone()])
        .flatten();
    [module_file.to_path_buf(), config.compromised_list.clone()]
        .into_iter()
        .chain(tls)
        .chain(oidc)
        .collect()
}


pub fn accept(_settings: &ApiSettings) -> Result<(), BoxError> {
    Ok(())
}


/// Refuses a change to something fixed when the server started, naming it.
pub fn validate_fixed(startup: &ApiConfig, settings: &ApiSettings) -> Result<(), BoxError> {
    let next = &settings.config;
    [
        ("listen", startup.address == next.address),
        ("header_read_timeout_seconds", startup.header_read_timeout == next.header_read_timeout),
        ("enabling or disabling TLS", startup.tls.is_some() == next.tls.is_some()),
        ("name", startup.module == next.module),
        ("tenant", startup.tenant == next.tenant),
        ("accounts_store", startup.accounts_store == next.accounts_store),
        ("audit_log", startup.audit_log == next.audit_log),
        ("key_file", startup.key_file == next.key_file),
    ]
    .into_iter()
    .find(|(_, same)| !same)
    .map_or(Ok(()), |(name, _)| Err(BoxError::from(StartupError::RestartNeeded(name))))
}


pub fn section(name: &str, apply: impl Fn(&ApiSettings) + Send + Sync + 'static) -> Subscriber<ApiSettings> {
    Subscriber {
        section: name.to_owned(),
        validate: Box::new(accept),
        apply: Box::new(apply),
    }
}


pub fn apply_oidc(state: &SharedState, settings: &ApiSettings) {
    let current = state.oidc.load_full();
    if current.as_deref().map(|runtime| &runtime.fingerprint) != settings.oidc.as_deref().map(|runtime| &runtime.fingerprint) {
        state.oidc.store(settings.oidc.clone());
    }
}


pub fn apply_log_level(handle: &LogLevelHandle, settings: &ApiSettings) {
    handle
        .modify(|filter| *filter = settings.config.log_level)
        .unwrap_or_else(|error| tracing::error!(%error, "cannot change the log level"));
}


/// Validation first (all sections), effects after the swap; the fixed listener section carries the only refusals.
pub fn subscribers(state: &SharedState, startup: ApiConfig, tls: Option<RustlsConfig>, log: Option<LogLevelHandle>) -> Vec<Subscriber<ApiSettings>> {
    let (for_limits, for_oidc, for_list) = (state.clone(), state.clone(), state.clone());
    vec![
        Subscriber {
            section: "listener".to_owned(),
            validate: Box::new(move |settings| validate_fixed(&startup, settings)),
            apply: Box::new(|_| ()),
        },
        section("limits", move |settings| for_limits.limits.store(Arc::new(settings.config.limits))),
        section("tls", move |settings| {
            tls.iter()
                .zip(settings.tls.iter())
                .for_each(|(live, next)| live.reload_from_config(Arc::clone(next)));
        }),
        section("oidc", move |settings| apply_oidc(&for_oidc, settings)),
        section("compromised", move |settings| {
            for_list.compromised.store(Arc::clone(&settings.compromised))
        }),
        section("log", move |settings| log.iter().for_each(|handle| apply_log_level(handle, settings))),
    ]
}


pub fn audit_into(state: &SharedState) -> Box<SharedAuditFn> {
    let log = state.clone();
    Box::new(move |entry| append(&log.audit, entry))
}


/// Opens the engine on the configuration the state was built from.
pub fn open_reload(
    state: &SharedState,
    settings: ApiSettings,
    module_file: &Path,
    tls: Option<RustlsConfig>,
    log: Option<LogLevelHandle>,
) -> Result<Arc<ReloadEngine<ApiSettings>>, ConfigError> {
    let context = ReloadContext {
        actor_id: RELOAD_ACTOR.to_owned(),
        tenant: state.tenant.clone(),
        module: state.module.clone(),
        target: module_file.display().to_string(),
        request_id: RELOAD_REQUEST_ID.to_owned(),
    };
    let startup = settings.config.clone();
    open_engine(
        first_then_file(settings, module_file.to_path_buf()),
        settings_state,
        subscribers(state, startup, tls, log),
        audit_into(state),
        context,
    )
    .map(Arc::new)
}
