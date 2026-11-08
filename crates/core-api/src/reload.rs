use crate::config::api_config;
use crate::error::StartupError;
use crate::model::{ApiConfig, ApiSettings, ApiState, Bound, ListenerSetup, PreparedAudit, Rewatch, Sockets, Watching};
use crate::oidc::load_oidc;
use crate::server::{bind_socket, check_transport, load_tls, retire_socket, spawn_generation, DRAIN_TIMEOUT};
use crate::state::{lock_auth, read_compromised_digested};
use crate::types::{LogLevelHandle, PendingAudit, PendingSockets, ServerHandle, SharedState, WatchGuard};
use axum_server::tls_rustls::RustlsConfig;
use core_audit::log::{append, open_file_log};
use core_audit::model::Outcome;
use core_auth::rbac::builtin_catalog;
use core_auth::store::load_store_file;
use core_config::error::ConfigError;
use core_config::load::load_module;
use core_config::model::ModuleConfig;
use core_config::reload::{module_state, open_engine, reload_entry, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use core_config::watch::watch_files;
use data_encoding::HEXLOWER;
use same_file::Handle;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};
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


/// Reads and checks every file the configuration points at, so a swap can no longer fail; each digest is of the bytes that were parsed.
pub fn build_settings(module: ModuleConfig) -> Result<ApiSettings, StartupError> {
    let config = api_config(&module)?;
    check_transport(config.address, config.tls.as_ref())?;
    let loaded_tls = config.tls.as_ref().map(load_tls).transpose()?;
    let oidc = config
        .oidc
        .as_ref()
        .map(|files| load_oidc(files, &builtin_catalog()).map(Arc::new))
        .transpose()?;
    let (list, list_digest) = read_compromised_digested(&config.compromised_list)?;
    let tls_digests = loaded_tls.iter().flat_map(|loaded| {
        [
            (FINGERPRINT_TLS_CERTIFICATE.to_owned(), loaded.certificate_digest.clone()),
            (FINGERPRINT_TLS_KEY.to_owned(), loaded.key_digest.clone()),
        ]
    });
    let oidc_digest = oidc.iter().map(|runtime| (FINGERPRINT_OIDC.to_owned(), runtime.fingerprint.clone()));
    let fingerprints = tls_digests
        .chain(oidc_digest)
        .chain([(FINGERPRINT_COMPROMISED.to_owned(), list_digest)])
        .collect();
    Ok(ApiSettings {
        module,
        config,
        tls: loaded_tls.map(|loaded| Arc::new(loaded.config)),
        oidc,
        compromised: Arc::new(list),
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
        .flat_map(|files| [Some(files.config.clone()), files.ca_file.clone(), Some(files.secret_file.clone())])
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


/// Refuses a change to an identity field: `name`, `tenant` and `key_file` are fixed by the deployment (see the crate notes).
pub fn validate_fixed(startup: &ApiConfig, settings: &ApiSettings) -> Result<(), BoxError> {
    let next = &settings.config;
    [
        ("name", startup.module == next.module),
        ("tenant", startup.tenant == next.tenant),
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


/// A moved accounts store must exist and parse (mode included) before it replaces the old one; nothing is created, not even the lock file.
pub fn check_store(state: &ApiState, settings: &ApiSettings) -> Result<(), BoxError> {
    let next = &settings.config.accounts_store;
    if **state.store_path.load() == *next {
        Ok(())
    } else {
        fs::metadata(next)?;
        load_store_file(next).map(|_| ()).map_err(BoxError::from)
    }
}


/// Points the state at the new accounts store; the sessions issued under the old one end, and the switch is audited once.
pub fn switch_store(state: &ApiState, context: &ReloadContext, settings: &ApiSettings) {
    let next = &settings.config.accounts_store;
    let previous = state.store_path.swap(Arc::new(next.clone()));
    if *previous != *next {
        lock_auth(state).sessions.clear();
        state.callback_accounts.lock().unwrap_or_else(PoisonError::into_inner).clear();
        let moved = format!(
            "accounts_store moved from {} to {}, every session revoked",
            previous.display(),
            next.display()
        );
        append(
            &state.audit,
            reload_entry(context, Outcome::Success, [("result", "applied".to_owned()), ("diff", moved)]),
        )
        .map(|_| ())
        .unwrap_or_else(|error| tracing::error!(%error, "cannot record the accounts store switch"));
    }
}


/// Opens and verifies the new audit log and keeps it for `switch_audit`; the same file under another name (`..`, a link) is not a move.
pub fn prepare_audit(
    state: &ApiState,
    current: &Mutex<PathBuf>,
    prepared: &Mutex<Option<PreparedAudit>>,
    settings: &ApiSettings,
) -> Result<(), BoxError> {
    let next = &settings.config.audit_log;
    prepared.lock().unwrap_or_else(PoisonError::into_inner).take();
    let renamed = *current.lock().unwrap_or_else(PoisonError::into_inner) != *next;
    let opened = renamed
        .then(|| {
            open_file_log(next).map_err(BoxError::from).and_then(|log| {
                let candidate = log.state.into_inner().unwrap_or_else(PoisonError::into_inner);
                let same = {
                    let running = state.audit.state.lock().unwrap_or_else(PoisonError::into_inner);
                    Handle::from_file(running.writer.try_clone()?)? == Handle::from_file(candidate.writer.try_clone()?)?
                };
                Ok((!same).then(|| PreparedAudit {
                    path: next.clone(),
                    state: candidate,
                }))
            })
        })
        .transpose()?
        .flatten();
    *prepared.lock().unwrap_or_else(PoisonError::into_inner) = opened;
    Ok(())
}


/// Swaps the open log under its own lock, so appenders see either the old or the new file; the old log got the reload record before.
pub fn switch_audit(
    state: &ApiState,
    context: &ReloadContext,
    current: &Mutex<PathBuf>,
    prepared: &Mutex<Option<PreparedAudit>>,
    settings: &ApiSettings,
) {
    let next = prepared
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .filter(|candidate| candidate.path == settings.config.audit_log);
    next.into_iter().for_each(|candidate| {
        let previous = std::mem::replace(&mut *current.lock().unwrap_or_else(PoisonError::into_inner), candidate.path);
        *state.audit.state.lock().unwrap_or_else(PoisonError::into_inner) = candidate.state;
        let moved = format!("audit_log moved from {} to {}", previous.display(), settings.config.audit_log.display());
        append(
            &state.audit,
            reload_entry(context, Outcome::Success, [("result", "applied".to_owned()), ("diff", moved)]),
        )
        .map(|_| ())
        .unwrap_or_else(|error| tracing::error!(%error, "cannot record the audit log switch in the new log"));
    });
}


/// Binds the new address (or clones the running socket when only TLS or the header timeout changes) before anything is swapped, so a bind failure refuses the reload.
pub fn prepare_sockets(setup: &ListenerSetup, pending: &Mutex<Option<Sockets>>, settings: &ApiSettings) -> Result<(), BoxError> {
    let next = &settings.config;
    pending.lock().unwrap_or_else(PoisonError::into_inner).take();
    let current = setup.listener.current.lock().unwrap_or_else(PoisonError::into_inner);
    let sockets = current
        .bound
        .as_ref()
        .filter(|bound| {
            bound.address != next.address || bound.header_read_timeout != next.header_read_timeout || bound.tls.is_some() != next.tls.is_some()
        })
        .map(|bound| {
            let kept = if bound.address == next.address {
                bound.socket.try_clone().map_err(StartupError::from)
            } else {
                bind_socket(next.address)
            }?;
            kept.try_clone().map_err(StartupError::from).map(|server| Sockets { kept, server })
        })
        .transpose()?;
    *pending.lock().unwrap_or_else(PoisonError::into_inner) = sockets;
    Ok(())
}


/// Starts the new server first (never after a stop), then stops the old one from accepting and gives its connections `DRAIN_TIMEOUT` to finish.
pub fn switch_listener(setup: &ListenerSetup, pending: &Mutex<Option<Sockets>>, settings: &ApiSettings) {
    let taken = pending.lock().unwrap_or_else(PoisonError::into_inner).take();
    let mut current = setup.listener.current.lock().unwrap_or_else(PoisonError::into_inner);
    let wanted = taken.filter(|_| !current.stopped);
    wanted.into_iter().for_each(|sockets| {
        let config = &settings.config;
        let tls = settings.tls.clone().map(RustlsConfig::from_config);
        let handle = ServerHandle::new();
        let generation = current.bound.as_ref().map_or(0, |bound| bound.generation + 1);
        spawn_generation(setup, sockets.server, tls.clone(), config.header_read_timeout, handle.clone(), generation);
        let previous = current.bound.replace(Bound {
            socket: sockets.kept,
            tls,
            address: config.address,
            header_read_timeout: config.header_read_timeout,
            generation,
        });
        previous
            .iter()
            .filter(|old| old.address != config.address)
            .for_each(|old| retire_socket(&old.socket));
        std::mem::replace(&mut current.handle, handle).graceful_shutdown(Some(DRAIN_TIMEOUT));
    });
}


/// Watches what the new configuration points at; the old watch is replaced only once the new one exists.
pub fn rewatch(rewatch: &Rewatch, files: Vec<PathBuf>) -> Result<(), StartupError> {
    let mut watching = rewatch.watching.lock().unwrap_or_else(PoisonError::into_inner);
    if watching.as_ref().is_some_and(|current| current.files == files) {
        Ok(())
    } else {
        let engine = rewatch.engine.get().and_then(Weak::upgrade).ok_or(StartupError::EngineGone)?;
        let guard: WatchGuard = Box::new(watch_files(engine, &files, RELOAD_DEBOUNCE)?);
        *watching = Some(Watching { files, guard });
        Ok(())
    }
}


/// Watches the files of the new configuration; a failure is logged and the old watch stays.
pub fn follow_files(slot: &Rewatch, module_file: &Path, settings: &ApiSettings) {
    rewatch(slot, watched_files(module_file, &settings.config)).unwrap_or_else(|error| tracing::error!(%error, "cannot follow the watched files"));
}


/// Validation first (all sections), effects after the swap; the listener section validates last because it binds a socket.
pub fn subscribers(
    state: &SharedState,
    startup: ApiConfig,
    setup: ListenerSetup,
    module_file: PathBuf,
    context: ReloadContext,
    log: Option<LogLevelHandle>,
) -> Vec<Subscriber<ApiSettings>> {
    let (for_limits, for_oidc, for_list) = (state.clone(), state.clone(), state.clone());
    let (check_state, apply_state, audit_state, prepare_state) = (state.clone(), state.clone(), state.clone(), state.clone());
    let store_context = context.clone();
    let audit_path = Arc::new(Mutex::new(startup.audit_log.clone()));
    let audit_applied_path = Arc::clone(&audit_path);
    let prepared_audit = PendingAudit::default();
    let applied_audit = Arc::clone(&prepared_audit);
    let prepared_sockets = PendingSockets::default();
    let applied_sockets = Arc::clone(&prepared_sockets);
    let (listener_setup, tls_setup, watch_setup) = (setup.clone(), setup.clone(), setup.clone());
    vec![
        Subscriber {
            section: "identity".to_owned(),
            validate: Box::new(move |settings| validate_fixed(&startup, settings)),
            apply: Box::new(|_| ()),
        },
        section("limits", move |settings| for_limits.limits.store(Arc::new(settings.config.limits))),
        section("tls", move |settings| {
            tls_setup
                .listener
                .current
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .bound
                .iter()
                .flat_map(|bound| bound.tls.iter().zip(settings.tls.iter()))
                .for_each(|(live, next)| live.reload_from_config(Arc::clone(next)));
        }),
        section("oidc", move |settings| apply_oidc(&for_oidc, settings)),
        section("compromised", move |settings| {
            for_list.compromised.store(Arc::clone(&settings.compromised))
        }),
        section("log", move |settings| log.iter().for_each(|handle| apply_log_level(handle, settings))),
        Subscriber {
            section: "accounts_store".to_owned(),
            validate: Box::new(move |settings| check_store(&check_state, settings)),
            apply: Box::new(move |settings| switch_store(&apply_state, &store_context, settings)),
        },
        Subscriber {
            section: "audit_log".to_owned(),
            validate: Box::new(move |settings| prepare_audit(&prepare_state, &audit_path, &prepared_audit, settings)),
            apply: Box::new(move |settings| switch_audit(&audit_state, &context, &audit_applied_path, &applied_audit, settings)),
        },
        section("watch", move |settings| follow_files(&watch_setup.rewatch, &module_file, settings)),
        Subscriber {
            section: "listener".to_owned(),
            validate: Box::new(move |settings| prepare_sockets(&setup, &prepared_sockets, settings)),
            apply: Box::new(move |settings| switch_listener(&listener_setup, &applied_sockets, settings)),
        },
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
    setup: ListenerSetup,
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
    let rewatch_slot = Arc::clone(&setup.rewatch);
    let hooks = subscribers(state, startup, setup, module_file.to_path_buf(), context.clone(), log);
    open_engine(
        first_then_file(settings, module_file.to_path_buf()),
        settings_state,
        hooks,
        audit_into(state),
        context,
    )
    .map(Arc::new)
    .inspect(|engine| {
        rewatch_slot.engine.get_or_init(|| Arc::downgrade(engine));
    })
}
