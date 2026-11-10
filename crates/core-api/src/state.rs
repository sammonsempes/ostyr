use crate::error::StartupError;
use crate::model::{ApiConfig, ApiIdentity, ApiState, AuthInputs, StateInputs};
use crate::oidc::load_oidc;
use crate::previous::{read_previous_key, record_previous, remove_stale_previous, retire_previous, ROTATION_RESUMED};
use crate::reload::{content_digest, reseal_accounts, RELOAD_ACTOR};
use crate::routes::{core_access, openapi_document};
use crate::types::AccessTable;
use arc_swap::{ArcSwap, ArcSwapOption};
use core_audit::log::{open_file_log, AuditLog};
use core_audit::model::Outcome;
use core_auth::cli::read_key_file;
use core_auth::error::AuthError;
use core_auth::limiter::FAILURE_WINDOW_SECONDS;
use core_auth::model::Account;
use core_auth::password::verify_password;
use core_auth::policy::load_compromised;
use core_auth::random::os_random;
use core_auth::rbac::builtin_catalog;
use core_auth::secretbox::open_secret;
use core_auth::service::{Context, State};
use core_auth::session::{hash_token, is_revoked};
use core_auth::store::{load_store_file, read_store_locked, update_store_file};
use core_auth::types::{AccountMap, AttemptMap, CompromisedSet, CredentialMap, StoreKey, VerifyFn};
use core_config::reload::ReloadContext;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;
use tracing::Dispatch;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub const RATE_WINDOW_SECONDS: i64 = 60;


pub const RATE_MAX_REQUESTS: u32 = 30;


pub const MAX_CONCURRENT_HASHES: usize = 4;


pub const STARTUP_REQUEST_ID: &str = "startup";


pub const PREVIOUS_KEY_SUFFIX: &str = ".previous";


pub const MAX_TRACKED_SOURCES: usize = 10_000;


pub const MAX_TRACKED_ATTEMPTS: usize = 10_000;


pub fn merged_document(module: &str, extra_documents: Vec<OpenApiDocument>) -> OpenApiDocument {
    let mut document = openapi_document(module);
    extra_documents.into_iter().for_each(|extra| document.merge(extra));
    document
}


/// Reads the key, the list and the OIDC files once each, then builds the state from them.
pub fn build_state_from_files(
    config: &ApiConfig,
    extra_access: AccessTable,
    extra_documents: Vec<OpenApiDocument>,
) -> Result<ApiState, StartupError> {
    let oidc = config
        .oidc
        .as_ref()
        .map(|files| load_oidc(files, &builtin_catalog()).map(Arc::new))
        .transpose()?;
    let inputs = StateInputs {
        key: Arc::new(read_key_file(&config.key_file)?),
        compromised: Arc::new(read_compromised(&config.compromised_list)?),
        oidc,
    };
    build_state(config, &inputs, extra_access, extra_documents)
}


/// Builds the state from the key, the list and the OIDC runtime already read, so no file is read twice.
pub fn build_state(
    config: &ApiConfig,
    inputs: &StateInputs,
    extra_access: AccessTable,
    extra_documents: Vec<OpenApiDocument>,
) -> Result<ApiState, StartupError> {
    let audit = open_file_log(&config.audit_log)?;
    let (accounts, credentials) = load_sealed_store(config, &inputs.key, &audit)?;
    let catalog = builtin_catalog();
    let mut access = extra_access;
    access.extend(core_access());
    Ok(ApiState {
        identity: ArcSwap::from_pointee(ApiIdentity {
            module: config.module.clone(),
            tenant: config.tenant.clone(),
            generation: 0,
        }),
        auth: Mutex::new(State {
            accounts,
            credentials,
            ..State::default()
        }),
        audit,
        key: ArcSwap::new(inputs.key.clone()),
        compromised: ArcSwap::new(inputs.compromised.clone()),
        catalog,
        random: os_random,
        clock: OffsetDateTime::now_utc,
        store_path: ArcSwap::from_pointee(config.accounts_store.clone()),
        limiter: Mutex::new(BTreeMap::new()),
        access,
        document: serde_json::to_value(merged_document(&config.module, extra_documents))?,
        verify: verify_password,
        hashing: Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES)),
        dispatch: tracing::dispatcher::get_default(Dispatch::clone),
        limits: Arc::new(ArcSwap::from_pointee(config.limits)),
        oidc: ArcSwapOption::new(inputs.oidc.clone()),
        callback_accounts: Mutex::new(BTreeSet::new()),
        forwarders: ArcSwap::from_pointee(Vec::new()),
        ignored_forwarding: AtomicU64::new(0),
    })
}


/// The path where the previous key of an interrupted rotation is kept (T033E).
pub fn previous_key_path(key_file: &Path) -> PathBuf {
    let mut name = OsString::from(key_file.as_os_str());
    name.push(PREVIOUS_KEY_SUFFIX);
    PathBuf::from(name)
}


/// How many stored TOTP secrets `key` fails to open, and how many there are.
pub fn unopened_secrets(accounts: &AccountMap, key: &StoreKey) -> (usize, usize) {
    let secrets = accounts
        .iter()
        .filter_map(|(name, account)| account.totp.as_ref().map(|totp| (name, totp)));
    let total = secrets.clone().count();
    let failed = secrets
        .filter(|(name, totp)| open_secret(key, name, &totp.encrypted_secret).is_err())
        .count();
    (failed, total)
}


/// Refuses a key when any stored TOTP secret does not open, counting the failures and naming the previous-key path, instead of starting with broken TOTP.
pub fn check_store_key(accounts: &AccountMap, key: &StoreKey, key_file: &Path) -> Result<(), StartupError> {
    let (failed, total) = unopened_secrets(accounts, key);
    (failed == 0).then_some(()).ok_or_else(|| StartupError::StoreKeyMismatch {
        key_file: key_file.display().to_string(),
        previous: previous_key_path(key_file).display().to_string(),
        failed,
        total,
    })
}


/// Loads the store; when `key` does not open it but `<key_file>.previous` does, finishes the interrupted rotation first.
pub fn load_sealed_store(config: &ApiConfig, key: &StoreKey, audit: &AuditLog<File>) -> Result<(AccountMap, CredentialMap), StartupError> {
    let (accounts, credentials) = load_store_file(&config.accounts_store)?;
    match check_store_key(&accounts, key, Path::new(&config.key_file)) {
        Ok(()) => {
            remove_stale_previous(audit, &startup_context(config), Path::new(&config.key_file));
            Ok((accounts, credentials))
        }
        Err(mismatch) => resume_rotation(config, key, audit, &accounts, mismatch),
    }
}


/// The audit context of the key work done while the service starts.
pub fn startup_context(config: &ApiConfig) -> ReloadContext {
    ReloadContext {
        actor_id: RELOAD_ACTOR.to_owned(),
        tenant: config.tenant.clone(),
        module: config.module.clone(),
        target: config.key_file.clone(),
        request_id: STARTUP_REQUEST_ID.to_owned(),
    }
}


/// Re-seals the store from the previous key to `key`, audits it and removes the previous key; a store neither key opens stays refused.
pub fn resume_rotation(
    config: &ApiConfig,
    key: &StoreKey,
    audit: &AuditLog<File>,
    accounts: &AccountMap,
    mismatch: StartupError,
) -> Result<(AccountMap, CredentialMap), StartupError> {
    let key_file = Path::new(&config.key_file);
    let previous_file = previous_key_path(key_file);
    let found = read_previous_key(&previous_file).map_err(|source| StartupError::PreviousKey {
        file: previous_file.display().to_string(),
        source,
    })?;
    let previous = found.filter(|candidate| unopened_secrets(accounts, candidate).0 == 0).ok_or(mismatch)?;
    let context = startup_context(config);
    let reseal = |stored: &mut AccountMap, _: &mut CredentialMap| reseal_accounts(stored, &previous, key, os_random);
    let updated = update_store_file(&config.accounts_store, os_random, reseal)?;
    updated.saved?;
    let detail = format!("store re-sealed from {} under the key file", previous_file.display());
    record_previous(audit, &context, Outcome::Success, ROTATION_RESUMED, detail);
    retire_previous(audit, &context, key_file);
    load_store_file(&config.accounts_store).map_err(StartupError::from)
}


pub fn read_compromised(path: &Path) -> Result<CompromisedSet, StartupError> {
    read_compromised_digested(path).map(|(set, _)| set)
}


/// The list and the digest of the very bytes it was parsed from.
pub fn read_compromised_digested(path: &Path) -> Result<(CompromisedSet, String), StartupError> {
    let bytes = fs::read(path)?;
    Ok((load_compromised(BufReader::new(bytes.as_slice()))?, content_digest(&bytes)))
}


pub fn current_compromised(app: &ApiState) -> Arc<CompromisedSet> {
    app.compromised.load_full()
}


pub fn auth_inputs(app: &ApiState) -> AuthInputs {
    AuthInputs {
        compromised: current_compromised(app),
        key: app.key.load_full(),
        identity: app.identity.load_full(),
    }
}


pub fn lock_auth(app: &ApiState) -> MutexGuard<'_, State> {
    app.auth.lock().unwrap_or_else(PoisonError::into_inner)
}


/// The accounts of `previous` that an OIDC callback created: they live in memory only, but take the revocation marker the file holds for them.
pub fn memory_only_accounts(app: &ApiState, previous: &AccountMap, stored: &AccountMap) -> AccountMap {
    let created = app.callback_accounts.lock().unwrap_or_else(PoisonError::into_inner);
    previous
        .iter()
        .filter(|(name, _)| created.contains(*name))
        .map(|(name, account)| {
            let marker = account
                .sessions_valid_after
                .max(stored.get(name).and_then(|kept| kept.sessions_valid_after));
            (
                name.clone(),
                Account {
                    sessions_valid_after: marker,
                    ..account.clone()
                },
            )
        })
        .collect()
}


/// Replaces the in-memory accounts and credentials with the file's, read under the store lock, keeping the memory-only `oidc:` accounts.
pub fn refresh_accounts(app: &ApiState, auth: &mut State) -> Result<(), AuthError> {
    read_store_locked(&app.store_path.load())
        .inspect_err(|error| tracing::warn!(%error, "account store re-read failed, the request is refused"))
        .map(|(mut accounts, credentials)| {
            accounts.extend(memory_only_accounts(app, &auth.accounts, &accounts));
            auth.accounts = accounts;
            auth.credentials = credentials;
        })
}


/// Records the account an OIDC callback created, so `memory_only_accounts` can tell it from a deleted file account.
pub fn remember_callback_account(app: &ApiState, username: &str) {
    app.callback_accounts
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(username.to_owned());
}


/// True when the session of `token` predates the revocation marker of its owner, or its owner is no longer an account at all.
pub fn session_revoked(auth: &State, token: &str) -> bool {
    auth.sessions
        .get(&hash_token(token))
        .is_some_and(|session| !auth.accounts.contains_key(&session.user) || is_revoked(&auth.accounts, session))
}


pub fn prune_attempts(attempts: &mut AttemptMap, now: OffsetDateTime) {
    attempts.retain(|_, entry| {
        entry.locked_until.is_some_and(|until| until > now)
            || entry
                .failures
                .iter()
                .any(|failed_at| now - *failed_at < Duration::seconds(FAILURE_WINDOW_SECONDS))
    });
}


pub fn auth_context<'a>(app: &'a ApiState, request_id: &'a str, verify: VerifyFn<'a>, inputs: &'a AuthInputs) -> Context<'a, File> {
    Context {
        audit: &app.audit,
        random: app.random,
        verify,
        key: &inputs.key,
        compromised: &inputs.compromised,
        catalog: &app.catalog,
        tenant: &inputs.identity.tenant,
        request_id,
    }
}
