use crate::error::StartupError;
use crate::model::{ApiConfig, ApiState};
use crate::oidc::load_oidc;
use crate::routes::{core_access, openapi_document};
use crate::types::AccessTable;
use core_audit::log::open_file_log;
use core_auth::cli::read_key_file;
use core_auth::error::AuthError;
use core_auth::limiter::FAILURE_WINDOW_SECONDS;
use core_auth::model::Account;
use core_auth::password::verify_password;
use core_auth::policy::load_compromised;
use core_auth::random::os_random;
use core_auth::rbac::builtin_catalog;
use core_auth::service::{Context, State};
use core_auth::session::{hash_token, is_revoked};
use core_auth::store::{load_store_file, read_store_locked};
use core_auth::types::{AccountMap, AttemptMap, VerifyFn};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;
use tracing::Dispatch;
use utoipa::openapi::OpenApi as OpenApiDocument;


pub const RATE_WINDOW_SECONDS: i64 = 60;


pub const RATE_MAX_REQUESTS: u32 = 30;


pub const MAX_CONCURRENT_HASHES: usize = 4;


pub const MAX_TRACKED_SOURCES: usize = 10_000;


pub const MAX_TRACKED_ATTEMPTS: usize = 10_000;


pub fn merged_document(module: &str, extra_documents: Vec<OpenApiDocument>) -> OpenApiDocument {
    let mut document = openapi_document(module);
    extra_documents.into_iter().for_each(|extra| document.merge(extra));
    document
}


pub fn build_state(config: &ApiConfig, extra_access: AccessTable, extra_documents: Vec<OpenApiDocument>) -> Result<ApiState, StartupError> {
    let key = read_key_file(&config.key_file)?;
    let audit = open_file_log(&config.audit_log)?;
    let compromised = load_compromised(BufReader::new(File::open(&config.compromised_list)?))?;
    let (accounts, credentials) = load_store_file(&config.accounts_store)?;
    let catalog = builtin_catalog();
    let oidc = config.oidc.as_ref().map(|files| load_oidc(files, &catalog)).transpose()?;
    let mut access = extra_access;
    access.extend(core_access());
    Ok(ApiState {
        module: config.module.clone(),
        tenant: config.tenant.clone(),
        auth: Mutex::new(State {
            accounts,
            credentials,
            ..State::default()
        }),
        audit,
        key,
        compromised,
        catalog,
        random: os_random,
        clock: OffsetDateTime::now_utc,
        store_path: config.accounts_store.clone(),
        limiter: Mutex::new(BTreeMap::new()),
        access,
        document: serde_json::to_value(merged_document(&config.module, extra_documents))?,
        verify: verify_password,
        hashing: Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES)),
        dispatch: tracing::dispatcher::get_default(Dispatch::clone),
        max_sources: MAX_TRACKED_SOURCES,
        max_attempts: MAX_TRACKED_ATTEMPTS,
        body_timeout: config.body_read_timeout,
        oidc,
        callback_accounts: Mutex::new(BTreeSet::new()),
    })
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
    read_store_locked(&app.store_path)
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


pub fn auth_context<'a>(app: &'a ApiState, request_id: &'a str, verify: VerifyFn<'a>) -> Context<'a, File> {
    Context {
        audit: &app.audit,
        random: app.random,
        verify,
        key: &app.key,
        compromised: &app.compromised,
        catalog: &app.catalog,
        tenant: &app.tenant,
        request_id,
    }
}
