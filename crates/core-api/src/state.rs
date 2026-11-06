use crate::error::StartupError;
use crate::model::{ApiConfig, ApiState};
use crate::oidc::load_oidc;
use crate::routes::{core_access, openapi_document};
use crate::types::AccessTable;
use core_audit::log::open_file_log;
use core_auth::cli::read_key_file;
use core_auth::limiter::FAILURE_WINDOW_SECONDS;
use core_auth::password::verify_password;
use core_auth::policy::load_compromised;
use core_auth::random::os_random;
use core_auth::rbac::builtin_catalog;
use core_auth::service::{Context, State, OIDC_PREFIX};
use core_auth::store::{load_store_file, read_store_locked};
use core_auth::types::{AccountMap, AttemptMap, VerifyFn};
use std::collections::BTreeMap;
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
    })
}


pub fn lock_auth(app: &ApiState) -> MutexGuard<'_, State> {
    app.auth.lock().unwrap_or_else(PoisonError::into_inner)
}


/// The `oidc:` accounts of `previous` that `stored` does not hold: they live in memory only, created by an OIDC callback.
pub fn memory_only_accounts(previous: &AccountMap, stored: &AccountMap) -> AccountMap {
    previous
        .iter()
        .filter(|(name, _)| name.starts_with(OIDC_PREFIX) && !stored.contains_key(*name))
        .map(|(name, account)| (name.clone(), account.clone()))
        .collect()
}


/// Replaces the in-memory accounts and credentials with the file's, read under the store lock, keeping the memory-only `oidc:` accounts.
pub fn refresh_accounts(app: &ApiState, auth: &mut State) {
    match read_store_locked(&app.store_path) {
        Ok((mut accounts, credentials)) => {
            accounts.extend(memory_only_accounts(&auth.accounts, &accounts));
            auth.accounts = accounts;
            auth.credentials = credentials;
        }
        Err(error) => tracing::warn!(%error, "account store re-read failed, the in-memory copy is used"),
    }
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
