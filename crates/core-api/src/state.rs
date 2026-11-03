use crate::error::StartupError;
use crate::model::{ApiConfig, ApiState};
use crate::routes::{core_access, openapi_document};
use crate::types::AccessTable;
use core_audit::log::open_file_log;
use core_auth::cli::read_key_file;
use core_auth::password::verify_password;
use core_auth::policy::load_compromised;
use core_auth::random::os_random;
use core_auth::rbac::builtin_catalog;
use core_auth::service::{Context, State};
use core_auth::store::load_accounts_file;
use governor::{Quota, RateLimiter};
use std::fs::File;
use std::io::BufReader;
use std::num::NonZeroU32;
use std::sync::{Mutex, MutexGuard, PoisonError};
use time::OffsetDateTime;


pub const RATE_PER_MINUTE: NonZeroU32 = match NonZeroU32::new(60) {
    Some(value) => value,
    None => NonZeroU32::MIN,
};


pub const RATE_BURST: NonZeroU32 = match NonZeroU32::new(30) {
    Some(value) => value,
    None => NonZeroU32::MIN,
};


pub fn build_state(config: &ApiConfig, extra_access: AccessTable) -> Result<ApiState, StartupError> {
    let key = read_key_file(&config.key_file)?;
    let audit = open_file_log(&config.audit_log)?;
    let compromised = load_compromised(BufReader::new(File::open(&config.compromised_list)?))?;
    let accounts = load_accounts_file(&config.accounts_store)?;
    let mut access = extra_access;
    access.extend(core_access());
    Ok(ApiState {
        module: config.module.clone(),
        tenant: config.tenant.clone(),
        auth: Mutex::new(State {
            accounts,
            ..State::default()
        }),
        audit,
        key,
        compromised,
        catalog: builtin_catalog(),
        random: os_random,
        clock: OffsetDateTime::now_utc,
        store_path: config.accounts_store.clone(),
        limiter: RateLimiter::keyed(Quota::per_minute(RATE_PER_MINUTE).allow_burst(RATE_BURST)),
        access,
        document: serde_json::to_value(openapi_document(&config.module))?,
    })
}


pub fn lock_auth(app: &ApiState) -> MutexGuard<'_, State> {
    app.auth.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn auth_context<'a>(app: &'a ApiState, request_id: &'a str) -> Context<'a, File> {
    Context {
        audit: &app.audit,
        random: app.random,
        verify: &verify_password,
        key: &app.key,
        compromised: &app.compromised,
        catalog: &app.catalog,
        tenant: &app.tenant,
        request_id,
    }
}
