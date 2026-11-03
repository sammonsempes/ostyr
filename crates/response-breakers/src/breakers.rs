use crate::config::{breaker_loader, config_state, BreakerConfig};
use crate::error::BreakerError;
use crate::store::{open_store, Store};
use crate::types::{ClockFn, SyncFn};
use core_config::reload::{open_engine, ReloadContext, ReloadEngine};
use core_config::types::SharedAuditFn;
use std::path::PathBuf;
use std::sync::Arc;


pub const MODULE: &str = "response-breakers";


pub const RELOAD_REQUEST_ID: &str = "breakers-reload";


/// Limits come from the reload engine (lock-free reads), counters from the durable store.
pub struct Breakers {
    pub engine: Arc<ReloadEngine<BreakerConfig>>,
    pub store: Store,
    pub audit: Arc<SharedAuditFn>,
    pub clock: Box<ClockFn>,
}


pub struct BreakerSettings {
    pub config_path: PathBuf,
    pub store_path: PathBuf,
    pub sync: SyncFn,
    pub audit: Arc<SharedAuditFn>,
    pub clock: Box<ClockFn>,
}


/// Fails when the limits file or the counter file is invalid: a breaker that cannot read its state must not start.
pub fn open_breakers(settings: BreakerSettings) -> Result<Breakers, BreakerError> {
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: "all".to_owned(),
        module: MODULE.to_owned(),
        target: settings.config_path.display().to_string(),
        request_id: RELOAD_REQUEST_ID.to_owned(),
    };
    let reload_audit = Arc::clone(&settings.audit);
    let engine = open_engine(
        breaker_loader(settings.config_path),
        config_state,
        Vec::new(),
        Box::new(move |entry| reload_audit(entry)),
        context,
    )?;
    Ok(Breakers {
        engine: Arc::new(engine),
        store: open_store(&settings.store_path, settings.sync)?,
        audit: settings.audit,
        clock: settings.clock,
    })
}
