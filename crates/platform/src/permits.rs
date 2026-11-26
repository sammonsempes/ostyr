use crate::error::PlatformError;
use crate::model::Module;
use crate::types::Permits;
use alerts::backend::MAX_CONNECTIONS;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{from_fn_with_state, Next};
use axum::response::Response;
use axum::Router;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use strum::VariantArray;
use tokio::sync::Semaphore;


pub const LARGE_CAP: usize = MAX_CONNECTIONS;


pub const SMALL_CAP: usize = 4;


pub const HUNTS_LATE_CLOSE: usize = 2;


pub const PLATFORM_PG_BUDGET: usize = 78;


/// The module's connection cap: an exhaustive match, so a new module without a cap does not compile.
pub fn module_cap(module: Module) -> usize {
    match module {
        Module::Alerts | Module::Cases => LARGE_CAP,
        Module::Cmdb
        | Module::Risk
        | Module::Hunts
        | Module::Certificates
        | Module::Oncall
        | Module::Dhcp
        | Module::Compliance
        | Module::Vulnerabilities
        | Module::RemoteShell
        | Module::Posture
        | Module::Status
        | Module::Grc
        | Module::AttackPaths
        | Module::Playbooks => SMALL_CAP,
    }
}


/// PostgreSQL connections the platform can hold at once: every cap, risk's cancel connection again, and the hunts late close.
pub fn connection_demand() -> usize {
    Module::VARIANTS.iter().map(|module| module_cap(*module)).sum::<usize>() + module_cap(Module::Risk) + HUNTS_LATE_CLOSE
}


pub fn module_name(module: Module) -> &'static str {
    match module {
        Module::Alerts => "alerts",
        Module::Cases => "cases",
        Module::Cmdb => "cmdb",
        Module::Risk => "risk",
        Module::Hunts => "hunts",
        Module::Certificates => "certificates",
        Module::Oncall => "oncall",
        Module::Dhcp => "dhcp",
        Module::Compliance => "compliance",
        Module::Vulnerabilities => "vulnerabilities",
        Module::RemoteShell => "remote_shell",
        Module::Posture => "posture",
        Module::Status => "status",
        Module::Grc => "grc",
        Module::AttackPaths => "attack_paths",
        Module::Playbooks => "playbooks",
    }
}


pub fn module_permits(module: Module) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(module_cap(module)))
}


/// One semaphore per selected module: a flood of one module cannot take a permit of another.
pub fn module_semaphores(modules: &[Module]) -> Permits {
    modules.iter().map(|module| (*module, module_permits(*module))).collect()
}


/// The migration lease at start: one permit, before any request is served.
pub fn start_permits() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(1))
}


pub fn permits_of(permits: &Permits, module: Module) -> Result<&Arc<Semaphore>, PlatformError> {
    permits
        .iter()
        .find(|(listed, _semaphore)| *listed == module)
        .map(|(_listed, semaphore)| semaphore)
        .ok_or(PlatformError::MissingPermits)
}


#[derive(Clone, Debug)]
pub struct RefusalCounter {
    pub module: &'static str,
    pub cap: usize,
    pub status: StatusCode,
    pub refusals: Arc<AtomicU64>,
}


/// The status the module answers when its pool is full: its 429, and for risk its fixed 503.
pub fn refusal_status(module: Module) -> StatusCode {
    if module == Module::Risk {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::TOO_MANY_REQUESTS
    }
}


pub fn refusal_counter(module: Module) -> RefusalCounter {
    RefusalCounter {
        module: module_name(module),
        cap: module_cap(module),
        status: refusal_status(module),
        refusals: Arc::new(AtomicU64::new(0)),
    }
}


/// Counts a refusal and warns at the first one and at each power of two (1, 2, 4, 8, ...), so the log stays bounded.
pub fn note_refusal(counter: &RefusalCounter) -> u64 {
    let count = counter.refusals.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let module = counter.module;
    let cap = counter.cap;
    if count.is_power_of_two() {
        tracing::warn!(module, cap, "platform module connection cap reached");
    }
    count
}


/// Observes the module's reply: the cap itself is the semaphore the backend leases from, never this layer.
pub async fn count_refusals(State(counter): State<RefusalCounter>, request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    if response.status() == counter.status {
        note_refusal(&counter);
    }
    response
}


pub fn counted<RouterState: Clone + Send + Sync + 'static>(router: Router<RouterState>, module: Module) -> Router<RouterState> {
    router.layer(from_fn_with_state(refusal_counter(module), count_refusals))
}
