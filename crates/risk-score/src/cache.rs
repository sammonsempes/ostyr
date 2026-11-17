use crate::api_model::{Bounds, Cached, Computed, Entry, Joined, RiskState, Unavailable};
use crate::model::Weights;
use crate::types::{ComputeFn, Flight, NowFn};
use core_config::reload::{current_config, ReloadEngine};
use core_pg::scope::{tenant_of, TenantScope};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::time::{timeout, Instant};


/// Total deadline of one computation, and of a request waiting for the computation of its tenant.
pub const MAX_COMPUTE_SECONDS: u64 = 60;


pub const CACHE_SECONDS: u64 = 60;


/// Tenants whose last result is kept: one entry each, so no request value grows the map.
pub const MAX_CACHED_TENANTS: usize = 1_000;


pub fn default_bounds() -> Bounds {
    Bounds {
        max_tenants: MAX_CACHED_TENANTS,
        cache: Duration::from_secs(CACHE_SECONDS),
        deadline: Duration::from_secs(MAX_COMPUTE_SECONDS),
    }
}


pub fn risk_state(compute: ComputeFn, weights: Arc<ReloadEngine<Weights>>, now: NowFn) -> RiskState {
    RiskState {
        compute,
        weights,
        now,
        slots: Arc::default(),
        uncached: Arc::default(),
        bounds: default_bounds(),
    }
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> MutexGuard<'_, Guarded> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn is_fresh(cached: &Cached, weights: &Arc<Weights>, bounds: &Bounds) -> bool {
    Arc::ptr_eq(&cached.weights, weights) && cached.at.elapsed() < bounds.cache
}


pub fn computation_failed() -> Unavailable {
    tracing::warn!("risk scores computation failed");
    Unavailable
}


pub fn deadline_passed() -> Unavailable {
    tracing::warn!("risk scores computation passed its deadline");
    Unavailable
}


pub async fn compute_once(state: &RiskState, scope: TenantScope, weights: Arc<Weights>) -> Result<Arc<Computed>, Unavailable> {
    let now = (state.now)();
    let tenant = tenant_of(&scope).to_owned();
    tracing::info!(%tenant, "risk scores computing");
    let result = (state.compute)(scope, weights, now).await;
    result
        .map(|outcome| Arc::new(Computed { computed_at: now, outcome }))
        .map_err(|_error| computation_failed())
}


pub fn fresh_entry() -> Entry {
    Entry {
        cached: None,
        flight: Flight::default(),
    }
}


/// An entry stays while a request holds its flight or its cached result is still served.
pub fn is_live(entry: &Entry, weights: &Arc<Weights>, bounds: &Bounds) -> bool {
    Arc::strong_count(&entry.flight) > 1 || entry.cached.as_ref().is_some_and(|cached| is_fresh(cached, weights, bounds))
}


/// The tenant's fresh result, else its flight (created if none): stale and idle entries are removed on the way.
pub fn join(state: &RiskState, tenant: &str, weights: &Arc<Weights>) -> Joined {
    let mut slots = lock(&state.slots);
    slots.retain(|_, entry| is_live(entry, weights, &state.bounds));
    let entry = slots.entry(tenant.to_owned()).or_insert_with(fresh_entry);
    let hit = entry
        .cached
        .as_ref()
        .filter(|cached| is_fresh(cached, weights, &state.bounds))
        .map(|cached| Arc::clone(&cached.computed));
    match hit {
        Some(computed) => Joined::Hit(computed),
        None => Joined::Wait(Arc::clone(&entry.flight)),
    }
}


/// Called by the computing request before its flight completes: the entry is replaced by a cached one, or removed.
pub fn finish(state: &RiskState, tenant: &str, weights: Arc<Weights>, started: Instant, result: &Result<Arc<Computed>, Unavailable>) {
    let mut slots = lock(&state.slots);
    slots.remove(tenant);
    let room = slots.values().filter(|entry| entry.cached.is_some()).count() < state.bounds.max_tenants;
    match (result, room) {
        (Ok(computed), true) => {
            let cached = Cached {
                weights,
                at: started,
                computed: Arc::clone(computed),
            };
            slots.insert(
                tenant.to_owned(),
                Entry {
                    cached: Some(cached),
                    flight: Flight::default(),
                },
            );
        }
        (Ok(_), false) => {
            let counted = state.uncached.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(counted, "risk scores tenant beyond the cache cap, computed uncached");
        }
        (Err(_), _) => (),
    }
}


pub async fn run_flight(state: &RiskState, scope: TenantScope, weights: Arc<Weights>) -> Result<Arc<Computed>, Unavailable> {
    let tenant = tenant_of(&scope).to_owned();
    let started = Instant::now();
    let result = timeout(state.bounds.deadline, compute_once(state, scope, Arc::clone(&weights)))
        .await
        .map_err(|_elapsed| deadline_passed())
        .and_then(|inner| inner);
    finish(state, &tenant, weights, started, &result);
    result
}


/// One computation per tenant: the first request computes under its own deadline, the others share its outcome, failure included.
pub async fn flight(state: &RiskState, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    let weights = current_config(&state.weights);
    match join(state, tenant_of(&scope), &weights) {
        Joined::Hit(computed) => Ok(computed),
        Joined::Wait(shared) => shared.get_or_init(|| run_flight(state, scope, weights)).await.clone(),
    }
}


/// The tenant's scores: served from the cache, else computed once at a time per tenant; the computation carries the deadline.
pub async fn scores_for(state: &RiskState, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    flight(state, scope).await
}


pub fn uncached_count(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}
