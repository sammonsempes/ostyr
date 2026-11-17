use crate::api_model::{Bounds, Cached, Computed, RiskState, Unavailable};
use crate::model::Weights;
use crate::types::{ComputeFn, NowFn, Slot};
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


/// The tenant's single-flight slot, created while the map is under its cap; `None` for a tenant beyond it.
pub fn slot_of(state: &RiskState, tenant: &str) -> Option<Slot> {
    let mut slots = lock(&state.slots);
    let known = slots.get(tenant).cloned();
    known.or_else(|| {
        (slots.len() < state.bounds.max_tenants).then(|| {
            let fresh = Slot::default();
            slots.insert(tenant.to_owned(), Arc::clone(&fresh));
            fresh
        })
    })
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


pub async fn cached_flight(state: &RiskState, slot: &Slot, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    let mut held = slot.lock().await;
    let weights = current_config(&state.weights);
    let hit = held
        .as_ref()
        .filter(|cached| is_fresh(cached, &weights, &state.bounds))
        .map(|cached| Arc::clone(&cached.computed));
    match hit {
        Some(computed) => Ok(computed),
        None => {
            let started = Instant::now();
            let computed = compute_once(state, scope, Arc::clone(&weights)).await?;
            *held = Some(Cached {
                weights,
                at: started,
                computed: Arc::clone(&computed),
            });
            Ok(computed)
        }
    }
}


pub async fn flight(state: &RiskState, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    match slot_of(state, tenant_of(&scope)) {
        Some(slot) => cached_flight(state, &slot, scope).await,
        None => {
            let counted = state.uncached.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(counted, "risk scores tenant beyond the cache cap, computed uncached");
            compute_once(state, scope, current_config(&state.weights)).await
        }
    }
}


/// The tenant's scores: served from the cache, else computed once at a time per tenant, and never longer than the total deadline.
pub async fn scores_for(state: &RiskState, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    timeout(state.bounds.deadline, flight(state, scope))
        .await
        .map_err(|_elapsed| deadline_passed())
        .and_then(|inner| inner)
}


pub fn uncached_count(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}
