use crate::api_model::{Bounds, Cached, Computed, Entry, FlightRun, Joined, RiskState, Unavailable};
use crate::model::Weights;
use crate::types::{ComputeFn, Flight, NowFn, SlotMap};
use core_config::reload::{current_config, ReloadEngine};
use core_pg::scope::{tenant_of, TenantScope};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::watch;
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
        flight: None,
        flight_weights: None,
    }
}


/// An entry stays while its flight runs or its cached result is still served.
pub fn is_live(entry: &Entry, weights: &Arc<Weights>, bounds: &Bounds) -> bool {
    entry.flight.is_some() || entry.cached.as_ref().is_some_and(|cached| is_fresh(cached, weights, bounds))
}


/// The tenant's running flight of these weights, else a new one: the task is spawned by the caller once the slot lock is released.
pub fn start_flight(state: &RiskState, entry: &mut Entry, scope: TenantScope, weights: &Arc<Weights>) -> (Flight, Option<(FlightRun, TenantScope)>) {
    let same_weights = entry.flight_weights.as_ref().is_some_and(|started| Arc::ptr_eq(started, weights));
    let running = entry.flight.clone().filter(|_| same_weights);
    match running {
        Some(receiver) => (receiver, None),
        None => {
            let (sender, receiver) = watch::channel(None);
            let run = FlightRun {
                state: state.clone(),
                tenant: tenant_of(&scope).to_owned(),
                weights: Arc::clone(weights),
                started: Instant::now(),
                result: None,
                sender,
            };
            entry.flight = Some(receiver.clone());
            entry.flight_weights = Some(Arc::clone(weights));
            (receiver, Some((run, scope)))
        }
    }
}


/// The tenant's fresh result, else its flight of the current weights (started if none): stale and idle entries are removed on the way.
pub fn join(state: &RiskState, scope: TenantScope, weights: &Arc<Weights>) -> Joined {
    let mut slots = lock(&state.slots);
    slots.retain(|_, entry| is_live(entry, weights, &state.bounds));
    let entry = slots.entry(tenant_of(&scope).to_owned()).or_insert_with(fresh_entry);
    let hit = entry
        .cached
        .as_ref()
        .filter(|cached| is_fresh(cached, weights, &state.bounds))
        .map(|cached| Arc::clone(&cached.computed));
    match hit {
        Some(computed) => Joined::Hit(computed),
        None => {
            let (receiver, pending) = start_flight(state, entry, scope, weights);
            drop(slots);
            pending.into_iter().for_each(|(run, run_scope)| {
                tokio::spawn(run_flight(run, run_scope));
            });
            Joined::Wait(receiver)
        }
    }
}


/// Called when the flight ends: the entry is replaced by a cached one, or removed; a flight of replaced weights leaves the slot to its successor.
pub fn finish(state: &RiskState, tenant: &str, weights: Arc<Weights>, started: Instant, result: &Result<Arc<Computed>, Unavailable>) {
    let current = current_config(&state.weights);
    let mut slots = lock(&state.slots);
    let superseded = slots
        .get(tenant)
        .and_then(|entry| entry.flight_weights.as_ref().or(entry.cached.as_ref().map(|cached| &cached.weights)))
        .is_some_and(|owner| !Arc::ptr_eq(owner, &weights));
    if !superseded {
        settle(state, &mut slots, &current, tenant, (weights, started), result);
    }
}


pub fn settle(
    state: &RiskState,
    slots: &mut SlotMap,
    current: &Arc<Weights>,
    tenant: &str,
    (weights, started): (Arc<Weights>, Instant),
    result: &Result<Arc<Computed>, Unavailable>,
) {
    slots.remove(tenant);
    slots.retain(|_, entry| is_live(entry, current, &state.bounds));
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
                    flight: None,
                    flight_weights: None,
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


/// Runs when the flight task ends, however it ends: a task dropped before its result answers its waiters with a failure.
pub fn conclude(run: &mut FlightRun) {
    let outcome = run.result.take().unwrap_or_else(|| Err(flight_dropped()));
    finish(&run.state, &run.tenant, Arc::clone(&run.weights), run.started, &outcome);
    run.sender.send_replace(Some(outcome));
}


pub fn flight_dropped() -> Unavailable {
    tracing::warn!("risk scores flight ended without a result");
    Unavailable
}


/// The computation under its deadline, in a task of its own: the permit and the session are released by the computation itself.
pub async fn run_flight(mut run: FlightRun, scope: TenantScope) {
    let computed = timeout(run.state.bounds.deadline, compute_once(&run.state, scope, Arc::clone(&run.weights))).await;
    run.result = Some(computed.map_err(|_elapsed| deadline_passed()).and_then(|inner| inner));
}


/// A waiter answers when the flight does, or at its own deadline with the fixed failure; the flight goes on either way.
pub async fn await_flight(state: &RiskState, mut receiver: Flight) -> Result<Arc<Computed>, Unavailable> {
    let waited = timeout(state.bounds.deadline, receiver.wait_for(Option::is_some))
        .await
        .map_err(|_elapsed| deadline_passed())?;
    let seen = waited.map_err(|_closed| flight_dropped())?;
    seen.clone().unwrap_or(Err(Unavailable))
}


/// One computation per tenant at a time; every request shares its outcome, failure included, under its own deadline.
pub async fn flight(state: &RiskState, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    let weights = current_config(&state.weights);
    match join(state, scope, &weights) {
        Joined::Hit(computed) => Ok(computed),
        Joined::Wait(receiver) => await_flight(state, receiver).await,
    }
}


/// The tenant's scores: served from the cache, else computed once at a time per tenant; the computation carries the deadline.
pub async fn scores_for(state: &RiskState, scope: TenantScope) -> Result<Arc<Computed>, Unavailable> {
    flight(state, scope).await
}


pub fn uncached_count(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}
