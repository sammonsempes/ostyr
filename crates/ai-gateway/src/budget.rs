use crate::chat::{prepare, send};
use crate::error::AiError;
use crate::limits::{ALERT_PERCENT, BUDGET_80_RULE, BUDGET_SPENT_RULE, HELD_EXPIRY_SECONDS, MICROS_PER_SECOND, PERCENT, REQUEST_OVERHEAD_BYTES};
use crate::model::{Answer, Deps};
use crate::settings::AiSettings;
use crate::types::{BudgetExecutor, BudgetRows, WallClockFn};
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{insert_alerts, summarise};
use alerts::types::Executor;
use core_pg::migrate::Migration;
use core_pg::scope::{tenant_of, TenantScope};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const MIGRATION_NAMESPACE: &str = "ai_gateway";


pub const MIGRATIONS: [Migration; 2] = [
    Migration {
        version: "ai_gateway_0001",
        sql: include_str!("../migrations/ai_gateway_0001.sql"),
    },
    Migration {
        version: "ai_gateway_0002",
        sql: include_str!("../migrations/ai_gateway_0002.sql"),
    },
];


/// Server and client deadline of every statement.
pub const STATEMENT_DEADLINE: Duration = Duration::from_secs(10);


/// Params: `$2` UTC day, `$3` reservation, `$4` call cap, `$5` token cap, `$6` seconds a held reservation stays live. One statement reserves one call and the tokens when both caps hold, on insert and on update alike; no row means refused. A held count older than `$6` is a crashed call's and restarts from zero.
pub const RESERVE_SQL: &str = "INSERT INTO ai_budget_day (tenant, day, calls, tokens, held_calls, held_tokens, held_at) \
    SELECT $1, $2::text::date, 1, $3::bigint, 1, $3::bigint, now() WHERE $3::bigint <= $5::bigint AND 1 <= $4::bigint \
    ON CONFLICT (tenant, day) DO UPDATE SET calls = ai_budget_day.calls + 1, tokens = ai_budget_day.tokens + $3::bigint, \
    held_calls = CASE WHEN ai_budget_day.held_at > now() - $6::bigint * interval '1 second' THEN ai_budget_day.held_calls ELSE 0 END + 1, \
    held_tokens = CASE WHEN ai_budget_day.held_at > now() - $6::bigint * interval '1 second' THEN ai_budget_day.held_tokens ELSE 0 END + $3::bigint, \
    held_at = now() \
    WHERE ai_budget_day.calls + 1 <= $4::bigint AND ai_budget_day.tokens + $3::bigint <= $5::bigint \
    RETURNING calls, tokens";


/// Params: `$2` UTC day of the reservation, `$3` tokens to give back, `$4` the whole reservation, released from the held counts. No total goes below zero. Runs after every call, a failed one included (it gives back nothing).
pub const SETTLE_SQL: &str = "UPDATE ai_budget_day SET tokens = GREATEST(tokens - $3::bigint, 0), held_calls = GREATEST(held_calls - 1, 0), \
    held_tokens = GREATEST(held_tokens - $4::bigint, 0) WHERE tenant = $1 AND day = $2::text::date RETURNING calls, tokens";


/// Params: `$2` UTC day, `$3` seconds a held reservation stays live. The day's calls (never given back) and the tokens no call in flight holds.
pub const SETTLED_SQL: &str = "SELECT calls, \
    tokens - CASE WHEN held_at > now() - $3::bigint * interval '1 second' THEN held_tokens ELSE 0 END \
    FROM ai_budget_day WHERE tenant = $1 AND day = $2::text::date";


/// A bound statement parameter; the tenant is `$1` and is added by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Text(String),
    Int(i64),
}


/// Bounds the reservations waiting on the budget store at once; a fuller gate refuses with `BudgetBusy`.
#[derive(Debug)]
pub struct Gate {
    waiting: AtomicUsize,
    limit: usize,
}


/// One place in the gate, given back on drop.
pub struct Place<'a> {
    gate: &'a Gate,
}


impl Drop for Place<'_> {
    fn drop(&mut self) {
        self.gate.waiting.fetch_sub(1, Ordering::SeqCst);
    }
}


pub fn new_gate(limit: usize) -> Gate {
    Gate {
        waiting: AtomicUsize::new(0),
        limit,
    }
}


pub fn waiting(gate: &Gate) -> usize {
    gate.waiting.load(Ordering::SeqCst)
}


/// A place when fewer than `limit` are taken; `None` otherwise (the unused place is dropped, so the count is back).
pub fn enter(gate: &Gate) -> Option<Place<'_>> {
    let before = gate.waiting.fetch_add(1, Ordering::SeqCst);
    let place = Place { gate };
    (before < gate.limit).then_some(place)
}


/// The two stores a budgeted call talks to: the budget table and the alert store, behind one gate.
#[derive(Clone, Copy)]
pub struct Stores<'a, 'b> {
    pub budget: BudgetExecutor<'a, 'b>,
    pub alerts: Executor<'a, 'b>,
    pub gate: &'a Gate,
}


#[derive(Clone, Copy)]
pub struct BudgetDeps {
    pub chat: Deps,
    pub wall_clock: WallClockFn,
}


/// Which alert a threshold raises.
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
}


pub const RULE_80: Rule = Rule {
    id: BUDGET_80_RULE,
    title: "AI budget at 80 percent",
    severity: Severity::Medium,
};


pub const RULE_SPENT: Rule = Rule {
    id: BUDGET_SPENT_RULE,
    title: "AI budget spent",
    severity: Severity::High,
};


/// Why a reservation was refused, from the settled totals of the day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Exhausted,
    Busy,
    TooLarge,
}


/// The UTC day as `YYYY-MM-DD`.
pub fn day_text(micros: u64) -> Result<String, AiError> {
    let seconds = (micros / MICROS_PER_SECOND) as i64;
    let moment = OffsetDateTime::from_unix_timestamp(seconds)?;
    Ok(moment.date().to_string())
}


pub fn single_row(rows: BudgetRows) -> Result<Option<(i64, i64)>, AiError> {
    match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some(*row)),
        _ => Err(AiError::BadReply),
    }
}


/// Reserves one call and `tokens` for the tenant's day; `None` when either cap would be passed.
pub async fn reserve(
    exec: BudgetExecutor<'_, '_>,
    scope: &TenantScope,
    settings: &AiSettings,
    day: &str,
    tokens: i64,
) -> Result<Option<(i64, i64)>, AiError> {
    let params = vec![
        Param::Text(day.to_owned()),
        Param::Int(tokens),
        Param::Int(i64::from(settings.max_calls_per_day)),
        Param::Int(i64::from(settings.max_tokens_per_day)),
        Param::Int(HELD_EXPIRY_SECONDS),
    ];
    let rows = exec(scope.clone(), RESERVE_SQL, params).await?;
    single_row(rows)
}


/// Releases the reservation made on `day` and gives back `tokens` of it.
pub async fn give_back(
    exec: BudgetExecutor<'_, '_>,
    scope: &TenantScope,
    day: &str,
    tokens: i64,
    reserved: i64,
) -> Result<Option<(i64, i64)>, AiError> {
    let params = vec![Param::Text(day.to_owned()), Param::Int(tokens), Param::Int(reserved)];
    let rows = exec(scope.clone(), SETTLE_SQL, params).await?;
    single_row(rows)
}


/// The `(calls, tokens)` of the day: all calls, and the tokens no call in flight holds; no row is zero.
pub async fn read_settled(exec: BudgetExecutor<'_, '_>, scope: &TenantScope, day: &str) -> Result<(i64, i64), AiError> {
    let params = vec![Param::Text(day.to_owned()), Param::Int(HELD_EXPIRY_SECONDS)];
    let rows = exec(scope.clone(), SETTLED_SQL, params).await?;
    let settled = single_row(rows)?;
    Ok(settled.unwrap_or((0, 0)))
}


/// Tokens to give back: the reservation minus the peer's claim clamped to the reservation; a missing count gives nothing back.
pub fn refund(reserved: i64, answer: &Answer) -> i64 {
    match (answer.prompt_tokens, answer.completion_tokens) {
        (Some(prompt), Some(completion)) => reserved - (i64::from(prompt) + i64::from(completion)).min(reserved),
        _ => 0,
    }
}


/// True when `after` is at or over the alert percentage of `cap` and `before` was under it.
pub fn crossed(before: i64, after: i64, cap: i64) -> bool {
    after * PERCENT >= cap * ALERT_PERCENT && before * PERCENT < cap * ALERT_PERCENT
}


pub fn crossed_80(totals: (i64, i64), reserved: i64, settings: &AiSettings) -> bool {
    let (calls, tokens) = totals;
    crossed(calls - 1, calls, i64::from(settings.max_calls_per_day)) || crossed(tokens - reserved, tokens, i64::from(settings.max_tokens_per_day))
}


/// `Exhausted` when the settled totals leave no room for one call of `max_tokens` plus a minimal body, or the call cap is reached; `Busy` when this request would fit once the calls in flight settle; `TooLarge` otherwise.
pub fn verdict(settled: (i64, i64), reserved: i64, settings: &AiSettings) -> Verdict {
    let (calls, tokens) = settled;
    let call_cap = i64::from(settings.max_calls_per_day);
    let token_cap = i64::from(settings.max_tokens_per_day);
    let smallest = i64::from(settings.max_tokens) + i64::from(REQUEST_OVERHEAD_BYTES);
    if calls >= call_cap || tokens + smallest > token_cap {
        Verdict::Exhausted
    } else if tokens + reserved <= token_cap {
        Verdict::Busy
    } else {
        Verdict::TooLarge
    }
}


pub fn build_alert(scope: &TenantScope, rule: &Rule, day: &str, now_micros: u64, detail: &Value) -> Alert {
    let tenant = tenant_of(scope);
    let event_ids = vec![day.to_owned()];
    Alert {
        id: alert_id(tenant, rule.id, &event_ids),
        tenant: tenant.to_owned(),
        rule_id: rule.id.to_owned(),
        rule_title: rule.title.to_owned(),
        severity: rule.severity,
        event_time: day.to_owned(),
        created_micros: now_micros,
        host_name: None,
        user_name: None,
        event_ids,
        summary: summarise(detail),
    }
}


/// One alert per tenant, rule and day (the store dedupes on the derived id); a store failure is logged and never stops the call.
pub async fn notify(exec: Executor<'_, '_>, scope: &TenantScope, rule: &Rule, day: &str, now_micros: u64, detail: &Value) {
    let alert = build_alert(scope, rule, day, now_micros, detail);
    let outcome = insert_alerts(exec, scope, &[alert]).await;
    if let Err(error) = outcome {
        let message = format!("ai budget alert {} not stored: {error}", rule.id);
        warn!("{message}");
    }
}


/// Releases the reservation and gives back the unused part; a store failure keeps the reservation (fail closed) and is logged. Returns the tokens given back and the totals.
pub async fn settle(exec: BudgetExecutor<'_, '_>, scope: &TenantScope, day: &str, reserved: i64, owed: i64, totals: (i64, i64)) -> (i64, (i64, i64)) {
    match give_back(exec, scope, day, owed, reserved).await {
        Ok(Some(settled)) => (owed, settled),
        Ok(None) => (0, totals),
        Err(error) => {
            let message = format!("ai budget settle failed: {error}");
            warn!("{message}");
            (0, totals)
        }
    }
}


pub fn log_budget(tenant: &str, day: &str, reserved: i64, returned: i64, totals: (i64, i64)) {
    let settled = reserved - returned;
    let summary = format!(
        "tenant={tenant} day={day} reserved_tokens={reserved} settled_tokens={settled} day_calls={} day_tokens={}",
        totals.0, totals.1
    );
    info!("ai budget {summary}");
}


/// What a refused reservation becomes: the spent alert and `BudgetSpent` whenever no room is left for this request (exhausted or too large), `BudgetBusy` while calls in flight hold the room.
pub async fn refusal(stores: &Stores<'_, '_>, scope: &TenantScope, settings: &AiSettings, day: &str, now: u64, reserved: i64) -> AiError {
    match read_settled(stores.budget, scope, day).await {
        Ok(settled) => match verdict(settled, reserved, settings) {
            Verdict::Exhausted | Verdict::TooLarge => {
                let detail = json!({"max_calls": settings.max_calls_per_day, "max_tokens": settings.max_tokens_per_day, "settled_calls": settled.0, "settled_tokens": settled.1});
                notify(stores.alerts, scope, &RULE_SPENT, day, now, &detail).await;
                AiError::BudgetSpent
            }
            Verdict::Busy => {
                warn!("ai budget busy: the room is held by calls in flight");
                AiError::BudgetBusy
            }
        },
        Err(error) => error,
    }
}


/// Takes a place in the gate, reserves, and turns a refusal into its error; the place is held until the store answered.
pub async fn reservation(
    stores: &Stores<'_, '_>,
    scope: &TenantScope,
    settings: &AiSettings,
    day: &str,
    now: u64,
    reserved: i64,
) -> Result<(i64, i64), AiError> {
    let place = enter(stores.gate);
    if place.is_none() {
        warn!("ai budget busy: too many reservations wait on the store");
    }
    let _held = place.ok_or(AiError::BudgetBusy)?;
    let outcome = reserve(stores.budget, scope, settings, day, reserved).await?;
    match outcome {
        Some(totals) => Ok(totals),
        None => Err(refusal(stores, scope, settings, day, now, reserved).await),
    }
}


/// One model call under the tenant's daily budget: reserve before any model I/O, settle after (a failed call releases its reservation and keeps the tokens). The model call blocks the thread (ureq), so a caller on an async runtime runs this on a blocking-capable worker.
pub async fn budgeted_chat(
    stores: &Stores<'_, '_>,
    scope: &TenantScope,
    settings: &AiSettings,
    instructions: &str,
    data: &Value,
    deps: &BudgetDeps,
) -> Result<Answer, AiError> {
    let prepared = prepare(settings, instructions, data, &deps.chat)?;
    let now = (deps.wall_clock)();
    let day = day_text(now)?;
    let reserved = prepared.request.body.len() as i64 + i64::from(settings.max_tokens);
    let totals = reservation(stores, scope, settings, &day, now, reserved).await?;
    if crossed_80(totals, reserved, settings) {
        let detail = json!({
            "calls": totals.0, "tokens": totals.1,
            "max_calls": settings.max_calls_per_day, "max_tokens": settings.max_tokens_per_day
        });
        notify(stores.alerts, scope, &RULE_80, &day, now, &detail).await;
    }
    let outcome = send(&prepared, settings.max_response_bytes, &deps.chat);
    let owed = outcome.as_ref().map_or(0, |answer| refund(reserved, answer));
    let (returned, settled) = settle(stores.budget, scope, &day, reserved, owed, totals).await;
    log_budget(tenant_of(scope), &day, reserved, returned, settled);
    outcome
}
