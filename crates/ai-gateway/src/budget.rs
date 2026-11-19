use crate::chat::{prepare, send};
use crate::error::AiError;
use crate::limits::{ALERT_PERCENT, BUDGET_80_RULE, BUDGET_SPENT_RULE, MICROS_PER_SECOND, PERCENT};
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
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{info, warn};


pub const MIGRATION_NAMESPACE: &str = "ai_gateway";


pub const MIGRATIONS: [Migration; 1] = [Migration {
    version: "ai_gateway_0001",
    sql: include_str!("../migrations/ai_gateway_0001.sql"),
}];


/// Server and client deadline of every statement.
pub const STATEMENT_DEADLINE: Duration = Duration::from_secs(10);


/// Params: `$2` UTC day, `$3` reservation, `$4` call cap, `$5` token cap. One statement reserves one call and the tokens when both caps hold, on insert and on update alike; no row means the budget is spent.
pub const RESERVE_SQL: &str = "INSERT INTO ai_budget_day (tenant, day, calls, tokens) \
    SELECT $1, $2::text::date, 1, $3::bigint WHERE $3::bigint <= $5::bigint AND 1 <= $4::bigint \
    ON CONFLICT (tenant, day) DO UPDATE SET calls = ai_budget_day.calls + 1, tokens = ai_budget_day.tokens + $3::bigint \
    WHERE ai_budget_day.calls + 1 <= $4::bigint AND ai_budget_day.tokens + $3::bigint <= $5::bigint \
    RETURNING calls, tokens";


/// Params: `$2` UTC day of the reservation, `$3` tokens to give back; the total never goes below zero.
pub const SETTLE_SQL: &str = "UPDATE ai_budget_day SET tokens = GREATEST(tokens - $3::bigint, 0) \
    WHERE tenant = $1 AND day = $2::text::date RETURNING calls, tokens";


/// A bound statement parameter; the tenant is `$1` and is added by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Text(String),
    Int(i64),
}


/// The two stores a budgeted call talks to: the budget table and the alert store.
#[derive(Clone, Copy)]
pub struct Stores<'a, 'b> {
    pub budget: BudgetExecutor<'a, 'b>,
    pub alerts: Executor<'a, 'b>,
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
    ];
    let rows = exec(scope.clone(), RESERVE_SQL, params).await?;
    single_row(rows)
}


/// Gives back `tokens` of the reservation made on `day`.
pub async fn give_back(exec: BudgetExecutor<'_, '_>, scope: &TenantScope, day: &str, tokens: i64) -> Result<Option<(i64, i64)>, AiError> {
    let rows = exec(scope.clone(), SETTLE_SQL, vec![Param::Text(day.to_owned()), Param::Int(tokens)]).await?;
    single_row(rows)
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


/// Gives back the unused part of the reservation; a store failure keeps the reservation (fail closed) and is logged. Returns the tokens given back and the totals.
pub async fn settle(
    exec: BudgetExecutor<'_, '_>,
    scope: &TenantScope,
    day: &str,
    reserved: i64,
    answer: &Answer,
    totals: (i64, i64),
) -> (i64, (i64, i64)) {
    let owed = refund(reserved, answer);
    if owed > 0 {
        match give_back(exec, scope, day, owed).await {
            Ok(Some(settled)) => (owed, settled),
            Ok(None) => (0, totals),
            Err(error) => {
                let message = format!("ai budget settle failed: {error}");
                warn!("{message}");
                (0, totals)
            }
        }
    } else {
        (0, totals)
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


/// One model call under the tenant's daily budget: reserve before any model I/O, settle after. The model call blocks the thread (ureq), so a caller on an async runtime runs this on a blocking-capable worker.
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
    match reserve(stores.budget, scope, settings, &day, reserved).await? {
        None => {
            let detail = json!({"max_calls": settings.max_calls_per_day, "max_tokens": settings.max_tokens_per_day, "requested_tokens": reserved});
            notify(stores.alerts, scope, &RULE_SPENT, &day, now, &detail).await;
            Err(AiError::BudgetSpent)
        }
        Some(totals) => {
            if crossed_80(totals, reserved, settings) {
                let detail = json!({
                    "calls": totals.0, "tokens": totals.1,
                    "max_calls": settings.max_calls_per_day, "max_tokens": settings.max_tokens_per_day
                });
                notify(stores.alerts, scope, &RULE_80, &day, now, &detail).await;
            }
            let answer = send(&prepared, settings.max_response_bytes, &deps.chat)?;
            let (returned, settled) = settle(stores.budget, scope, &day, reserved, &answer, totals).await;
            log_budget(tenant_of(scope), &day, reserved, returned, settled);
            Ok(answer)
        }
    }
}
