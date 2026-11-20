use crate::common::{block_on_ready, deps, scripted, settings, CALL_CAP, TOKENS, TOKEN_CAP};
use crate::types::{Statements, TestResult};
use ai_gateway::budget::{
    budgeted_chat, crossed, crossed_80, day_text, enter, new_gate, read_settled, refund, single_row, verdict, waiting, BudgetDeps, Gate, Param,
    Stores, Verdict, MIGRATIONS, MIGRATION_NAMESPACE, RESERVE_SQL, SETTLED_SQL, SETTLE_SQL, STATEMENT_DEADLINE,
};
use ai_gateway::error::AiError;
use ai_gateway::limits::{HELD_EXPIRY_SECONDS, REQUEST_OVERHEAD_BYTES};
use ai_gateway::model::{Answer, FinishReason};
use ai_gateway::settings::{validate_ai, AiSettings};
use ai_gateway::types::{BudgetFuture, BudgetRows};
use alerts::types::RowFuture;
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::{ready, Future};
use std::sync::{Arc, Mutex, MutexGuard};


pub const DAY_ONE_END: u64 = 1_700_006_399_000_000;


pub const DAY_TWO_START: u64 = 1_700_006_400_000_000;


pub const DAY_ONE: &str = "2023-11-14";


pub const DAY_TWO: &str = "2023-11-15";


const FOUR: usize = 4;


const CALLS_ONE: i64 = 1;


const CALLS_TWO: i64 = 2;


const CALLS_THREE: i64 = 3;


const CALLS_FOUR: i64 = 4;


const PROMPT_USED: u32 = 2;


const COMPLETION_USED: u32 = 1;


const REFUNDED: i64 = 2;


const TWO_ALERTS: usize = 2;


const RESERVE_AND_SETTLE: usize = 2;


const CALLS_BEFORE_SPENT: usize = 4;


const FIVE: i64 = 5;


const USED_TOKENS: i64 = 14;


const FIVE_CALLS: u32 = 5;


const ONE_CALL: u32 = 1;


const SHORT_OF_CAP: i64 = 1;


const WAITING: usize = 64;


const SEEDED_TOKENS: i64 = 240;


const FIFTY: usize = 50;


const GATE_LIMIT: usize = 2;


const TWICE: i64 = 2;


const SMALL_DAILY_CAP: u32 = 500;


#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Broken,
    TwoRows,
    SettleBroken,
    SettleEmpty,
    SettledBroken,
    AlertsBroken,
}


pub struct Model {
    pub rows: Mutex<HashMap<(String, String), (i64, i64)>>,
    pub held: Mutex<HashMap<(String, String), (i64, i64)>>,
    pub log: Mutex<Statements>,
    pub alerts: Mutex<HashMap<(String, String), String>>,
    pub alert_statements: Mutex<usize>,
    pub mode: Mode,
}


pub fn model(mode: Mode) -> Arc<Model> {
    Arc::new(Model {
        rows: Mutex::new(HashMap::new()),
        held: Mutex::new(HashMap::new()),
        log: Mutex::new(Vec::new()),
        alerts: Mutex::new(HashMap::new()),
        alert_statements: Mutex::new(0),
        mode,
    })
}


pub fn lock<Guarded>(mutex: &Mutex<Guarded>) -> Result<MutexGuard<'_, Guarded>, PgError> {
    mutex.lock().map_err(|_poisoned| PgError::InvalidTenant)
}


pub fn reserve_row(model: &Model, tenant: &str, params: &[Param]) -> Result<BudgetRows, PgError> {
    match params {
        [Param::Text(day), Param::Int(tokens), Param::Int(max_calls), Param::Int(max_tokens), Param::Int(HELD_EXPIRY_SECONDS)] => {
            let mut rows = lock(&model.rows)?;
            let mut held = lock(&model.held)?;
            let key = (tenant.to_owned(), day.clone());
            let (calls, used) = rows.get(&key).copied().unwrap_or((0, 0));
            let (held_calls, held_tokens) = held.get(&key).copied().unwrap_or((0, 0));
            if calls < *max_calls && used + tokens <= *max_tokens {
                rows.insert(key.clone(), (calls + 1, used + tokens));
                held.insert(key, (held_calls + 1, held_tokens + tokens));
                Ok(vec![(calls + 1, used + tokens)])
            } else {
                Ok(vec![])
            }
        }
        _ => Err(PgError::InvalidTenant),
    }
}


pub fn settle_row(model: &Model, tenant: &str, params: &[Param]) -> Result<BudgetRows, PgError> {
    match params {
        [Param::Text(day), Param::Int(give), Param::Int(reserved)] => {
            let mut rows = lock(&model.rows)?;
            let mut held = lock(&model.held)?;
            let key = (tenant.to_owned(), day.clone());
            let found = rows.get(&key).copied();
            let updated = found.map(|(calls, used)| (calls, (used - give).max(0)));
            if let Some(row) = updated {
                rows.insert(key.clone(), row);
            }
            let (held_calls, held_tokens) = held.get(&key).copied().unwrap_or((0, 0));
            held.insert(key, ((held_calls - 1).max(0), (held_tokens - reserved).max(0)));
            Ok(updated.into_iter().collect())
        }
        _ => Err(PgError::InvalidTenant),
    }
}


pub fn settled_row(model: &Model, tenant: &str, params: &[Param]) -> Result<BudgetRows, PgError> {
    match params {
        [Param::Text(day), Param::Int(HELD_EXPIRY_SECONDS)] => {
            let key = (tenant.to_owned(), day.clone());
            let found = lock(&model.rows)?.get(&key).copied();
            let (_held_calls, held_tokens) = lock(&model.held)?.get(&key).copied().unwrap_or((0, 0));
            Ok(found.map(|(calls, used)| (calls, used - held_tokens)).into_iter().collect())
        }
        _ => Err(PgError::InvalidTenant),
    }
}


pub fn apply_statement(model: &Model, scope: &TenantScope, sql: &'static str, params: &[Param]) -> Result<BudgetRows, PgError> {
    let tenant = tenant_of(scope);
    lock(&model.log)?.push((tenant.to_owned(), sql, params.to_vec()));
    match (model.mode, sql) {
        (Mode::Broken, _) | (Mode::SettleBroken, SETTLE_SQL) | (Mode::SettledBroken, SETTLED_SQL) => Err(PgError::InvalidTenant),
        (Mode::TwoRows, _) => Ok(vec![(CALLS_ONE, CALLS_ONE), (CALLS_TWO, CALLS_TWO)]),
        (Mode::SettleEmpty, SETTLE_SQL) => Ok(vec![]),
        (_, RESERVE_SQL) => reserve_row(model, tenant, params),
        (_, SETTLE_SQL) => settle_row(model, tenant, params),
        (_, SETTLED_SQL) => settled_row(model, tenant, params),
        _ => Err(PgError::InvalidTenant),
    }
}


pub fn make_budget_exec(model: &Arc<Model>) -> impl Fn(TenantScope, &'static str, Vec<Param>) -> BudgetFuture<'static> + Sync + 'static {
    let shared = Arc::clone(model);
    move |scope, sql, params| -> BudgetFuture<'static> { Box::pin(ready(apply_statement(&shared, &scope, sql, &params))) }
}


pub fn stored_document(stored: &mut HashMap<(String, String), String>, tenant: &str, doc: &Value) -> Result<bool, PgError> {
    let id = doc.get("id").and_then(Value::as_str).ok_or(PgError::InvalidTenant)?;
    let rule = doc.get("rule_id").and_then(Value::as_str).ok_or(PgError::InvalidTenant)?;
    Ok(stored.insert((tenant.to_owned(), id.to_owned()), rule.to_owned()).is_none())
}


pub fn store_alerts(model: &Model, tenant: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    *lock(&model.alert_statements)? += 1;
    let text = params.first().ok_or(PgError::InvalidTenant)?;
    let docs: Vec<Value> = serde_json::from_str(text).map_err(|_malformed| PgError::InvalidTenant)?;
    let mut stored = lock(&model.alerts)?;
    let results = docs
        .iter()
        .map(|doc| stored_document(&mut stored, tenant, doc))
        .collect::<Result<Vec<bool>, PgError>>()?;
    let fresh = results.iter().filter(|inserted| **inserted).count();
    Ok(vec![vec![fresh.to_string()]])
}


pub fn make_alert_exec(model: &Arc<Model>) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'static> + Sync + 'static {
    let shared = Arc::clone(model);
    move |scope, _sql, params| -> RowFuture<'static> {
        let outcome = if shared.mode == Mode::AlertsBroken {
            Err(PgError::InvalidTenant)
        } else {
            store_alerts(&shared, tenant_of(&scope), &params)
        };
        Box::pin(ready(outcome))
    }
}


pub fn wall_one() -> u64 {
    DAY_ONE_END
}


pub fn wall_two() -> u64 {
    DAY_TWO_START
}


pub fn wall_broken() -> u64 {
    u64::MAX
}


pub fn budget_deps(wall_clock: fn() -> u64) -> BudgetDeps {
    BudgetDeps {
        chat: deps(scripted),
        wall_clock,
    }
}


pub fn capped(script: &str, calls: u32, tokens: u32) -> AiSettings {
    AiSettings {
        max_calls_per_day: calls,
        max_tokens_per_day: tokens,
        ..settings(script)
    }
}


pub async fn gated_call(model: &Arc<Model>, gate: &Gate, tenant: &str, used: &AiSettings, wall_clock: fn() -> u64) -> Result<Answer, AiError> {
    let budget = make_budget_exec(model);
    let alerts = make_alert_exec(model);
    let stores = Stores {
        budget: &budget,
        alerts: &alerts,
        gate,
    };
    let scope = tenant_scope(tenant)?;
    let data = json!({"a": 1});
    let chat_deps = budget_deps(wall_clock);
    let outcome = budgeted_chat(&stores, &scope, used, "Summarise.", &data, &chat_deps).await;
    outcome
}


pub async fn budgeted_call(model: &Arc<Model>, tenant: &str, used: &AiSettings, wall_clock: fn() -> u64) -> Result<Answer, AiError> {
    gated_call(model, &new_gate(WAITING), tenant, used, wall_clock).await
}


pub fn seed(model: &Model, tenant: &str, day: &str, total: (i64, i64), held: (i64, i64)) -> Result<(), PgError> {
    lock(&model.rows)?.insert((tenant.to_owned(), day.to_owned()), total);
    lock(&model.held)?.insert((tenant.to_owned(), day.to_owned()), held);
    Ok(())
}


pub fn held_row(model: &Model, tenant: &str, day: &str) -> Result<Option<(i64, i64)>, PgError> {
    Ok(lock(&model.held)?.get(&(tenant.to_owned(), day.to_owned())).copied())
}


pub fn day_row(model: &Model, tenant: &str, day: &str) -> Result<Option<(i64, i64)>, PgError> {
    Ok(lock(&model.rows)?.get(&(tenant.to_owned(), day.to_owned())).copied())
}


pub fn rule_count(model: &Model, rule: &str) -> Result<usize, PgError> {
    Ok(lock(&model.alerts)?.values().filter(|stored| stored.as_str() == rule).count())
}


pub fn statements(model: &Model) -> Result<usize, PgError> {
    Ok(lock(&model.log)?.len())
}


pub async fn measured_reservation() -> Result<i64, Box<dyn std::error::Error>> {
    let probe = model(Mode::Normal);
    budgeted_call(&probe, "probe", &capped("nofinish", CALL_CAP, TOKEN_CAP), wall_one).await?;
    Ok(day_row(&probe, "probe", DAY_ONE)?.ok_or("no row")?.1)
}


#[tokio::test]
async fn a_call_reserves_then_gives_back_what_the_model_did_not_use() -> TestResult {
    let reserved = measured_reservation().await?;
    assert!(reserved > USED_TOKENS);
    let spent = model(Mode::Normal);
    budgeted_call(&spent, "acme", &capped("ok", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(day_row(&spent, "acme", DAY_ONE)?, Some((1, USED_TOKENS)));
    assert_eq!(statements(&spent)?, RESERVE_AND_SETTLE);
    Ok(())
}


#[tokio::test]
async fn a_peer_claim_is_clamped_to_the_reservation() -> TestResult {
    let reserved = measured_reservation().await?;
    let huge = model(Mode::Normal);
    budgeted_call(&huge, "acme", &capped("hugeusage", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(day_row(&huge, "acme", DAY_ONE)?, Some((1, reserved)));
    assert_eq!(statements(&huge)?, RESERVE_AND_SETTLE);
    let zero = model(Mode::Normal);
    budgeted_call(&zero, "acme", &capped("zerousage", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(day_row(&zero, "acme", DAY_ONE)?, Some((1, 0)));
    let negative = model(Mode::Normal);
    let refused = budgeted_call(&negative, "acme", &capped("negusage", CALL_CAP, TOKEN_CAP), wall_one).await;
    assert!(matches!(refused, Err(AiError::Malformed { .. })));
    assert_eq!(day_row(&negative, "acme", DAY_ONE)?, Some((1, reserved)));
    let missing = model(Mode::Normal);
    budgeted_call(&missing, "acme", &capped("nofinish", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(day_row(&missing, "acme", DAY_ONE)?, Some((1, reserved)));
    assert_eq!(statements(&missing)?, RESERVE_AND_SETTLE);
    Ok(())
}


#[test]
fn the_refund_never_exceeds_the_reservation_or_goes_negative() -> TestResult {
    let answer = |prompt, completion| Answer {
        content: String::new(),
        prompt_tokens: prompt,
        completion_tokens: completion,
        finish_reason: FinishReason::Stop,
    };
    assert_eq!(refund(FIVE, &answer(Some(u32::MAX), Some(u32::MAX))), 0);
    assert_eq!(refund(FIVE, &answer(Some(0), Some(0))), FIVE);
    assert_eq!(refund(FIVE, &answer(Some(PROMPT_USED), Some(COMPLETION_USED))), REFUNDED);
    assert_eq!(refund(FIVE, &answer(None, Some(1))), 0);
    assert_eq!(refund(FIVE, &answer(Some(1), None)), 0);
    Ok(())
}


#[tokio::test]
async fn a_spent_budget_refuses_before_the_transport_is_called() -> TestResult {
    let calls = model(Mode::Normal);
    budgeted_call(&calls, "acme", &capped("ok", ONE_CALL, TOKEN_CAP), wall_one).await?;
    let refused = budgeted_call(&calls, "acme", &capped("ok", ONE_CALL, TOKEN_CAP), wall_one).await;
    assert!(matches!(refused, Err(AiError::BudgetSpent)));
    let transport = budgeted_call(&calls, "acme", &capped("transport", ONE_CALL, TOKEN_CAP), wall_one).await;
    assert!(matches!(transport, Err(AiError::BudgetSpent)), "the transport was reached");
    assert_eq!(day_row(&calls, "acme", DAY_ONE)?.map(|row| row.0), Some(1));
    let reserved = measured_reservation().await?;
    let tokens = model(Mode::Normal);
    let small = u32::try_from(reserved - SHORT_OF_CAP)?;
    let refused_first = budgeted_call(&tokens, "acme", &capped("transport", CALL_CAP, small), wall_one).await;
    assert!(matches!(refused_first, Err(AiError::BudgetSpent)));
    assert_eq!(day_row(&tokens, "acme", DAY_ONE)?, None);
    Ok(())
}


#[tokio::test]
async fn the_80_percent_alert_and_the_spent_alert_are_raised_once_each() -> TestResult {
    let calls = model(Mode::Normal);
    let used = capped("ok", FIVE_CALLS, TOKEN_CAP);
    for _ in 0..FOUR - 1 {
        budgeted_call(&calls, "acme", &used, wall_one).await?;
    }
    assert_eq!(rule_count(&calls, "ai.budget_80")?, 0);
    budgeted_call(&calls, "acme", &used, wall_one).await?;
    assert_eq!(rule_count(&calls, "ai.budget_80")?, 1);
    budgeted_call(&calls, "acme", &used, wall_one).await?;
    assert_eq!(*lock(&calls.alert_statements)?, 1);
    for _ in 0..FOUR - 1 {
        let refused = budgeted_call(&calls, "acme", &used, wall_one).await;
        assert!(matches!(refused, Err(AiError::BudgetSpent)));
    }
    assert_eq!(rule_count(&calls, "ai.budget_80")?, 1);
    assert_eq!(rule_count(&calls, "ai.budget_spent")?, 1);
    assert_eq!(lock(&calls.alerts)?.len(), TWO_ALERTS);
    assert_eq!(*lock(&calls.alert_statements)?, CALLS_BEFORE_SPENT);
    Ok(())
}


#[tokio::test]
async fn crossing_the_token_cap_share_raises_the_80_percent_alert() -> TestResult {
    let reserved = measured_reservation().await?;
    let tokens = model(Mode::Normal);
    let cap = u32::try_from(reserved + SHORT_OF_CAP)?;
    budgeted_call(&tokens, "acme", &capped("ok", CALL_CAP, cap), wall_one).await?;
    assert_eq!(rule_count(&tokens, "ai.budget_80")?, 1);
    Ok(())
}


#[test]
fn the_threshold_is_crossed_only_by_the_call_that_passes_it() -> TestResult {
    assert!(crossed(CALLS_THREE, CALLS_FOUR, FIVE));
    assert!(!crossed(CALLS_FOUR, FIVE, FIVE));
    assert!(!crossed(CALLS_TWO, CALLS_THREE, FIVE));
    let used = capped("ok", FIVE_CALLS, TOKEN_CAP);
    assert!(crossed_80((CALLS_FOUR, 0), 0, &used));
    assert!(!crossed_80((CALLS_TWO, 0), 0, &used));
    Ok(())
}


#[tokio::test]
async fn another_tenants_budget_is_untouched() -> TestResult {
    let both = model(Mode::Normal);
    let used = capped("ok", ONE_CALL, TOKEN_CAP);
    budgeted_call(&both, "acme", &used, wall_one).await?;
    assert!(matches!(budgeted_call(&both, "acme", &used, wall_one).await, Err(AiError::BudgetSpent)));
    budgeted_call(&both, "globex", &used, wall_one).await?;
    assert_eq!(day_row(&both, "globex", DAY_ONE)?.map(|row| row.0), Some(1));
    assert!(lock(&both.log)?
        .iter()
        .all(|(tenant, _sql, _params)| tenant == "acme" || tenant == "globex"));
    assert_eq!(lock(&both.alerts)?.keys().filter(|(tenant, _id)| tenant == "globex").count(), 1);
    assert_eq!(lock(&both.alerts)?.keys().filter(|(tenant, _id)| tenant == "acme").count(), TWO_ALERTS);
    Ok(())
}


#[tokio::test]
async fn the_budget_restarts_at_utc_midnight() -> TestResult {
    let days = model(Mode::Normal);
    let used = capped("ok", ONE_CALL, TOKEN_CAP);
    budgeted_call(&days, "acme", &used, wall_one).await?;
    assert!(matches!(budgeted_call(&days, "acme", &used, wall_one).await, Err(AiError::BudgetSpent)));
    budgeted_call(&days, "acme", &used, wall_two).await?;
    assert_eq!(day_row(&days, "acme", DAY_ONE)?.map(|row| row.0), Some(1));
    assert_eq!(day_row(&days, "acme", DAY_TWO)?.map(|row| row.0), Some(1));
    assert_eq!(day_text(DAY_ONE_END)?, DAY_ONE);
    assert_eq!(day_text(DAY_TWO_START)?, DAY_TWO);
    assert!(matches!(day_text(u64::MAX), Err(AiError::Clock(_))));
    Ok(())
}


#[tokio::test]
async fn a_clock_outside_the_calendar_refuses_before_the_store() -> TestResult {
    let broken = model(Mode::Normal);
    let refused = budgeted_call(&broken, "acme", &capped("transport", CALL_CAP, TOKEN_CAP), wall_broken).await;
    assert!(matches!(refused, Err(AiError::Clock(_))));
    assert_eq!(statements(&broken)?, 0);
    Ok(())
}


#[tokio::test]
async fn a_local_refusal_never_reaches_the_store() -> TestResult {
    let local = model(Mode::Normal);
    let mut invalid = capped("transport", CALL_CAP, TOKEN_CAP);
    invalid.max_tokens = 0;
    assert!(matches!(
        budgeted_call(&local, "acme", &invalid, wall_one).await,
        Err(AiError::Settings { field: "max_tokens" })
    ));
    assert_eq!(statements(&local)?, 0);
    Ok(())
}


#[tokio::test]
async fn a_store_failure_refuses_the_call_before_the_model() -> TestResult {
    let broken = model(Mode::Broken);
    let refused = budgeted_call(&broken, "acme", &capped("transport", CALL_CAP, TOKEN_CAP), wall_one).await;
    assert!(matches!(refused, Err(AiError::Store(_))), "the transport was reached");
    let two = model(Mode::TwoRows);
    let odd = budgeted_call(&two, "acme", &capped("transport", CALL_CAP, TOKEN_CAP), wall_one).await;
    assert!(matches!(odd, Err(AiError::BadReply)));
    assert!(matches!(single_row(vec![]), Ok(None)));
    Ok(())
}


#[tokio::test]
async fn a_failed_settle_keeps_the_reservation_and_the_answer() -> TestResult {
    let reserved = measured_reservation().await?;
    let broken = model(Mode::SettleBroken);
    let answer = budgeted_call(&broken, "acme", &capped("ok", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(answer.content, "hello");
    assert_eq!(day_row(&broken, "acme", DAY_ONE)?, Some((1, reserved)));
    let empty = model(Mode::SettleEmpty);
    budgeted_call(&empty, "acme", &capped("ok", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(day_row(&empty, "acme", DAY_ONE)?, Some((1, reserved)));
    Ok(())
}


#[tokio::test]
async fn a_failing_alert_store_never_stops_the_call() -> TestResult {
    let alerts = model(Mode::AlertsBroken);
    let used = capped("ok", ONE_CALL, TOKEN_CAP);
    budgeted_call(&alerts, "acme", &used, wall_one).await?;
    assert!(matches!(budgeted_call(&alerts, "acme", &used, wall_one).await, Err(AiError::BudgetSpent)));
    assert_eq!(lock(&alerts.alerts)?.len(), 0);
    Ok(())
}


#[tokio::test]
async fn the_alert_carries_the_scope_tenant_and_the_day() -> TestResult {
    let stored = model(Mode::Normal);
    let used = capped("ok", ONE_CALL, TOKEN_CAP);
    budgeted_call(&stored, "acme", &used, wall_one).await?;
    assert!(matches!(budgeted_call(&stored, "acme", &used, wall_one).await, Err(AiError::BudgetSpent)));
    assert!(lock(&stored.alerts)?.keys().all(|(tenant, _id)| tenant == "acme"));
    Ok(())
}


#[test]
fn the_statements_are_one_conditional_write_each() -> TestResult {
    assert!(RESERVE_SQL.starts_with("INSERT INTO ai_budget_day"));
    assert!(RESERVE_SQL.contains("SELECT $1, $2::text::date, 1, $3::bigint, 1, $3::bigint, now() WHERE $3::bigint <= $5::bigint AND 1 <= $4::bigint"));
    assert!(RESERVE_SQL.contains("held_at > now() - $6::bigint * interval '1 second'"));
    assert!(RESERVE_SQL.contains("ON CONFLICT (tenant, day) DO UPDATE SET calls = ai_budget_day.calls + 1"));
    assert!(RESERVE_SQL.contains("WHERE ai_budget_day.calls + 1 <= $4::bigint AND ai_budget_day.tokens + $3::bigint <= $5::bigint"));
    assert!(RESERVE_SQL.ends_with("RETURNING calls, tokens"));
    assert_eq!(RESERVE_SQL.matches(';').count(), 0);
    assert!(SETTLE_SQL.contains("GREATEST(tokens - $3::bigint, 0)"));
    assert!(
        SETTLE_SQL.contains("held_calls = GREATEST(held_calls - 1, 0)") && SETTLE_SQL.contains("held_tokens = GREATEST(held_tokens - $4::bigint, 0)")
    );
    assert!(
        SETTLED_SQL.starts_with("SELECT calls, tokens - CASE WHEN held_at > now() - $3::bigint * interval '1 second' THEN held_tokens ELSE 0 END")
    );
    assert!(SETTLED_SQL.ends_with("FROM ai_budget_day WHERE tenant = $1 AND day = $2::text::date"));
    assert_eq!(SETTLED_SQL.matches(';').count() + SETTLE_SQL.matches(';').count(), 0);
    assert!(SETTLE_SQL.contains("WHERE tenant = $1 AND day = $2::text::date"));
    check_embedded(&MIGRATIONS)?;
    check_namespace(MIGRATION_NAMESPACE)?;
    assert!(MIGRATIONS
        .iter()
        .take(1)
        .all(|migration| migration.sql.contains("PRIMARY KEY (tenant, day)")));
    assert!(MIGRATIONS
        .iter()
        .skip(1)
        .all(|migration| migration.sql.contains("held_calls") && migration.sql.contains("held_tokens")));
    assert!(!STATEMENT_DEADLINE.is_zero());
    Ok(())
}


#[tokio::test]
async fn a_burst_reaching_the_call_cap_is_spent_with_one_alert() -> TestResult {
    let stored = model(Mode::Normal);
    let used = capped("transport", FIVE_CALLS, TOKEN_CAP);
    seed(&stored, "acme", DAY_ONE, (FIVE, SEEDED_TOKENS), (FIVE, SEEDED_TOKENS))?;
    let gate = new_gate(WAITING);
    let outcomes = sequential_calls(FIFTY, &stored, &gate, &used).await?;
    assert!(outcomes.iter().all(|outcome| matches!(outcome, Err(AiError::BudgetSpent))));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 1);
    seed(&stored, "acme", DAY_ONE, (FIVE, SEEDED_TOKENS), (0, 0))?;
    let spent = gated_call(&stored, &gate, "acme", &used, wall_one).await;
    assert!(matches!(spent, Err(AiError::BudgetSpent)));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 1);
    assert!(matches!(
        gated_call(&stored, &gate, "acme", &used, wall_one).await,
        Err(AiError::BudgetSpent)
    ));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 1);
    Ok(())
}


pub async fn sequential_calls(count: usize, stored: &Arc<Model>, gate: &Gate, used: &AiSettings) -> Result<Vec<Result<Answer, AiError>>, PgError> {
    let mut outcomes = Vec::new();
    for _ in 0..count {
        outcomes.push(gated_call(stored, gate, "acme", used, wall_one).await);
    }
    Ok(outcomes)
}


#[tokio::test]
async fn the_token_room_held_in_flight_is_busy_and_settled_exhaustion_alerts() -> TestResult {
    let reserved = measured_reservation().await?;
    let cap = reserved * TWICE;
    let used = capped("transport", CALL_CAP, u32::try_from(cap)?);
    let stored = model(Mode::Normal);
    let seeded = cap - i64::from(TOKENS) - i64::from(REQUEST_OVERHEAD_BYTES) + 1;
    seed(&stored, "acme", DAY_ONE, (1, seeded), (1, seeded))?;
    assert!(matches!(budgeted_call(&stored, "acme", &used, wall_one).await, Err(AiError::BudgetBusy)));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 0);
    seed(&stored, "acme", DAY_ONE, (1, seeded), (0, 0))?;
    assert!(matches!(budgeted_call(&stored, "acme", &used, wall_one).await, Err(AiError::BudgetSpent)));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 1);
    Ok(())
}


#[tokio::test]
async fn a_request_too_large_for_the_room_alone_is_spent_with_the_alert() -> TestResult {
    let reserved = measured_reservation().await?;
    let stored = model(Mode::Normal);
    let small = u32::try_from(reserved - SHORT_OF_CAP)?;
    let refused = budgeted_call(&stored, "acme", &capped("transport", CALL_CAP, small), wall_one).await;
    assert!(matches!(refused, Err(AiError::BudgetSpent)));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 1);
    let again = budgeted_call(&stored, "acme", &capped("transport", CALL_CAP, small), wall_one).await;
    assert!(matches!(again, Err(AiError::BudgetSpent)));
    assert_eq!(rule_count(&stored, "ai.budget_spent")?, 1);
    Ok(())
}


#[test]
fn the_verdict_follows_the_settled_totals_only() -> TestResult {
    let used = capped("ok", FIVE_CALLS, TOKEN_CAP);
    let reserved = i64::from(TOKENS) + i64::from(REQUEST_OVERHEAD_BYTES);
    assert_eq!(verdict((FIVE, 0), reserved, &used), Verdict::Exhausted);
    assert_eq!(verdict((CALLS_FOUR, 0), reserved, &used), Verdict::Busy);
    let tight = capped("ok", FIVE_CALLS, u32::try_from(reserved)?);
    assert_eq!(verdict((0, 1), reserved, &tight), Verdict::Exhausted);
    assert_eq!(verdict((0, 0), reserved, &tight), Verdict::Busy);
    assert_eq!(verdict((0, 0), reserved + 1, &tight), Verdict::TooLarge);
    Ok(())
}


#[tokio::test]
async fn a_failed_call_releases_its_reservation_and_keeps_the_tokens() -> TestResult {
    let reserved = measured_reservation().await?;
    let stored = model(Mode::Normal);
    let failed = budgeted_call(&stored, "acme", &capped("transport", CALL_CAP, TOKEN_CAP), wall_one).await;
    assert!(matches!(failed, Err(AiError::Protocol)));
    assert_eq!(day_row(&stored, "acme", DAY_ONE)?, Some((1, reserved)));
    assert_eq!(held_row(&stored, "acme", DAY_ONE)?, Some((0, 0)));
    budgeted_call(&stored, "acme", &capped("ok", CALL_CAP, TOKEN_CAP), wall_one).await?;
    assert_eq!(held_row(&stored, "acme", DAY_ONE)?, Some((0, 0)));
    Ok(())
}


#[tokio::test]
async fn the_settled_read_of_a_day_without_a_row_is_zero() -> TestResult {
    let empty = model(Mode::Normal);
    let budget = make_budget_exec(&empty);
    let scope = tenant_scope("acme")?;
    assert_eq!(read_settled(&budget, &scope, DAY_ONE).await?, (0, 0));
    seed(&empty, "acme", DAY_ONE, (CALLS_THREE, FIVE), (1, 1))?;
    assert_eq!(read_settled(&budget, &scope, DAY_ONE).await?, (CALLS_THREE, FIVE - 1));
    let two = model(Mode::TwoRows);
    assert!(matches!(
        read_settled(&make_budget_exec(&two), &scope, DAY_ONE).await,
        Err(AiError::BadReply)
    ));
    Ok(())
}


#[tokio::test]
async fn the_gate_refuses_a_wait_over_its_limit_without_touching_the_store() -> TestResult {
    let gate = new_gate(GATE_LIMIT);
    let first = enter(&gate).ok_or("first")?;
    let second = enter(&gate).ok_or("second")?;
    assert_eq!(waiting(&gate), GATE_LIMIT);
    assert!(enter(&gate).is_none());
    assert_eq!(waiting(&gate), GATE_LIMIT);
    drop(first);
    assert_eq!(waiting(&gate), 1);
    drop(second);
    assert_eq!(waiting(&gate), 0);
    let stored = model(Mode::Normal);
    let full = new_gate(0);
    let refused = gated_call(&stored, &full, "acme", &capped("transport", CALL_CAP, TOKEN_CAP), wall_one).await;
    assert!(matches!(refused, Err(AiError::BudgetBusy)));
    assert_eq!(statements(&stored)?, 0);
    assert_eq!(waiting(&full), 0);
    Ok(())
}


pub fn stalled(_scope: TenantScope, _sql: &'static str, _params: Vec<Param>) -> BudgetFuture<'static> {
    Box::pin(std::future::pending())
}


#[test]
fn waiting_reservations_are_bounded_and_a_stalled_store_is_not_a_store_failure() -> TestResult {
    let gate = new_gate(GATE_LIMIT);
    let stored = model(Mode::Normal);
    let alerts = make_alert_exec(&stored);
    let stores = Stores {
        budget: &stalled,
        alerts: &alerts,
        gate: &gate,
    };
    let scope = tenant_scope("acme")?;
    let used = capped("ok", CALL_CAP, TOKEN_CAP);
    let data = json!({"a": 1});
    let chat_deps = budget_deps(wall_one);
    let call = || budgeted_chat(&stores, &scope, &used, "Summarise.", &data, &chat_deps);
    let mut first = Box::pin(call());
    let mut second = Box::pin(call());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(first.as_mut().poll(&mut context).is_pending());
    assert!(second.as_mut().poll(&mut context).is_pending());
    assert_eq!(waiting(&gate), GATE_LIMIT);
    let third = block_on_ready(call()).ok_or("the third waited")?;
    assert!(matches!(third, Err(AiError::BudgetBusy)));
    drop(first);
    assert_eq!(waiting(&gate), 1);
    drop(second);
    assert_eq!(waiting(&gate), 0);
    Ok(())
}


#[test]
fn a_daily_token_cap_below_one_reservation_is_refused_at_load() -> TestResult {
    let floor = TOKENS + REQUEST_OVERHEAD_BYTES;
    assert!(validate_ai(&capped("ok", CALL_CAP, floor)).is_ok());
    let refused = validate_ai(&capped("ok", CALL_CAP, floor - 1));
    assert!(matches!(refused, Err(AiError::Settings { field: "max_tokens_per_day" })));
    assert!(matches!(
        validate_ai(&capped("ok", CALL_CAP, SMALL_DAILY_CAP)),
        Err(AiError::Settings { field: "max_tokens_per_day" })
    ));
    Ok(())
}


#[tokio::test]
async fn a_minimal_request_is_never_smaller_than_the_overhead_constant() -> TestResult {
    let stored = model(Mode::Normal);
    let used = capped("nofinish", CALL_CAP, TOKEN_CAP);
    let budget = make_budget_exec(&stored);
    let alerts = make_alert_exec(&stored);
    let gate = new_gate(WAITING);
    let stores = Stores {
        budget: &budget,
        alerts: &alerts,
        gate: &gate,
    };
    let scope = tenant_scope("acme")?;
    let chat_deps = budget_deps(wall_one);
    budgeted_chat(&stores, &scope, &used, "", &json!(null), &chat_deps).await?;
    let body = day_row(&stored, "acme", DAY_ONE)?.ok_or("no row")?.1 - i64::from(TOKENS);
    assert!(body >= i64::from(REQUEST_OVERHEAD_BYTES), "{body}");
    Ok(())
}


#[test]
fn only_budgeted_chat_sends_to_a_model() -> TestResult {
    let read = |name: &str| std::fs::read_to_string(format!("{}/src/{name}.rs", env!("CARGO_MANIFEST_DIR")));
    let chat_source = read("chat")?;
    let transport_source = read("transport")?;
    let budget_source = read("budget")?;
    for forbidden in ["pub fn chat(", "pub fn send(", "pub fn prepare(", "pub async fn chat("] {
        assert!(!chat_source.contains(forbidden) && !budget_source.contains(forbidden), "{forbidden}");
    }
    assert!(!transport_source.contains("pub fn ureq_transport("));
    assert!(chat_source.contains("pub(crate) fn send(") && chat_source.contains("pub(crate) fn prepare("));
    assert!(transport_source.contains("pub(crate) fn ureq_transport("));
    let model_source = read("model")?;
    assert!(model_source.contains("pub(crate) transport: TransportFn") && model_source.contains("pub(crate) url: String"));
    assert!(!model_source.contains("pub transport") && !model_source.contains("pub url"));
    Ok(())
}


#[tokio::test]
async fn a_failed_settled_read_after_a_refusal_is_a_store_failure_without_an_alert() -> TestResult {
    let stored = model(Mode::SettledBroken);
    let used = capped("transport", FIVE_CALLS, TOKEN_CAP);
    seed(&stored, "acme", DAY_ONE, (FIVE, SEEDED_TOKENS), (0, 0))?;
    let refused = budgeted_call(&stored, "acme", &used, wall_one).await;
    assert!(matches!(refused, Err(AiError::Store(_))), "the transport was reached");
    assert_eq!(*lock(&stored.alert_statements)?, 0);
    Ok(())
}
