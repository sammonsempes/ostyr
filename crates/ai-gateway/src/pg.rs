use crate::budget::{budgeted_chat, BudgetDeps, Gate, Param, Stores, STATEMENT_DEADLINE};
use crate::chat::{production_deps, wall_micros};
use crate::error::AiError;
use crate::model::Answer;
use crate::settings::AiSettings;
use crate::types::{BudgetFuture, BudgetRows};
use alerts::pg::pg_executor;
use core_pg::error::{reduce, PgError};
use core_pg::query::scoped_query;
use core_pg::scope::TenantScope;
use core_pg::types::SqlParameter;
use serde_json::Value;
use std::time::Duration;
use tokio_postgres::Client;


const CALLS_COLUMN: usize = 0;


const TOKENS_COLUMN: usize = 1;


/// `scoped_query` binds the tenant as `$1`; `params` start at `$2`; each row is `(calls, tokens)` as `bigint`.
pub async fn pg_budget_rows(
    client: &Client,
    deadline: Duration,
    scope: TenantScope,
    sql: &'static str,
    params: Vec<Param>,
) -> Result<BudgetRows, PgError> {
    let bound: Vec<SqlParameter<'_>> = params
        .iter()
        .map(|param| match param {
            Param::Text(text) => text as SqlParameter<'_>,
            Param::Int(number) => number as SqlParameter<'_>,
        })
        .collect();
    let rows = scoped_query(client, &scope, sql, &bound, deadline).await?;
    rows.iter()
        .map(|row| Ok((row.try_get(CALLS_COLUMN).map_err(reduce)?, row.try_get(TOKENS_COLUMN).map_err(reduce)?)))
        .collect()
}


/// The budget executor against a real connection.
pub fn pg_budget_executor<'a>(client: &'a Client, deadline: Duration) -> impl Fn(TenantScope, &'static str, Vec<Param>) -> BudgetFuture<'a> + 'a {
    move |scope, sql, params| -> BudgetFuture<'a> { Box::pin(pg_budget_rows(client, deadline, scope, sql, params)) }
}


/// The only public path to the production transport: the budget and alert statements run on `client`, the caller cannot replace them.
pub async fn pg_chat(
    client: &Client,
    gate: &Gate,
    scope: &TenantScope,
    settings: &AiSettings,
    instructions: &'static str,
    data: &Value,
) -> Result<Answer, AiError> {
    let budget = pg_budget_executor(client, STATEMENT_DEADLINE);
    let alerts = pg_executor(client, STATEMENT_DEADLINE);
    let stores = Stores {
        budget: &budget,
        alerts: &alerts,
        gate,
    };
    let deps = BudgetDeps {
        chat: production_deps(),
        wall_clock: wall_micros,
    };
    budgeted_chat(&stores, scope, settings, instructions, data, &deps).await
}
