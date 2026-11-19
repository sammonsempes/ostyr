use crate::budget::Param;
use crate::error::AiError;
use crate::model::{HttpReply, HttpRequest};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;


pub type TransportFn = fn(&HttpRequest) -> Result<HttpReply, AiError>;


pub type RandomFn = fn(&mut [u8]) -> Result<(), AiError>;


pub type ClockFn = fn() -> u64;


/// Wall clock in microseconds since the Unix epoch; picks the UTC day of the budget.
pub type WallClockFn = fn() -> u64;


/// Rows of `(calls, tokens)` as the store answered them.
pub type BudgetRows = Vec<(i64, i64)>;


pub type BudgetFuture<'a> = Pin<Box<dyn Future<Output = Result<BudgetRows, PgError>> + Send + 'a>>;


/// Runs one budget statement for a tenant: the tenant is `$1`, the parameters start at `$2`.
pub type BudgetExecutor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<Param>) -> BudgetFuture<'b> + Sync + 'a);
