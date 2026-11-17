use crate::api_model::Cached;
use crate::error::RiskError;
use crate::model::Weights;
use crate::source::Outcome;
use core_pg::scope::TenantScope;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type ComputeFuture = Pin<Box<dyn Future<Output = Result<Outcome, RiskError>> + Send>>;


/// One whole computation for a tenant: the scope, the weights snapshot it keeps to the end, and `now` in Unix seconds.
pub type ComputeFn = Arc<dyn Fn(TenantScope, Arc<Weights>, i64) -> ComputeFuture + Send + Sync>;


pub type NowFn = Arc<dyn Fn() -> i64 + Send + Sync>;


pub type Slot = Arc<tokio::sync::Mutex<Option<Cached>>>;


pub type SlotMap = BTreeMap<String, Slot>;
