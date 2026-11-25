use crate::error::ConnectorError;
use crate::model::{ConnectorCall, ConnectorResult};
use crate::params::Resolved;
use serde_json::Value;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;


pub type ParamMap = BTreeMap<String, Value>;


pub type ResolvedMap = BTreeMap<String, Resolved>;


pub type ConnectorFn = dyn Fn(&ConnectorCall) -> Result<ConnectorResult, ConnectorError> + Send + Sync;


pub type MonotonicFn = dyn Fn() -> Duration + Send + Sync;


pub type NowFn = fn() -> time::OffsetDateTime;


pub type WaitFn = fn(Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>;


pub type LiveFn<'a> = &'a (dyn Fn() -> crate::service::Live + Sync);


pub type InterruptWait = Pin<Box<dyn Future<Output = io::Result<()>>>>;


pub type MigrationRun = Pin<Box<dyn Future<Output = Result<Vec<String>, core_pg::error::PgError>>>>;


pub type MigrateFn = fn(std::sync::Arc<core_pg::settings::PgSettings>) -> MigrationRun;


pub type ControlFuture<'a> = Pin<Box<dyn Future<Output = Result<(), core_pg::error::PgError>> + Send + 'a>>;


/// Crosses one transaction boundary on the round's connection.
pub type ControlFn<'a> = &'a (dyn Fn(core_pg::transaction::Boundary) -> ControlFuture<'a> + Sync);
