//! Type aliases.

use crate::error::StoreError;
use crate::model::{FindingsPage, UnmatchedReason};
use core_pg::scope::TenantScope;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type UnmatchedCounts = BTreeMap<UnmatchedReason, usize>;


pub type CursorSplit = for<'a> fn(&'a str) -> Result<Vec<&'a str>, StoreError>;


pub type ReadFuture = Pin<Box<dyn Future<Output = Result<FindingsPage, StoreError>> + Send>>;


pub type ListFn = Arc<dyn Fn(TenantScope, Option<Vec<String>>, usize) -> ReadFuture + Send + Sync>;


pub type AssetFn = Arc<dyn Fn(TenantScope, String) -> ReadFuture + Send + Sync>;


/// Resolves when the process is told to stop; production waits for `SIGTERM` or `SIGINT`.
pub type InterruptWait = Pin<Box<dyn Future<Output = ()> + Send>>;


/// The sleep between two rounds.
pub type WaitFn<'a> = dyn Fn(std::time::Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + 'a;


/// The wall clock in microseconds since the Unix epoch, one reading per round.
pub type NowFn<'a> = dyn Fn() -> u64 + 'a;


/// The one start read of the settings file; production passes `load_settings`.
pub type StartRead = fn(&std::path::Path) -> Result<crate::service::ServiceSettings, core_config::error::ConfigError>;
