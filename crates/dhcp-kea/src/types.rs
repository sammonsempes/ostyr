use crate::error::HistoryError;
use crate::history::LookupResult;
use crate::row::Converted;
use core_pg::scope::TenantScope;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;


pub type MalformedCounts = BTreeMap<String, u64>;


pub type LeaseKey = (i64, i64, String, String, u32);


pub type SeenLeases = BTreeSet<LeaseKey>;


pub type FileIdentity = (u64, u64);


pub type PauseFn = fn(Duration);


pub type Label = (String, String);


pub type LookupFuture = Pin<Box<dyn Future<Output = Result<LookupResult, HistoryError>> + Send>>;


pub type AtLookupFn = Arc<dyn Fn(TenantScope, String, i64) -> LookupFuture + Send + Sync>;


pub type MacLookupFn = Arc<dyn Fn(TenantScope, String, i64, i64) -> LookupFuture + Send + Sync>;


pub type InterruptWait = Pin<Box<dyn Future<Output = std::io::Result<()>>>>;


pub type WaitFn = fn(Duration) -> Pin<Box<dyn Future<Output = ()>>>;


pub type LeaseRef<'a> = (&'a str, &'a Converted);
