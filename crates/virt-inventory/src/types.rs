use crate::cmdb_sync::SyncReport;
use crate::error::RoundError;
use crate::model::Context;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;


pub type InterruptWait = Pin<Box<dyn Future<Output = std::io::Result<()>>>>;


pub type RoundFuture<'a> = Pin<Box<dyn Future<Output = Result<SyncReport, RoundError>> + 'a>>;


pub type RoundFn = for<'a> fn(&'a Context) -> RoundFuture<'a>;


pub type WaitFuture = Pin<Box<dyn Future<Output = ()>>>;


pub type WaitFn = fn(Duration) -> WaitFuture;
