use crate::error::InventoryStoreError;
use crate::model::{CertDetail, CertPage, ListRequest};
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type ApiFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, InventoryStoreError>> + Send>>;


pub type ListFn = Arc<dyn Fn(TenantScope, ListRequest) -> ApiFuture<CertPage> + Send + Sync>;


pub type GetFn = Arc<dyn Fn(TenantScope, String) -> ApiFuture<Option<CertDetail>> + Send + Sync>;


pub type InterruptWait = Pin<Box<dyn Future<Output = std::io::Result<()>>>>;


pub type InterruptFn = fn() -> std::io::Result<InterruptWait>;


pub type WaitFn = fn(std::time::Duration) -> Pin<Box<dyn Future<Output = ()>>>;


pub type ServiceFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + 'a>>;


/// The SIGHUP stream armed before any file is read; the reload thread takes it over once the engine exists.
#[cfg(unix)]
pub type ReloadSignals = signal_hook::iterator::Signals;


#[cfg(not(unix))]
pub struct ReloadSignals;


/// Stops the settings file watch and joins its thread.
pub type StopWatchFn = Box<dyn FnOnce()>;
