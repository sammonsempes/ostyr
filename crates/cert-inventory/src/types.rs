use crate::error::InventoryStoreError;
use crate::model::{CertDetail, CertPage, ListRequest};
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type ApiFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, InventoryStoreError>> + Send>>;


pub type ListFn = Arc<dyn Fn(TenantScope, ListRequest) -> ApiFuture<CertPage> + Send + Sync>;


pub type GetFn = Arc<dyn Fn(TenantScope, String) -> ApiFuture<Option<CertDetail>> + Send + Sync>;
