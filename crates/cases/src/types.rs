use crate::error::CaseStoreError;
use crate::model::ObservableKind;
use crate::stored::{CaseDetail, CasePage, SummaryList};
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


/// An observable compared across cases: its kind and its normalised value.
pub type ObservableKey = (ObservableKind, String);


pub type CaseFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, CaseStoreError>> + Send>>;


pub type SummaryListFn = Arc<dyn Fn(TenantScope, CasePage) -> CaseFuture<SummaryList> + Send + Sync>;


pub type DetailGetFn = Arc<dyn Fn(TenantScope, String) -> CaseFuture<Option<CaseDetail>> + Send + Sync>;
