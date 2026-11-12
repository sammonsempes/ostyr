use crate::error::CaseStoreError;
use crate::model::{Comment, ObservableKind};
use crate::stored::{CaseDetail, CasePage, LinkList, LinkPage, SummaryList};
use crate::transition::CaseAction;
use core_pg::scope::TenantScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


/// An observable compared across cases: its kind and its normalised value.
pub type ObservableKey = (ObservableKind, String);


pub type CaseFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, CaseStoreError>> + Send>>;


pub type SummaryListFn = Arc<dyn Fn(TenantScope, CasePage) -> CaseFuture<SummaryList> + Send + Sync>;


pub type DetailGetFn = Arc<dyn Fn(TenantScope, String) -> CaseFuture<Option<CaseDetail>> + Send + Sync>;


/// Unix seconds; a function pointer so production and tests share one instantiation.
pub type ClockFn = fn() -> i64;


/// Scope, case id, action, actor, now: applies the action and answers the case as read back.
pub type ActFn = Arc<dyn Fn(TenantScope, String, CaseAction, String, i64) -> CaseFuture<CaseDetail> + Send + Sync>;


/// Scope, case id, comment: appends the comment.
pub type CommentFn = Arc<dyn Fn(TenantScope, String, Comment) -> CaseFuture<()> + Send + Sync>;


/// Scope, case id, alert id, actor, now: links the alert; `true` when newly linked.
pub type LinkFn = Arc<dyn Fn(TenantScope, String, String, String, i64) -> CaseFuture<bool> + Send + Sync>;


/// Scope, case id, page: the alert ids linked to the case.
pub type LinksFn = Arc<dyn Fn(TenantScope, String, LinkPage) -> CaseFuture<LinkList> + Send + Sync>;
