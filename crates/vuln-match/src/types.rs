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


pub type ListFn = Arc<dyn Fn(TenantScope, Option<String>, usize) -> ReadFuture + Send + Sync>;


pub type AssetFn = Arc<dyn Fn(TenantScope, String) -> ReadFuture + Send + Sync>;
