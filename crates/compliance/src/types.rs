use crate::error::ReadError;
use crate::read_model::{AssetResults, ListRequest, StatePage, StoredState};
use core_pg::scope::TenantScope;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type Row = BTreeMap<String, String>;


pub type QueryResult<'a> = Result<&'a [Row], &'a str>;


pub type StateKey = (String, String, String);


pub type RunEntry<'a> = (&'a str, &'a str, &'a str, &'a crate::model::Verdict);


pub type PlannedEntry = (StateKey, &'static str);


pub type Served = (Vec<StoredState>, usize, Option<StateKey>);


pub type ReadFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, ReadError>> + Send>>;


pub type ListFn = Arc<dyn Fn(TenantScope, ListRequest) -> ReadFuture<StatePage> + Send + Sync>;


pub type AssetFn = Arc<dyn Fn(TenantScope, String) -> ReadFuture<Option<AssetResults>> + Send + Sync>;
