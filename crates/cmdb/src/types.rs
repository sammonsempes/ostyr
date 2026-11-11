use crate::error::StoreError;
use crate::model::{Attribute, IdentityKey};
use crate::stored::{AssetDetail, AssetPage, SummaryList};
use core_pg::error::PgError;
use core_pg::scope::TenantScope;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type KeyMap = BTreeMap<IdentityKey, String>;


pub type AttributeMap = BTreeMap<String, Attribute>;


pub type ObservedMap = BTreeMap<String, String>;


pub type TruthMap = BTreeMap<String, String>;


pub type RowMap = BTreeMap<String, String>;


pub type ColumnMap = BTreeMap<String, String>;


pub type KeyColumnMap = BTreeMap<IdentityKey, String>;


pub type IdSet = BTreeSet<String>;


pub type RawRow = (u64, Result<RowMap, String>);


pub type Row = Vec<String>;


pub type VersionMap = BTreeMap<String, i64>;


pub type RowFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Row>, PgError>> + Send + 'a>>;


/// Runs one statement for a tenant: the tenant is bound as `$1`, the parameters start at `$2`, every column comes back as text.
pub type Executor<'a, 'b> = &'a (dyn Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'b> + Sync);


pub type ApiFuture<Output> = Pin<Box<dyn Future<Output = Result<Output, StoreError>> + Send>>;


pub type SummaryListFn = Arc<dyn Fn(TenantScope, AssetPage) -> ApiFuture<SummaryList> + Send + Sync>;


pub type DetailGetFn = Arc<dyn Fn(TenantScope, String) -> ApiFuture<Option<AssetDetail>> + Send + Sync>;
