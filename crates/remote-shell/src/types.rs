use crate::error::StoreError;
use crate::store_model::{ListFilter, Page, SessionRow};
use agent_command::model::KeyClass;
use core_auth::types::RoleSet;
use core_pg::scope::TenantScope;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;


pub type Seconds = i64;


pub type ApproverRoles = BTreeMap<String, RoleSet>;


pub const HASH_LEN: usize = 32;


pub type ChainHash = [u8; HASH_LEN];


pub type Row = Vec<crate::store_model::Cell>;


pub type PageFuture = Pin<Box<dyn Future<Output = Result<Page, StoreError>> + Send>>;


pub type GetFuture = Pin<Box<dyn Future<Output = Result<Option<SessionRow>, StoreError>> + Send>>;


pub type ListFn = Arc<dyn Fn(TenantScope, ListFilter, Option<String>, u32) -> PageFuture + Send + Sync>;


pub type GetFn = Arc<dyn Fn(TenantScope, String) -> GetFuture + Send + Sync>;


pub type BoxedCause = Box<dyn std::error::Error + Send + Sync>;


/// The durable per-agent sequence allocator the sensitive key shares with patch-rollout: `(agent id, class)` to the next number.
pub type SequenceFn<'counter> = dyn FnMut(&str, KeyClass) -> Result<u64, BoxedCause> + 'counter;
