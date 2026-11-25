use crate::model::GroupLimits;
use alerts::error::StoreError;
use alerts::model::{Alert, Backend, Cursor};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;
use utoipa::ToSchema;


/// What the route reads and how long it may take: the pages, the limits of the grouping and the overall deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPlan {
    pub limits: GroupLimits,
    pub max_pages: usize,
    pub deadline: Duration,
}


/// The injected store and the route-level semaphore that bounds the group reads in flight.
#[derive(Clone)]
pub struct GroupRoute {
    pub backend: Backend,
    pub reads: Arc<Semaphore>,
}


/// The alerts read so far and the cursor of the page still unread, if any.
#[derive(Debug, Default)]
pub struct Read {
    pub alerts: Vec<Alert>,
    pub next: Option<Cursor>,
    pub done: bool,
}


#[derive(Debug, Error)]
pub enum ReadStop {
    #[error("the read deadline passed")]
    Late,
    #[error(transparent)]
    Store(#[from] StoreError),
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct GroupView {
    pub rule_id: String,
    pub host_name: Option<String>,
    pub user_name: Option<String>,
    pub representative: String,
    pub alert_ids: Vec<String>,
    pub omitted: bool,
    pub alert_count: u64,
    pub duplicates: u64,
    pub first_time: String,
    pub last_time: String,
    pub max_severity: String,
    /// Older unread alerts could belong to this group, so its count, first time and severity may be understated.
    pub cut_at_older: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct GroupListView {
    pub groups: Vec<GroupView>,
    /// False when older alerts of the tenant remain unread.
    pub complete: bool,
    pub alerts_read: usize,
    pub oldest_read: Option<String>,
}
