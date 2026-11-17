use crate::model::Weights;
use crate::source::Outcome;
use crate::types::{ComputeFn, NowFn, SlotMap};
use core_api::model::ApiError;
use core_config::reload::ReloadEngine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;
use utoipa::{IntoParams, ToSchema};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_tenants: usize,
    pub cache: Duration,
    pub deadline: Duration,
}


/// What the REST routes read through: injected, so a test serves the routes from memory and a paused clock.
#[derive(Clone)]
pub struct RiskState {
    pub compute: ComputeFn,
    pub weights: Arc<ReloadEngine<Weights>>,
    pub now: NowFn,
    pub slots: Arc<Mutex<SlotMap>>,
    pub uncached: Arc<AtomicU64>,
    pub bounds: Bounds,
}


/// The computed scores of one tenant and the clock reading they were computed at.
#[derive(Debug, PartialEq, Eq)]
pub struct Computed {
    pub computed_at: i64,
    pub outcome: Outcome,
}


/// A result tagged with the weights snapshot it used: after a swap the tag no longer matches and the entry is never served.
pub struct Cached {
    pub weights: Arc<Weights>,
    pub at: Instant,
    pub computed: Arc<Computed>,
}


#[derive(Debug, Error, PartialEq, Eq)]
#[error("risk scores are unavailable")]
pub struct Unavailable;


#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    Api(ApiError),
    Unavailable,
}


impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Failure::Api(error)
    }
}


impl From<Unavailable> for Failure {
    fn from(_unavailable: Unavailable) -> Self {
        Failure::Unavailable
    }
}


/// `GET /risk/entities` query: both values are checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Number of entities, 1 to 500, default 50.
    pub limit: Option<String>,
    /// `host` or `user`.
    pub kind: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct EntityView {
    pub kind: String,
    pub id: String,
    pub value: u8,
    pub contributions_used: usize,
    pub contributions_dropped: usize,
}


/// The bound that stopped the read: `limit` is `alerts`, `contributions` or `entities`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct TruncatedView {
    pub limit: String,
    pub read: usize,
    pub cap: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RiskListView {
    pub computed_at: i64,
    pub alerts_read: usize,
    pub informational: usize,
    pub refused: BTreeMap<String, usize>,
    pub truncated: Option<TruncatedView>,
    pub entities: Vec<EntityView>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct RiskEntityView {
    pub computed_at: i64,
    pub truncated: Option<TruncatedView>,
    pub entity: EntityView,
}
