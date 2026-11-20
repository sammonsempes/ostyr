use crate::types::{ClockFn, CreateFn, ResolveFn, UpdateFn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use utoipa::ToSchema;


/// The tenant the page belongs to and the services it declares; a caller of another tenant sees none, so any service is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageServices {
    pub tenant: String,
    pub services: BTreeSet<String>,
}


/// What the write routes go through: injected, so a test serves them from memory and production from PostgreSQL.
#[derive(Clone)]
pub struct StatusBackend {
    pub create: CreateFn,
    pub update: UpdateFn,
    pub resolve: ResolveFn,
    pub clock: ClockFn,
    pub page: Arc<PageServices>,
}


/// `POST /status/incidents` body; the tenant and the actor come from the session, never from here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    /// A service the page declares.
    pub service: String,
    /// Public when `published`: at most 200 characters.
    pub title: String,
    pub published: bool,
    /// Epoch seconds, not more than 300 seconds ahead of the server clock.
    pub started_at: i64,
    /// Internal, never on the public page: at most 2000 characters.
    #[serde(default)]
    pub internal_note: String,
}


/// `POST /status/incidents/{id}/updates` body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    /// The version the caller read, from the last reply.
    pub version: i64,
    pub at: i64,
    /// Public when the incident is: at most 500 characters.
    pub message: String,
    #[serde(default)]
    pub internal_note: String,
}


/// `POST /status/incidents/{id}/resolve` body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub version: i64,
    pub at: i64,
}


/// The incident id and the version the next write must present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct IncidentView {
    pub id: i64,
    pub version: i64,
}
