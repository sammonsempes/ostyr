use crate::types::{GetFn, ListFn};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};


/// What the REST routes read through: injected, so a test serves the routes from memory; `clock` gives Unix seconds, read once per request.
#[derive(Clone)]
pub struct CertBackend {
    pub list: ListFn,
    pub get: GetFn,
    pub clock: fn() -> i64,
}


/// `GET /certificates` query: every value is checked by hand so a bad one is a stable 400.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// Unix seconds: only certificates whose `not_after` is below it.
    pub expiring_before: Option<String>,
    /// Opaque cursor from `next_cursor`.
    pub cursor: Option<String>,
    /// Page size, 1 to 500, default 50.
    pub limit: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CertView {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub key_type: String,
    pub key_bits: Option<usize>,
    pub self_signed: bool,
    pub first_seen: String,
    pub last_seen: String,
    /// `expired`, `near` or `ok`.
    pub expiry: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CertListView {
    pub items: Vec<CertView>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SightingView {
    pub kind: String,
    pub reference: String,
    pub last_seen: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CertDetailView {
    #[serde(flatten)]
    pub cert: CertView,
    pub sightings: Vec<SightingView>,
    pub sightings_skipped: usize,
    pub sightings_truncated: bool,
}
