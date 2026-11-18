use crate::fetch_error::{FetchError, Refusal};
use crate::model::Limits;
use crate::types::{ExecFn, HttpFn, LoadFn};
use rusty_s3::{Bucket, Credentials};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;


pub const DEFAULT_MAX_OBJECTS: usize = 100;


pub const DEFAULT_FETCH_TIMEOUT_MS: u64 = 60_000;


pub fn default_max_objects() -> usize {
    DEFAULT_MAX_OBJECTS
}


pub fn default_fetch_timeout_ms() -> u64 {
    DEFAULT_FETCH_TIMEOUT_MS
}


/// One bucket prefix of one tenant: `credentials` is relative to the secrets directory and starts with the tenant name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchSource {
    pub id: String,
    pub tenant: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub credentials: String,
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_max_objects")]
    pub max_objects_per_run: usize,
    #[serde(default = "default_fetch_timeout_ms")]
    pub timeout_ms: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchSettings {
    pub secrets_dir: PathBuf,
    pub sources: Vec<FetchSource>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub max_response: u64,
    pub ca_file: Option<PathBuf>,
    pub timeout: Duration,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedObject {
    pub key: String,
    pub etag: String,
    pub size: u64,
}


/// One listing page: the objects whose key passed the filters, the count of the others and the next token.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Page {
    pub objects: Vec<ListedObject>,
    pub skipped: usize,
    pub last_key: Option<String>,
    pub next_token: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    pub objects: Vec<ListedObject>,
    pub last_key: Option<String>,
    pub skipped_key: usize,
    pub incomplete: bool,
}


/// The part of the key space one listing covered: after `after`, up to `until`, or to the end when `complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeenWindow<'a> {
    pub after: Option<&'a str>,
    pub until: Option<&'a str>,
    pub complete: bool,
}


/// The ledger's answer: the keys still to serve in order, and the count of versions it could not record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeenOrder {
    pub keys: Vec<String>,
    pub unrecorded: usize,
}


/// The page walk in progress; `done` is set by the first page without a continuation token.
#[derive(Debug, Default)]
pub struct Walk {
    pub token: Option<String>,
    pub last_key: Option<String>,
    pub done: bool,
    pub objects: Vec<ListedObject>,
    pub skipped: usize,
}


/// The XML fields of one `Contents` element before the key filter.
#[derive(Debug, Default)]
pub struct Pending {
    pub key: Option<String>,
    pub etag: Option<String>,
    pub size: Option<u64>,
}


/// The XML walk state of one listing page.
#[derive(Debug, Default)]
pub struct Reading {
    pub path: Vec<String>,
    pub text: String,
    pub pending: Pending,
    pub contents: Vec<Pending>,
    pub seen_root: bool,
    pub truncated: bool,
    pub url_encoded: bool,
    pub token: Option<String>,
}


/// Totals over every source of the round; a refused object is named by a digest of its key, a failed source by its id.
#[derive(Debug, Default)]
pub struct FetchReport {
    pub listed: usize,
    pub skipped_key: usize,
    pub already_loaded: usize,
    pub already_refused: usize,
    pub loaded: usize,
    pub deferred: usize,
    pub incomplete_listings: usize,
    pub in_backoff: usize,
    pub permanent_refused: usize,
    pub transient_refused: usize,
    pub seen_full: usize,
    pub refused: Vec<(String, Refusal)>,
    pub failed_sources: Vec<(String, FetchError)>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectOutcome {
    Loaded,
    AlreadyLoaded,
    AlreadyRefused,
    InBackoff,
    Refused(Refusal),
}


/// How the ledger remembers a refusal: a permanent one is never retried for that ETag, a transient one is retried after a backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remembered {
    Permanent(&'static str),
    Transient(&'static str),
}


/// What every object of one source needs: the world, the source, its bucket and its credentials.
pub struct SourceRun<'a> {
    pub env: &'a FetchEnv<'a>,
    pub source: &'a FetchSource,
    pub bucket: Bucket,
    pub credentials: Credentials,
}


/// The injected world of a round: the HTTP step, the ledger executor, the ClickHouse load and the export limits.
pub struct FetchEnv<'a> {
    pub http: &'a HttpFn<'a>,
    pub exec: &'a ExecFn<'a>,
    pub load: &'a LoadFn<'a>,
    pub limits: &'a Limits,
}
