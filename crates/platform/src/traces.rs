use crate::error::PlatformError;
use crate::merge::ACTOR;
use crate::model::Module;
use alerts::settings::module_audit;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::header::{CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use core_api::config::{SETTING_TLS_CERTIFICATE, SETTING_TLS_KEY};
use core_api::model::{AdmittedSender, ApiIdentity, Requirement, Rule};
use core_api::routes::route_key;
use core_api::state::replace_senders;
use core_api::types::{AccessTable, SharedListener, SharedState, StartupReloadFn};
use core_config::error::ConfigError;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, ReloadOutcome, Subscriber};
use core_config::types::SettingsMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::task::JoinError;
use traces_ingest::receive::{fixed, receive_export, Reply, STATUS_INTERNAL};
use traces_ingest::reload::{sampling_loader, sampling_state, settings_loader, settings_state};
use traces_ingest::sampling::Sampling;
use traces_ingest::senders::{senders_loader, senders_state};
use traces_ingest::settings::{ceiling_limits, TracesSettings};
use traces_ingest::types::SenderTable;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa::OpenApi;


pub const SETTING_TRACES_SETTINGS: &str = "traces.settings_file";


pub const SETTING_TRACES_SAMPLING: &str = "traces.sampling_file";


pub const SETTING_SENDERS_FILE: &str = "otlp.senders_file";


pub const TRACES_PATH: &str = "/v1/traces";


pub const STARTUP_REQUEST: &str = "startup";


pub const SENDERS_SECTION: &str = "senders";


pub const RETRY_AFTER_SECONDS: &str = "1";


/// The three files of the module: the ClickHouse settings, the sampling and the senders (shared by every OTLP route).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracesFiles {
    pub settings: PathBuf,
    pub sampling: PathBuf,
    pub senders: PathBuf,
}


/// One live snapshot per engine: a request reads each once.
#[derive(Clone)]
pub struct TracesRuntime {
    pub settings: Arc<ReloadEngine<TracesSettings>>,
    pub sampling: Arc<ReloadEngine<Sampling>>,
    pub senders: Arc<ReloadEngine<SenderTable>>,
}


/// Hands a new sender table to core-api, which admits tokens from it; the table is replaced whole.
pub fn push_senders(listener: &SharedListener, table: &SenderTable) {
    match listener.state.get() {
        Some(state) => replace_senders(state, table.clone()),
        None => tracing::error!("core-api has no state yet: the sender table was not handed over"),
    }
}


/// Runs once at start, after core-api built its state and before it listens: hands over the first table.
pub fn senders_startup(listener: SharedListener, engine: Arc<ReloadEngine<SenderTable>>) -> StartupReloadFn {
    Box::new(move || {
        push_senders(&listener, &current_config(&engine));
        ReloadOutcome::Unchanged
    })
}


pub fn context_of(tenant: &str, module: &str, file: &Path) -> ReloadContext {
    ReloadContext {
        actor_id: ACTOR.to_owned(),
        tenant: tenant.to_owned(),
        module: module.to_owned(),
        target: file.display().to_string(),
        request_id: STARTUP_REQUEST.to_owned(),
    }
}


/// Reads the three files once (a bad first file is an error: the module never starts open); later reloads are audited in the module audit log.
pub fn open_traces(files: &TracesFiles, tenant: &str, module: &str, listener: &SharedListener) -> Result<TracesRuntime, ConfigError> {
    let hand_over = listener.clone();
    let senders_subscriber = Subscriber {
        section: SENDERS_SECTION.to_owned(),
        validate: Box::new(|_| Ok(())),
        apply: Box::new(move |table: &SenderTable| push_senders(&hand_over, table)),
    };
    Ok(TracesRuntime {
        settings: Arc::new(open_engine(
            settings_loader(files.settings.clone()),
            settings_state,
            Vec::new(),
            module_audit(listener.clone()),
            context_of(tenant, module, &files.settings),
        )?),
        sampling: Arc::new(open_engine(
            sampling_loader(files.sampling.clone()),
            sampling_state,
            Vec::new(),
            module_audit(listener.clone()),
            context_of(tenant, module, &files.sampling),
        )?),
        senders: Arc::new(open_engine(
            senders_loader(files.senders.clone()),
            senders_state,
            vec![senders_subscriber],
            module_audit(listener.clone()),
            context_of(tenant, module, &files.senders),
        )?),
    })
}


#[derive(OpenApi)]
#[openapi(paths(export_endpoint))]
pub struct TracesDoc;


/// The files of the module file, required (and read) only when `traces` is selected.
pub fn traces_files_of(settings: &SettingsMap, modules: &[Module]) -> Result<Option<TracesFiles>, PlatformError> {
    if modules.contains(&Module::Traces) {
        let file_of = |key: &str, missing: PlatformError| settings.get(key).map(PathBuf::from).ok_or(missing);
        Ok(Some(TracesFiles {
            settings: file_of(SETTING_TRACES_SETTINGS, PlatformError::MissingTracesSettings)?,
            sampling: file_of(SETTING_TRACES_SAMPLING, PlatformError::MissingTracesSampling)?,
            senders: file_of(SETTING_SENDERS_FILE, PlatformError::MissingSendersFile)?,
        }))
    } else {
        Ok(None)
    }
}


/// Bearer tokens never travel in clear: with `traces` selected both TLS settings are required, loopback included.
pub fn require_tls(settings: &SettingsMap, modules: &[Module]) -> Result<(), PlatformError> {
    let has_tls = settings.contains_key(SETTING_TLS_CERTIFICATE) && settings.contains_key(SETTING_TLS_KEY);
    if modules.contains(&Module::Traces) && !has_tls {
        Err(PlatformError::TlsRequired)
    } else {
        Ok(())
    }
}


/// The sender ceiling is the largest `max_request_bytes` the settings admit; the settings value is checked again on the snapshot (413).
pub fn traces_access() -> AccessTable {
    [(
        route_key("POST", TRACES_PATH),
        Rule {
            requirement: Requirement::Sender(ceiling_limits().max_request_bytes),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


pub fn traces_document() -> OpenApiDocument {
    TracesDoc::openapi()
}


pub fn traces_router(runtime: TracesRuntime) -> Router<SharedState> {
    Router::new().route(TRACES_PATH, post(export_endpoint).with_state(runtime))
}


/// Whether a sender of this name is in the current table.
pub fn sender_listed(table: &SenderTable, name: &str) -> bool {
    table.values().any(|listed| listed == name)
}


pub fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
}


/// One settings snapshot and one sampling snapshot for the whole request; the sender is re-checked in the current table before every batch.
pub fn process(runtime: &TracesRuntime, tenant: &str, sender: &str, body: &[u8], now: u64) -> Reply {
    let settings = current_config(&runtime.settings);
    let sampling = current_config(&runtime.sampling);
    let started = Instant::now();
    let admitted = || sender_listed(&current_config(&runtime.senders), sender);
    receive_export(&settings, &sampling, body, tenant, &admitted, now, &|| started.elapsed())
}


pub fn response_of(reply: Reply) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(reply.content_type));
    if reply.retry_after {
        headers.insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
    }
    (
        StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        headers,
        reply.body,
    )
        .into_response()
}


/// A task that ended without a reply (panic or cancellation) is a fixed 500, logged without detail.
pub fn joined(result: Result<Reply, JoinError>) -> Response {
    match result {
        Ok(reply) => response_of(reply),
        Err(error) => {
            tracing::error!(%error, "the export task failed");
            response_of(fixed(STATUS_INTERNAL, "the export failed", false))
        }
    }
}


#[utoipa::path(
    post,
    path = "/v1/traces",
    request_body(content = Vec<u8>, content_type = "application/x-protobuf"),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "ExportTraceServiceResponse, with a partial success count when spans were not stored"),
        (status = 400, description = "Malformed or refused request"),
        (status = 401, description = "Unknown token or a sender removed meanwhile"),
        (status = 413, description = "Body over the limit"),
        (status = 415, description = "Not application/x-protobuf, or a content encoding"),
        (status = 429, description = "Sender or global decode slots full, Retry-After given"),
        (status = 503, description = "The span store is unavailable, Retry-After given")
    )
)]
pub async fn export_endpoint(
    State(runtime): State<TracesRuntime>,
    Extension(identity): Extension<Arc<ApiIdentity>>,
    Extension(admitted): Extension<AdmittedSender>,
    body: Bytes,
) -> Response {
    let task = tokio::task::spawn_blocking(move || {
        let held = admitted;
        process(&runtime, &identity.tenant, &held.name, &body, now_nanos())
    });
    joined(task.await)
}
