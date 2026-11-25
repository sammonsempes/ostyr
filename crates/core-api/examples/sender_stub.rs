use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::middleware::{from_fn, Next};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::logging::json_dispatch;
use core_api::model::{ApiConfig, Limits, Requirement, Rule};
use core_api::routes::build_router;
use core_api::server::serve;
use core_api::state::{build_state_from_files, replace_senders, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_WINDOW_SECONDS};
use core_api::types::{AccessTable, ServerHandle, SharedState};
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use std::fs;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;


const SENDER_BODY_CEILING: usize = 4_194_304;


const BODY_TIMEOUT_SECONDS: u64 = 10;


const MAX_CONNECTIONS: usize = 64;


const FLOOD_RATE: u32 = 100_000;


const LOG_TARGET: &str = "sender_stub";


async fn ingest(State(handled): State<Arc<AtomicU64>>, body: Bytes) -> String {
    let count = handled.fetch_add(1, Ordering::SeqCst).saturating_add(1);
    tracing::info!(target: LOG_TARGET, handler_calls = count, body_len = body.len(), "handler reached");
    format!("accepted {}", body.len())
}


async fn count_body(request: Request, next: Next) -> Response {
    let read = Arc::new(AtomicU64::new(0));
    let (parts, body) = request.into_parts();
    let seen = read.clone();
    let stream = body.into_data_stream().map(move |chunk| {
        if let Ok(bytes) = &chunk {
            seen.fetch_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX), Ordering::SeqCst);
        }
        chunk
    });
    let response = next.run(Request::from_parts(parts, Body::from_stream(stream))).await;
    let bytes_read = read.load(Ordering::SeqCst);
    let status = response.status().as_u16();
    tracing::info!(target: LOG_TARGET, status, bytes_read, "body counter");
    response
}


fn sender_table(path: &Path) -> Result<core_api::types::SenderTable, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| {
            line.split_once(' ')
                .map(|(name, digest)| (digest.to_owned(), name.to_owned()))
                .ok_or_else(|| "a senders line is `<name> <sha256 hex>`".into())
        })
        .collect()
}


fn config_in(directory: &Path, address: &str) -> Result<ApiConfig, Box<dyn std::error::Error>> {
    let key_file = directory.join("store.key");
    let compromised_list = directory.join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    Ok(ApiConfig {
        module: "sender-stub".to_owned(),
        tenant: "acme".to_owned(),
        address: address.parse()?,
        tls: None,
        accounts_store: directory.join("accounts.json"),
        audit_log: directory.join("audit.log"),
        key_file: key_file.display().to_string(),
        compromised_list,
        header_read_timeout: Duration::from_secs(BODY_TIMEOUT_SECONDS),
        limits: Limits {
            rate_max_requests: FLOOD_RATE,
            rate_window_seconds: RATE_WINDOW_SECONDS,
            max_sources: MAX_TRACKED_SOURCES,
            max_attempts: MAX_TRACKED_ATTEMPTS,
            body_read_timeout: Duration::from_secs(BODY_TIMEOUT_SECONDS),
            max_connections_per_source: MAX_CONNECTIONS,
        },
        log_level: DEFAULT_LOG_LEVEL,
        oidc: None,
    })
}


fn access() -> AccessTable {
    [(
        "POST /ingest".to_owned(),
        Rule {
            requirement: Requirement::Sender(SENDER_BODY_CEILING),
            sensitive: false,
        },
    )]
    .into_iter()
    .collect()
}


async fn serve_stub(directory: &str, address: &str, senders: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_in(Path::new(directory), address)?;
    update_store_file(&config.accounts_store, os_random, |_, _| Ok(()))?.saved?;
    let built = build_state_from_files(&config, access(), Vec::new())?;
    replace_senders(&built, sender_table(Path::new(senders))?);
    let state: SharedState = Arc::new(built);
    let handled = Arc::new(AtomicU64::new(0));
    let extra = Router::new().route("/ingest", post(ingest).with_state(handled));
    let router = build_router(state, extra).layer(from_fn(count_body));
    serve(&config, router, ServerHandle::new()).await?;
    Ok(())
}


async fn run(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match arguments {
        [directory, address, senders] => serve_stub(directory, address, senders).await,
        _ => Err("usage: sender_stub <directory> <listen address> <senders file>".into()),
    }
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    tracing::dispatcher::set_global_default(json_dispatch(tracing_subscriber::fmt::writer::BoxMakeWriter::new(stdout)))
        .map_err(std::io::Error::other)?;
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
