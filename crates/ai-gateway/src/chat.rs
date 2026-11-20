use crate::error::AiError;
use crate::limits::STATUS_OK;
use crate::model::{Answer, Deps, HttpRequest};
use crate::request::{build_request, new_nonce, read_authorization};
use crate::response::{parse_answer, read_body};
use crate::settings::{endpoint_url, validate_ai, AiSettings};
use crate::transport::ureq_transport;
use crate::types::{ClockFn, RandomFn, TransportFn};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::info;


static ORIGIN: OnceLock<Instant> = OnceLock::new();


/// Milliseconds on a monotonic clock, from the first call of the process.
pub fn monotonic_millis() -> u64 {
    ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}


/// Wall clock in microseconds since the Unix epoch.
pub fn wall_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as u64)
}


pub fn os_random(buffer: &mut [u8]) -> Result<(), AiError> {
    getrandom::fill(buffer).map_err(AiError::from)
}


pub(crate) fn production_deps() -> Deps {
    Deps {
        transport: ureq_transport,
        keyed: true,
        random: os_random,
        clock: monotonic_millis,
    }
}


/// Deps with a caller-chosen transport; it gets a request without the key, and the production transport is not nameable outside the crate.
pub fn custom_deps(transport: TransportFn, random: RandomFn, clock: ClockFn) -> Deps {
    Deps {
        transport,
        keyed: false,
        random,
        clock,
    }
}


/// One line per call: counts and duration, never instructions, telemetry or content.
pub fn log_call(model: &str, request_bytes: usize, response_bytes: usize, answer: &Answer, duration_ms: u64) {
    let summary = format!(
        "model={model} request_bytes={request_bytes} response_bytes={response_bytes} prompt_tokens={:?} completion_tokens={:?} duration_ms={duration_ms}",
        answer.prompt_tokens, answer.completion_tokens
    );
    info!("ai call {summary}");
}


/// A validated request ready to send: nothing has left the process yet.
pub struct Prepared {
    pub request: HttpRequest,
    pub started: u64,
    pub model: String,
}


/// Validates, builds the tagged request and reads the key; no model I/O.
pub(crate) fn prepare(settings: &AiSettings, instructions: &str, data: &Value, deps: &Deps) -> Result<Prepared, AiError> {
    validate_ai(settings)?;
    let started = (deps.clock)();
    let nonce = new_nonce(deps.random)?;
    let body = build_request(settings, instructions, data, &nonce)?;
    let key_file = settings.api_key_file.as_deref().filter(|_path| deps.keyed);
    let authorization = key_file.map(read_authorization).transpose()?;
    let request = HttpRequest {
        url: endpoint_url(settings),
        authorization,
        body,
        timeout: Duration::from_secs(settings.timeout_seconds),
        ca_file: settings.ca_file.clone(),
    };
    Ok(Prepared {
        request,
        started,
        model: settings.model.clone(),
    })
}


/// Sends a prepared request, waits at most the request's timeout, and reads a bounded answer.
pub(crate) fn send(prepared: &Prepared, max_response_bytes: usize, deps: &Deps) -> Result<Answer, AiError> {
    let request_bytes = prepared.request.body.len();
    let reply = (deps.transport)(&prepared.request)?;
    if reply.status == STATUS_OK {
        let bytes = read_body(reply, max_response_bytes)?;
        let answer = parse_answer(&bytes)?;
        log_call(
            &prepared.model,
            request_bytes,
            bytes.len(),
            &answer,
            (deps.clock)().saturating_sub(prepared.started),
        );
        Ok(answer)
    } else {
        Err(AiError::Status { status: reply.status })
    }
}
