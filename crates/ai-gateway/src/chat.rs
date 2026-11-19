use crate::error::AiError;
use crate::limits::STATUS_OK;
use crate::model::{Answer, Deps, HttpRequest};
use crate::request::{build_request, new_nonce, read_authorization};
use crate::response::{parse_answer, read_body};
use crate::settings::{endpoint_url, validate_ai, AiSettings};
use crate::transport::ureq_transport;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tracing::info;


static ORIGIN: OnceLock<Instant> = OnceLock::new();


/// Milliseconds on a monotonic clock, from the first call of the process.
pub fn monotonic_millis() -> u64 {
    ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}


pub fn os_random(buffer: &mut [u8]) -> Result<(), AiError> {
    getrandom::fill(buffer).map_err(AiError::from)
}


pub fn production_deps() -> Deps {
    Deps {
        transport: ureq_transport,
        random: os_random,
        clock: monotonic_millis,
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


/// Sends the instructions and the telemetry, waits at most `timeout_seconds`, and reads a bounded answer. One settings snapshot serves the whole call.
pub fn chat(settings: &AiSettings, instructions: &str, data: &Value, deps: &Deps) -> Result<Answer, AiError> {
    validate_ai(settings)?;
    let started = (deps.clock)();
    let nonce = new_nonce(deps.random)?;
    let body = build_request(settings, instructions, data, &nonce)?;
    let authorization = settings.api_key_file.as_deref().map(read_authorization).transpose()?;
    let request_bytes = body.len();
    let request = HttpRequest {
        url: endpoint_url(settings),
        authorization,
        body,
        timeout: Duration::from_secs(settings.timeout_seconds),
        ca_file: settings.ca_file.clone(),
    };
    let reply = (deps.transport)(&request)?;
    if reply.status == STATUS_OK {
        let bytes = read_body(reply, settings.max_response_bytes)?;
        let answer = parse_answer(&bytes)?;
        log_call(
            &settings.model,
            request_bytes,
            bytes.len(),
            &answer,
            (deps.clock)().saturating_sub(started),
        );
        Ok(answer)
    } else {
        Err(AiError::Status { status: reply.status })
    }
}
