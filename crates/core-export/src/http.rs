use crate::error::{ExportError, PermanentRejection};
use crate::otlp::{rejected_records, MAX_RESPONSE_BYTES};
use crate::types::BoxError;
use std::time::Duration;
use ureq::config::Config;
use ureq::http::Response;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;
use ureq::Body;


pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);


pub const NO_REDIRECTS: u32 = 0;


pub const CONTENT_TYPE: &str = "application/json";


/// With a CA bundle only that CA is trusted (private CA); without one the Mozilla roots are. No redirect is ever followed, so a bearer token cannot be sent to another host.
pub fn build_agent(ca_pem: Option<&[u8]>) -> Result<Agent, ExportError> {
    let roots = match ca_pem {
        Some(pem) => RootCerts::new_with_certs(&[Certificate::from_pem(pem).map_err(ExportError::Certificate)?]),
        None => RootCerts::WebPki,
    };
    let tls = TlsConfig::builder().root_certs(roots).build();
    let config = Config::builder()
        .tls_config(tls)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .max_redirects(NO_REDIRECTS)
        .proxy(None)
        .build();
    Ok(Agent::new_with_config(config))
}


/// Any status of 400 and above is an error (ureq default), so a rejecting receiver triggers the retry.
pub fn send_json(agent: &Agent, url: &str, token: Option<&str>, body: &str) -> Result<Response<Body>, BoxError> {
    let request = agent.post(url).content_type(CONTENT_TYPE);
    let outcome = match token {
        Some(value) => request.header("Authorization", format!("Bearer {value}")).send(body),
        None => request.send(body),
    };
    outcome.map_err(BoxError::from)
}


/// Only a 2xx answer counts as delivered; a redirect is a failure whose `Location` is never read or logged.
pub fn post_json(agent: &Agent, url: &str, token: Option<&str>, body: &str) -> Result<(), BoxError> {
    let response = send_json(agent, url, token, body)?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(BoxError::from(REDIRECT_REFUSED))
    }
}


pub const REDIRECT_REFUSED: &str = "the webhook receiver did not answer 2xx (redirects are never followed)";


/// Only a 2xx answer counts as delivered (a redirect or a 1xx is an error). An accepted request is never retried because of its response: an unreadable or oversized body is logged, `rejectedLogRecords` is logged.
pub fn post_otlp(agent: &Agent, url: &str, token: Option<&str>, body: &str) -> Result<(), BoxError> {
    let mut response = send_json(agent, url, token, body).map_err(classify_status)?;
    if !response.status().is_success() {
        Err(BoxError::from(format!("OTLP receiver answered status {}", response.status())))?;
    }
    let text = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_string()
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "OTLP response body unreadable or over the limit");
            String::new()
        });
    let rejected = rejected_records(&text);
    if rejected > 0 {
        tracing::warn!(rejected, "OTLP receiver rejected log records");
    }
    Ok(())
}


pub const STATUS_CLIENT_ERROR_FIRST: u16 = 400;


pub const STATUS_REQUEST_TIMEOUT: u16 = 408;


pub const STATUS_TOO_MANY_REQUESTS: u16 = 429;


pub const STATUS_CLIENT_ERROR_LAST: u16 = 499;


/// A 4xx answer other than 408 and 429 is a permanent failure (OTLP/HTTP "Failures"); everything else keeps its error.
pub fn classify_status(error: BoxError) -> BoxError {
    let permanent = match error.downcast_ref::<ureq::Error>() {
        Some(ureq::Error::StatusCode(status)) if is_permanent(*status) => Some(*status),
        _ => None,
    };
    permanent.map_or(error, |status| BoxError::from(PermanentRejection { status }))
}


pub fn is_permanent(status: u16) -> bool {
    (STATUS_CLIENT_ERROR_FIRST..=STATUS_CLIENT_ERROR_LAST).contains(&status) && status != STATUS_REQUEST_TIMEOUT && status != STATUS_TOO_MANY_REQUESTS
}
