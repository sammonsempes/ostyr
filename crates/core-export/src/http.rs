use crate::error::ExportError;
use crate::otlp::{rejected_records, MAX_RESPONSE_BYTES};
use crate::types::BoxError;
use std::time::Duration;
use ureq::config::Config;
use ureq::http::Response;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;
use ureq::Body;


pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);


pub const CONTENT_TYPE: &str = "application/json";


/// With a CA bundle only that CA is trusted (private CA); without one the Mozilla roots are.
pub fn build_agent(ca_pem: Option<&[u8]>) -> Result<Agent, ExportError> {
    let roots = match ca_pem {
        Some(pem) => RootCerts::new_with_certs(&[Certificate::from_pem(pem).map_err(ExportError::Certificate)?]),
        None => RootCerts::WebPki,
    };
    let tls = TlsConfig::builder().root_certs(roots).build();
    let config = Config::builder().tls_config(tls).timeout_global(Some(REQUEST_TIMEOUT)).build();
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


pub fn post_json(agent: &Agent, url: &str, token: Option<&str>, body: &str) -> Result<(), BoxError> {
    send_json(agent, url, token, body).map(|_response| ())
}


/// An accepted request is never retried because of its response: an unreadable or oversized body is logged, `rejectedLogRecords` is logged.
pub fn post_otlp(agent: &Agent, url: &str, token: Option<&str>, body: &str) -> Result<(), BoxError> {
    let mut response = send_json(agent, url, token, body)?;
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
