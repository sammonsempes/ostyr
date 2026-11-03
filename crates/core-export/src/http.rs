use crate::error::ExportError;
use crate::types::BoxError;
use std::time::Duration;
use ureq::config::Config;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;


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
pub fn post_json(agent: &Agent, url: &str, token: Option<&str>, body: &str) -> Result<(), BoxError> {
    let request = agent.post(url).content_type(CONTENT_TYPE);
    let outcome = match token {
        Some(value) => request.header("Authorization", format!("Bearer {value}")).send(body),
        None => request.send(body),
    };
    outcome.map(|_response| ()).map_err(BoxError::from)
}
