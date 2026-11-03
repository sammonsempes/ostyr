use crate::error::ClientError;
use crate::model::{HttpMethod, HttpReply, HttpRequest};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use ureq::http::{Method, Request};
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;


pub const BEARER_PREFIX: &str = "Bearer ";


pub const JSON_TYPE: &str = "application/json";


pub fn load_roots(path: &Path) -> Result<RootCerts, ClientError> {
    let pem = fs::read(path).map_err(|source| ClientError::CaFile {
        path: path.to_path_buf(),
        source,
    })?;
    let certificate = Certificate::from_pem(&pem)?;
    Ok(RootCerts::Specific(Arc::new(vec![certificate])))
}


/// Builds an HTTPS-only agent that trusts the CA file when given, the bundled web roots otherwise.
pub fn build_agent(ca_file: Option<&Path>) -> Result<Agent, ClientError> {
    let roots = ca_file.map(load_roots).transpose()?.unwrap_or(RootCerts::WebPki);
    let config = Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .tls_config(TlsConfig::builder().root_certs(roots).build())
        .build();
    Ok(Agent::new_with_config(config))
}


pub fn method_of(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
    }
}


/// Sends one request and returns the status and body, whatever the status.
pub fn send_request(ca_file: Option<&Path>, request: &HttpRequest) -> Result<HttpReply, ClientError> {
    let agent = build_agent(ca_file)?;
    let builder = Request::builder()
        .method(method_of(request.method))
        .uri(&request.url)
        .header("Content-Type", JSON_TYPE);
    let authorized = request.token.iter().fold(builder, |current, token| {
        current.header("Authorization", format!("{BEARER_PREFIX}{token}"))
    });
    let mut response = agent.run(authorized.body(request.body.clone())?)?;
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string()?;
    Ok(HttpReply { status, body })
}
