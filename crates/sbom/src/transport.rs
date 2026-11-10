//! The `ureq` transport: TLS only, a CA from the settings, no redirect, no proxy, bounded bodies and deadlines.

use crate::error::StoreError;
use crate::limits::{MAX_CA_BYTES, NO_REDIRECTS};
use crate::model::{HttpRequest, HttpResponse, StoreMethod};
use crate::signing::open_regular;
use crate::store_settings::{open_store, StoreSettings};
use crate::types::{BoxError, HttpFn};
use std::io::Read;
use std::time::Duration;
use ureq::config::Config;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::{Agent, Error};


/// With a CA file only that CA is trusted (private CA); without one the Mozilla roots are.
pub fn build_agent(settings: &StoreSettings) -> Result<Agent, StoreError> {
    let roots = match &settings.ca_file {
        Some(path) => {
            let mut pem = String::new();
            open_regular(path)?.take(MAX_CA_BYTES + 1).read_to_string(&mut pem)?;
            let oversize = u64::try_from(pem.len()).unwrap_or(u64::MAX) > MAX_CA_BYTES;
            crate::settings::ensure(!oversize, StoreError::CaTooLarge)?;
            RootCerts::new_with_certs(&[Certificate::from_pem(pem.as_bytes()).map_err(StoreError::Certificate)?])
        }
        None => RootCerts::WebPki,
    };
    let config = Config::builder()
        .tls_config(TlsConfig::builder().root_certs(roots).build())
        .timeout_connect(Some(Duration::from_millis(settings.connect_millis)))
        .timeout_recv_response(Some(Duration::from_millis(settings.read_millis)))
        .timeout_recv_body(Some(Duration::from_millis(settings.read_millis)))
        .timeout_global(Some(Duration::from_millis(settings.total_millis)))
        .max_redirects(NO_REDIRECTS)
        .https_only(true)
        .http_status_as_error(false)
        .proxy(None)
        .build();
    Ok(Agent::new_with_config(config))
}


/// A refusal that would quote the presigned URL is replaced by a fixed text.
pub fn redact(error: Error) -> BoxError {
    match error {
        Error::BadUri(_) | Error::RequireHttpsOnly(_) => BoxError::from("the request URL was refused"),
        other => BoxError::from(other),
    }
}


/// The body is read through `take(max_response)`, so a hostile server cannot make the caller buffer more.
pub fn send(agent: &Agent, request: &HttpRequest) -> Result<HttpResponse, BoxError> {
    let response = match request.method {
        StoreMethod::Get => agent.get(&request.url).call(),
        StoreMethod::Put => agent.put(&request.url).send(request.body.as_slice()),
    }
    .map_err(redact)?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let limit = u64::try_from(request.max_response).unwrap_or(u64::MAX);
    response.into_body().into_reader().take(limit).read_to_end(&mut body)?;
    Ok(HttpResponse { status, body })
}


pub fn agent_transport(agent: Agent) -> Box<HttpFn> {
    Box::new(move |request| send(&agent, request))
}


pub fn open_https_store(settings: &StoreSettings) -> Result<crate::model::Store, StoreError> {
    open_store(settings, agent_transport(build_agent(settings)?))
}
