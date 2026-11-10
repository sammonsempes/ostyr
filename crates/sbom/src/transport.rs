//! The `ureq` transport: TLS only, a CA from the settings, no redirect, no proxy, bounded bodies and deadlines.

use crate::error::StoreError;
use crate::limits::{MAX_CA_BYTES, NO_REDIRECTS};
use crate::model::{HttpRequest, HttpResponse, StoreMethod};
use crate::signing::open_regular;
use crate::store_settings::{open_store, StoreSettings};
use crate::types::{BoxError, HttpFn};
use std::io::{BufReader, Read};
use std::time::Duration;
use ureq::config::Config;
use ureq::tls::{parse_pem, PemItem, RootCerts, TlsConfig};
use ureq::{Agent, Error};


/// With a CA file every certificate of the bundle is trusted and nothing else (private CA); without one the Mozilla roots are, by design.
pub fn build_agent(settings: &StoreSettings) -> Result<Agent, StoreError> {
    let roots = match &settings.ca_file {
        Some(path) => {
            let mut pem = String::new();
            let mut capped = open_regular(path)?.take(MAX_CA_BYTES + 1);
            capped.read_to_string(&mut pem)?;
            crate::settings::ensure(capped.limit() > 0, StoreError::CaTooLarge)?;
            let certificates = parse_pem(pem.as_bytes())
                .filter_map(|item| match item {
                    Ok(PemItem::Certificate(certificate)) => Some(Ok(certificate)),
                    Ok(_other) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::Certificate)?;
            crate::settings::ensure(
                !certificates.is_empty(),
                StoreError::Certificate(Error::Tls("no certificate in the CA file")),
            )?;
            RootCerts::new_with_certs(&certificates)
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
    let body = BufReader::new(response.into_body().into_reader())
        .bytes()
        .take(request.max_response)
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(HttpResponse { status, body })
}


pub fn agent_transport(agent: Agent) -> Box<HttpFn> {
    Box::new(move |request| send(&agent, request))
}


pub fn open_https_store(settings: &StoreSettings) -> Result<crate::model::Store, StoreError> {
    open_store(settings, agent_transport(build_agent(settings)?))
}
