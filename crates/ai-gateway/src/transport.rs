use crate::error::AiError;
use crate::limits::MAX_CA_BYTES;
use crate::model::{HttpReply, HttpRequest};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::{Agent, Error as UreqError};


pub const JSON_TYPE: &str = "application/json";


pub const NO_REDIRECTS: u32 = 0;


/// Maps a ureq error to a fixed variant: its text can hold the peer's certificate names, so none of it is kept.
pub fn ureq_error(error: &UreqError) -> AiError {
    match error {
        UreqError::Timeout(_) => AiError::Timeout,
        UreqError::Tls(_) | UreqError::Pem(_) | UreqError::Rustls(_) => AiError::Tls,
        UreqError::HostNotFound | UreqError::ConnectionFailed => AiError::Connect,
        UreqError::Io(inner) => io_class(inner),
        _ => AiError::Protocol,
    }
}


/// ureq carries a TLS failure as an `io::Error` around a rustls error: that is `Tls`; any other I/O failure keeps its kind only.
pub fn io_class(error: &io::Error) -> AiError {
    let tls = error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>());
    tls.map_or(AiError::Io { kind: error.kind() }, |_refusal| AiError::Tls)
}


/// A read failure goes through `io_class`; a ureq error wrapped by the body reader goes through `ureq_error`.
pub fn body_error(error: io::Error) -> AiError {
    let wrapped = error.get_ref().and_then(|inner| inner.downcast_ref::<UreqError>());
    wrapped.map_or_else(|| io_class(&error), ureq_error)
}


/// The PEM of the one extra root, read through a size bound.
pub fn ca_certificate(path: &Path) -> Result<Certificate<'static>, AiError> {
    let mut pem = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_CA_BYTES).read_to_end(&mut pem))
        .map_err(|_error| AiError::CaFile)?;
    Certificate::from_pem(&pem)
        .map(|certificate| certificate.to_owned())
        .map_err(|_error| AiError::CaFile)
}


/// With a CA file only that CA is trusted (private CA); without one the Mozilla roots are. No redirect is followed and no proxy is used.
pub fn ureq_transport(request: &HttpRequest) -> Result<HttpReply, AiError> {
    let roots = match &request.ca_file {
        Some(path) => RootCerts::new_with_certs(&[ca_certificate(path)?]),
        None => RootCerts::WebPki,
    };
    let config = Agent::config_builder()
        .tls_config(TlsConfig::builder().root_certs(roots).build())
        .timeout_global(Some(request.timeout))
        .max_redirects(NO_REDIRECTS)
        .proxy(None)
        .http_status_as_error(false)
        .build();
    let base = Agent::new_with_config(config).post(&request.url).header("Content-Type", JSON_TYPE);
    let call = request
        .authorization
        .iter()
        .fold(base, |builder, value| builder.header("Authorization", value.as_str()));
    let response = call.send(request.body.as_slice()).map_err(|error| ureq_error(&error))?;
    Ok(HttpReply {
        status: response.status().as_u16(),
        body: Box::new(response.into_body().into_reader()),
    })
}
