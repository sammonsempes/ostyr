use crate::fetch_error::{HttpClass, HttpFailure};
use crate::fetch_model::{HttpRequest, HttpResponse};
use siem_ingest::clickhouse::{new_agent, read_ca};
use siem_ingest::settings::is_loopback_http;
use std::fs::File;
use std::io::{Error as IoError, Read};
use ureq::{Agent, Error};


/// A timeout and an I/O error keep their class; every other ureq error (a bad URL, a refused scheme) is `Other`, and none keeps its text.
pub fn classify(error: Error) -> HttpFailure {
    match error {
        Error::Timeout(_) => HttpFailure(HttpClass::Timeout),
        Error::Io(source) => HttpFailure(HttpClass::Io(source.kind())),
        _other => HttpFailure(HttpClass::Other),
    }
}


pub fn read_class(error: &IoError) -> HttpFailure {
    HttpFailure(HttpClass::Io(error.kind()))
}


pub fn ca_failure<Cause>(_cause: Cause) -> HttpFailure {
    HttpFailure(HttpClass::Ca)
}


/// The CA file is read for every request, so a swapped file applies at once; plain HTTP is accepted for loopback only; no redirect, no proxy.
pub fn agent_for_request(request: &HttpRequest) -> Result<Agent, HttpFailure> {
    let pem = request
        .ca_file
        .as_deref()
        .map(|path| read_ca(File::open(path).map_err(ca_failure)?).map_err(ca_failure))
        .transpose()?;
    new_agent(pem.as_deref(), !is_loopback_http(&request.url)).map_err(ca_failure)
}


/// The body is read through `take(max_response)` and the whole call is under one deadline, so a hostile or stalled server cannot hold the round.
pub fn send(request: &HttpRequest) -> Result<HttpResponse, HttpFailure> {
    let agent = agent_for_request(request)?;
    let response = agent
        .get(&request.url)
        .config()
        .timeout_global(Some(request.timeout))
        .timeout_connect(Some(request.timeout))
        .build()
        .call()
        .map_err(classify)?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(request.max_response)
        .read_to_end(&mut body)
        .map_err(|error| read_class(&error))?;
    Ok(HttpResponse { status, body })
}
