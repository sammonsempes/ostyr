use serde::Serialize;
use std::collections::BTreeMap;


#[derive(Debug, Serialize)]
pub struct CaddyConfig {
    pub apps: Apps,
}


#[derive(Debug, Serialize)]
pub struct Apps {
    pub http: Http,
}


#[derive(Debug, Serialize)]
pub struct Http {
    pub servers: BTreeMap<String, Server>,
}


#[derive(Debug, Serialize)]
pub struct Server {
    pub listen: Vec<String>,
    pub automatic_https: AutomaticHttps,
    pub routes: Vec<CaddyRoute>,
}


#[derive(Debug, Serialize)]
pub struct AutomaticHttps {
    pub disable: bool,
}


#[derive(Debug, Serialize)]
pub struct CaddyRoute {
    #[serde(rename = "match", skip_serializing_if = "Vec::is_empty")]
    pub matchers: Vec<Matcher>,
    pub handle: Vec<Handle>,
}


#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Handle {
    Proxy(Handler),
    Answer(StaticResponse),
}


#[derive(Debug, Serialize)]
pub struct StaticResponse {
    pub handler: &'static str,
    pub status_code: u16,
}


#[derive(Debug, Serialize)]
pub struct Matcher {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub header: BTreeMap<String, Vec<String>>,
}


#[derive(Debug, Serialize)]
pub struct Handler {
    pub handler: &'static str,
    pub upstreams: Vec<Upstream>,
    pub health_checks: HealthChecks,
    pub headers: Headers,
}


#[derive(Debug, Serialize)]
pub struct Headers {
    pub request: RequestHeaders,
}


#[derive(Debug, Serialize)]
pub struct RequestHeaders {
    pub set: BTreeMap<String, Vec<String>>,
}


#[derive(Debug, Serialize)]
pub struct Upstream {
    pub dial: String,
}


#[derive(Debug, Serialize)]
pub struct HealthChecks {
    pub active: Active,
    pub passive: Passive,
}


#[derive(Debug, Serialize)]
pub struct Active {
    pub uri: String,
    pub interval: String,
}


#[derive(Debug, Serialize)]
pub struct Passive {
    pub fail_duration: String,
    pub max_fails: u32,
}
