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
    #[serde(rename = "match")]
    pub matchers: Vec<Matcher>,
    pub handle: Vec<Handler>,
}


#[derive(Debug, Serialize)]
pub struct Matcher {
    pub host: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
}


#[derive(Debug, Serialize)]
pub struct Handler {
    pub handler: &'static str,
    pub upstreams: Vec<Upstream>,
    pub health_checks: HealthChecks,
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
