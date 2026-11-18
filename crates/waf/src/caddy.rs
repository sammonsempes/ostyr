use serde::Serialize;
use std::collections::BTreeMap;


#[derive(Debug, Serialize)]
pub struct CaddyConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin: Option<Admin>,
    pub apps: Apps,
}


#[derive(Debug, Serialize)]
pub struct Admin {
    pub listen: String,
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}


#[derive(Debug, Serialize)]
pub struct Apps {
    pub http: Http,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsApp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pki: Option<PkiApp>,
}


#[derive(Debug, Serialize)]
pub struct PkiApp {
    pub certificate_authorities: Authorities,
}


#[derive(Debug, Serialize)]
pub struct Authorities {
    pub local: LocalAuthority,
}


#[derive(Debug, Serialize)]
pub struct LocalAuthority {
    pub install_trust: bool,
}


#[derive(Debug, Serialize)]
pub struct TlsApp {
    pub automation: Automation,
}


#[derive(Debug, Serialize)]
pub struct Automation {
    pub policies: Vec<Policy>,
}


#[derive(Debug, Serialize)]
pub struct Policy {
    pub subjects: Vec<String>,
    pub issuers: Vec<IssuerConfig>,
}


#[derive(Debug, Serialize)]
pub struct IssuerConfig {
    pub module: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trusted_roots_pem_files: Vec<String>,
}


#[derive(Debug, Serialize)]
pub struct Http {
    pub servers: BTreeMap<String, Server>,
}


#[derive(Debug, Serialize)]
pub struct Server {
    pub listen: Vec<String>,
    pub automatic_https: AutomaticHttps,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_connection_policies: Vec<ConnectionPolicy>,
    pub routes: Vec<CaddyRoute>,
}


#[derive(Debug, Serialize)]
pub struct AutomaticHttps {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_redirects: Option<bool>,
}


#[derive(Debug, Serialize)]
pub struct ConnectionPolicy {
    pub protocol_min: &'static str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RequestHeaders>,
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
