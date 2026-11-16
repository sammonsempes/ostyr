use crate::caddy::CaddyConfig;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::Value;


/// First pass: only counts the routes, each one is skipped without being materialised.
#[derive(Debug, Deserialize)]
pub struct RouteCount {
    pub routes: Vec<IgnoredAny>,
}


/// Second pass: each route stays a value so that one malformed route refuses only itself.
#[derive(Debug, Deserialize)]
pub struct RawFile {
    pub routes: Vec<Value>,
    #[serde(default)]
    pub tls: Option<RawTls>,
}


#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RawIssuer {
    Acme,
    Internal,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTls {
    pub issuer: RawIssuer,
    pub directory: Option<String>,
    pub email: Option<String>,
    pub ca_root_file: Option<String>,
    pub hsts_max_age_seconds: Option<u64>,
    #[serde(default)]
    pub hsts_include_subdomains: bool,
}


/// A validated certificate issuer.
#[derive(Debug, PartialEq, Eq)]
pub enum Issuer {
    Acme {
        directory: String,
        email: String,
        ca_root_file: Option<String>,
    },
    Internal,
}


/// A validated `tls:` section; `hsts` is the header value, none when the max age is 0.
#[derive(Debug, PartialEq, Eq)]
pub struct Tls {
    pub issuer: Issuer,
    pub hsts: Option<String>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRoute {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub backends: Vec<String>,
    pub health: Option<RawHealth>,
}


#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHealth {
    pub path: Option<String>,
    pub interval_seconds: Option<u64>,
}


/// A route that passed every check, ready to render.
#[derive(Debug, PartialEq, Eq)]
pub struct Route {
    pub hosts: Vec<String>,
    pub prefixes: Vec<String>,
    pub backends: Vec<String>,
    pub health_path: String,
    pub interval_seconds: u64,
}


/// A route left out, with a fixed-text reason that never holds text from the file.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub index: usize,
    pub reason: &'static str,
    pub shadowed_by: Option<usize>,
}


#[derive(Debug)]
pub struct Rendered {
    pub config: CaddyConfig,
    pub refused: Vec<Refusal>,
}


/// What the rendered Caddy configuration may cost: upstream handlers (routes x backends) and pretty JSON bytes.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub upstreams: usize,
    pub bytes: usize,
}
