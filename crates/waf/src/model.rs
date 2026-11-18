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


/// The checked bytes of the private ACME CA root and the content-addressed file name they are written under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaRoot {
    pub name: String,
    pub pem: String,
}


/// A validated certificate issuer.
#[derive(Debug, PartialEq, Eq)]
pub enum Issuer {
    Acme {
        directory: String,
        email: String,
        ca_root: Option<CaRoot>,
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
    pub ca_root: Option<CaRoot>,
    pub refused: Vec<Refusal>,
}


/// What the rendered Caddy configuration may cost: upstream handlers (routes x backends) and pretty JSON bytes.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub upstreams: usize,
    pub bytes: usize,
}


/// How a Caddy command ended; the exit code is the only thing kept of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    Success,
    Failed(Option<i32>),
    TimedOut,
}


/// The apply settings file, strict: the routes file to watch, where the rendered file goes, and how Caddy is reached.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplySettings {
    pub routes_file: String,
    pub out_dir: String,
    #[serde(default = "default_program")]
    pub caddy_program: String,
    #[serde(default = "default_socket")]
    pub admin_socket: String,
    #[serde(default = "default_deadline")]
    pub deadline_seconds: u64,
}


pub fn default_program() -> String {
    crate::limits::DEFAULT_CADDY_PROGRAM.to_owned()
}


pub fn default_socket() -> String {
    crate::limits::DEFAULT_ADMIN_SOCKET.to_owned()
}


pub fn default_deadline() -> u64 {
    crate::limits::DEFAULT_DEADLINE_SECONDS
}


/// One rendered configuration ready for Caddy: the JSON bytes, the checked CA root and the routes left out.
#[derive(Debug)]
pub struct Applied {
    pub id: String,
    pub epoch: u64,
    pub settings: ApplySettings,
    pub json: String,
    pub ca_root: Option<CaRoot>,
    pub refused: Vec<Refusal>,
}


/// How a delivery ended: Caddy answered, or its client failed and the daemon was later found to hold the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Confirmed,
    Late,
}
