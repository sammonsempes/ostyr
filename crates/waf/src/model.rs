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
