use crate::error::PolicyError;
use crate::limits::{
    DEFAULT_EXPIRE_SECONDS, DEFAULT_HEADER_READ_TIMEOUT_MS, DEFAULT_MAX_RECORDS, DEFAULT_MIN_CONFIDENCE, DEFAULT_NEGATIVE_TTL_SECONDS,
    DEFAULT_REFRESH_SECONDS, DEFAULT_RESPONSE_TIMEOUT_MS, DEFAULT_RETRY_SECONDS, DEFAULT_SINKHOLE_MAX_CONNECTIONS, DEFAULT_SINKHOLE_PER_SOURCE,
    DEFAULT_TTL_SECONDS, DEFAULT_UNBOUND_COMMAND, DEFAULT_UNBOUND_TIMEOUT_SECONDS, DEFAULT_ZONEFILE, MAX_HEADER_READ_TIMEOUT_MS, MAX_PAGE_TEXT_CHARS,
    MAX_RECORDS_LIMIT, MAX_RESPONSE_TIMEOUT_MS, MAX_SETTING_BYTES, MAX_SINKHOLE_CONNECTIONS, MAX_SINKHOLE_PER_SOURCE, MAX_UNBOUND_TIMEOUT_SECONDS,
};
use crate::name::normalise_name;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{ConfigState, SharedAuditFn};
use intel_feeds::limits::MAX_CONFIDENCE;
use intel_feeds::model::Tlp;
use ipnet::IpNet;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;


pub const POLICY_SECTION: &str = "rpz";


/// What the zone says about a trigger: `Cname` redirects to a sinkhole host.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Nxdomain,
    Nodata,
    Passthru,
    Cname(String),
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub action: Action,
    #[serde(default)]
    pub min_confidence: u8,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actions {
    #[serde(default)]
    pub domain: Rule,
    #[serde(default)]
    pub ipv4: Rule,
    #[serde(default)]
    pub ipv6: Rule,
    #[serde(default)]
    pub cidr: Rule,
}


#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Soa {
    pub mname: String,
    pub rname: String,
    #[serde(default = "default_refresh")]
    pub refresh: u32,
    #[serde(default = "default_retry")]
    pub retry: u32,
    #[serde(default = "default_expire")]
    pub expire: u32,
    #[serde(default = "default_negative_ttl")]
    pub minimum: u32,
}


/// Unbound side of the zone: the `rpz:` block, the control command and its deadline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unbound {
    #[serde(default = "default_command")]
    pub command: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_zonefile")]
    pub zonefile: String,
    #[serde(default)]
    pub action_override: Option<Action>,
    #[serde(default)]
    pub log_name: Option<String>,
}


impl Default for Unbound {
    fn default() -> Self {
        Self {
            command: default_command(),
            timeout_seconds: default_timeout(),
            zonefile: default_zonefile(),
            action_override: None,
            log_name: None,
        }
    }
}


pub fn default_command() -> String {
    DEFAULT_UNBOUND_COMMAND.to_owned()
}


pub fn default_timeout() -> u64 {
    DEFAULT_UNBOUND_TIMEOUT_SECONDS
}


pub fn default_zonefile() -> String {
    DEFAULT_ZONEFILE.to_owned()
}


/// Texts of the sinkhole information page.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkholePage {
    pub contact: String,
    pub organisation: String,
}


/// The sinkhole listener: `listen` is read at start only, the bounds apply to the next connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkholeServer {
    pub listen: SocketAddr,
    #[serde(default = "default_sinkhole_connections")]
    pub max_connections: usize,
    #[serde(default = "default_sinkhole_per_source")]
    pub max_connections_per_source: usize,
    #[serde(default = "default_header_read_timeout")]
    pub header_read_timeout_ms: u64,
    #[serde(default = "default_response_timeout")]
    pub response_timeout_ms: u64,
}


pub fn default_sinkhole_connections() -> usize {
    DEFAULT_SINKHOLE_MAX_CONNECTIONS
}


pub fn default_sinkhole_per_source() -> usize {
    DEFAULT_SINKHOLE_PER_SOURCE
}


pub fn default_header_read_timeout() -> u64 {
    DEFAULT_HEADER_READ_TIMEOUT_MS
}


pub fn default_response_timeout() -> u64 {
    DEFAULT_RESPONSE_TIMEOUT_MS
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub zone: String,
    pub soa: Soa,
    pub ns: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: u8,
    #[serde(default = "default_tlp_allowed")]
    pub tlp_allowed: Vec<Tlp>,
    #[serde(default = "default_wildcard")]
    pub wildcard: bool,
    #[serde(default = "default_max_records")]
    pub max_records: usize,
    #[serde(default)]
    pub allowlist: Allowlist,
    #[serde(default)]
    pub actions: Actions,
    #[serde(default)]
    pub unbound: Unbound,
    #[serde(default)]
    pub sinkhole_page: Option<SinkholePage>,
    #[serde(default)]
    pub sinkhole_server: Option<SinkholeServer>,
}


pub fn default_refresh() -> u32 {
    DEFAULT_REFRESH_SECONDS
}


pub fn default_retry() -> u32 {
    DEFAULT_RETRY_SECONDS
}


pub fn default_expire() -> u32 {
    DEFAULT_EXPIRE_SECONDS
}


pub fn default_negative_ttl() -> u32 {
    DEFAULT_NEGATIVE_TTL_SECONDS
}


pub fn default_ttl() -> u32 {
    DEFAULT_TTL_SECONDS
}


pub fn default_min_confidence() -> u8 {
    DEFAULT_MIN_CONFIDENCE
}


/// TLP:RED and TLP:AMBER+STRICT are never published unless the policy lists them.
pub fn default_tlp_allowed() -> Vec<Tlp> {
    vec![Tlp::Clear, Tlp::Green, Tlp::Amber]
}


pub fn default_wildcard() -> bool {
    true
}


pub fn default_max_records() -> usize {
    DEFAULT_MAX_RECORDS
}


#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Invalid(#[from] PolicyError),
}


/// Networks of the allowlist, parsed.
pub fn parse_networks(allowlist: &Allowlist) -> Result<Vec<IpNet>, PolicyError> {
    allowlist
        .cidrs
        .iter()
        .map(|value| {
            value.parse::<IpNet>().map_err(|source| PolicyError::Network {
                value: value.clone(),
                source,
            })
        })
        .collect()
}


/// A name is stored in the form it is written in the zone, so it must already be canonical.
pub fn check_name(field: &str, value: &str) -> Result<(), PolicyError> {
    let canonical = normalise_name(value).map_err(|source| PolicyError::Name {
        field: field.to_owned(),
        source,
    })?;
    if canonical == value {
        Ok(())
    } else {
        Err(PolicyError::NotCanonical {
            field: field.to_owned(),
            canonical,
        })
    }
}


pub fn check_confidence(field: &str, value: u8) -> Result<(), PolicyError> {
    if value > MAX_CONFIDENCE {
        Err(PolicyError::Confidence(field.to_owned()))
    } else {
        Ok(())
    }
}


pub fn check_rule(field: &str, rule: &Rule) -> Result<(), PolicyError> {
    check_confidence(&format!("actions.{field}.min_confidence"), rule.min_confidence)?;
    match &rule.action {
        Action::Cname(host) => check_name(&format!("actions.{field}.action"), host),
        _ => Ok(()),
    }
}


/// A setting written into the Unbound configuration or run as a command: bounded, printable, no quote or backslash.
pub fn check_setting(field: &str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > MAX_SETTING_BYTES || value.chars().any(|character| character.is_control() || "\"\\".contains(character)) {
        Err(PolicyError::Setting(field.to_owned()))
    } else {
        Ok(())
    }
}


/// ASCII printable or a Latin letter (French accents included): an allowlist, so no control, format, bidirectional or invisible character passes.
pub fn is_page_char(character: char) -> bool {
    (' '..='~').contains(&character) || (('\u{c0}'..='\u{24f}').contains(&character) && character != '\u{d7}' && character != '\u{f7}')
}


/// Page text: 1 to `MAX_PAGE_TEXT_CHARS` characters of the allowlist with something visible; the error names the field only.
pub fn check_page_text(field: &str, value: &str) -> Result<(), PolicyError> {
    if value.trim().is_empty() || value.chars().count() > MAX_PAGE_TEXT_CHARS || !value.chars().all(is_page_char) {
        Err(PolicyError::Setting(field.to_owned()))
    } else {
        Ok(())
    }
}


pub fn check_sinkhole_page(page: &SinkholePage) -> Result<(), PolicyError> {
    check_page_text("sinkhole_page.contact", &page.contact)?;
    check_page_text("sinkhole_page.organisation", &page.organisation)
}


/// Each bound inside its range; the total deadline covers the header read.
pub fn check_sinkhole_server(server: &SinkholeServer) -> Result<(), PolicyError> {
    let checks = [
        (
            "sinkhole_server.max_connections",
            (1..=MAX_SINKHOLE_CONNECTIONS).contains(&server.max_connections),
        ),
        (
            "sinkhole_server.max_connections_per_source",
            (1..=MAX_SINKHOLE_PER_SOURCE).contains(&server.max_connections_per_source),
        ),
        (
            "sinkhole_server.header_read_timeout_ms",
            (1..=MAX_HEADER_READ_TIMEOUT_MS).contains(&server.header_read_timeout_ms),
        ),
        (
            "sinkhole_server.response_timeout_ms",
            (server.header_read_timeout_ms..=MAX_RESPONSE_TIMEOUT_MS).contains(&server.response_timeout_ms),
        ),
    ];
    checks
        .into_iter()
        .find(|(_, valid)| !valid)
        .map_or(Ok(()), |(field, _)| Err(PolicyError::Setting(field.to_owned())))
}


pub fn check_unbound(unbound: &Unbound) -> Result<(), PolicyError> {
    check_setting("unbound.command", &unbound.command)?;
    check_setting("unbound.zonefile", &unbound.zonefile)?;
    unbound
        .log_name
        .as_deref()
        .map_or(Ok(()), |name| check_setting("unbound.log_name", name))?;
    if unbound.timeout_seconds == 0 || unbound.timeout_seconds > MAX_UNBOUND_TIMEOUT_SECONDS {
        Err(PolicyError::Setting("unbound.timeout_seconds".to_owned()))?;
    }
    match &unbound.action_override {
        Some(Action::Cname(host)) => check_name("unbound.action_override", host),
        _ => Ok(()),
    }
}


/// Names canonical, confidences within 0 to 100, at least one name server, a bounded zone size, parsable allowlist networks.
pub fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    check_name("zone", &policy.zone)?;
    check_name("soa.mname", &policy.soa.mname)?;
    check_name("soa.rname", &policy.soa.rname)?;
    if policy.ns.is_empty() {
        Err(PolicyError::NoNameServer)?;
    }
    policy.ns.iter().try_for_each(|host| check_name("ns", host))?;
    check_confidence("min_confidence", policy.min_confidence)?;
    if policy.max_records == 0 || policy.max_records > MAX_RECORDS_LIMIT {
        Err(PolicyError::MaxRecords(MAX_RECORDS_LIMIT))?;
    }
    policy
        .allowlist
        .domains
        .iter()
        .try_for_each(|domain| check_name("allowlist.domains", domain))?;
    parse_networks(&policy.allowlist)?;
    check_rule("domain", &policy.actions.domain)?;
    check_rule("ipv4", &policy.actions.ipv4)?;
    check_rule("ipv6", &policy.actions.ipv6)?;
    check_rule("cidr", &policy.actions.cidr)?;
    policy.sinkhole_page.as_ref().map_or(Ok(()), check_sinkhole_page)?;
    policy.sinkhole_server.as_ref().map_or(Ok(()), check_sinkhole_server)?;
    check_unbound(&policy.unbound)
}


/// One key holding the whole policy: the diff is for audit, not for display.
pub fn policy_state(policy: &Policy) -> ConfigState {
    ConfigState::from([(format!("{POLICY_SECTION}.policy"), format!("{policy:#?}"))])
}


pub fn policy_subscriber() -> Subscriber<Policy> {
    Subscriber {
        section: POLICY_SECTION.to_owned(),
        validate: Box::new(|policy| validate_policy(policy).map_err(Into::into)),
        apply: Box::new(|_policy| ()),
    }
}


/// Loads and validates the first policy; later reloads are validated by the subscriber and refused when invalid.
pub fn open_policy(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<Policy>, OpenError> {
    let engine = open_engine(
        Box::new(move || load_file::<Policy>(&path)),
        policy_state,
        vec![policy_subscriber()],
        audit,
        context,
    )?;
    validate_policy(&current_config(&engine))?;
    Ok(engine)
}


pub fn listen_of(policy: &Policy) -> Option<SocketAddr> {
    policy.sinkhole_server.map(|server| server.listen)
}


/// A file that adds, removes or changes the listen address is refused (so audited): it is read at start only.
pub fn load_fixed_listen(path: &Path, baseline: Option<SocketAddr>) -> Result<Policy, ConfigError> {
    let policy = load_file::<Policy>(path)?;
    if listen_of(&policy) == baseline {
        Ok(policy)
    } else {
        Err(ConfigError::WatchedFile {
            file: "sinkhole_server.listen".to_owned(),
            reason: "read at start only, restart the service to change it".to_owned(),
        })
    }
}


/// The engine whose every load, the first included, must carry `baseline` as listen address.
pub fn open_with_listen(
    path: PathBuf,
    baseline: Option<SocketAddr>,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<Policy>, OpenError> {
    let engine = open_engine(
        Box::new(move || load_fixed_listen(&path, baseline)),
        policy_state,
        vec![policy_subscriber()],
        audit,
        context,
    )?;
    validate_policy(&current_config(&engine))?;
    Ok(engine)
}


/// Like `open_policy`, with the listen address of the first read held fixed by every reload.
pub fn open_serving_policy(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<Policy>, OpenError> {
    let baseline = listen_of(&load_file::<Policy>(&path)?);
    open_with_listen(path, baseline, audit, context)
}
