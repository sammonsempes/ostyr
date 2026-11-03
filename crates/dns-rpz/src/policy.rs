use crate::error::PolicyError;
use crate::limits::{
    DEFAULT_EXPIRE_SECONDS, DEFAULT_MAX_RECORDS, DEFAULT_MIN_CONFIDENCE, DEFAULT_NEGATIVE_TTL_SECONDS, DEFAULT_REFRESH_SECONDS,
    DEFAULT_RETRY_SECONDS, DEFAULT_TTL_SECONDS, MAX_RECORDS_LIMIT,
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
use std::path::PathBuf;
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
    check_rule("cidr", &policy.actions.cidr)
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
