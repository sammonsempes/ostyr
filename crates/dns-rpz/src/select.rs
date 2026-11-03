use crate::error::PolicyError;
use crate::model::{Entry, SkipReason};
use crate::name::{check_length, is_under, normalise_name};
use crate::policy::{parse_networks, Action, Actions, Allowlist, Policy, Rule};
use crate::trigger::{net_trigger, parse_net};
use intel_feeds::model::{Ioc, IocType};
use ipnet::IpNet;
use std::fmt::Display;
use time::OffsetDateTime;
use tracing::debug;


/// The allowlist, parsed once per run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allow {
    pub domains: Vec<String>,
    pub nets: Vec<IpNet>,
}


pub fn reason_key(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::UnsupportedType => "unsupported_type",
        SkipReason::Expired => "expired",
        SkipReason::Tlp => "tlp",
        SkipReason::LowConfidence => "low_confidence",
        SkipReason::Allowlisted => "allowlisted",
        SkipReason::InvalidName => "invalid_name",
        SkipReason::Duplicate => "duplicate",
        SkipReason::MalformedLine => "malformed_line",
    }
}


pub fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Nxdomain => "nxdomain",
        Action::Nodata => "nodata",
        Action::Passthru => "passthru",
        Action::Cname(_) => "cname",
    }
}


/// The record data of the trigger: `.` NXDOMAIN, `*.` NODATA, `rpz-passthru.`, or the sinkhole host.
pub fn rdata(action: &Action) -> String {
    match action {
        Action::Nxdomain => ".".to_owned(),
        Action::Nodata => "*.".to_owned(),
        Action::Passthru => "rpz-passthru.".to_owned(),
        Action::Cname(host) => format!("{host}."),
    }
}


/// Hashes and URLs have no RPZ trigger.
pub fn rule_for(ioc_type: IocType, actions: &Actions) -> Option<&Rule> {
    match ioc_type {
        IocType::Domain => Some(&actions.domain),
        IocType::Ipv4 => Some(&actions.ipv4),
        IocType::Ipv6 => Some(&actions.ipv6),
        IocType::Cidr => Some(&actions.cidr),
        IocType::Url | IocType::Md5 | IocType::Sha1 | IocType::Sha256 => None,
    }
}


pub fn invalid_value(value: &str, error: impl Display) -> SkipReason {
    debug!(value, %error, "IOC value cannot be a trigger");
    SkipReason::InvalidName
}


/// Expiry, TLP and confidence, the stricter of the policy and the rule deciding.
pub fn check_filters(ioc: &Ioc, policy: &Policy, rule: &Rule, now: OffsetDateTime) -> Result<(), SkipReason> {
    if ioc.expires_at.is_some_and(|expires_at| expires_at <= now) {
        Err(SkipReason::Expired)
    } else if !policy.tlp_allowed.contains(&ioc.tlp) {
        Err(SkipReason::Tlp)
    } else if ioc.confidence < policy.min_confidence.max(rule.min_confidence) {
        Err(SkipReason::LowConfidence)
    } else {
        Ok(())
    }
}


/// With wildcards an allowlisted subdomain makes its blocked parent unsafe too, so the parent is skipped.
pub fn domain_allowed(name: &str, allowed: &[String], wildcard: bool) -> bool {
    allowed
        .iter()
        .any(|parent| is_under(name, parent) || (wildcard && is_under(parent, name)))
}


pub fn net_allowed(net: &IpNet, allowed: &[IpNet]) -> bool {
    allowed.iter().any(|other| other.contains(net) || net.contains(other))
}


pub fn make_entry(owner: String, wildcard: bool, rule: &Rule, ioc: &Ioc) -> Entry {
    Entry {
        owner,
        wildcard,
        rdata: rdata(&rule.action),
        action: action_name(&rule.action),
        confidence: ioc.confidence,
    }
}


pub fn domain_entry(ioc: &Ioc, rule: &Rule, policy: &Policy, allow: &Allow) -> Result<Entry, SkipReason> {
    let name = normalise_name(&ioc.value).map_err(|error| invalid_value(&ioc.value, error))?;
    check_length(&name, &policy.zone, policy.wildcard).map_err(|error| invalid_value(&ioc.value, error))?;
    if domain_allowed(&name, &allow.domains, policy.wildcard) {
        Err(SkipReason::Allowlisted)
    } else {
        Ok(make_entry(name, policy.wildcard, rule, ioc))
    }
}


pub fn net_entry(ioc: &Ioc, rule: &Rule, allow: &Allow) -> Result<Entry, SkipReason> {
    let net = parse_net(&ioc.value).map_err(|error| invalid_value(&ioc.value, error))?;
    let trigger = net_trigger(net).ok_or_else(|| invalid_value(&ioc.value, "prefix length 0"))?;
    if net_allowed(&net, &allow.nets) {
        Err(SkipReason::Allowlisted)
    } else {
        Ok(make_entry(trigger, false, rule, ioc))
    }
}


/// The trigger of one IOC, or the reason it is not published.
pub fn decide(ioc: &Ioc, policy: &Policy, allow: &Allow, now: OffsetDateTime) -> Result<Entry, SkipReason> {
    let rule = rule_for(ioc.ioc_type, &policy.actions).ok_or(SkipReason::UnsupportedType)?;
    check_filters(ioc, policy, rule, now)?;
    match ioc.ioc_type {
        IocType::Domain => domain_entry(ioc, rule, policy, allow),
        _ => net_entry(ioc, rule, allow),
    }
}


/// Allowlist domains are canonical by validation; the networks are parsed again here.
pub fn compile_allow(allowlist: &Allowlist) -> Result<Allow, PolicyError> {
    parse_networks(allowlist).map(|nets| Allow {
        domains: allowlist.domains.clone(),
        nets,
    })
}
