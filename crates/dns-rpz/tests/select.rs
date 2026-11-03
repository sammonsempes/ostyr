#[path = "common/clock.rs"]
mod clock;
#[path = "common/ioc.rs"]
mod ioc;
#[path = "common/logging.rs"]
mod logging;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use clock::now;
use dns_rpz::model::{Entry, SkipReason};
use dns_rpz::policy::{Action, Allowlist, Policy};
use dns_rpz::select::{action_name, compile_allow, decide, rdata, reason_key, rule_for, Allow};
use intel_feeds::limits::MAX_CONFIDENCE;
use intel_feeds::model::{Ioc, IocType, Tlp};
use ioc::ioc;
use logging::init_logging;
use sample::sample_policy;
use time::Duration;
use types::TestResult;


const HIGH: u8 = 90;


const LOW: u8 = 20;


const RULE_MINIMUM: u8 = 95;


const FULL_LABEL: usize = 63;


const LAST_LABEL: usize = 48;


fn allowing(domains: &[&str], cidrs: &[&str]) -> Result<Allow, dns_rpz::error::PolicyError> {
    compile_allow(&Allowlist {
        domains: domains.iter().map(ToString::to_string).collect(),
        cidrs: cidrs.iter().map(ToString::to_string).collect(),
    })
}


fn decided(candidate: &Ioc, policy: &Policy, allow: &Allow) -> Result<Entry, SkipReason> {
    init_logging();
    decide(candidate, policy, allow, now())
}


fn domain(value: &str) -> Ioc {
    ioc(IocType::Domain, value, HIGH, Tlp::Amber)
}


#[test]
fn a_domain_becomes_a_trigger_with_its_wildcard() -> TestResult {
    let entry = decided(&domain("Evil.Example.COM."), &sample_policy(), &Allow::default())?;
    assert_eq!(
        entry,
        Entry {
            owner: "evil.example.com".to_owned(),
            wildcard: true,
            rdata: ".".to_owned(),
            action: "nxdomain",
            confidence: HIGH,
        }
    );
    Ok(())
}


#[test]
fn the_wildcard_follows_the_policy() -> TestResult {
    let mut policy = sample_policy();
    policy.wildcard = false;
    assert!(!decided(&domain("evil.example.com"), &policy, &Allow::default())?.wildcard);
    Ok(())
}


#[test]
fn addresses_and_networks_become_rpz_ip_triggers_whatever_the_declared_type() -> TestResult {
    let policy = sample_policy();
    let allow = Allow::default();
    let host = decided(&ioc(IocType::Ipv4, "10.0.0.1", HIGH, Tlp::Amber), &policy, &allow)?;
    assert_eq!((host.owner.as_str(), host.wildcard), ("32.1.0.0.10.rpz-ip", false));
    let net = decided(&ioc(IocType::Cidr, "2001:db8::/32", HIGH, Tlp::Amber), &policy, &allow)?;
    assert_eq!(net.owner, "32.zz.db8.2001.rpz-ip");
    let mislabelled = decided(&ioc(IocType::Ipv6, "10.0.0.1", HIGH, Tlp::Amber), &policy, &allow)?;
    assert_eq!(mislabelled.owner, host.owner);
    Ok(())
}


#[test]
fn urls_and_hashes_are_unsupported() -> TestResult {
    let policy = sample_policy();
    [IocType::Url, IocType::Md5, IocType::Sha1, IocType::Sha256].iter().for_each(|ioc_type| {
        assert_eq!(
            decided(&ioc(*ioc_type, "x", HIGH, Tlp::Clear), &policy, &Allow::default()),
            Err(SkipReason::UnsupportedType)
        );
        assert!(rule_for(*ioc_type, &policy.actions).is_none());
    });
    [IocType::Domain, IocType::Ipv4, IocType::Ipv6, IocType::Cidr]
        .iter()
        .for_each(|ioc_type| assert!(rule_for(*ioc_type, &policy.actions).is_some()));
    Ok(())
}


#[test]
fn tlp_red_and_amber_strict_are_not_published_by_default() -> TestResult {
    let policy = sample_policy();
    let outcome = |tlp| decided(&ioc(IocType::Domain, "evil.example.com", HIGH, tlp), &policy, &Allow::default());
    assert_eq!(outcome(Tlp::Red), Err(SkipReason::Tlp));
    assert_eq!(outcome(Tlp::AmberStrict), Err(SkipReason::Tlp));
    assert!(outcome(Tlp::Clear).is_ok() && outcome(Tlp::Green).is_ok() && outcome(Tlp::Amber).is_ok());
    Ok(())
}


#[test]
fn a_policy_can_allow_tlp_red_explicitly() -> TestResult {
    let mut policy = sample_policy();
    policy.tlp_allowed.push(Tlp::Red);
    assert!(decided(&ioc(IocType::Domain, "evil.example.com", HIGH, Tlp::Red), &policy, &Allow::default()).is_ok());
    Ok(())
}


#[test]
fn the_stricter_of_the_policy_and_the_rule_minimum_decides() -> TestResult {
    let mut policy = sample_policy();
    let allow = Allow::default();
    assert_eq!(
        decided(&ioc(IocType::Domain, "evil.example.com", LOW, Tlp::Amber), &policy, &allow),
        Err(SkipReason::LowConfidence)
    );
    policy.actions.domain.min_confidence = RULE_MINIMUM;
    assert_eq!(decided(&domain("evil.example.com"), &policy, &allow), Err(SkipReason::LowConfidence));
    policy.min_confidence = 0;
    assert_eq!(decided(&domain("evil.example.com"), &policy, &allow), Err(SkipReason::LowConfidence));
    policy.actions.domain.min_confidence = HIGH;
    assert!(decided(&domain("evil.example.com"), &policy, &allow).is_ok());
    Ok(())
}


#[test]
fn an_ioc_expires_at_its_expiry_instant() -> TestResult {
    let policy = sample_policy();
    let expiring = |offset: Duration| {
        let mut candidate = domain("evil.example.com");
        candidate.expires_at = Some(now() + offset);
        decided(&candidate, &policy, &Allow::default())
    };
    assert_eq!(expiring(Duration::ZERO), Err(SkipReason::Expired));
    assert_eq!(expiring(-Duration::SECOND), Err(SkipReason::Expired));
    assert!(expiring(Duration::SECOND).is_ok());
    Ok(())
}


#[test]
fn the_allowlist_beats_a_high_confidence_ioc() -> TestResult {
    let policy = sample_policy();
    let allow = allowing(&["example.org"], &["10.0.0.0/8", "fd00::/8"])?;
    let blocked = |candidate: Ioc| decided(&candidate, &policy, &allow);
    assert_eq!(blocked(domain("example.org")), Err(SkipReason::Allowlisted));
    assert_eq!(blocked(domain("deep.sub.example.org")), Err(SkipReason::Allowlisted));
    assert!(blocked(domain("notexample.org")).is_ok());
    assert_eq!(
        blocked(ioc(IocType::Ipv4, "10.200.0.1", MAX_CONFIDENCE, Tlp::Clear)),
        Err(SkipReason::Allowlisted)
    );
    assert_eq!(
        blocked(ioc(IocType::Cidr, "10.0.0.0/8", MAX_CONFIDENCE, Tlp::Clear)),
        Err(SkipReason::Allowlisted)
    );
    assert_eq!(
        blocked(ioc(IocType::Cidr, "10.0.0.0/7", MAX_CONFIDENCE, Tlp::Clear)),
        Err(SkipReason::Allowlisted)
    );
    assert_eq!(
        blocked(ioc(IocType::Ipv6, "fd00::1", MAX_CONFIDENCE, Tlp::Clear)),
        Err(SkipReason::Allowlisted)
    );
    assert!(blocked(ioc(IocType::Ipv4, "192.0.2.1", MAX_CONFIDENCE, Tlp::Clear)).is_ok());
    Ok(())
}


#[test]
fn with_wildcards_a_parent_of_an_allowlisted_domain_is_not_blocked() -> TestResult {
    let allow = allowing(&["api.example.com"], &[])?;
    let mut policy = sample_policy();
    assert_eq!(decided(&domain("example.com"), &policy, &allow), Err(SkipReason::Allowlisted));
    policy.wildcard = false;
    assert!(decided(&domain("example.com"), &policy, &allow).is_ok());
    Ok(())
}


#[test]
fn names_and_prefixes_that_cannot_be_triggers_are_invalid() -> TestResult {
    let policy = sample_policy();
    let allow = Allow::default();
    let full = "a".repeat(FULL_LABEL);
    let long = format!("{full}.{full}.{full}.{}", "a".repeat(LAST_LABEL));
    [
        ioc(IocType::Domain, "_dmarc.example.com", HIGH, Tlp::Amber),
        ioc(IocType::Domain, &long, HIGH, Tlp::Amber),
        ioc(IocType::Cidr, "0.0.0.0/0", HIGH, Tlp::Amber),
        ioc(IocType::Ipv6, "::/0", HIGH, Tlp::Amber),
        ioc(IocType::Ipv4, "not-an-address", HIGH, Tlp::Amber),
    ]
    .iter()
    .for_each(|candidate| assert_eq!(decided(candidate, &policy, &allow), Err(SkipReason::InvalidName), "{}", candidate.value));
    Ok(())
}


#[test]
fn every_action_has_its_rdata_and_name() -> TestResult {
    assert_eq!(rdata(&Action::Nxdomain), ".");
    assert_eq!(rdata(&Action::Nodata), "*.");
    assert_eq!(rdata(&Action::Passthru), "rpz-passthru.");
    assert_eq!(rdata(&Action::Cname("sinkhole.example.org".to_owned())), "sinkhole.example.org.");
    let names = [Action::Nxdomain, Action::Nodata, Action::Passthru, Action::Cname(String::new())]
        .iter()
        .map(action_name)
        .collect::<Vec<_>>();
    assert_eq!(names, ["nxdomain", "nodata", "passthru", "cname"]);
    Ok(())
}


#[test]
fn every_reason_has_a_distinct_key() -> TestResult {
    let keys = [
        SkipReason::UnsupportedType,
        SkipReason::Expired,
        SkipReason::Tlp,
        SkipReason::LowConfidence,
        SkipReason::Allowlisted,
        SkipReason::InvalidName,
        SkipReason::Duplicate,
        SkipReason::MalformedLine,
    ]
    .map(reason_key);
    let distinct = keys.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), keys.len());
    Ok(())
}


#[test]
fn an_unparsable_allowlist_network_is_an_error() -> TestResult {
    assert!(allowing(&[], &["10.0.0.0/33"]).is_err());
    Ok(())
}
