#[path = "common/engine.rs"]
mod engine;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/sample.rs"]
mod sample;
#[path = "common/types.rs"]
mod types;


use core_config::load::load_file;
use core_config::reload::{current_config, reload, ReloadOutcome};
use dns_rpz::error::PolicyError;
use dns_rpz::limits::{DEFAULT_MAX_RECORDS, DEFAULT_MIN_CONFIDENCE, DEFAULT_TTL_SECONDS, MAX_RECORDS_LIMIT};
use dns_rpz::policy::{policy_state, validate_policy, Action, OpenError, Policy, Rule};
use engine::{engine_for, policy_text, replace_file};
use fixtures::fixture;
use intel_feeds::limits::MAX_CONFIDENCE;
use intel_feeds::model::Tlp;
use sample::sample_policy;
use tempfile::tempdir;
use types::TestResult;


const FIXTURE_MIN_CONFIDENCE: u8 = 60;


const OVER: u8 = MAX_CONFIDENCE + 1;


const FIXTURE_ALLOWLIST_SIZE: usize = 4;


#[test]
fn the_fixture_policy_loads_and_validates() -> TestResult {
    let policy: Policy = load_file(&fixture("policy.yaml"))?;
    validate_policy(&policy)?;
    assert_eq!(
        policy.actions.ipv4,
        Rule {
            action: Action::Cname("sinkhole.example.org".to_owned()),
            min_confidence: FIXTURE_MIN_CONFIDENCE
        }
    );
    assert_eq!(policy.actions.ipv6.action, Action::Nodata);
    assert_eq!(policy.actions.cidr.action, Action::Passthru);
    assert_eq!(policy.allowlist.domains.len() + policy.allowlist.cidrs.len(), FIXTURE_ALLOWLIST_SIZE);
    assert_eq!(policy_state(&policy).len(), 1);
    Ok(())
}


#[test]
fn defaults_apply_to_a_minimal_policy() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let policy = current_config(&engine_for(&path)?);
    assert_eq!(policy.ttl, DEFAULT_TTL_SECONDS);
    assert_eq!(policy.min_confidence, DEFAULT_MIN_CONFIDENCE);
    assert_eq!(policy.max_records, DEFAULT_MAX_RECORDS);
    assert_eq!(policy.tlp_allowed, [Tlp::Clear, Tlp::Green, Tlp::Amber]);
    assert!(policy.wildcard && policy.allowlist.domains.is_empty());
    assert_eq!(policy.actions.domain, Rule::default());
    assert_eq!(Rule::default().action, Action::Nxdomain);
    Ok(())
}


#[test]
fn an_invalid_first_policy_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text("surprise: true\n"))?;
    assert!(matches!(engine_for(&path), Err(OpenError::Config(_))));
    replace_file(&path, &policy_text("min_confidence: 101\n"))?;
    assert!(matches!(engine_for(&path), Err(OpenError::Invalid(PolicyError::Confidence(_)))));
    Ok(())
}


#[test]
fn names_must_be_canonical_and_valid() -> TestResult {
    let with = |change: &dyn Fn(&mut Policy)| {
        let mut policy = sample_policy();
        change(&mut policy);
        validate_policy(&policy)
    };
    assert!(validate_policy(&sample_policy()).is_ok());
    assert!(
        matches!(with(&|policy| policy.zone = "RPZ.example.org".to_owned()), Err(PolicyError::NotCanonical { canonical, .. }) if canonical == "rpz.example.org")
    );
    assert!(matches!(
        with(&|policy| policy.zone = "rpz.example.org.".to_owned()),
        Err(PolicyError::NotCanonical { .. })
    ));
    assert!(matches!(with(&|policy| policy.zone = "bad_zone".to_owned()), Err(PolicyError::Name { field, .. }) if field == "zone"));
    assert!(matches!(
        with(&|policy| policy.soa.mname = "bad_name".to_owned()),
        Err(PolicyError::Name { .. })
    ));
    assert!(matches!(
        with(&|policy| policy.soa.rname = "bad_name".to_owned()),
        Err(PolicyError::Name { .. })
    ));
    assert!(matches!(with(&|policy| policy.ns.clear()), Err(PolicyError::NoNameServer)));
    assert!(matches!(
        with(&|policy| policy.ns.push("bad_host".to_owned())),
        Err(PolicyError::Name { .. })
    ));
    assert!(matches!(
        with(&|policy| policy.allowlist.domains.push("Bad.Example".to_owned())),
        Err(PolicyError::NotCanonical { .. })
    ));
    Ok(())
}


#[test]
fn numbers_and_networks_are_bounded() -> TestResult {
    let with = |change: &dyn Fn(&mut Policy)| {
        let mut policy = sample_policy();
        change(&mut policy);
        validate_policy(&policy)
    };
    assert!(matches!(with(&|policy| policy.min_confidence = OVER), Err(PolicyError::Confidence(_))));
    assert!(matches!(with(&|policy| policy.max_records = 0), Err(PolicyError::MaxRecords(_))));
    assert!(matches!(
        with(&|policy| policy.max_records = MAX_RECORDS_LIMIT + 1),
        Err(PolicyError::MaxRecords(_))
    ));
    assert!(with(&|policy| policy.max_records = MAX_RECORDS_LIMIT).is_ok());
    assert!(matches!(
        with(&|policy| policy.allowlist.cidrs.push("10.0.0.0/33".to_owned())),
        Err(PolicyError::Network { value, .. }) if value == "10.0.0.0/33"
    ));
    Ok(())
}


#[test]
fn every_rule_is_checked() -> TestResult {
    let with = |change: &dyn Fn(&mut Policy)| {
        let mut policy = sample_policy();
        change(&mut policy);
        validate_policy(&policy)
    };
    let sinkhole = |host: &str| Action::Cname(host.to_owned());
    assert!(with(&|policy| policy.actions.domain.action = sinkhole("sinkhole.example.org")).is_ok());
    assert!(matches!(
        with(&|policy| policy.actions.domain.action = sinkhole("Bad_Host")),
        Err(PolicyError::Name { .. })
    ));
    assert!(matches!(
        with(&|policy| policy.actions.domain.min_confidence = OVER),
        Err(PolicyError::Confidence(_))
    ));
    assert!(matches!(
        with(&|policy| policy.actions.ipv4.min_confidence = OVER),
        Err(PolicyError::Confidence(_))
    ));
    assert!(matches!(
        with(&|policy| policy.actions.ipv6.action = sinkhole("x_y")),
        Err(PolicyError::Name { .. })
    ));
    assert!(matches!(
        with(&|policy| policy.actions.cidr.min_confidence = OVER),
        Err(PolicyError::Confidence(_))
    ));
    Ok(())
}


#[test]
fn an_allowlist_change_is_applied_without_restart_and_a_bad_file_keeps_the_old_one() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("policy.yaml");
    replace_file(&path, &policy_text(""))?;
    let engine = engine_for(&path)?;
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    replace_file(&path, &policy_text("allowlist:\n  domains: [example.net]\n"))?;
    assert_eq!(
        reload(&engine),
        ReloadOutcome::Applied {
            keys: vec!["rpz.policy".to_owned()]
        }
    );
    assert_eq!(current_config(&engine).allowlist.domains, ["example.net"]);
    replace_file(&path, &policy_text("allowlist:\n  domains: [Example.Net]\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("canonical")));
    replace_file(&path, &policy_text("max_records: 0\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    replace_file(&path, "zone: [\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).allowlist.domains, ["example.net"]);
    Ok(())
}
