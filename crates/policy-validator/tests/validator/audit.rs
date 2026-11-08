use crate::support::{bench, exclusion, failing_audit_engine, hash, replace_file, validation_context, GOOD_PATH};
use crate::types::TestResult;
use core_audit::model::{Outcome, Record};
use core_config::reload::{reload, ReloadOutcome};
use policy_validator::audit::{validate_audited, ValidateError, AUDIT_MODULE, VALIDATE_ACTION};
use policy_validator::model::{AsrChange, AsrState, Decision, Proposal, Reason, Scope, SelectorKind};
use std::fs;
use std::path::Path;


fn records(audit_file: &Path) -> Result<Vec<Record>, Box<dyn std::error::Error>> {
    Ok(fs::read_to_string(audit_file)?
        .lines()
        .map(serde_json::from_str::<Record>)
        .collect::<Result<Vec<_>, _>>()?)
}


const TWO_RECORDS: usize = 2;


#[test]
fn every_verdict_is_audited_with_outcome_reasons_and_version() -> TestResult {
    let bench = bench("{}")?;
    let accepted = validate_audited(
        &bench.engine,
        &validation_context(),
        &Proposal::Exclusion(exclusion(Scope::Global, SelectorKind::Hash, &hash())),
    )?;
    let refused = validate_audited(
        &bench.engine,
        &validation_context(),
        &Proposal::Exclusion(exclusion(Scope::Global, SelectorKind::Path, GOOD_PATH)),
    )?;
    assert_eq!(accepted.decision, Decision::Accepted);
    assert_eq!(refused.reasons, vec![Reason::PathAtWideScope]);
    let found = records(&bench.audit_file)?;
    assert_eq!(found.len(), TWO_RECORDS);
    let (first, second) = (found.first().ok_or("no first record")?, found.get(1).ok_or("no second record")?);
    assert_eq!((first.action.as_str(), first.module.as_str()), (VALIDATE_ACTION, AUDIT_MODULE));
    assert_eq!(first.outcome, Outcome::Success);
    assert_eq!(second.outcome, Outcome::Denied);
    assert_eq!(first.parameters.get("decision").map(String::as_str), Some("Accepted"));
    assert_eq!(first.parameters.get("version"), Some(&accepted.version));
    assert_eq!(first.parameters.get("selector_kind").map(String::as_str), Some("Hash"));
    assert_eq!(first.parameters.get("scope").map(String::as_str), Some("Global"));
    assert_eq!(first.parameters.get("engine").map(String::as_str), Some("Sigma"));
    assert!(second
        .parameters
        .get("reasons")
        .is_some_and(|text| text.starts_with("path_at_wide_scope")));
    assert_eq!(first.target, "exclusion");
    assert_eq!(first.request_id, "req");
    Ok(())
}


#[test]
fn the_selector_text_never_reaches_the_audit() -> TestResult {
    let bench = bench("{}")?;
    let secret = "/usr/bin/tool --token hunter2";
    validate_audited(
        &bench.engine,
        &validation_context(),
        &Proposal::Exclusion(exclusion(Scope::SingleEndpoint, SelectorKind::CommandLine, secret)),
    )?;
    assert!(!fs::read_to_string(&bench.audit_file)?.contains("hunter2"));
    Ok(())
}


#[test]
fn an_asr_change_is_audited_with_its_new_state() -> TestResult {
    let bench = bench("{}")?;
    let proposal = Proposal::AsrChange(AsrChange {
        rule_id: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2".to_owned(),
        new_state: AsrState::Disabled,
        impact: crate::support::impact(),
    });
    let verdict = validate_audited(&bench.engine, &validation_context(), &proposal)?;
    assert_eq!(verdict.decision, Decision::Refused);
    let found = records(&bench.audit_file)?;
    let record = found.first().ok_or("no record")?;
    assert_eq!(record.target, "asr_change");
    assert_eq!(record.parameters.get("new_state").map(String::as_str), Some("Disabled"));
    assert_eq!(record.outcome, Outcome::Denied);
    Ok(())
}


#[test]
fn a_failing_audit_refuses_the_proposal() -> TestResult {
    let (_dir, engine) = failing_audit_engine()?;
    let outcome = validate_audited(
        &engine,
        &validation_context(),
        &Proposal::Exclusion(exclusion(Scope::Global, SelectorKind::Hash, &hash())),
    );
    assert!(matches!(outcome, Err(ValidateError::Audit(_))));
    assert!(outcome.err().is_some_and(|error| error.to_string().contains("refused")));
    Ok(())
}


#[test]
fn a_verdict_uses_the_configuration_in_force_after_a_reload() -> TestResult {
    let bench = bench("{}")?;
    let proposal = Proposal::Exclusion(exclusion(Scope::Global, SelectorKind::Hash, &hash()));
    let before = validate_audited(&bench.engine, &validation_context(), &proposal)?;
    assert_eq!(before.decision, Decision::Accepted);
    replace_file(&bench.policy_file, "interpreters: [tool]\n")?;
    assert!(matches!(reload(&bench.engine), ReloadOutcome::Applied { .. }));
    let after = validate_audited(&bench.engine, &validation_context(), &proposal)?;
    assert_eq!(after.reasons, vec![Reason::SystemBinary { name: "tool.exe".to_owned() }]);
    assert_ne!(before.version, after.version);
    Ok(())
}
