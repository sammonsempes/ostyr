#[path = "common/types.rs"]
mod types;


use grc::error::GrcError;
use grc::evaluate::{evaluate, evaluate_framework};
use grc::evidence::verify_evidence;
use grc::model::{Control, ControlKind, ControlStatus, Framework, IndicatorValue, ManualEvidence, Threshold};
use time::OffsetDateTime;
use types::TestResult;


const NOW: i64 = 1_800_000_000;


const HOUR: i64 = 3_600;


const MAX_AGE_HOURS: u32 = 24;


const MAX_AGE_SECONDS: i64 = 86_400;


const HIGH_LIMIT: f64 = 90.0;


const HIGH_PARTIAL: f64 = 70.0;


const LOW_LIMIT: f64 = 10.0;


const LOW_PARTIAL: f64 = 30.0;


const STEP: f64 = 0.5;


const LOW_VALUE: f64 = 5.0;


const VERSION: u32 = 1;


fn at(seconds: i64) -> Result<OffsetDateTime, time::error::ComponentRange> {
    OffsetDateTime::from_unix_timestamp(seconds)
}


fn control(compliant: Threshold, partial: Threshold) -> Control {
    Control {
        id: "C1".to_owned(),
        title: "title".to_owned(),
        kind: ControlKind::Technical,
        indicator: Some("edr.share".to_owned()),
        max_age_hours: Some(MAX_AGE_HOURS),
        compliant: Some(compliant),
        partial: Some(partial),
    }
}


fn organisational() -> Control {
    Control {
        id: "O1".to_owned(),
        title: "policy".to_owned(),
        kind: ControlKind::Organisational,
        indicator: None,
        max_age_hours: None,
        compliant: None,
        partial: None,
    }
}


fn indicator(value: f64, observed: i64) -> Result<IndicatorValue, time::error::ComponentRange> {
    Ok(IndicatorValue {
        tenant: "acme".to_owned(),
        name: "edr.share".to_owned(),
        value,
        observed_at: at(observed)?,
        source: "edr".to_owned(),
    })
}


fn manual(review_until: i64, owner: &str) -> Result<ManualEvidence, time::error::ComponentRange> {
    Ok(ManualEvidence {
        tenant: "acme".to_owned(),
        control: "O1".to_owned(),
        owner: owner.to_owned(),
        recorded_at: at(NOW - HOUR)?,
        review_until: at(review_until)?,
    })
}


fn status_of(control: &Control, value: f64) -> Result<ControlStatus, time::error::ComponentRange> {
    Ok(evaluate(control, Some(&indicator(value, NOW)?), None, at(NOW)?).status)
}


#[test]
fn at_least_boundaries_are_inclusive() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    let cases = [
        (HIGH_LIMIT + STEP, ControlStatus::Compliant),
        (HIGH_LIMIT, ControlStatus::Compliant),
        (HIGH_LIMIT - STEP, ControlStatus::PartiallyCompliant),
        (HIGH_PARTIAL + STEP, ControlStatus::PartiallyCompliant),
        (HIGH_PARTIAL, ControlStatus::PartiallyCompliant),
        (HIGH_PARTIAL - STEP, ControlStatus::NonCompliant),
    ];
    for (value, expected) in cases {
        assert_eq!(status_of(&subject, value)?, expected);
    }
    Ok(())
}


#[test]
fn at_most_boundaries_are_inclusive() -> TestResult {
    let subject = control(Threshold::AtMost(LOW_LIMIT), Threshold::AtMost(LOW_PARTIAL));
    let cases = [
        (LOW_LIMIT - STEP, ControlStatus::Compliant),
        (LOW_LIMIT, ControlStatus::Compliant),
        (LOW_LIMIT + STEP, ControlStatus::PartiallyCompliant),
        (LOW_PARTIAL - STEP, ControlStatus::PartiallyCompliant),
        (LOW_PARTIAL, ControlStatus::PartiallyCompliant),
        (LOW_PARTIAL + STEP, ControlStatus::NonCompliant),
    ];
    for (value, expected) in cases {
        assert_eq!(status_of(&subject, value)?, expected);
    }
    Ok(())
}


#[test]
fn a_graded_status_carries_verifiable_evidence() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    let result = evaluate(&subject, Some(&indicator(HIGH_LIMIT, NOW)?), None, at(NOW)?);
    let evidence = result.evidence.ok_or("no evidence")?;
    assert_eq!(evidence.indicator, "edr.share");
    assert_eq!(evidence.observed_at, NOW);
    assert_eq!(evidence.source, "edr");
    verify_evidence(&evidence)?;
    Ok(())
}


#[test]
fn a_missing_value_is_not_assessable_without_evidence() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    let result = evaluate(&subject, None, None, at(NOW)?);
    assert_eq!(result.status, ControlStatus::NotAssessable);
    assert!(result.evidence.is_none());
    Ok(())
}


#[test]
fn a_stale_value_is_not_assessable_but_keeps_its_evidence() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    let exactly_at_limit = evaluate(&subject, Some(&indicator(HIGH_LIMIT, NOW - MAX_AGE_SECONDS)?), None, at(NOW)?);
    assert_eq!(exactly_at_limit.status, ControlStatus::Compliant);
    let stale = evaluate(&subject, Some(&indicator(HIGH_LIMIT, NOW - MAX_AGE_SECONDS - 1)?), None, at(NOW)?);
    assert_eq!(stale.status, ControlStatus::NotAssessable);
    assert!(stale.evidence.is_some());
    Ok(())
}


#[test]
fn a_value_from_the_future_is_not_assessable() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    let result = evaluate(&subject, Some(&indicator(HIGH_LIMIT, NOW + 1)?), None, at(NOW)?);
    assert_eq!(result.status, ControlStatus::NotAssessable);
    Ok(())
}


#[test]
fn a_non_finite_value_is_not_assessable() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(status_of(&subject, value)?, ControlStatus::NotAssessable);
    }
    Ok(())
}


#[test]
fn a_value_of_another_indicator_is_not_assessable() -> TestResult {
    let subject = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    let mut other = indicator(HIGH_LIMIT, NOW)?;
    other.name = "other".to_owned();
    let result = evaluate(&subject, Some(&other), None, at(NOW)?);
    assert_eq!(result.status, ControlStatus::NotAssessable);
    assert!(result.evidence.is_none());
    Ok(())
}


#[test]
fn an_incomplete_technical_control_is_not_assessable() -> TestResult {
    let value = indicator(HIGH_LIMIT, NOW)?;
    let mut without_thresholds = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    without_thresholds.compliant = None;
    let mut without_age = control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL));
    without_age.max_age_hours = None;
    for subject in [without_thresholds, without_age] {
        assert_eq!(evaluate(&subject, Some(&value), None, at(NOW)?).status, ControlStatus::NotAssessable);
    }
    Ok(())
}


#[test]
fn an_organisational_control_needs_manual_evidence() -> TestResult {
    let subject = organisational();
    assert_eq!(evaluate(&subject, None, None, at(NOW)?).status, ControlStatus::NotAssessable);
    let valid = manual(NOW + HOUR, "ciso")?;
    let result = evaluate(&subject, None, Some(&valid), at(NOW)?);
    assert_eq!(result.status, ControlStatus::Compliant);
    let evidence = result.evidence.ok_or("no evidence")?;
    assert_eq!(evidence.indicator, "manual:O1");
    assert_eq!(evidence.source, format!("owner=ciso;tenant=acme;review_until={}", NOW + HOUR));
    verify_evidence(&evidence)?;
    let later = evaluate(&subject, None, Some(&manual(NOW + HOUR + HOUR, "ciso")?), at(NOW)?);
    assert_ne!(later.evidence.ok_or("no evidence")?.sha256, evidence.sha256);
    let mut foreign = manual(NOW + HOUR, "ciso")?;
    foreign.tenant = "other".to_owned();
    let other = evaluate(&subject, None, Some(&foreign), at(NOW)?);
    assert_ne!(other.evidence.ok_or("no evidence")?.sha256, evidence.sha256);
    Ok(())
}


#[test]
fn an_expired_review_date_is_not_assessable() -> TestResult {
    let subject = organisational();
    for review_until in [NOW, NOW - HOUR] {
        let result = evaluate(&subject, None, Some(&manual(review_until, "ciso")?), at(NOW)?);
        assert_eq!(result.status, ControlStatus::NotAssessable);
        assert!(result.evidence.is_some());
    }
    Ok(())
}


#[test]
fn manual_evidence_needs_an_owner_and_the_right_control() -> TestResult {
    let subject = organisational();
    let blank = manual(NOW + HOUR, "  ")?;
    assert_eq!(evaluate(&subject, None, Some(&blank), at(NOW)?).status, ControlStatus::NotAssessable);
    let mut other = manual(NOW + HOUR, "ciso")?;
    other.control = "O2".to_owned();
    let result = evaluate(&subject, None, Some(&other), at(NOW)?);
    assert_eq!(result.status, ControlStatus::NotAssessable);
    assert!(result.evidence.is_none());
    Ok(())
}


fn framework() -> Framework {
    Framework {
        framework: "demo".to_owned(),
        version: VERSION,
        controls: vec![
            control(Threshold::AtLeast(HIGH_LIMIT), Threshold::AtLeast(HIGH_PARTIAL)),
            organisational(),
        ],
    }
}


#[test]
fn a_framework_is_evaluated_for_one_tenant() -> TestResult {
    let report = evaluate_framework(
        "acme",
        &framework(),
        &[indicator(HIGH_LIMIT, NOW)?],
        &[manual(NOW + HOUR, "ciso")?],
        at(NOW)?,
    )?;
    assert_eq!(report.tenant, "acme");
    assert_eq!(report.framework, "demo");
    assert_eq!(report.version, VERSION);
    let statuses: Vec<ControlStatus> = report.results.iter().map(|result| result.status).collect();
    assert_eq!(statuses, [ControlStatus::Compliant, ControlStatus::Compliant]);
    let empty = evaluate_framework("acme", &framework(), &[], &[], at(NOW)?)?;
    assert!(empty.results.iter().all(|result| result.status == ControlStatus::NotAssessable));
    Ok(())
}


#[test]
fn an_invalid_tenant_is_refused() -> TestResult {
    for tenant in ["-x", "", "a b"] {
        assert!(matches!(
            evaluate_framework(tenant, &framework(), &[], &[], at(NOW)?),
            Err(GrcError::Tenant(_))
        ));
    }
    Ok(())
}


#[test]
fn an_input_of_another_tenant_is_refused() -> TestResult {
    let mut foreign_indicator = indicator(HIGH_LIMIT, NOW)?;
    foreign_indicator.tenant = "other".to_owned();
    let refused_indicator = evaluate_framework("acme", &framework(), &[foreign_indicator], &[], at(NOW)?);
    assert!(matches!(refused_indicator, Err(GrcError::TenantMismatch)));
    let mut foreign_manual = manual(NOW + HOUR, "ciso")?;
    foreign_manual.tenant = "other".to_owned();
    let refused_manual = evaluate_framework("acme", &framework(), &[indicator(HIGH_LIMIT, NOW)?], &[foreign_manual], at(NOW)?);
    assert!(matches!(refused_manual, Err(GrcError::TenantMismatch)));
    Ok(())
}


#[test]
fn a_repeated_input_is_refused() -> TestResult {
    let twice = [indicator(HIGH_LIMIT, NOW)?, indicator(LOW_VALUE, NOW)?];
    assert!(matches!(
        evaluate_framework("acme", &framework(), &twice, &[], at(NOW)?),
        Err(GrcError::Duplicate)
    ));
    let records = [manual(NOW + HOUR, "ciso")?, manual(NOW + HOUR, "cto")?];
    assert!(matches!(
        evaluate_framework("acme", &framework(), &[], &records, at(NOW)?),
        Err(GrcError::Duplicate)
    ));
    Ok(())
}
