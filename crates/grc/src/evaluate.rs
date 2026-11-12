use crate::error::GrcError;
use crate::evidence::make_evidence;
use crate::model::{Control, ControlKind, ControlResult, ControlStatus, Framework, IndicatorValue, ManualEvidence, Report, Threshold};
use core_pg::scope::{tenant_of, tenant_scope};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};


pub const MANUAL_INDICATOR_PREFIX: &str = "manual:";


pub const MANUAL_VALUE: f64 = 1.0;


/// A threshold is met at its boundary: `at_least` is `>=`, `at_most` is `<=`.
pub fn threshold_met(threshold: &Threshold, value: f64) -> bool {
    match threshold {
        Threshold::AtLeast(limit) => value >= *limit,
        Threshold::AtMost(limit) => value <= *limit,
    }
}


pub fn grade(compliant: &Threshold, partial: &Threshold, value: f64) -> ControlStatus {
    if threshold_met(compliant, value) {
        ControlStatus::Compliant
    } else if threshold_met(partial, value) {
        ControlStatus::PartiallyCompliant
    } else {
        ControlStatus::NonCompliant
    }
}


/// Not assessable: a non-finite value, one observed after `now`, or one older than `max_age`.
pub fn usable(value: &IndicatorValue, max_age: Duration, now: OffsetDateTime) -> bool {
    let age = now - value.observed_at;
    value.value.is_finite() && age >= Duration::ZERO && age <= max_age
}


fn evaluate_technical(control: &Control, value: Option<&IndicatorValue>, now: OffsetDateTime) -> ControlResult {
    let thresholds = control.compliant.as_ref().zip(control.partial.as_ref());
    let max_age = control.max_age_hours.map(|hours| Duration::hours(i64::from(hours)));
    let matching = value.filter(|observed| Some(&observed.name) == control.indicator.as_ref());
    let (status, evidence) = match (matching, thresholds, max_age) {
        (Some(observed), Some((compliant, partial)), Some(limit)) => {
            let status = if usable(observed, limit, now) {
                grade(compliant, partial, observed.value)
            } else {
                ControlStatus::NotAssessable
            };
            let evidence = make_evidence(&observed.name, observed.value, observed.observed_at.unix_timestamp(), &observed.source);
            (status, Some(evidence))
        }
        _ => (ControlStatus::NotAssessable, None),
    };
    ControlResult {
        control: control.id.clone(),
        status,
        evidence,
    }
}


fn evaluate_organisational(control: &Control, manual: Option<&ManualEvidence>, now: OffsetDateTime) -> ControlResult {
    let (status, evidence) = match manual.filter(|record| record.control == control.id) {
        Some(record) => {
            let status = if record.review_until > now && !record.owner.trim().is_empty() {
                ControlStatus::Compliant
            } else {
                ControlStatus::NotAssessable
            };
            let indicator = format!("{MANUAL_INDICATOR_PREFIX}{}", control.id);
            let evidence = make_evidence(&indicator, MANUAL_VALUE, record.recorded_at.unix_timestamp(), &record.owner);
            (status, Some(evidence))
        }
        None => (ControlStatus::NotAssessable, None),
    };
    ControlResult {
        control: control.id.clone(),
        status,
        evidence,
    }
}


pub fn evaluate(control: &Control, value: Option<&IndicatorValue>, manual: Option<&ManualEvidence>, now: OffsetDateTime) -> ControlResult {
    match control.kind {
        ControlKind::Technical => evaluate_technical(control, value, now),
        ControlKind::Organisational => evaluate_organisational(control, manual, now),
    }
}


fn all_unique<'a>(names: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    let mut remaining = names;
    remaining.all(|name| seen.insert(name))
}


/// Every input must carry the tenant and be unique by name or control; one foreign or repeated input refuses the whole run.
pub fn evaluate_framework(
    tenant: &str,
    framework: &Framework,
    indicators: &[IndicatorValue],
    manual: &[ManualEvidence],
    now: OffsetDateTime,
) -> Result<Report, GrcError> {
    let scope = tenant_scope(tenant)?;
    let expected = tenant_of(&scope);
    let own_tenant = indicators.iter().all(|value| value.tenant == expected) && manual.iter().all(|record| record.tenant == expected);
    let unique = all_unique(indicators.iter().map(|value| value.name.as_str())) && all_unique(manual.iter().map(|record| record.control.as_str()));
    if !own_tenant {
        Err(GrcError::TenantMismatch)
    } else if !unique {
        Err(GrcError::Duplicate)
    } else {
        let results = framework
            .controls
            .iter()
            .map(|control| {
                let value = indicators.iter().find(|candidate| Some(&candidate.name) == control.indicator.as_ref());
                let record = manual.iter().find(|candidate| candidate.control == control.id);
                evaluate(control, value, record, now)
            })
            .collect();
        Ok(Report {
            tenant: expected.to_owned(),
            framework: framework.framework.clone(),
            version: framework.version,
            results,
        })
    }
}
