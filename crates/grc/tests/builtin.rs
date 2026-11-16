#[path = "common/types.rs"]
mod types;


use grc::builtin::{builtin_framework, resolve_framework, BUILTIN, BUILTIN_COUNT, BUILTIN_PREFIX, KNOWN_INDICATORS};
use grc::error::GrcError;
use grc::evaluate::evaluate_framework;
use grc::load::MAX_ID_CHARS;
use grc::model::{ControlKind, ControlStatus, IndicatorValue};
use std::collections::BTreeSet;
use std::io::Write;
use time::OffsetDateTime;
use types::TestResult;


const NOW: i64 = 1_800_000_000;


const TITLE_LIMIT: usize = 80;


const LONG_FACTOR: usize = 4;


const COMPLIANT_VALUE: f64 = 0.97;


const PARTIAL_VALUE: f64 = 0.85;


const FAILING_VALUE: f64 = 0.5;


const COUNTS: [(&str, usize); BUILTIN_COUNT] = [
    ("nis2", 10),
    ("iso27001-2022", 93),
    ("gdpr", 3),
    ("anssi-hygiene", 42),
    ("cis-v8", 18),
    ("dora", 26),
];


fn indicator(name: &str, value: f64) -> Result<IndicatorValue, time::error::ComponentRange> {
    Ok(IndicatorValue {
        tenant: "acme".to_owned(),
        name: name.to_owned(),
        value,
        observed_at: OffsetDateTime::from_unix_timestamp(NOW)?,
        source: "test".to_owned(),
    })
}


#[test]
fn each_builtin_loads_with_its_control_count() -> TestResult {
    for (name, count) in COUNTS {
        let framework = builtin_framework(name)?;
        assert_eq!(framework.controls.len(), count, "{name}");
        assert_eq!(framework.framework, name);
    }
    assert_eq!(BUILTIN.len(), COUNTS.len());
    Ok(())
}


#[test]
fn indicators_match_the_vocabulary_both_ways() -> TestResult {
    let known: BTreeSet<&str> = KNOWN_INDICATORS.iter().copied().collect();
    let mut used = BTreeSet::new();
    for (name, _) in BUILTIN {
        for control in builtin_framework(name)?.controls {
            assert_eq!(control.kind == ControlKind::Technical, control.indicator.is_some());
            if let Some(indicator_name) = control.indicator {
                assert!(known.contains(indicator_name.as_str()), "{name} {indicator_name}");
                used.insert(indicator_name);
            }
        }
    }
    assert_eq!(used.len(), known.len());
    Ok(())
}


#[test]
fn titles_are_short() -> TestResult {
    for (name, _) in BUILTIN {
        for control in builtin_framework(name)?.controls {
            assert!(control.title.chars().count() <= TITLE_LIMIT, "{name} {}", control.id);
        }
    }
    Ok(())
}


#[test]
fn unknown_names_are_refused() -> TestResult {
    assert!(matches!(builtin_framework("nope"), Err(GrcError::UnknownBuiltin { .. })));
    assert!(matches!(resolve_framework("builtin:"), Err(GrcError::UnknownBuiltin { .. })));
    assert!(matches!(resolve_framework("builtin:nope"), Err(GrcError::UnknownBuiltin { .. })));
    let long = "x".repeat(MAX_ID_CHARS * LONG_FACTOR);
    match builtin_framework(&long) {
        Err(GrcError::UnknownBuiltin { name }) => assert_eq!(name.len(), MAX_ID_CHARS),
        other => assert!(other.is_err()),
    }
    Ok(())
}


#[test]
fn builtin_prefix_and_plain_path_resolve() -> TestResult {
    let named = resolve_framework(&format!("{BUILTIN_PREFIX}nis2"))?;
    assert_eq!(named, builtin_framework("nis2")?);
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(b"framework: mine\nversion: 1\ncontrols: []\n")?;
    let path = file.path().display().to_string();
    assert_eq!(resolve_framework(&path)?.framework, "mine");
    assert!(resolve_framework("/nonexistent/grc-framework.yaml").is_err());
    Ok(())
}


#[test]
fn iso_evaluation_with_a_frozen_clock() -> TestResult {
    let framework = builtin_framework("iso27001-2022")?;
    let values = [
        indicator("endpoint.full_protection_ratio", COMPLIANT_VALUE)?,
        indicator("hardening.mean_score_ratio", PARTIAL_VALUE)?,
        indicator("patch.on_time_ratio", FAILING_VALUE)?,
    ];
    let report = evaluate_framework("acme", &framework, &values, &[], OffsetDateTime::from_unix_timestamp(NOW)?)?;
    let status = |id: &str| report.results.iter().find(|result| result.control == id).map(|result| result.status);
    assert_eq!(status("A.8.7"), Some(ControlStatus::Compliant));
    assert_eq!(status("A.8.9"), Some(ControlStatus::PartiallyCompliant));
    assert_eq!(status("A.8.19"), Some(ControlStatus::NonCompliant));
    assert_eq!(status("A.5.1"), Some(ControlStatus::NotAssessable));
    assert_eq!(status("A.8.8"), Some(ControlStatus::NotAssessable));
    Ok(())
}
