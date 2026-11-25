#[path = "common/types.rs"]
mod types;


use compliance::alerting::is_id;
use compliance::evaluate::evaluate;
use compliance::load::load_baseline;
use compliance::model::{Baseline, Control, Framework, Target, Verdict};
use compliance::types::Row;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use time::OffsetDateTime;
use types::TestResult;


const ANSSI_FILE: &str = "baselines/anssi-linux.yaml";


const STIG_FILE: &str = "baselines/disa-stig-rhel9.yaml";


const FIXTURE_FILE: &str = "tests/fixtures/osquery-baselines.json";


const MINIMUM_CONTROLS: usize = 15;


const DISTINCT_DIVISOR: usize = 2;


#[derive(Deserialize)]
struct Fixture {
    pass: Vec<Row>,
    fail: Vec<Row>,
}


fn path_of(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}


fn fixtures() -> Result<BTreeMap<String, BTreeMap<String, Fixture>>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path_of(FIXTURE_FILE))?)?)
}


fn target() -> Target {
    Target {
        device: "lab".to_string(),
        tags: Vec::new(),
    }
}


fn verdict_of(control: &Control, rows: &[Row]) -> Verdict {
    evaluate(control, &[], &target(), OffsetDateTime::UNIX_EPOCH, Ok(rows))
}


fn load(relative: &str) -> Result<Baseline, Box<dyn std::error::Error>> {
    Ok(load_baseline(&path_of(relative))?)
}


fn check_baseline(relative: &str, framework: Framework) -> TestResult {
    let baseline = load(relative)?;
    assert!(baseline.controls.len() >= MINIMUM_CONTROLS);
    assert!(is_id(&baseline.name));
    baseline.controls.iter().for_each(|control| {
        assert!(is_id(&control.id), "{}", control.id);
        assert!(control.query.starts_with("SELECT "), "{}", control.id);
        assert!(!control.query.contains(';'), "{}", control.id);
        assert!(!control.frameworks.is_empty(), "{}", control.id);
        assert!(
            control.frameworks.iter().all(|reference| reference.framework == framework),
            "{}",
            control.id
        );
        assert!(control.correction.is_none(), "{}", control.id);
    });
    let queries: BTreeSet<&String> = baseline.controls.iter().map(|control| &control.query).collect();
    assert!(queries.len() > baseline.controls.len() / DISTINCT_DIVISOR);
    Ok(())
}


fn check_fixtures(relative: &str) -> TestResult {
    let baseline = load(relative)?;
    let all = fixtures()?;
    let cases = all.get(&baseline.name).ok_or("no fixtures for the baseline")?;
    let controls: BTreeSet<&String> = baseline.controls.iter().map(|control| &control.id).collect();
    assert_eq!(cases.keys().collect::<BTreeSet<&String>>(), controls);
    baseline.controls.iter().try_for_each(|control| -> TestResult {
        let case = cases.get(&control.id).ok_or("no case")?;
        assert_eq!(verdict_of(control, &case.pass), Verdict::Pass, "{} pass", control.id);
        assert!(matches!(verdict_of(control, &case.fail), Verdict::Fail { .. }), "{} fail", control.id);
        Ok(())
    })
}


#[test]
fn the_anssi_baseline_loads_through_strict_parsing() -> TestResult {
    check_baseline(ANSSI_FILE, Framework::Anssi)
}


#[test]
fn the_stig_baseline_loads_through_strict_parsing() -> TestResult {
    check_baseline(STIG_FILE, Framework::DisaStig)
}


#[test]
fn every_anssi_control_passes_and_fails_on_its_fixture() -> TestResult {
    check_fixtures(ANSSI_FILE)
}


#[test]
fn every_stig_control_passes_and_fails_on_its_fixture() -> TestResult {
    check_fixtures(STIG_FILE)
}


#[test]
fn a_failed_query_is_an_error_never_a_pass() -> TestResult {
    let baseline = load(ANSSI_FILE)?;
    let control = baseline.controls.first().ok_or("no control")?;
    let verdict = evaluate(control, &[], &target(), OffsetDateTime::UNIX_EPOCH, Err("no such table"));
    assert!(matches!(verdict, Verdict::Error { .. }));
    Ok(())
}
