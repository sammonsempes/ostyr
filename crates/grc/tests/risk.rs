#[path = "common/types.rs"]
mod types;


use grc::error::GrcError;
use grc::load::{is_owner, parse_framework, MAX_OWNER_BYTES};
use grc::model::Framework;
use grc::risk::{load_risks, parse_risks, ActionStatus, Treatment, MAX_ACTIONS, MAX_RISKS, MAX_RISK_CONTROLS};
use std::io::Write;
use types::TestResult;


const ACTION_COUNT: usize = 2;


const FRAMEWORK: &str = "framework: demo-1
version: 1
controls:
  - id: A.5.1
    title: Policies are written and reviewed
    kind: organisational
  - id: KEV-MTTF
    title: Known exploited flaws are fixed fast
    kind: technical
    indicator: kev.mean_time_to_fix_hours
    max_age_hours: 24
    compliant:
      at_most: 72
    partial:
      at_most: 168
  - id: EDR
    title: Share of devices with anti-malware
    kind: technical
    indicator: edr.share
    max_age_hours: 48
    compliant: {at_least: 95}
    partial: {at_least: 80}
";


const REGISTER: &str = "tenant: acme
risks:
  - id: R1
    title: Unpatched flaws
    likelihood: 5
    impact: 4
    treatment: mitigate
    owner: ciso
    controls: [KEV-MTTF, EDR]
    review_by: 2026-12-01
actions:
  - id: AC1
    risk: R1
    control: KEV-MTTF
    title: Patch the exposed hosts
    owner: it.ops@example.org
    due: 2026-11-01
    status: open
  - id: AC2
    risk: R1
    title: Review the patch cadence
    owner: ciso
    due: 2026-10-01
    status: done
    done_on: 2026-09-30
";


fn framework() -> Result<Framework, GrcError> {
    parse_framework(&mut FRAMEWORK.as_bytes(), "f.yaml")
}


fn reason_of(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    match parse_risks(&mut text.as_bytes(), "r.yaml", &framework()?) {
        Err(GrcError::Invalid { reason, .. }) => Ok(reason),
        other => Err(format!("expected an Invalid error, got {other:?}").into()),
    }
}


#[test]
fn a_valid_register_loads() -> TestResult {
    let register = parse_risks(&mut REGISTER.as_bytes(), "r.yaml", &framework()?)?;
    assert_eq!(register.tenant, "acme");
    assert_eq!(register.risks.len(), 1);
    assert_eq!(register.actions.len(), ACTION_COUNT);
    let risk = register.risks.first().ok_or("no risk")?;
    assert_eq!(risk.treatment, Treatment::Mitigate);
    assert_eq!(risk.controls.len(), ACTION_COUNT);
    assert_eq!(register.actions.first().ok_or("no action")?.status, ActionStatus::Open);
    assert_eq!(register.actions.get(1).ok_or("no action")?.status, ActionStatus::Done);
    assert!(register.actions.get(1).ok_or("no action")?.done_on.is_some());
    Ok(())
}


#[test]
fn a_register_loads_from_a_file_and_a_missing_file_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("risks.yaml");
    std::fs::File::create(&path)?.write_all(REGISTER.as_bytes())?;
    assert_eq!(load_risks(&path, &framework()?)?.risks.len(), 1);
    assert!(matches!(
        load_risks(&directory.path().join("absent.yaml"), &framework()?),
        Err(GrcError::Config(_))
    ));
    Ok(())
}


#[test]
fn an_unknown_risk_is_refused_with_the_index() -> TestResult {
    let text = REGISTER.replace("risk: R1\n    title: Review", "risk: R9\n    title: Review");
    assert_eq!(reason_of(&text)?, "actions[1]: unknown risk");
    Ok(())
}


#[test]
fn an_unknown_control_is_refused_with_the_index_and_never_the_value() -> TestResult {
    let in_risk = REGISTER.replace("[KEV-MTTF, EDR]", "[KEV-MTTF, SECRET-NAME]");
    let reason = reason_of(&in_risk)?;
    assert_eq!(reason, "risks[0]: unknown control");
    assert!(!reason.contains("SECRET-NAME"));
    let in_action = REGISTER.replace("control: KEV-MTTF", "control: SECRET-NAME");
    assert_eq!(reason_of(&in_action)?, "actions[0]: unknown control");
    Ok(())
}


#[test]
fn a_duplicate_id_is_refused() -> TestResult {
    let actions = REGISTER.replace("id: AC2", "id: AC1");
    assert_eq!(reason_of(&actions)?, "actions[1]: duplicate id");
    let second_risk = "  - id: R1\n    title: Again\n    likelihood: 1\n    impact: 1\n    treatment: accept\n    owner: ciso\n    controls: []\n    review_by: 2026-12-01\nactions:";
    let risks = REGISTER.replace("actions:", second_risk);
    assert_eq!(reason_of(&risks)?, "risks[1]: duplicate id");
    Ok(())
}


#[test]
fn done_on_and_done_must_agree() -> TestResult {
    let without_status = REGISTER.replace("status: open", "status: open\n    done_on: 2026-10-30");
    assert_eq!(reason_of(&without_status)?, "actions[0]: done_on is only allowed on a done action");
    let without_date = REGISTER.replace("\n    done_on: 2026-09-30", "");
    assert_eq!(reason_of(&without_date)?, "actions[1]: a done action needs done_on");
    let in_progress = REGISTER.replace("status: open", "status: in_progress");
    assert!(parse_risks(&mut in_progress.as_bytes(), "r.yaml", &framework()?).is_ok());
    Ok(())
}


#[test]
fn bad_fields_are_refused_by_index() -> TestResult {
    assert_eq!(reason_of(&REGISTER.replace("id: R1", "id: -x"))?, "risks[0]: invalid id");
    assert_eq!(
        reason_of(&REGISTER.replace("Unpatched flaws", "\"a\\u202Eb\""))?,
        "risks[0]: invalid title"
    );
    assert_eq!(
        reason_of(&REGISTER.replace("likelihood: 5", "likelihood: 0"))?,
        "risks[0]: likelihood and impact must be between 1 and 5"
    );
    assert_eq!(
        reason_of(&REGISTER.replace("impact: 4", "impact: 6"))?,
        "risks[0]: likelihood and impact must be between 1 and 5"
    );
    assert_eq!(
        reason_of(&REGISTER.replace("owner: ciso\n    controls", "owner: Ciso\n    controls"))?,
        "risks[0]: invalid owner"
    );
    assert_eq!(reason_of(&REGISTER.replace("id: AC1", "id: .x"))?, "actions[0]: invalid id");
    assert_eq!(
        reason_of(&REGISTER.replace("Patch the exposed hosts", "\" \""))?,
        "actions[0]: invalid title"
    );
    assert_eq!(
        reason_of(&REGISTER.replace("it.ops@example.org", "bob smith"))?,
        "actions[0]: invalid owner"
    );
    Ok(())
}


#[test]
fn an_owner_outside_the_allowlist_is_refused() -> TestResult {
    let long = "a".repeat(MAX_OWNER_BYTES + 1);
    let exact = "a".repeat(MAX_OWNER_BYTES);
    for bad in ["Alice", "alice\u{3164}", "-x", "", long.as_str(), "a b", "a/b"] {
        assert!(!is_owner(bad), "{bad:?}");
    }
    for good in ["ciso", "it.ops@example.org", "a_b+c-d", "x9", exact.as_str()] {
        assert!(is_owner(good), "{good:?}");
    }
    let text = REGISTER.replace("owner: ciso\n    controls", "owner: \"alice\\u3164\"\n    controls");
    assert_eq!(reason_of(&text)?, "risks[0]: invalid owner");
    Ok(())
}


#[test]
fn unknown_fields_bad_dates_and_bad_enums_are_refused() -> TestResult {
    let framework = framework()?;
    for text in [
        REGISTER.replace("tenant: acme", "tenant: acme\nextra: 1"),
        REGISTER.replace("review_by: 2026-12-01", "review_by: soon"),
        REGISTER.replace("due: 2026-11-01", "due: 2026-13-01"),
        REGISTER.replace("done_on: 2026-09-30", "done_on: yesterday"),
        REGISTER.replace("treatment: mitigate", "treatment: ignore"),
        REGISTER.replace("status: open", "status: closed"),
    ] {
        assert!(
            matches!(parse_risks(&mut text.as_bytes(), "r.yaml", &framework), Err(GrcError::Config(_))),
            "{text}"
        );
    }
    Ok(())
}


#[test]
fn counts_at_the_cap_plus_one_are_refused() -> TestResult {
    let risk = "  - id: R<n>\n    title: t\n    likelihood: 1\n    impact: 1\n    treatment: accept\n    owner: ciso\n    controls: []\n    review_by: 2026-12-01\n";
    let action = "  - id: A<n>\n    risk: R0\n    title: t\n    owner: ciso\n    due: 2026-11-01\n    status: open\n";
    let risks: String = (0..=MAX_RISKS).map(|number| risk.replace("<n>", &number.to_string())).collect();
    let risk_text = format!("tenant: acme\nrisks:\n{risks}actions: []\n");
    assert_eq!(reason_of(&risk_text)?, format!("more than {MAX_RISKS} risks"));
    let actions: String = (0..=MAX_ACTIONS).map(|number| action.replace("<n>", &number.to_string())).collect();
    let action_text = format!("tenant: acme\nrisks:\n{}actions:\n{actions}", risk.replace("<n>", "0"));
    assert_eq!(reason_of(&action_text)?, format!("more than {MAX_ACTIONS} actions"));
    let controls = vec!["EDR"; MAX_RISK_CONTROLS + 1].join(", ");
    let control_text = REGISTER.replace("[KEV-MTTF, EDR]", &format!("[{controls}]"));
    assert_eq!(reason_of(&control_text)?, "risks[0]: too many controls");
    let at_cap = vec!["EDR"; MAX_RISK_CONTROLS].join(", ");
    let accepted = REGISTER.replace("[KEV-MTTF, EDR]", &format!("[{at_cap}]"));
    assert!(parse_risks(&mut accepted.as_bytes(), "r.yaml", &framework()?).is_ok());
    Ok(())
}
