#[path = "common/types.rs"]
mod types;


use grc::error::GrcError;
use grc::model::{ControlResult, ControlStatus, Report};
use grc::render::{action_status_name, level_name, write_risks};
use grc::risk::{Action, ActionStatus, Register, Risk, Treatment};
use grc::risk_eval::{evaluate_risks, risk_level, RiskLevel};
use std::io::Write;
use time::format_description::well_known::Iso8601;
use time::Date;
use types::TestResult;


const LOW_EDGE: u8 = 4;


const MEDIUM_LOW_EDGE: u8 = 5;


const MEDIUM_HIGH_EDGE: u8 = 9;


const HIGH_LOW_EDGE: u8 = 10;


const HIGH_HIGH_EDGE: u8 = 16;


const CRITICAL_LOW_EDGE: u8 = 20;


const CRITICAL_MAX: u8 = 25;


const LIKELIHOOD: u8 = 5;


const IMPACT: u8 = 4;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk full"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


struct BudgetWriter {
    remaining: usize,
}


impl Write for BudgetWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() <= self.remaining {
            self.remaining -= buffer.len();
            Ok(buffer.len())
        } else {
            Err(std::io::Error::other("disk full"))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn day(text: &str) -> Result<Date, time::error::Parse> {
    Date::parse(text, &Iso8601::DATE)
}


fn report(statuses: &[(&str, ControlStatus)]) -> Report {
    Report {
        tenant: "acme".to_owned(),
        framework: "demo".to_owned(),
        version: 1,
        results: statuses
            .iter()
            .map(|(control, status)| ControlResult {
                control: (*control).to_owned(),
                status: *status,
                evidence: None,
            })
            .collect(),
    }
}


fn risk(controls: &[&str], treatment: Treatment) -> Result<Risk, time::error::Parse> {
    Ok(Risk {
        id: "R1".to_owned(),
        title: "Unpatched flaws".to_owned(),
        likelihood: LIKELIHOOD,
        impact: IMPACT,
        treatment,
        owner: "ciso".to_owned(),
        controls: controls.iter().map(|control| (*control).to_owned()).collect(),
        review_by: day("2026-12-01")?,
    })
}


fn action(id: &str, due: &str, status: ActionStatus) -> Result<Action, time::error::Parse> {
    Ok(Action {
        id: id.to_owned(),
        risk: "R1".to_owned(),
        control: None,
        title: "Patch".to_owned(),
        owner: "ciso".to_owned(),
        due: day(due)?,
        status,
        done_on: if status == ActionStatus::Done { Some(day("2026-10-01")?) } else { None },
    })
}


fn register(risks: Vec<Risk>, actions: Vec<Action>) -> Register {
    Register {
        tenant: "acme".to_owned(),
        risks,
        actions,
    }
}


#[test]
fn bands_have_fixed_edges() -> TestResult {
    assert_eq!(risk_level(1), RiskLevel::Low);
    assert_eq!(risk_level(LOW_EDGE), RiskLevel::Low);
    assert_eq!(risk_level(MEDIUM_LOW_EDGE), RiskLevel::Medium);
    assert_eq!(risk_level(MEDIUM_HIGH_EDGE), RiskLevel::Medium);
    assert_eq!(risk_level(HIGH_LOW_EDGE), RiskLevel::High);
    assert_eq!(risk_level(HIGH_HIGH_EDGE), RiskLevel::High);
    assert_eq!(risk_level(CRITICAL_LOW_EDGE), RiskLevel::Critical);
    assert_eq!(risk_level(CRITICAL_MAX), RiskLevel::Critical);
    Ok(())
}


#[test]
fn the_score_is_likelihood_times_impact() -> TestResult {
    let compliant = report(&[("EDR", ControlStatus::Compliant)]);
    let result = evaluate_risks(
        &register(vec![risk(&["EDR"], Treatment::Mitigate)?], vec![]),
        &compliant,
        day("2026-11-14")?,
    )?;
    let first = result.risks.first().ok_or("no risk")?;
    assert_eq!(first.score, CRITICAL_LOW_EDGE);
    assert_eq!(first.level, RiskLevel::Critical);
    assert!(!first.gap);
    assert!(!first.uncovered);
    assert!(!first.review_overdue);
    Ok(())
}


#[test]
fn any_status_but_compliant_is_a_gap_and_a_missing_control_too() -> TestResult {
    let today = day("2026-11-14")?;
    for status in [
        ControlStatus::NonCompliant,
        ControlStatus::PartiallyCompliant,
        ControlStatus::NotAssessable,
    ] {
        let current = report(&[("EDR", ControlStatus::Compliant), ("KEV", status)]);
        let result = evaluate_risks(&register(vec![risk(&["EDR", "KEV"], Treatment::Mitigate)?], vec![]), &current, today)?;
        assert!(result.risks.first().ok_or("no risk")?.gap, "{status:?}");
    }
    let missing = report(&[("EDR", ControlStatus::Compliant)]);
    let result = evaluate_risks(&register(vec![risk(&["KEV"], Treatment::Mitigate)?], vec![]), &missing, today)?;
    assert!(result.risks.first().ok_or("no risk")?.gap);
    let none = evaluate_risks(&register(vec![risk(&[], Treatment::Mitigate)?], vec![]), &missing, today)?;
    assert!(!none.risks.first().ok_or("no risk")?.gap);
    Ok(())
}


#[test]
fn uncovered_needs_a_gap_mitigation_and_no_pending_action() -> TestResult {
    let today = day("2026-11-14")?;
    let gap = report(&[("EDR", ControlStatus::NonCompliant)]);
    let uncovered = |treatment: Treatment, actions: Vec<Action>| -> Result<bool, Box<dyn std::error::Error>> {
        let result = evaluate_risks(&register(vec![risk(&["EDR"], treatment)?], actions), &gap, today)?;
        Ok(result.risks.first().ok_or("no risk")?.uncovered)
    };
    assert!(uncovered(Treatment::Mitigate, vec![])?);
    assert!(uncovered(Treatment::Mitigate, vec![action("A1", "2026-12-01", ActionStatus::Done)?])?);
    assert!(!uncovered(Treatment::Mitigate, vec![action("A1", "2026-12-01", ActionStatus::Open)?])?);
    assert!(!uncovered(
        Treatment::Mitigate,
        vec![action("A1", "2026-12-01", ActionStatus::InProgress)?]
    )?);
    for treatment in [Treatment::Accept, Treatment::Transfer, Treatment::Avoid] {
        assert!(!uncovered(treatment, vec![])?, "{treatment:?}");
    }
    let compliant = report(&[("EDR", ControlStatus::Compliant)]);
    let result = evaluate_risks(&register(vec![risk(&["EDR"], Treatment::Mitigate)?], vec![]), &compliant, today)?;
    assert!(!result.risks.first().ok_or("no risk")?.uncovered);
    Ok(())
}


#[test]
fn an_action_due_today_is_not_overdue_and_yesterday_is() -> TestResult {
    let today = day("2026-11-14")?;
    let actions = vec![
        action("TODAY", "2026-11-14", ActionStatus::Open)?,
        action("YESTERDAY", "2026-11-13", ActionStatus::Open)?,
        action("DONE", "2026-11-13", ActionStatus::Done)?,
        action("LATE", "2026-11-13", ActionStatus::InProgress)?,
    ];
    let result = evaluate_risks(&register(vec![risk(&[], Treatment::Accept)?], actions), &report(&[]), today)?;
    let flags: Vec<(&str, bool)> = result
        .risks
        .first()
        .ok_or("no risk")?
        .actions
        .iter()
        .map(|item| (item.id.as_str(), item.overdue))
        .collect();
    assert_eq!(flags, vec![("TODAY", false), ("YESTERDAY", true), ("DONE", false), ("LATE", true)]);
    Ok(())
}


#[test]
fn a_review_date_before_today_is_overdue_and_today_is_not() -> TestResult {
    let current = register(vec![risk(&[], Treatment::Accept)?], vec![]);
    let on_day = evaluate_risks(&current, &report(&[]), day("2026-12-01")?)?;
    assert!(!on_day.risks.first().ok_or("no risk")?.review_overdue);
    let after = evaluate_risks(&current, &report(&[]), day("2026-12-02")?)?;
    assert!(after.risks.first().ok_or("no risk")?.review_overdue);
    Ok(())
}


#[test]
fn actions_of_another_risk_are_not_attached() -> TestResult {
    let mut other = action("A1", "2026-12-01", ActionStatus::Open)?;
    other.risk = "R2".to_owned();
    let result = evaluate_risks(
        &register(vec![risk(&[], Treatment::Accept)?], vec![other]),
        &report(&[]),
        day("2026-11-14")?,
    )?;
    assert!(result.risks.first().ok_or("no risk")?.actions.is_empty());
    Ok(())
}


#[test]
fn a_tenant_mismatch_or_an_invalid_tenant_is_refused() -> TestResult {
    let mut foreign = register(vec![risk(&[], Treatment::Accept)?], vec![]);
    foreign.tenant = "other".to_owned();
    assert!(matches!(
        evaluate_risks(&foreign, &report(&[]), day("2026-11-14")?),
        Err(GrcError::TenantMismatch)
    ));
    foreign.tenant = "-x".to_owned();
    assert!(matches!(
        evaluate_risks(&foreign, &report(&[]), day("2026-11-14")?),
        Err(GrcError::Tenant(_))
    ));
    Ok(())
}


#[test]
fn risks_render_one_line_each_then_their_actions() -> TestResult {
    let gap = report(&[("EDR", ControlStatus::NonCompliant)]);
    let current = register(
        vec![risk(&["EDR"], Treatment::Mitigate)?],
        vec![action("A1", "2026-11-01", ActionStatus::Open)?],
    );
    let result = evaluate_risks(&current, &gap, day("2026-12-02")?)?;
    let mut out = Vec::new();
    write_risks(&mut out, &result)?;
    let out_text = String::from_utf8(out)?;
    assert_eq!(
        out_text,
        "risk\tR1\tcritical\tscore=20\tgap=true\tuncovered=false\treview_overdue=true\n  action\tA1\topen\tdue=2026-11-01\toverdue=true\n"
    );
    assert!(write_risks(&mut FailingWriter, &result).is_err());
    let first_line = out_text.lines().next().ok_or("no line")?.len() + 1;
    assert!(write_risks(&mut BudgetWriter { remaining: first_line }, &result).is_err());
    let no_actions = evaluate_risks(&register(vec![risk(&["EDR"], Treatment::Mitigate)?], vec![]), &gap, day("2026-11-14")?)?;
    assert!(write_risks(&mut FailingWriter, &no_actions).is_err());
    Ok(())
}


#[test]
fn names_cover_every_level_and_status() -> TestResult {
    assert_eq!(
        [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High, RiskLevel::Critical].map(level_name),
        ["low", "medium", "high", "critical"]
    );
    assert_eq!(
        [ActionStatus::Open, ActionStatus::InProgress, ActionStatus::Done].map(action_status_name),
        ["open", "in progress", "done"]
    );
    Ok(())
}
