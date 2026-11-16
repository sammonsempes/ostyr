#[path = "common/types.rs"]
mod types;


use grc::error::GrcError;
use grc::export::{escape_markdown, to_csv, to_json, to_markdown};
use grc::model::{Control, ControlKind, ControlResult, ControlStatus, Evidence, Framework, Report};
use grc::report::{build_report, ComplianceReport};
use grc::risk::{Action, ActionStatus, Register, Risk, Treatment};
use std::io::Write;
use time::format_description::well_known::Iso8601;
use time::Date;
use types::TestResult;


const DIGEST: &str = "abcdef0123";


const OBSERVED_AT: i64 = 1_700_000_000;


const MARKDOWN_COLUMNS: usize = 7;


const VALUE: f64 = 1.0;


const LIKELIHOOD: u8 = 2;


const IMPACT: u8 = 3;


const GAPS: usize = 3;


const UNASSESSED: usize = 2;


const NASTY_TITLES: [&str; 5] = [
    "=HYPERLINK(\"x\")",
    "| injected | cell",
    "[link](http://x)",
    "<script>alert(1)</script>",
    "two\nlines",
];


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk full"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("disk full"))
    }
}


struct FlushFailingWriter;


impl Write for FlushFailingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("disk full"))
    }
}


struct HeaderOnlyWriter {
    written: usize,
}


impl Write for HeaderOnlyWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.written == 0 {
            self.written += buffer.len();
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


fn control(id: &str, title: &str) -> Control {
    Control {
        id: id.to_owned(),
        title: title.to_owned(),
        kind: ControlKind::Technical,
        indicator: None,
        max_age_hours: None,
        compliant: None,
        partial: None,
    }
}


fn result(id: &str, status: ControlStatus, with_evidence: bool) -> ControlResult {
    ControlResult {
        control: id.to_owned(),
        status,
        evidence: with_evidence.then(|| Evidence {
            indicator: "i".to_owned(),
            value: VALUE,
            observed_at: OBSERVED_AT,
            source: "s".to_owned(),
            sha256: DIGEST.to_owned(),
        }),
    }
}


fn framework(titles: &[&str]) -> Framework {
    Framework {
        framework: "demo".to_owned(),
        version: 1,
        controls: titles
            .iter()
            .enumerate()
            .map(|(index, title)| control(&format!("C{index}"), title))
            .collect(),
    }
}


fn report(statuses: &[ControlStatus]) -> Report {
    Report {
        tenant: "acme".to_owned(),
        framework: "demo".to_owned(),
        version: 1,
        results: statuses
            .iter()
            .enumerate()
            .map(|(index, status)| result(&format!("C{index}"), *status, *status != ControlStatus::NotAssessable))
            .collect(),
    }
}


fn register(risks: Vec<Risk>, actions: Vec<Action>) -> Register {
    Register {
        tenant: "acme".to_owned(),
        risks,
        actions,
    }
}


fn risk(id: &str, controls: &[&str]) -> Result<Risk, time::error::Parse> {
    Ok(Risk {
        id: id.to_owned(),
        title: "t".to_owned(),
        likelihood: LIKELIHOOD,
        impact: IMPACT,
        treatment: Treatment::Mitigate,
        owner: "ciso".to_owned(),
        controls: controls.iter().map(|name| (*name).to_owned()).collect(),
        review_by: day("2026-12-01")?,
    })
}


fn action(id: &str, risk_id: &str, due: &str, status: ActionStatus) -> Result<Action, time::error::Parse> {
    Ok(Action {
        id: id.to_owned(),
        risk: risk_id.to_owned(),
        control: None,
        title: format!("Do {id}"),
        owner: "ciso".to_owned(),
        due: day(due)?,
        status,
        done_on: if status == ActionStatus::Done { Some(day("2026-10-01")?) } else { None },
    })
}


fn demo() -> Result<ComplianceReport, Box<dyn std::error::Error>> {
    let statuses = [
        ControlStatus::Compliant,
        ControlStatus::PartiallyCompliant,
        ControlStatus::NonCompliant,
        ControlStatus::NotAssessable,
    ];
    let register = register(
        vec![risk("R2", &["C1", "C2"])?, risk("R1", &["C1"])?],
        vec![
            action("A2", "R1", "2026-12-31", ActionStatus::InProgress)?,
            action("A1", "R1", "2026-11-01", ActionStatus::Open)?,
            action("A3", "R1", "2026-11-01", ActionStatus::Done)?,
            action("A4", "R2", "2026-12-31", ActionStatus::Open)?,
        ],
    );
    Ok(build_report(
        &framework(&["Patching", "Backups", "Logging", "Training"]),
        &report(&statuses),
        &register,
        day("2026-11-16")?,
    )?)
}


fn csv_of(report: &ComplianceReport) -> Result<String, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    to_csv(report, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}


fn json_of(report: &ComplianceReport) -> Result<String, Box<dyn std::error::Error>> {
    let mut buffer = Vec::new();
    to_json(report, &mut buffer)?;
    Ok(String::from_utf8(buffer)?)
}


#[test]
fn markdown_is_golden_and_deterministic() -> TestResult {
    let built = demo()?;
    let expected = "# Compliance report: demo v1

- Tenant: acme
- Generated: 2026-11-16

## Summary

- compliant: 1
- partially compliant: 1
- non compliant: 1
- not assessable: 1

## Controls

| Control | Title | Status | Evidence digest | Evidence time | Risks | Open actions |
| --- | --- | --- | --- | --- | --- | --- |
| C0 | Patching | compliant | abcdef0123 | 1700000000 |  |  |
| C1 | Backups | partially compliant | abcdef0123 | 1700000000 | R1, R2 | A1, A2, A4 |
| C2 | Logging | non compliant | abcdef0123 | 1700000000 | R2 | A4 |
| C3 | Training | not assessable | none | none |  |  |

## Gaps

| Control | Title | Status | Risks |
| --- | --- | --- | --- |
| C1 | Backups | partially compliant | R1, R2 |
| C2 | Logging | non compliant | R2 |
| C3 | Training | not assessable |  |

## Action plan

| Control | Risk | Action | Title | Owner | Status | Due | Overdue |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | R1 | A1 | Do A1 | ciso | open | 2026-11-01 | true |
| C1 | R1 | A2 | Do A2 | ciso | in progress | 2026-12-31 | false |
| C1 | R2 | A4 | Do A4 | ciso | open | 2026-12-31 | false |
| C2 | R2 | A4 | Do A4 | ciso | open | 2026-12-31 | false |
";
    assert_eq!(to_markdown(&built), expected);
    assert_eq!(to_markdown(&demo()?), to_markdown(&built));
    Ok(())
}


#[test]
fn csv_is_golden_and_deterministic() -> TestResult {
    let built = demo()?;
    let expected = "control,title,status,evidence_digest,evidence_time,linked_risks,open_actions
C0,Patching,compliant,abcdef0123,1700000000,,
C1,Backups,partially compliant,abcdef0123,1700000000,R1 R2,A1 A2 A4
C2,Logging,non compliant,abcdef0123,1700000000,R2,A4
C3,Training,not assessable,none,none,,
";
    assert_eq!(csv_of(&built)?, expected);
    assert_eq!(csv_of(&demo()?)?, csv_of(&built)?);
    Ok(())
}


#[test]
fn json_carries_the_whole_report_and_is_deterministic() -> TestResult {
    let built = demo()?;
    let text = json_of(&built)?;
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(parsed.pointer("/tenant"), Some(&serde_json::json!("acme")));
    assert_eq!(parsed.pointer("/generated"), Some(&serde_json::json!("2026-11-16")));
    assert_eq!(parsed.pointer("/counts/not_assessable"), Some(&serde_json::json!(1)));
    assert_eq!(parsed.pointer("/controls/3/evidence_digest"), Some(&serde_json::Value::Null));
    assert_eq!(parsed.pointer("/controls/1/open_actions"), Some(&serde_json::json!(["A1", "A2", "A4"])));
    assert_eq!(parsed.pointer("/gaps").and_then(serde_json::Value::as_array).map(Vec::len), Some(GAPS));
    assert_eq!(parsed.pointer("/plan/0/overdue"), Some(&serde_json::json!(true)));
    assert_eq!(parsed.pointer("/plan/1/overdue"), Some(&serde_json::json!(false)));
    assert_eq!(json_of(&demo()?)?, text);
    Ok(())
}


#[test]
fn hostile_titles_are_neutralised_everywhere() -> TestResult {
    let statuses = [ControlStatus::Compliant; NASTY_TITLES.len()];
    let built = build_report(
        &framework(&NASTY_TITLES),
        &report(&statuses),
        &register(vec![], vec![]),
        day("2026-11-16")?,
    )?;
    let csv_text = csv_of(&built)?;
    let mut reader = csv::Reader::from_reader(csv_text.as_bytes());
    let titles: Vec<String> = reader
        .records()
        .map(|record| record.map(|fields| fields.get(1).unwrap_or("").to_owned()))
        .collect::<Result<_, _>>()?;
    assert_eq!(titles.first().map(String::as_str), Some("'=HYPERLINK(\"x\")"));
    assert_eq!(titles.get(1).map(String::as_str), Some("| injected | cell"));
    assert_eq!(titles.get(NASTY_TITLES.len() - 1).map(String::as_str), Some("two\nlines"));
    let markdown = to_markdown(&built);
    assert!(!markdown.contains("<script>"));
    assert!(!markdown.contains("[link]"));
    assert!(markdown.contains("\\| injected \\| cell"));
    markdown.lines().filter(|line| line.starts_with("| C")).try_for_each(|line| {
        let columns = line.replace("\\|", "").matches('|').count() - 1;
        if columns == MARKDOWN_COLUMNS {
            Ok(())
        } else {
            Err(format!("wrong column count: {line}"))
        }
    })?;
    let json = json_of(&built)?;
    assert!(json.contains("<script>alert(1)</script>"));
    assert!(json.contains("=HYPERLINK(\\\"x\\\")"));
    Ok(())
}


#[test]
fn escape_covers_every_special_and_line_breaks() -> TestResult {
    assert_eq!(
        escape_markdown("a|b\\c`d*e_f[g]h<i>j&k~l"),
        "a\\|b\\\\c\\`d\\*e\\_f\\[g\\]h\\<i\\>j\\&k\\~l"
    );
    assert_eq!(escape_markdown("x\r\ny"), "x  y");
    Ok(())
}


#[test]
fn an_empty_framework_gives_empty_sections() -> TestResult {
    let built = build_report(&framework(&[]), &report(&[]), &register(vec![], vec![]), day("2026-11-16")?)?;
    assert!(built.controls.is_empty());
    let markdown = to_markdown(&built);
    assert!(markdown.contains("## Gaps\n\nNone.\n"));
    assert!(markdown.contains("## Action plan\n\nNone.\n"));
    assert_eq!(csv_of(&built)?.lines().count(), 1);
    Ok(())
}


#[test]
fn no_evidence_is_never_compliant() -> TestResult {
    let statuses = [ControlStatus::NotAssessable; UNASSESSED];
    let built = build_report(&framework(&["A", "B"]), &report(&statuses), &register(vec![], vec![]), day("2026-11-16")?)?;
    assert_eq!(built.counts.compliant, 0);
    assert_eq!(built.counts.not_assessable, UNASSESSED);
    assert_eq!(built.gaps.len(), UNASSESSED);
    assert!(built
        .controls
        .iter()
        .all(|row| row.evidence_digest.is_none() && row.status == "not assessable"));
    Ok(())
}


#[test]
fn a_control_missing_from_the_framework_has_an_empty_title() -> TestResult {
    let built = build_report(
        &framework(&[]),
        &report(&[ControlStatus::Compliant]),
        &register(vec![], vec![]),
        day("2026-11-16")?,
    )?;
    assert_eq!(built.controls.first().map(|row| row.title.as_str()), Some(""));
    Ok(())
}


#[test]
fn another_tenant_register_is_refused() -> TestResult {
    let mut other = register(vec![], vec![]);
    other.tenant = "globex".to_owned();
    let refused = build_report(&framework(&[]), &report(&[]), &other, day("2026-11-16")?);
    assert!(matches!(refused, Err(GrcError::TenantMismatch)));
    Ok(())
}


#[test]
fn write_failures_are_reported() -> TestResult {
    let built = demo()?;
    assert!(matches!(to_csv(&built, &mut FailingWriter), Err(GrcError::Csv(_))));
    assert!(matches!(to_csv(&built, &mut HeaderOnlyWriter { written: 0 }), Err(GrcError::Csv(_))));
    assert!(matches!(to_csv(&built, &mut FlushFailingWriter), Err(GrcError::Io(_))));
    assert!(matches!(to_json(&built, &mut FailingWriter), Err(GrcError::Serialize(_))));
    Ok(())
}
