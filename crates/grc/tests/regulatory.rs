#[path = "common/types.rs"]
mod types;


use grc::error::GrcError;
use grc::regulatory::{
    add_month, aware_field, build_regulatory, deadlines, format_utc, load_incident, parse_incident, render_drafts, status_at, status_label, to_json,
    Deadline, Incident, RegulatoryReport, Status, Step, DRAFT_HEADER, MAX_INCIDENT_BYTES, MAX_LIST_ITEMS, MAX_SUMMARY_CHARS,
};
use std::io::Write;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use types::TestResult;


const OUTSIDE_HOURS: i64 = 7;


const SOON_HOURS: i64 = 6;


const NIS2_COUNT: usize = 3;


const BOTH_COUNT: usize = 4;


const OVER_LIST: usize = 101;


const OVER_BYTES: usize = 300_000;


const OVER_SUMMARY: usize = 2_001;


const INCIDENT: &str = "case_id: INC-1
title: Ransomware on file server
aware_at: 2026-01-31T10:00:00Z
regimes: [nis2]
summary: Files encrypted.
affected_services: [files, backup]
personal_data:
  categories: [customer names]
  approximate_count: 120
cross_border: false
actions_taken: [host isolated]
contact:
  name: Alice Martin
  role: CISO
";


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk full"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("disk full"))
    }
}


fn parse(text: &str) -> Result<Incident, GrcError> {
    parse_incident(&mut text.as_bytes(), "incident.yaml")
}


fn reason_of(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    match parse(text) {
        Err(GrcError::Invalid { reason, .. }) => Ok(reason),
        Err(other) => Ok(other.to_string()),
        Ok(_) => Err("accepted".into()),
    }
}


fn at(text: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(text, &Rfc3339)
}


fn with_aware(aware: &str, regimes: &str) -> String {
    INCIDENT
        .replace("2026-01-31T10:00:00Z", aware)
        .replace("regimes: [nis2]", &format!("regimes: {regimes}"))
}


fn due_of(incident: &Incident, step: Step) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    deadlines(incident)?
        .into_iter()
        .find(|deadline| deadline.step == step)
        .map(|deadline| deadline.due)
        .ok_or_else(|| "no such step".into())
}


#[test]
fn the_month_step_clamps_to_the_last_day() -> TestResult {
    let january = parse(INCIDENT)?;
    assert_eq!(due_of(&january, Step::Nis2FinalReport)?, at("2026-02-28T10:00:00Z")?);
    assert_eq!(due_of(&january, Step::Nis2EarlyWarning)?, at("2026-02-01T10:00:00Z")?);
    assert_eq!(due_of(&january, Step::Nis2Notification)?, at("2026-02-03T10:00:00Z")?);
    let leap = parse(&with_aware("2028-01-31T10:00:00Z", "[nis2]"))?;
    assert_eq!(due_of(&leap, Step::Nis2FinalReport)?, at("2028-02-29T10:00:00Z")?);
    let december = parse(&with_aware("2026-12-15T10:00:00Z", "[nis2]"))?;
    assert_eq!(due_of(&december, Step::Nis2FinalReport)?, at("2027-01-15T10:00:00Z")?);
    Ok(())
}


#[test]
fn an_offset_time_is_normalised_and_the_year_end_is_crossed() -> TestResult {
    let incident = parse(&with_aware("2026-12-15T23:30:00+02:00", "[nis2]"))?;
    assert_eq!(incident.aware_at, at("2026-12-15T21:30:00Z")?);
    assert_eq!(due_of(&incident, Step::Nis2EarlyWarning)?, at("2026-12-16T21:30:00Z")?);
    let late = parse(&with_aware("2026-12-31T23:30:00Z", "[nis2]"))?;
    assert_eq!(due_of(&late, Step::Nis2EarlyWarning)?, at("2027-01-01T23:30:00Z")?);
    assert_eq!(due_of(&late, Step::Nis2FinalReport)?, at("2027-01-31T23:30:00Z")?);
    Ok(())
}


#[test]
fn a_deadline_beyond_year_9999_refuses_the_incident() -> TestResult {
    let incident = parse(&with_aware("9999-12-31T22:00:00Z", "[nis2]"))?;
    assert!(matches!(deadlines(&incident), Err(GrcError::Invalid { .. })));
    assert!(matches!(
        render_drafts(&incident, at("2026-01-01T00:00:00Z")?),
        Err(GrcError::Invalid { .. })
    ));
    assert!(add_month(at("9999-12-15T00:00:00Z")?).is_none());
    assert!(add_month(at("9999-11-15T00:00:00Z")?).is_some());
    Ok(())
}


#[test]
fn a_time_outside_the_supported_years_is_refused_at_load() -> TestResult {
    let text = with_aware("9999-12-31T23:00:00-02:00", "[nis2]");
    assert!(reason_of(&text)?.contains("aware_at"));
    let before = with_aware("0000-01-01T00:00:00+02:00", "[nis2]");
    assert!(reason_of(&before)?.contains("aware_at"));
    let garbage = with_aware("SECRET-TEXT", "[nis2]");
    let message = reason_of(&garbage)?;
    assert!(message.contains("aware_at") && !message.contains("SECRET-TEXT"));
    assert!(parse(&with_aware("0000-01-01T00:00:00Z", "[nis2]")).is_ok());
    Ok(())
}


#[test]
fn the_status_changes_at_each_boundary() -> TestResult {
    let incident = parse(INCIDENT)?;
    let deadline = deadlines(&incident)?.into_iter().next().ok_or("no deadline")?;
    let due = deadline.due;
    assert_eq!(status_at(&deadline, due - Duration::hours(OUTSIDE_HOURS)), Status::Due);
    assert_eq!(
        status_at(&deadline, due - Duration::hours(SOON_HOURS) - Duration::seconds(1)),
        Status::Due
    );
    assert_eq!(status_at(&deadline, due - Duration::hours(SOON_HOURS)), Status::DueSoon);
    assert_eq!(status_at(&deadline, due - Duration::seconds(1)), Status::DueSoon);
    assert_eq!(status_at(&deadline, due), Status::Overdue);
    assert_eq!(status_at(&deadline, due + Duration::hours(1)), Status::Overdue);
    assert_eq!(status_label(Status::Due), "due");
    assert_eq!(status_label(Status::DueSoon), "due soon");
    assert_eq!(status_label(Status::Overdue), "overdue");
    Ok(())
}


#[test]
fn only_the_selected_regimes_produce_steps() -> TestResult {
    assert_eq!(deadlines(&parse(INCIDENT)?)?.len(), NIS2_COUNT);
    let gdpr = parse(&with_aware("2026-01-31T10:00:00Z", "[gdpr]"))?;
    let steps = deadlines(&gdpr)?;
    assert_eq!(steps.len(), 1);
    assert_eq!(steps.first().map(|deadline| deadline.step), Some(Step::GdprNotification));
    assert_eq!(steps.first().map(|deadline| deadline.due), Some(at("2026-02-03T10:00:00Z")?));
    let both = parse(&with_aware("2026-01-31T10:00:00Z", "[gdpr, nis2]"))?;
    assert_eq!(deadlines(&both)?.len(), BOTH_COUNT);
    Ok(())
}


#[test]
fn the_markdown_holds_the_header_the_table_and_placeholders() -> TestResult {
    let both = parse(&with_aware("2026-01-31T10:00:00Z", "[nis2, gdpr]"))?;
    let text = render_drafts(&both, at("2026-02-03T04:00:00Z")?)?;
    assert!(text.starts_with(&format!("{DRAFT_HEADER}\n")));
    assert!(text.contains("| NIS 2 | NIS 2 early warning | 2026-02-01T10:00:00Z | overdue | Directive (EU) 2022/2555, Article 23(4)(a) |"));
    assert!(text.contains("| GDPR | GDPR notification to the supervisory authority | 2026-02-03T10:00:00Z | due soon |"));
    assert!(text.contains("Directive (EU) 2022/2555, Article 23(4)(d)"));
    assert!(text.contains("Regulation (EU) 2016/679, Article 33(1)"));
    assert!(text.contains("unlawful or malicious acts"));
    assert!(text.contains("[to complete: ...]"));
    assert!(text.contains("Likely consequences"));
    assert!(text.contains("- Personal data: customer names (approximately 120"));
    assert!(text.contains("- Cross-border, as declared by the operator: no"));
    let nis2_only = render_drafts(&parse(INCIDENT)?, at("2026-01-01T00:00:00Z")?)?;
    assert!(!nis2_only.contains("Personal data"));
    Ok(())
}


#[test]
fn missing_facts_become_placeholders() -> TestResult {
    let bare = INCIDENT
        .replace("affected_services: [files, backup]", "affected_services: []")
        .replace("actions_taken: [host isolated]", "actions_taken: []")
        .replace("cross_border: false", "cross_border: true")
        .replace("regimes: [nis2]", "regimes: [gdpr]")
        .replace("personal_data:\n  categories: [customer names]\n  approximate_count: 120\n", "");
    let text = render_drafts(&parse(&bare)?, at("2026-01-01T00:00:00Z")?)?;
    assert!(text.contains("- Affected services: [to complete: affected services]"));
    assert!(text.contains("- Actions taken: [to complete: actions taken]"));
    assert!(text.contains("- Personal data: [to complete: categories and approximate number of data subjects]"));
    assert!(text.contains("operator: yes"));
    Ok(())
}


#[test]
fn hostile_text_is_escaped_and_the_header_stays_first() -> TestResult {
    let hostile = INCIDENT.replace(
        "title: Ransomware on file server",
        "title: \"a | b\\n# DRAFT removed\\n[x](javascript:alert(1))\\r\\nend\"",
    );
    let text = render_drafts(&parse(&hostile)?, at("2026-01-01T00:00:00Z")?)?;
    assert!(text.starts_with(DRAFT_HEADER));
    assert!(text.contains("a \\| b # DRAFT removed \\[x\\](javascript:alert(1))  end"));
    assert!(!text.contains("\n# DRAFT removed"));
    assert!(!text.contains("[x]("));
    Ok(())
}


#[test]
fn bad_input_is_refused_with_the_field_and_never_the_text() -> TestResult {
    let unknown = INCIDENT.replace("cross_border: false", "cross_border: false\nsecret_field: x");
    let message = reason_of(&unknown)?;
    assert!(message.contains("secret_field") || message.contains("unknown"));
    let services = format!("[{}]", vec!["s"; OVER_LIST].join(", "));
    assert_eq!(
        reason_of(&INCIDENT.replace("[files, backup]", &services))?,
        "affected_services: too many entries"
    );
    let actions = format!("[{}]", vec!["s"; OVER_LIST].join(", "));
    assert_eq!(
        reason_of(&INCIDENT.replace("[host isolated]", &actions))?,
        "actions_taken: too many entries"
    );
    assert_eq!(MAX_LIST_ITEMS + 1, OVER_LIST);
    let long = "SECRET".repeat(OVER_SUMMARY);
    let summary = reason_of(&INCIDENT.replace("Files encrypted.", &long))?;
    assert_eq!(summary, "summary: invalid text");
    assert!(MAX_SUMMARY_CHARS < long.chars().count());
    assert_eq!(
        reason_of(&INCIDENT.replace("Ransomware on file server", "\"bad\\u0007bell\""))?,
        "title: invalid text"
    );
    assert_eq!(reason_of(&INCIDENT.replace("INC-1", "-bad"))?, "case_id: invalid identifier");
    assert_eq!(reason_of(&INCIDENT.replace("Alice Martin", "\"\\u202eAlice\""))?, "contact: invalid text");
    assert_eq!(
        reason_of(&INCIDENT.replace("role: CISO", "role: \"\\u202eCISO\""))?,
        "contact: invalid text"
    );
    assert_eq!(
        reason_of(&INCIDENT.replace("[host isolated]", "[\"\\u0007\"]"))?,
        "actions_taken: invalid text"
    );
    assert_eq!(
        reason_of(&INCIDENT.replace("[customer names]", "[\"\\u0007\"]"))?,
        "personal_data.categories: invalid text"
    );
    let categories = format!("[{}]", vec!["c"; OVER_LIST].join(", "));
    assert_eq!(
        reason_of(&INCIDENT.replace("[customer names]", &categories))?,
        "personal_data.categories: too many entries"
    );
    Ok(())
}


#[test]
fn regimes_are_checked() -> TestResult {
    assert_eq!(reason_of(&INCIDENT.replace("[nis2]", "[]"))?, "regimes: at least one is required");
    assert_eq!(reason_of(&INCIDENT.replace("[nis2]", "[nis2, gdpr, nis2]"))?, "regimes: too many entries");
    assert_eq!(reason_of(&INCIDENT.replace("[nis2]", "[nis2, nis2]"))?, "regimes: duplicate entry");
    Ok(())
}


#[test]
fn a_file_over_the_cap_is_refused_and_a_file_loads() -> TestResult {
    let big = format!("{INCIDENT}{}\n", " ".repeat(OVER_BYTES));
    assert!(u64::try_from(big.len())? > MAX_INCIDENT_BYTES);
    assert!(matches!(parse(&big), Err(GrcError::Config(_))));
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("incident.yaml");
    std::fs::File::create(&path)?.write_all(INCIDENT.as_bytes())?;
    assert_eq!(load_incident(&path)?.case_id, "INC-1");
    assert!(matches!(load_incident(&directory.path().join("absent.yaml")), Err(GrcError::Config(_))));
    Ok(())
}


#[test]
fn json_output_round_trips_and_a_failing_writer_is_reported() -> TestResult {
    let incident = parse(&with_aware("2026-01-31T10:00:00+01:00", "[nis2, gdpr]"))?;
    let report = build_regulatory(&incident, at("2026-02-02T00:00:00Z")?)?;
    let mut bytes = Vec::new();
    to_json(&report, &mut bytes)?;
    let back: RegulatoryReport = serde_json::from_slice(&bytes)?;
    assert_eq!(back, report);
    assert_eq!(back.header, DRAFT_HEADER);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value.pointer("/deadlines/0/deadline/step"),
        Some(&serde_json::json!("nis2_early_warning"))
    );
    assert_eq!(value.pointer("/incident/aware_at"), Some(&serde_json::json!("2026-01-31T09:00:00Z")));
    assert!(matches!(to_json(&report, &mut FailingWriter), Err(GrcError::Serialize(_))));
    let deadline: Deadline = back.deadlines.first().ok_or("none")?.deadline.clone();
    assert_eq!(deadline.reference, "Directive (EU) 2022/2555, Article 23(4)(a)");
    Ok(())
}


#[test]
fn the_time_field_rejects_a_non_string() -> TestResult {
    let result = aware_field(&mut serde_json::Deserializer::from_str("12"));
    assert!(result.is_err());
    assert_eq!(format_utc(at("2026-01-02T03:04:05Z")?), "2026-01-02T03:04:05Z");
    Ok(())
}
