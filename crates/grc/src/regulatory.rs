use crate::error::GrcError;
use crate::export::escape_markdown;
use crate::load::{is_identifier, is_printable_text, MAX_ID_CHARS, MAX_TITLE_CHARS};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text_capped};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, Month, OffsetDateTime, UtcOffset};


pub const DRAFT_HEADER: &str = "DRAFT - human review required before sending";


pub const MAX_INCIDENT_BYTES: u64 = 262_144;


pub const MAX_REGIMES: usize = 2;


pub const MAX_LIST_ITEMS: usize = 100;


pub const MAX_SUMMARY_CHARS: usize = 2_000;


pub const EARLY_WARNING_HOURS: i64 = 24;


pub const NOTIFICATION_HOURS: i64 = 72;


pub const DUE_SOON_HOURS: i64 = 6;


pub const MAX_YEAR: i32 = 9_999;


const TO_COMPLETE: &str = "[to complete: ";


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Regime {
    Nis2,
    Gdpr,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Nis2EarlyWarning,
    Nis2Notification,
    Nis2FinalReport,
    GdprNotification,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Due,
    DueSoon,
    Overdue,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalData {
    pub categories: Vec<String>,
    pub approximate_count: u64,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub name: String,
    pub role: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incident {
    pub case_id: String,
    pub title: String,
    #[serde(serialize_with = "time::serde::rfc3339::serialize", deserialize_with = "aware_field")]
    pub aware_at: OffsetDateTime,
    pub regimes: Vec<Regime>,
    pub summary: String,
    pub affected_services: Vec<String>,
    pub personal_data: Option<PersonalData>,
    pub cross_border: bool,
    pub actions_taken: Vec<String>,
    pub contact: Contact,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deadline {
    pub regime: Regime,
    pub step: Step,
    #[serde(with = "time::serde::rfc3339")]
    pub due: OffsetDateTime,
    pub reference: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlineStatus {
    pub deadline: Deadline,
    pub status: Status,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulatoryReport {
    pub header: String,
    #[serde(with = "time::serde::rfc3339")]
    pub now: OffsetDateTime,
    pub incident: Incident,
    pub deadlines: Vec<DeadlineStatus>,
}


const ALL_STEPS: [Step; 4] = [
    Step::Nis2EarlyWarning,
    Step::Nis2Notification,
    Step::Nis2FinalReport,
    Step::GdprNotification,
];


pub fn regime_of(step: Step) -> Regime {
    match step {
        Step::Nis2EarlyWarning | Step::Nis2Notification | Step::Nis2FinalReport => Regime::Nis2,
        Step::GdprNotification => Regime::Gdpr,
    }
}


pub fn step_label(step: Step) -> &'static str {
    match step {
        Step::Nis2EarlyWarning => "NIS 2 early warning",
        Step::Nis2Notification => "NIS 2 incident notification",
        Step::Nis2FinalReport => "NIS 2 final report",
        Step::GdprNotification => "GDPR notification to the supervisory authority",
    }
}


pub fn step_reference(step: Step) -> &'static str {
    match step {
        Step::Nis2EarlyWarning => "Directive (EU) 2022/2555, Article 23(4)(a)",
        Step::Nis2Notification => "Directive (EU) 2022/2555, Article 23(4)(b)",
        Step::Nis2FinalReport => "Directive (EU) 2022/2555, Article 23(4)(d)",
        Step::GdprNotification => "Regulation (EU) 2016/679, Article 33(1)",
    }
}


pub fn status_label(status: Status) -> &'static str {
    match status {
        Status::Due => "due",
        Status::DueSoon => "due soon",
        Status::Overdue => "overdue",
    }
}


fn step_fields(step: Step) -> &'static [&'static str] {
    match step {
        Step::Nis2EarlyWarning => &[
            "Suspected to be caused by unlawful or malicious acts (yes, no, unknown)",
            "Could have a cross-border impact (yes, no, unknown)",
        ],
        Step::Nis2Notification => &[
            "Initial assessment of the incident, its severity and its impact",
            "Indicators of compromise, if available",
        ],
        Step::Nis2FinalReport => &[
            "Detailed description of the incident, its severity and its impact",
            "Type of threat or root cause",
            "Mitigation measures applied and ongoing",
            "Cross-border impact, where applicable",
        ],
        Step::GdprNotification => &[
            "Likely consequences of the personal data breach",
            "Measures taken or proposed to address the breach and to mitigate its effects",
            "Reasons for the delay, if notified after 72 hours",
        ],
    }
}


/// Keeps a UTC time in years 0 to 9999, the only range RFC 3339 can write back.
pub fn within_years(time: OffsetDateTime) -> Option<OffsetDateTime> {
    Some(time).filter(|value| (0..=MAX_YEAR).contains(&value.year()))
}


fn normalise(time: OffsetDateTime) -> Option<OffsetDateTime> {
    time.checked_to_offset(UtcOffset::UTC).and_then(within_years)
}


/// An RFC 3339 time, normalised to UTC; the error never repeats the value.
pub fn aware_field<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<OffsetDateTime, Source::Error> {
    let text = String::deserialize(deserializer)?;
    OffsetDateTime::parse(&text, &Rfc3339)
        .ok()
        .and_then(normalise)
        .ok_or_else(|| Source::Error::custom("invalid time, expected RFC 3339 with a UTC year from 0 to 9999"))
}


/// Text of at most `max` characters; line breaks are allowed (flattened when rendered), other control characters are not.
pub fn is_report_text(text: &str, max: usize) -> bool {
    let flattened: String = text
        .chars()
        .map(|character| if matches!(character, '\n' | '\r') { ' ' } else { character })
        .collect();
    is_printable_text(&flattened, max)
}


fn check_list(items: &[String], field: &str) -> Result<(), String> {
    if items.len() > MAX_LIST_ITEMS {
        Err(format!("{field}: too many entries"))
    } else if !items.iter().all(|item| is_report_text(item, MAX_TITLE_CHARS)) {
        Err(format!("{field}: invalid text"))
    } else {
        Ok(())
    }
}


fn check_regimes(regimes: &[Regime]) -> Result<(), String> {
    let distinct: BTreeSet<&Regime> = regimes.iter().collect();
    if regimes.is_empty() {
        Err("regimes: at least one is required".to_owned())
    } else if regimes.len() > MAX_REGIMES {
        Err("regimes: too many entries".to_owned())
    } else if distinct.len() != regimes.len() {
        Err("regimes: duplicate entry".to_owned())
    } else {
        Ok(())
    }
}


/// Names the field, never its value.
pub fn check_incident(incident: &Incident) -> Result<(), String> {
    if !is_identifier(&incident.case_id, MAX_ID_CHARS) {
        Err("case_id: invalid identifier".to_owned())
    } else if !is_report_text(&incident.title, MAX_TITLE_CHARS) {
        Err("title: invalid text".to_owned())
    } else if !is_report_text(&incident.summary, MAX_SUMMARY_CHARS) {
        Err("summary: invalid text".to_owned())
    } else if !(is_report_text(&incident.contact.name, MAX_TITLE_CHARS) && is_report_text(&incident.contact.role, MAX_TITLE_CHARS)) {
        Err("contact: invalid text".to_owned())
    } else {
        check_regimes(&incident.regimes)
            .and_then(|()| check_list(&incident.affected_services, "affected_services"))
            .and_then(|()| check_list(&incident.actions_taken, "actions_taken"))
            .and_then(|()| {
                incident
                    .personal_data
                    .as_ref()
                    .map_or(Ok(()), |data| check_list(&data.categories, "personal_data.categories"))
            })
    }
}


pub fn parse_incident(reader: &mut dyn Read, file: &str) -> Result<Incident, GrcError> {
    let text = read_text_capped(reader, file, MAX_INCIDENT_BYTES)?;
    let incident: Incident = parse_document(&text, file)?;
    check_incident(&incident)
        .map_err(|reason| GrcError::Invalid {
            file: file.to_owned(),
            reason,
        })
        .map(|()| incident)
}


pub fn load_incident(path: &Path) -> Result<Incident, GrcError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    parse_incident(&mut handle, &file)
}


fn add_hours(start: OffsetDateTime, hours: i64) -> Option<OffsetDateTime> {
    start.checked_add(Duration::hours(hours)).and_then(within_years)
}


/// Same day of the next month in UTC, clamped to its last day (31 January gives 28 or 29 February).
pub fn add_month(start: OffsetDateTime) -> Option<OffsetDateTime> {
    let date = start.date();
    let month = date.month().next();
    let year = if month == Month::January { date.year() + 1 } else { date.year() };
    let day = date.day().min(month.length(year));
    Date::from_calendar_date(year, month, day)
        .ok()
        .map(|next| start.replace_date(next))
        .and_then(within_years)
}


fn due_at(start: OffsetDateTime, step: Step) -> Option<OffsetDateTime> {
    match step {
        Step::Nis2EarlyWarning => add_hours(start, EARLY_WARNING_HOURS),
        Step::Nis2Notification | Step::GdprNotification => add_hours(start, NOTIFICATION_HOURS),
        Step::Nis2FinalReport => add_month(start),
    }
}


/// One deadline per step of each selected regime, NIS 2 first; a due time beyond UTC year 9999 refuses the whole incident.
pub fn deadlines(incident: &Incident) -> Result<Vec<Deadline>, GrcError> {
    ALL_STEPS
        .iter()
        .filter(|step| incident.regimes.contains(&regime_of(**step)))
        .map(|step| {
            due_at(incident.aware_at, *step)
                .map(|due| Deadline {
                    regime: regime_of(*step),
                    step: *step,
                    due,
                    reference: step_reference(*step).to_owned(),
                })
                .ok_or_else(|| GrcError::Invalid {
                    file: "deadlines".to_owned(),
                    reason: "a deadline leaves the supported years".to_owned(),
                })
        })
        .collect()
}


/// `Overdue` from the due time on, `DueSoon` with `DUE_SOON_HOURS` or less left, else `Due`.
pub fn status_at(deadline: &Deadline, now: OffsetDateTime) -> Status {
    let remaining = deadline.due - now;
    if remaining <= Duration::ZERO {
        Status::Overdue
    } else if remaining <= Duration::hours(DUE_SOON_HOURS) {
        Status::DueSoon
    } else {
        Status::Due
    }
}


pub fn build_regulatory(incident: &Incident, now: OffsetDateTime) -> Result<RegulatoryReport, GrcError> {
    let statuses = deadlines(incident)?
        .into_iter()
        .map(|deadline| DeadlineStatus {
            status: status_at(&deadline, now),
            deadline,
        })
        .collect();
    Ok(RegulatoryReport {
        header: DRAFT_HEADER.to_owned(),
        now,
        incident: incident.clone(),
        deadlines: statuses,
    })
}


/// Infallible for a time already in UTC years 0 to 9999.
pub fn format_utc(time: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}


fn escaped_list(items: &[String], missing: &str) -> String {
    if items.is_empty() {
        format!("{TO_COMPLETE}{missing}]")
    } else {
        items.iter().map(|item| escape_markdown(item)).collect::<Vec<String>>().join(", ")
    }
}


fn personal_data_line(data: Option<&PersonalData>) -> String {
    match data {
        Some(found) => format!(
            "- Personal data: {} (approximately {} data subjects or records)",
            escaped_list(&found.categories, "categories of personal data"),
            found.approximate_count
        ),
        None => format!("- Personal data: {TO_COMPLETE}categories and approximate number of data subjects]"),
    }
}


fn fact_lines(incident: &Incident, step: Step) -> Vec<String> {
    let declared = if incident.cross_border { "yes" } else { "no" };
    let mut lines = vec![
        format!("- Case: {}", escape_markdown(&incident.case_id)),
        format!("- Incident: {}", escape_markdown(&incident.title)),
        format!("- Aware at: {}", format_utc(incident.aware_at)),
        format!("- Summary: {}", escape_markdown(&incident.summary)),
        format!("- Affected services: {}", escaped_list(&incident.affected_services, "affected services")),
        format!("- Cross-border, as declared by the operator: {declared}"),
        format!("- Actions taken: {}", escaped_list(&incident.actions_taken, "actions taken")),
        format!(
            "- Contact: {} ({})",
            escape_markdown(&incident.contact.name),
            escape_markdown(&incident.contact.role)
        ),
    ];
    if regime_of(step) == Regime::Gdpr {
        lines.push(personal_data_line(incident.personal_data.as_ref()));
    }
    lines
}


fn section(incident: &Incident, entry: &DeadlineStatus) -> Vec<String> {
    let step = entry.deadline.step;
    let mut lines = vec![
        String::new(),
        format!("## {} (due {})", step_label(step), format_utc(entry.deadline.due)),
        String::new(),
        format!("- Legal reference: {}", step_reference(step)),
    ];
    lines.extend(fact_lines(incident, step));
    lines.extend(step_fields(step).iter().map(|field| format!("- {field}: {TO_COMPLETE}...]")));
    lines
}


fn table_row(entry: &DeadlineStatus) -> String {
    let regime = if entry.deadline.regime == Regime::Nis2 { "NIS 2" } else { "GDPR" };
    format!(
        "| {regime} | {} | {} | {} | {} |",
        step_label(entry.deadline.step),
        format_utc(entry.deadline.due),
        status_label(entry.status),
        escape_markdown(&entry.deadline.reference)
    )
}


/// Markdown drafts: the fixed header first, the deadlines table, one section per step; every operator text is escaped.
pub fn render_drafts(incident: &Incident, now: OffsetDateTime) -> Result<String, GrcError> {
    let report = build_regulatory(incident, now)?;
    let mut lines = vec![
        DRAFT_HEADER.to_owned(),
        String::new(),
        format!("# Regulatory incident drafts: {}", escape_markdown(&incident.case_id)),
        String::new(),
        "| Regime | Step | Due (UTC) | Status | Reference |".to_owned(),
        "| --- | --- | --- | --- | --- |".to_owned(),
    ];
    lines.extend(report.deadlines.iter().map(table_row));
    report.deadlines.iter().for_each(|entry| lines.extend(section(incident, entry)));
    lines.push(String::new());
    Ok(lines.join("\n"))
}


/// The same data as the Markdown drafts, as pretty JSON.
pub fn to_json(report: &RegulatoryReport, output: &mut dyn Write) -> Result<(), GrcError> {
    serde_json::to_writer_pretty(output, report)?;
    Ok(())
}
