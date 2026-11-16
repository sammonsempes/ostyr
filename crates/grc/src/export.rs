use crate::error::GrcError;
use crate::report::ComplianceReport;
use sla_report::export::neutralise_cell;
use std::io::Write;


pub const NONE_TEXT: &str = "none";


pub const CSV_COLUMNS: usize = 7;


pub const CSV_BUFFER_BYTES: usize = 64;


pub const CSV_HEADER: [&str; CSV_COLUMNS] = [
    "control",
    "title",
    "status",
    "evidence_digest",
    "evidence_time",
    "linked_risks",
    "open_actions",
];


pub const MARKDOWN_SPECIALS: [char; 11] = ['|', '\\', '`', '*', '_', '[', ']', '<', '>', '&', '~'];


/// Escapes every Markdown special character and turns a line break into a space, so a text cannot add a cell, a link or HTML.
pub fn escape_markdown(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == '\n' || character == '\r' {
                " ".to_owned()
            } else if MARKDOWN_SPECIALS.contains(&character) {
                format!("\\{character}")
            } else {
                character.to_string()
            }
        })
        .collect()
}


fn list_text(items: &[String]) -> String {
    items.iter().map(|item| escape_markdown(item)).collect::<Vec<String>>().join(", ")
}


fn row(cells: &[String]) -> String {
    format!("| {} |", cells.join(" | "))
}


fn table(header: &[&str], rows: Vec<Vec<String>>) -> Vec<String> {
    let titles: Vec<String> = header.iter().map(|title| (*title).to_owned()).collect();
    let separator: Vec<String> = header.iter().map(|_| "---".to_owned()).collect();
    let mut lines = vec![row(&titles), row(&separator)];
    lines.extend(rows.iter().map(|cells| row(cells)));
    lines
}


/// Markdown report: summary, one row per control, gaps, action plan.
pub fn to_markdown(report: &ComplianceReport) -> String {
    let counts = &report.counts;
    let controls: Vec<Vec<String>> = report
        .controls
        .iter()
        .map(|control| {
            vec![
                escape_markdown(&control.id),
                escape_markdown(&control.title),
                escape_markdown(&control.status),
                control.evidence_digest.as_deref().map_or(NONE_TEXT.to_owned(), escape_markdown),
                control.evidence_time.map_or(NONE_TEXT.to_owned(), |time| time.to_string()),
                list_text(&control.risks),
                list_text(&control.open_actions),
            ]
        })
        .collect();
    let gaps: Vec<Vec<String>> = report
        .gaps
        .iter()
        .map(|gap| {
            vec![
                escape_markdown(&gap.control),
                escape_markdown(&gap.title),
                escape_markdown(&gap.status),
                list_text(&gap.risks),
            ]
        })
        .collect();
    let plan: Vec<Vec<String>> = report
        .plan
        .iter()
        .map(|item| {
            vec![
                escape_markdown(&item.control),
                escape_markdown(&item.risk),
                escape_markdown(&item.action),
                escape_markdown(&item.title),
                escape_markdown(&item.owner),
                escape_markdown(&item.status),
                item.due.clone(),
                item.overdue.to_string(),
            ]
        })
        .collect();
    let mut lines = vec![
        format!("# Compliance report: {} v{}", escape_markdown(&report.framework), report.version),
        String::new(),
        format!("- Tenant: {}", escape_markdown(&report.tenant)),
        format!("- Generated: {}", report.generated),
        String::new(),
        "## Summary".to_owned(),
        String::new(),
        format!("- compliant: {}", counts.compliant),
        format!("- partially compliant: {}", counts.partially_compliant),
        format!("- non compliant: {}", counts.non_compliant),
        format!("- not assessable: {}", counts.not_assessable),
        String::new(),
        "## Controls".to_owned(),
        String::new(),
    ];
    lines.extend(table(
        &["Control", "Title", "Status", "Evidence digest", "Evidence time", "Risks", "Open actions"],
        controls,
    ));
    lines.extend([String::new(), "## Gaps".to_owned(), String::new()]);
    lines.extend(if gaps.is_empty() {
        vec!["None.".to_owned()]
    } else {
        table(&["Control", "Title", "Status", "Risks"], gaps)
    });
    lines.extend([String::new(), "## Action plan".to_owned(), String::new()]);
    lines.extend(if plan.is_empty() {
        vec!["None.".to_owned()]
    } else {
        table(&["Control", "Risk", "Action", "Title", "Owner", "Status", "Due", "Overdue"], plan)
    });
    lines.push(String::new());
    lines.join("\n")
}


/// One CSV row per control; every text cell goes through the formula neutraliser of `sla-report`.
pub fn to_csv(report: &ComplianceReport, output: &mut dyn Write) -> Result<(), GrcError> {
    let mut writer = csv::WriterBuilder::new().buffer_capacity(CSV_BUFFER_BYTES).from_writer(output);
    writer.write_record(CSV_HEADER)?;
    report.controls.iter().try_for_each(|control| {
        writer.write_record([
            neutralise_cell(&control.id),
            neutralise_cell(&control.title),
            neutralise_cell(&control.status),
            control.evidence_digest.as_deref().map_or(NONE_TEXT.to_owned(), neutralise_cell),
            control.evidence_time.map_or(NONE_TEXT.to_owned(), |time| time.to_string()),
            neutralise_cell(&control.risks.join(" ")),
            neutralise_cell(&control.open_actions.join(" ")),
        ])
    })?;
    writer.flush()?;
    Ok(())
}


/// The whole report as pretty JSON; text is plain, JSON escapes it.
pub fn to_json(report: &ComplianceReport, output: &mut dyn Write) -> Result<(), GrcError> {
    serde_json::to_writer_pretty(output, report)?;
    Ok(())
}
