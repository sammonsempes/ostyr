use crate::error::ExportError;
use crate::model::{Report, ReportLine};
use std::io::Write;


pub const CSV_COLUMNS: usize = 7;


pub const CSV_BUFFER_BYTES: usize = 64;


pub const CSV_HEADER: [&str; CSV_COLUMNS] = [
    "service",
    "objective_percent",
    "availability_percent",
    "budget_used_seconds",
    "budget_allowed_seconds",
    "down_seconds",
    "unknown_seconds",
];


pub const INJECTION_PREFIXES: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];


pub fn neutralise_cell(cell: &str) -> String {
    let dangerous = cell.starts_with(INJECTION_PREFIXES);
    if dangerous {
        format!("'{cell}")
    } else {
        cell.to_string()
    }
}


pub fn csv_record(line: &ReportLine) -> [String; CSV_COLUMNS] {
    [
        neutralise_cell(&line.name),
        line.objective_percent.clone(),
        line.availability_percent.as_deref().unwrap_or("").to_string(),
        line.budget_used_seconds.to_string(),
        line.budget_allowed_seconds.to_string(),
        line.down_seconds.to_string(),
        line.unknown_seconds.to_string(),
    ]
}


pub fn to_csv<Output: Write>(report: &Report, output: Output) -> Result<(), ExportError> {
    let mut writer = csv::WriterBuilder::new().buffer_capacity(CSV_BUFFER_BYTES).from_writer(output);
    writer.write_record(CSV_HEADER)?;
    report.lines.iter().try_for_each(|line| writer.write_record(csv_record(line)))?;
    writer.flush()?;
    Ok(())
}


pub fn to_json<Output: Write>(report: &Report, output: Output) -> Result<(), ExportError> {
    serde_json::to_writer(output, report)?;
    Ok(())
}
