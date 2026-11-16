//! Usage: db_health <databases.yaml> <name> <settings.csv> <connections.csv> <activity.csv> <replication.csv>; prints the verdict and measures.

use app_health::db::{assess_db, db_measures, load_db_expectations, unknown_lags};
use app_health::error::NtpError;
use app_health::pg::{parse_pg_activity, parse_pg_connections, parse_pg_replication, parse_pg_settings};
use std::io::Write;


const MAX_CSV_BYTES: u64 = 65_536;


const FILE_COUNT: usize = 4;


fn keep<Item>(label: &str, parsed: Result<Item, NtpError>) -> Result<Option<Item>, std::io::Error> {
    match parsed {
        Ok(item) => Ok(Some(item)),
        Err(error) => writeln!(std::io::stdout(), "unreadable {label}: {error}").map(|()| None),
    }
}


fn report(expectations_path: &str, name: &str, files: [&String; FILE_COUNT]) -> Result<(), Box<dyn std::error::Error>> {
    let [settings_path, connections_path, activity_path, replication_path] = files;
    let expectations = load_db_expectations(&std::fs::read_to_string(expectations_path)?, expectations_path)?;
    let expectation = expectations
        .iter()
        .find(|item| item.name == name)
        .ok_or("database not in the expectations file")?;
    let settings = keep("settings", parse_pg_settings(std::fs::File::open(settings_path)?, MAX_CSV_BYTES))?;
    let connections = keep("connections", parse_pg_connections(std::fs::File::open(connections_path)?, MAX_CSV_BYTES))?;
    let activity = keep("activity", parse_pg_activity(std::fs::File::open(activity_path)?, MAX_CSV_BYTES))?;
    let replication = keep("replication", parse_pg_replication(std::fs::File::open(replication_path)?, MAX_CSV_BYTES))?;
    let verdict = assess_db(
        expectation,
        settings.as_ref(),
        connections.as_ref(),
        activity.as_ref(),
        replication.as_ref(),
    );
    let measures = db_measures(expectation, connections.as_ref(), activity.as_ref(), replication.as_ref());
    let unknown = replication.as_ref().map(unknown_lags);
    let at_least = activity.as_ref().map(|item| item.at_least);
    let mut out = std::io::stdout();
    writeln!(
        out,
        "database={name} verdict={verdict:?} activity_at_least={at_least:?} unknown_lags={unknown:?}"
    )?;
    writeln!(out, "measures={measures:?}")?;
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [expectations_path, name, settings, connections, activity, replication] => {
            report(expectations_path, name, [settings, connections, activity, replication])
        }
        _ => Err("usage: db_health <databases.yaml> <name> <settings.csv> <connections.csv> <activity.csv> <replication.csv>".into()),
    }
}
