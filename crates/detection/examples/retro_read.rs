use detection::retro::{run_retro, RetroOutcome, RetroQuery, RetroSettings, MAX_EXECUTION_SECONDS, MAX_ROWS_TO_READ};
use sigma_sql::mapping::parse_mapping;
use std::error::Error;
use std::fs;
use std::io::{stdout, Write};
use std::time::Instant;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str =
    "usage: retro_read <url> <user> <password-file> <ca-file|-> <database> <tenant> <rule.yml> <mapping.yaml> <start-rfc3339> <end-rfc3339> <max-rows>";


const TIMEOUT_MS: u64 = 60_000;


fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [url, user, password_file, ca_file, database, tenant, rule, mapping, start, end, max_rows] => {
            let settings = RetroSettings {
                url: url.clone(),
                user: user.clone(),
                password_file: password_file.into(),
                ca_file: (ca_file != "-").then(|| ca_file.into()),
                database: database.clone(),
                timeout_ms: TIMEOUT_MS,
                max_rows: max_rows.parse()?,
                max_execution_seconds: MAX_EXECUTION_SECONDS,
                max_rows_to_read: MAX_ROWS_TO_READ,
            };
            let query = RetroQuery {
                rule_text: fs::read_to_string(rule)?,
                tenant: tenant.clone(),
                start: OffsetDateTime::parse(start, &Rfc3339)?,
                end: OffsetDateTime::parse(end, &Rfc3339)?,
            };
            let started = Instant::now();
            let outcome = run_retro(&settings, &parse_mapping(&fs::read_to_string(mapping)?)?, &query, &|| started.elapsed());
            let mut out = stdout();
            match outcome {
                Ok(RetroOutcome::Complete(found)) => writeln!(out, "complete ids={:?} refused={}", found.ids, found.refused)?,
                Ok(RetroOutcome::RowCap { found, cap }) => writeln!(out, "row_cap cap={cap} ids={:?} refused={}", found.ids, found.refused)?,
                Err(error) => writeln!(out, "error {error}")?,
            }
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args)
}
