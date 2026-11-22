//! Lab tool. `migrate_probe <pg.yaml>` applies one migration that sleeps 120 s and prints the outcome on stdout.

use core_pg::connect::connect;
use core_pg::migrate::{migrate, Migration};
use core_pg::settings::load_settings;
use std::io::{stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;


const USAGE: &str = "usage: migrate_probe <pg.yaml>";


const DEADLINE: Duration = Duration::from_secs(30);


const PROBE: [Migration; 1] = [Migration {
    version: "0001_sleep",
    sql: "SELECT pg_catalog.pg_sleep(120)",
}];


async fn run_command(arguments: &[String]) -> Result<String, String> {
    let settings = load_settings(Path::new(arguments.get(1).ok_or(USAGE)?)).map_err(|error| error.to_string())?;
    let client = connect(&settings).await.map_err(|error| error.to_string())?;
    let applied = migrate(&client, "probe", &PROBE, DEADLINE).await.map_err(|error| error.to_string())?;
    Ok(format!("applied {applied:?}"))
}


fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
    let outcome = runtime
        .map_err(|error| error.to_string())
        .and_then(|built| built.block_on(run_command(&arguments)));
    let line = outcome.unwrap_or_else(|error| format!("error: {error}"));
    let written = writeln!(stdout(), "{line}");
    ExitCode::from(u8::from(written.is_err()))
}
