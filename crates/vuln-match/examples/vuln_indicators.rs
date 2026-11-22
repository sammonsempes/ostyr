//! Lab tool. `vuln_indicators <pg.yaml> <tenant> [now micros|now]` prints the GRC indicator file (a JSON array) on stdout.

use alerts::pg::pg_executor;
use core_pg::connect::connect;
use core_pg::scope::tenant_scope;
use core_pg::settings::load_settings;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use vuln_match::indicator::{failure_text, indicator_json, kev_indicator, warning_line};


const USAGE: &str = "usage: vuln_indicators <pg.yaml> <tenant> [now micros|now]";


const DEADLINE: Duration = Duration::from_secs(30);


const ARG_SETTINGS: usize = 1;


const ARG_TENANT: usize = 2;


const ARG_NOW: usize = 3;


const NOW_WORD: &str = "now";


fn now_of(text: &str) -> Result<u64, String> {
    if text == NOW_WORD {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())
            .and_then(|elapsed| u64::try_from(elapsed.as_micros()).map_err(|error| error.to_string()))
    } else {
        text.parse().map_err(|_error| USAGE.to_owned())
    }
}


async fn run_command(arguments: &[String]) -> Result<(), String> {
    let settings = load_settings(Path::new(arguments.get(ARG_SETTINGS).ok_or(USAGE)?)).map_err(|error| error.to_string())?;
    let scope = tenant_scope(arguments.get(ARG_TENANT).ok_or(USAGE)?).map_err(|error| error.to_string())?;
    let now = now_of(arguments.get(ARG_NOW).map_or(NOW_WORD, String::as_str))?;
    let client = connect(&settings).await.map_err(|error| error.to_string())?;
    let exec = pg_executor(&client, DEADLINE);
    let outcome = kev_indicator(&exec, &scope, now).await.map_err(|error| failure_text(&error))?;
    let rows: Vec<_> = outcome.row.iter().cloned().collect();
    let text = indicator_json(&rows).map_err(|error| error.to_string())?;
    writeln!(stdout(), "{text}").map_err(|error| error.to_string())?;
    if rows.is_empty() {
        writeln!(stderr(), "{}", warning_line(&outcome.counts)).map_err(|error| error.to_string())
    } else {
        Ok(())
    }
}


#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    match run_command(&arguments).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let written = writeln!(stderr(), "{message}");
            if written.is_err() {
                tracing::error!("stderr is closed");
            }
            ExitCode::FAILURE
        }
    }
}
