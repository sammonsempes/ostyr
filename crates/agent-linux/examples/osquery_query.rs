//! Usage: `osquery_query <settings.yaml> <query>`. Runs one bounded osquery query and prints the rows as JSON lines. Unix only.
#[cfg(unix)]
use agent_linux::model::{LinuxFile, OsqueryEnv};
#[cfg(unix)]
use agent_linux::osquery::run_query;
#[cfg(unix)]
use agent_linux::sensor::run_update_command;
#[cfg(unix)]
use core_config::load::load_file;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::Path;


#[cfg(unix)]
const USAGE: &str = "usage: osquery_query <settings.yaml> <query>";


#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut arguments = std::env::args().skip(1);
    let path = arguments.next().ok_or(USAGE)?;
    let query = arguments.next().ok_or(USAGE)?;
    let file = load_file::<LinuxFile>(Path::new(&path))?;
    let state_dir = file.cursor_file.parent().ok_or(USAGE)?.to_path_buf();
    let env = OsqueryEnv {
        state_dir,
        trusted_uid: rustix::process::geteuid().as_raw(),
        run: run_update_command,
    };
    let result = run_query(&env, &file.osquery, &query).await?;
    let mut out = stdout();
    result.rows.iter().try_for_each(|row| writeln!(out, "{}", serde_json::to_string(row)?))?;
    writeln!(out, "refused_rows={}", result.refused_rows)?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
