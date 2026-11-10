//! Usage: `linux_agent <config.yaml>`. Follows the Tetragon export file and runs the agent channel. Unix only.
#[cfg(unix)]
use agent_linux::app::run_linux;
#[cfg(unix)]
use agent_linux::model::MAX_POLLS;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;


#[cfg(unix)]
const USAGE: &str = "usage: linux_agent <config.yaml>";


#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).try_init()?;
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    let totals = run_linux(Path::new(&path), MAX_POLLS, &|delay: Duration| Box::pin(tokio::time::sleep(delay))).await?;
    writeln!(stdout(), "{totals:?}")?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
