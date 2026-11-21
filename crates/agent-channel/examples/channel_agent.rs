//! Usage: `channel_agent <config.yaml>`. Sends the spooled events, then runs the command stream once.
use agent_channel::agent_app::{load_agent_file, run_agent};
use agent_channel::spool_dirs::open_spool_dirs;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use std::time::Duration;


const USAGE: &str = "usage: channel_agent <config.yaml>";


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).try_init()?;
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    let file = load_agent_file(Path::new(&path))?;
    let dirs = open_spool_dirs(&file)?;
    let outcome = run_agent(&file, &dirs, &|delay: Duration| Box::pin(tokio::time::sleep(delay))).await?;
    writeln!(
        stdout(),
        "acknowledged {} batches, accepted {} commands, refused {}, executed {}",
        outcome.acknowledged.len(),
        outcome.run.accepted,
        outcome.run.refused,
        outcome.executed
    )?;
    Ok(())
}
