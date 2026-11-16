//! Usage: `agent_isolation <isolate|release|status> <config.yaml>`. Applies, reads back or removes the nftables isolation table. Unix only.
#[cfg(unix)]
use agent_linux::isolation::run_isolation;
#[cfg(unix)]
use agent_linux::nft::run_nft;
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::Path;


#[cfg(unix)]
const PATH_POSITION: usize = 2;


#[cfg(unix)]
const USAGE: &str = "usage: agent_isolation <isolate|release|status> <config.yaml>";


#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).try_init()?;
    let action = std::env::args().nth(1).ok_or(USAGE)?;
    let path = std::env::args().nth(PATH_POSITION).ok_or(USAGE)?;
    writeln!(stdout(), "{}", run_isolation(Path::new(&path), &action, run_nft).await?)?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
