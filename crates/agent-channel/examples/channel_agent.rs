//! Usage: `channel_agent <config.yaml> [runs]`. Sends the spooled events, then runs the command stream once per run; `runs` (default 1) repeats it with one hold-down.
use agent_channel::agent_app::{load_agent_file, run_agent};
use agent_channel::relay::HoldDown;
use agent_channel::spool_dirs::open_spool_dirs;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use std::time::Duration;


const USAGE: &str = "usage: channel_agent <config.yaml> [runs]";


const RUN_PAUSE_SECONDS: u64 = 5;


const RUNS_ARGUMENT: usize = 2;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(std::io::stderr).try_init()?;
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    let runs: u64 = std::env::args().nth(RUNS_ARGUMENT).map_or(Ok(1), |text| text.parse())?;
    let file = load_agent_file(Path::new(&path))?;
    let dirs = open_spool_dirs(&file)?;
    let hold = HoldDown::default();
    for run in 0..runs {
        let outcome = run_agent(&file, &dirs, &|delay: Duration| Box::pin(tokio::time::sleep(delay)), None, &hold).await?;
        writeln!(
            stdout(),
            "run {run}: acknowledged {} batches, accepted {} commands, refused {}, executed {}, internal runs {}, relay runs {}",
            outcome.acknowledged.len(),
            outcome.run.accepted,
            outcome.run.refused,
            outcome.executed,
            outcome.internal_runs,
            outcome.relay_runs
        )?;
        tokio::time::sleep(Duration::from_secs(RUN_PAUSE_SECONDS)).await;
    }
    Ok(())
}
