use agent_channel::spool::{append_locked, pause_between_lock_attempts};
use agent_windows::cycle::sleep_seconds;
use agent_windows::defender::DEFAULT_DEFENDER_INTERVAL_SECONDS;
use agent_windows::defender_run::run_defender_rounds;
use agent_windows::model::{RunRequest, LOCK_ATTEMPTS};
use agent_windows::run::run_process;
use std::env;
use std::error::Error;
use std::io::Write;
use std::path::Path;


const USAGE: &str = "usage: defender_state <spool> [interval-seconds] [runs]";


fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let spool = arguments.next().ok_or(USAGE)?;
    let interval: u64 = arguments.next().map_or(Ok(DEFAULT_DEFENDER_INTERVAL_SECONDS), |text| text.parse())?;
    let runs: u32 = arguments.next().map_or(Ok(1), |text| text.parse())?;
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let mut run = |request: &RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| run_process(request, sink);
    let mut stdout = std::io::stdout();
    let mut sink = |line: &str| {
        writeln!(stdout, "{line}")?;
        append_locked(
            std::iter::once(Ok(line.to_string())),
            Path::new(&spool),
            LOCK_ATTEMPTS,
            &mut pause_between_lock_attempts,
        )
        .map(|_| ())
    };
    run_defender_rounds(interval, runs, &mut run, &mut sleep_seconds, &mut sink)?;
    Ok(())
}
