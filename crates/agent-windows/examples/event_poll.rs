use agent_channel::model::DEFAULT_MAX_MESSAGE_BYTES;
use agent_windows::cycle::{poll_cycle, sleep_seconds};
use agent_windows::model::{ChannelState, PollEnv, LOCK_ATTEMPTS, MAX_OUTPUT_BYTES, QUERY_DEADLINE_SECONDS, SECURITY, SYSMON, WEVTUTIL_PATH};
use agent_windows::run::run_process;
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use std::env;
use std::error::Error;
use std::io::Write;
use std::path::Path;


const USAGE: &str = "usage: event_poll <state-dir> <spool> [cycles] [max-spool-bytes] [drain-at-cycle]";


const DEFAULT_MAX_SPOOL_BYTES: u64 = 67_108_864;


const INTERVAL_SECONDS: u64 = 2;


const LINE_LIMIT_DIVISOR: usize = 2;


fn main() -> Result<(), Box<dyn Error>> {
    let mut paths = env::args().skip(1);
    let state_dir = paths.next().ok_or(USAGE)?;
    let spool = paths.next().ok_or(USAGE)?;
    let cycles: u32 = paths.next().map_or(Ok(1), |text| text.parse())?;
    let max_spool_bytes: u64 = paths.next().map_or(Ok(DEFAULT_MAX_SPOOL_BYTES), |text| text.parse())?;
    let drain_at: Option<u32> = paths.next().map(|text| text.parse()).transpose()?;
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let mut seen = SeenIds::new();
    let mut run = |request: &agent_windows::model::RunRequest<'_>, sink: &mut dyn FnMut(&[u8])| run_process(request, sink);
    let mut env = PollEnv {
        run: &mut run,
        encode: to_json,
        program: WEVTUTIL_PATH,
        state_dir: Path::new(&state_dir),
        spool: Path::new(&spool),
        line_limit: DEFAULT_MAX_MESSAGE_BYTES / LINE_LIMIT_DIVISOR,
        lock_attempts: LOCK_ATTEMPTS,
        max_output_bytes: MAX_OUTPUT_BYTES,
        deadline_seconds: QUERY_DEADLINE_SECONDS,
        max_spool_bytes,
        seen: &mut seen,
    };
    let mut stdout = std::io::stdout();
    let mut states = [ChannelState::default(), ChannelState::default()];
    (0..cycles).try_for_each(|cycle| {
        if drain_at == Some(cycle) {
            std::fs::remove_file(&spool)?;
        }
        [SYSMON, SECURITY].iter().zip(states.iter_mut()).try_for_each(|(channel, state)| {
            match poll_cycle(&mut env, channel, state, &mut |_| ()) {
                Ok(polls) => polls
                    .iter()
                    .try_for_each(|totals| writeln!(stdout, "cycle {cycle} {}: {totals:?}", channel.name)),
                Err(error) => writeln!(stdout, "cycle {cycle} {}: error: {error:?}", channel.name),
            }
        })?;
        sleep_seconds(INTERVAL_SECONDS);
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}
