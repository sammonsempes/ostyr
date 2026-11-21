use agent_channel::model::DEFAULT_MAX_MESSAGE_BYTES;
use agent_windows::model::{ChannelState, PollEnv, LOCK_ATTEMPTS, MAX_OUTPUT_BYTES, QUERY_DEADLINE_SECONDS, SECURITY, SYSMON, WEVTUTIL_PATH};
use agent_windows::poll::poll_channel;
use agent_windows::run::run_process;
use core_export::ecs::to_json;
use ecs_normalise::types::SeenIds;
use std::env;
use std::error::Error;
use std::io::Write;
use std::path::Path;


const USAGE: &str = "usage: event_poll <state-dir> <spool>";


const LINE_LIMIT_DIVISOR: usize = 2;


fn main() -> Result<(), Box<dyn Error>> {
    let mut paths = env::args().skip(1);
    let state_dir = paths.next().ok_or(USAGE)?;
    let spool = paths.next().ok_or(USAGE)?;
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
        seen: &mut seen,
    };
    let mut stdout = std::io::stdout();
    [SYSMON, SECURITY].iter().try_for_each(|channel| {
        let mut state = ChannelState::default();
        match poll_channel(&mut env, channel, &mut state) {
            Ok(totals) => writeln!(stdout, "{}: {totals:?}", channel.name),
            Err(error) => writeln!(stdout, "{}: error: {error:?}", channel.name),
        }
    })?;
    Ok(())
}
