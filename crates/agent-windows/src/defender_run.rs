use crate::defender::{defender_args, DEFENDER_DEADLINE_SECONDS, DEFENDER_MAX_OUTPUT_BYTES, MIN_DEFENDER_INTERVAL_SECONDS, POWERSHELL_PATH};
use crate::defender_parse::{parse_defender, refusal_reason};
use crate::error::DefenderError;
use crate::model::{RunEnd, RunRequest};
use crate::types::{Runner, Sink};
use serde_json::{json, Map, Value};
use tracing::warn;


pub fn defender_line(fields: Map<String, Value>) -> String {
    json!({"event": {"kind": "state", "dataset": "ostyr.windows.defender"}, "defender": fields}).to_string()
}


pub fn defender_refused_line(reason: &str) -> String {
    json!({"event": {"kind": "agent.event_refused"}, "agent": {"event_refused": {"dataset": "ostyr.windows.defender", "reason": reason}}}).to_string()
}


pub fn parsed_line(output: &[u8]) -> String {
    parse_defender(output).map_or_else(|refusal| defender_refused_line(refusal_reason(refusal)), defender_line)
}


pub fn defender_once(runner: Runner<'_>) -> String {
    let args = defender_args();
    let request = RunRequest {
        program: POWERSHELL_PATH,
        args: &args,
        max_bytes: DEFENDER_MAX_OUTPUT_BYTES,
        deadline_seconds: DEFENDER_DEADLINE_SECONDS,
    };
    let mut output: Vec<u8> = Vec::new();
    match runner(&request, &mut |chunk| output.extend_from_slice(chunk)) {
        Ok(RunEnd::Done) => parsed_line(&output),
        Ok(RunEnd::Capped) => defender_refused_line("oversized"),
        Ok(RunEnd::Deadline) => defender_refused_line("timeout"),
        Ok(RunEnd::Failed(_)) => defender_refused_line("exit_nonzero"),
        Err(error) => {
            let text = error.to_string();
            warn!(error = %text, "defender run failed");
            defender_refused_line("run_failed")
        }
    }
}


pub fn run_defender_rounds(
    interval_seconds: u64,
    max_runs: u32,
    runner: Runner<'_>,
    pause: &mut dyn FnMut(u64),
    sink: Sink<'_>,
) -> Result<u32, DefenderError> {
    if interval_seconds < MIN_DEFENDER_INTERVAL_SECONDS {
        Err(DefenderError::IntervalBelowFloor)
    } else {
        (0..max_runs)
            .try_for_each(|index| {
                sink(&defender_once(&mut *runner)).map_err(DefenderError::Sink)?;
                if index + 1 < max_runs {
                    pause(interval_seconds);
                }
                Ok(())
            })
            .map(|()| max_runs)
    }
}
