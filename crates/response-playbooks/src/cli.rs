use crate::bundle::{simulate_named, validate_bundle, Bundle};
use crate::error::CommandError;
use crate::model::SimulationInput;
use crate::render::{mode_label, render_trace};
use core_config::reload::{current_config, reload, ReloadEngine};
use response_breakers::breakers::Breakers;
use response_breakers::cli::describe;
use std::fs;
use std::io::{self, BufRead, Write};
use std::sync::Arc;


pub const QUIT_COMMAND: &str = "quit";


pub const DEFAULT_TENANT: &str = "acme";


pub const REQUEST_ID: &str = "simulation";


pub const DEFAULT_FLEET_SIZE: u64 = 10_000;


pub const USAGE: &str = "list | validate | reload | simulate <playbook> <alert-file> [fail-action-index] | quit";


pub struct Session {
    pub engine: Arc<ReloadEngine<Bundle>>,
    pub breakers: Breakers,
}


pub fn read_alert(path: &str, fail_action: Option<usize>) -> Result<SimulationInput, CommandError> {
    Ok(SimulationInput {
        tenant: DEFAULT_TENANT.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        alert: serde_json::from_str(&fs::read_to_string(path)?)?,
        fleet_size: DEFAULT_FLEET_SIZE,
        isolated_now: 0,
        fail_action,
    })
}


pub fn list(bundle: &Bundle) -> String {
    bundle
        .playbooks
        .iter()
        .map(|loaded| {
            format!(
                "{} v{} mode={}",
                loaded.playbook.name,
                loaded.playbook.version,
                mode_label(loaded.playbook.mode)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}


pub fn run_simulation(session: &Session, name: &str, path: &str, fail_action: Option<usize>) -> Result<String, CommandError> {
    let input = read_alert(path, fail_action)?;
    simulate_named(&current_config(&session.engine), &session.breakers, name, &input)
        .map(|trace| render_trace(&trace).trim_end().to_owned())
        .ok_or_else(|| CommandError::UnknownPlaybook(name.to_owned()))
}


pub fn execute(session: &Session, tokens: &[&str]) -> Result<String, CommandError> {
    match tokens {
        ["list"] => Ok(list(&current_config(&session.engine))),
        ["validate"] => {
            let bundle = current_config(&session.engine);
            validate_bundle(&bundle)?;
            Ok(format!("valid: {} playbook(s)", bundle.playbooks.len()))
        }
        ["reload"] => Ok(describe(&reload(&session.engine))),
        ["simulate", name, path] => run_simulation(session, name, path, None),
        ["simulate", name, path, fail] => run_simulation(session, name, path, Some(fail.parse()?)),
        _ => Err(CommandError::Usage(USAGE)),
    }
}


/// One command per line; a failing command is reported on `out` and the session goes on.
pub fn run_command<Output: Write>(session: &Session, line: &str, out: &mut Output) -> io::Result<()> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match execute(session, &tokens) {
        Ok(text) => writeln!(out, "{text}"),
        Err(error) => writeln!(out, "error: {error}"),
    }
}


/// Reads commands until `quit` or end of input.
pub fn run_session<Input: BufRead, Output: Write>(session: &Session, input: Input, out: &mut Output) -> io::Result<()> {
    input
        .lines()
        .take_while(|line| line.as_ref().map_or(true, |text| text.trim() != QUIT_COMMAND))
        .try_for_each(|line| line.and_then(|command| run_command(session, &command, out)))
}
