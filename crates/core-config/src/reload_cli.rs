use crate::model::ModuleConfig;
use crate::reload::{current_config, module_state, reload, ReloadEngine, ReloadOutcome};
use std::io::{self, BufRead, Write};


pub const QUIT_COMMAND: &str = "quit";


pub fn write_outcome<Output: Write>(outcome: &ReloadOutcome, out: &mut Output) -> io::Result<()> {
    match outcome {
        ReloadOutcome::Unchanged => writeln!(out, "unchanged"),
        ReloadOutcome::Applied { keys } => writeln!(out, "applied {}", keys.join(",")),
        ReloadOutcome::Refused { reason } => writeln!(out, "refused {reason}"),
    }
}


/// One command per line: `show` prints the current configuration, `reload` reloads explicitly, `quit` ends; anything else is reported.
pub fn run_command<Output: Write>(engine: &ReloadEngine<ModuleConfig>, command: &str, out: &mut Output) -> io::Result<()> {
    match command.trim() {
        "show" => module_state(&current_config(engine))
            .iter()
            .try_for_each(|(key, value)| writeln!(out, "{key}={value}")),
        "reload" => write_outcome(&reload(engine), out),
        other => writeln!(out, "unknown command `{other}`"),
    }
}


/// Reads commands until `quit` or end of input.
pub fn run_session<Input: BufRead, Output: Write>(engine: &ReloadEngine<ModuleConfig>, input: Input, out: &mut Output) -> io::Result<()> {
    input
        .lines()
        .take_while(|line| line.as_ref().map_or(true, |text| text.trim() != QUIT_COMMAND))
        .try_for_each(|line| line.and_then(|command| run_command(engine, &command, out)))
}
