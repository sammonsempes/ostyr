use custom_lint::run::{read_file, run};
use std::process::ExitCode;


fn main() -> anyhow::Result<ExitCode> {
    let violations = run(std::env::args_os().skip(1), &mut std::io::stdout(), read_file)?;
    Ok(if violations == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
