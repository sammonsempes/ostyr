use std::process::ExitCode;

use coverage_gate::run::run;

fn main() -> anyhow::Result<ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let passed = run(&args, std::io::stdout())?;
    Ok(if passed { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
