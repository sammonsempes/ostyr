use coverage_gate::run::run;
use std::process::ExitCode;


fn main() -> anyhow::Result<ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let passed = run(&args, std::io::stdout())?;
    Ok(if passed { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
