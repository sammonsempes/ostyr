//! Usage: ostyr-intel <settings.yaml>.


#[cfg(unix)]
fn main() -> std::process::ExitCode {
    intel_feeds::serve::main_exit(std::env::args().skip(1).collect())
}


#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
