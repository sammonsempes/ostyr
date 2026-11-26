#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    waf::serve::main_exit(std::env::args().skip(1).collect())
}


#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
