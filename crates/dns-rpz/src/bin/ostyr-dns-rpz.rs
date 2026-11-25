#[cfg(unix)]
fn main() -> std::process::ExitCode {
    dns_rpz::process::main_exit(std::env::args().skip(1).collect())
}


#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
