//! Usage: ostyr-dhcp <settings.yaml>.


#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<std::process::ExitCode> {
    use std::io::Write;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match dhcp_kea::serve::run(&arguments, dhcp_kea::serve::termination()?).await {
        Ok(()) => Ok(std::process::ExitCode::SUCCESS),
        Err(error) => writeln!(std::io::stderr(), "{error}").map(|()| std::process::ExitCode::FAILURE),
    }
}


#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
