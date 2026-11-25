//! Usage: ostyr-backup-monitor <settings.yaml>.


#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    backup_monitor::serve::main_exit(std::env::args().skip(1).collect()).await
}


#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
