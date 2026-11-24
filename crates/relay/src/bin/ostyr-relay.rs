#[cfg(unix)]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    relay::app::main_exit(std::env::args().skip(1).collect()).await
}


#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
