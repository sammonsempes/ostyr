use core_auth::cli::run;
use core_auth::random::os_random;
use std::io::{stderr, stdin, stdout, Write};
use std::process::ExitCode;
use time::OffsetDateTime;


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args, stdin().lock(), stdout(), OffsetDateTime::now_utc, os_random) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
