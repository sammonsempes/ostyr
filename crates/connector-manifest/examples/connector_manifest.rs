use connector_manifest::cli::{epoch_seconds, run};
use connector_manifest::error::ConnectorError;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};


const STDERR_BROKEN: u8 = 2;


fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = epoch_seconds(SystemTime::now().duration_since(UNIX_EPOCH)).and_then(|now| run(&words, now, &mut stdout()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => report(&error),
    }
}


fn report(error: &ConnectorError) -> ExitCode {
    match writeln!(stderr(), "{error}") {
        Ok(()) => ExitCode::FAILURE,
        Err(_) => ExitCode::from(STDERR_BROKEN),
    }
}
