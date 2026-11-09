use core_config::secret::SecretRef;
use core_export::cli::run;
use core_export::types::BoxError;
use std::io::{stderr, stdout, Write};
use std::process::ExitCode;


const NO_SECRET_BACKEND: &str = "no secret backend is wired to this example";


fn main() -> std::io::Result<ExitCode> {
    tracing_subscriber::fmt().with_writer(stderr).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let resolve = |_reference: &SecretRef| -> Result<String, BoxError> { Err(NO_SECRET_BACKEND.into()) };
    match run(&borrowed, &mut stdout(), &resolve) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
    }
}
