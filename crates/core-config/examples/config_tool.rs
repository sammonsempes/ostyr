use core_config::cli::{run, CliError};
use std::io::stdout;


fn main() -> Result<(), CliError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&borrowed, &mut stdout())
}
