#[cfg(unix)]
use core_config::trusted_program::{open_trusted_program, same_program};
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::Path;
use std::process::ExitCode;


#[cfg(unix)]
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = stdout();
    match args.iter().map(String::as_str).collect::<Vec<&str>>().as_slice() {
        [path, uid] => match open_trusted_program(Path::new(path), uid.parse()?) {
            Ok(_) => writeln!(out, "accepted")?,
            Err(error) => writeln!(out, "{error}")?,
        },
        [path, uid, replacement] => {
            let handle = open_trusted_program(Path::new(path), uid.parse()?)?;
            std::fs::rename(replacement, path)?;
            writeln!(out, "same after swap: {}", same_program(&handle, Path::new(path), uid.parse()?)?)?;
        }
        _ => writeln!(out, "usage: trusted_program <path> <uid> [replacement]")?,
    }
    Ok(ExitCode::SUCCESS)
}


#[cfg(not(unix))]
fn main() -> ExitCode {
    ExitCode::SUCCESS
}
