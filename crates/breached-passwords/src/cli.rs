use crate::error::{HashFileError, ListError};
use crate::hashes::read_hashes;
use crate::list::open_list;
use core_config::secret_file::{open_secret, SecretFileError};
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use thiserror::Error;


pub const USAGE: &str = "usage: <sorted-ntlm-list> <hash-file>";


#[derive(Debug, Error)]
pub enum CliError {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    List(#[from] ListError),
    #[error(transparent)]
    HashFile(#[from] HashFileError),
    #[error(transparent)]
    Secret(#[from] SecretFileError),
    #[error("cannot write output: {0}")]
    Output(#[from] io::Error),
}


/// Reads the hashes, checks the list whole in one pass and prints its SHA-256 on `err`, then a line index and a verdict per hash, after the pass.
pub fn run(args: &[&str], out: &mut dyn Write, err: &mut dyn Write) -> Result<(), CliError> {
    match args {
        [list_path, hash_path] => {
            let hashes = read_hashes(&mut open_secret(Path::new(hash_path))?)?;
            let list = open_list(Path::new(list_path), &hashes)?;
            let bytes = list.size;
            tracing::info!(bytes, "list opened and checked whole");
            writeln!(err, "list sha256 {} lines {}", list.sha256, list.lines)?;
            list.verdicts.iter().enumerate().try_for_each(|(index, verdict)| {
                let line = index + 1;
                if verdict.compromised {
                    writeln!(out, "{line} compromised")
                } else {
                    writeln!(out, "{line} clean")
                }
                .map_err(CliError::from)
            })
        }
        _ => Err(CliError::Usage),
    }
}


/// Runs the command, writes the `Display` form of any error to `err` and maps the outcome to an exit code.
pub fn run_reporting(args: &[&str], out: &mut dyn Write, err: &mut dyn Write) -> io::Result<ExitCode> {
    match run(args, out, err) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(err, "{error}").map(|()| ExitCode::FAILURE),
    }
}
