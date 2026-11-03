use crate::compile::{compile_rule, SqlOptions};
use crate::error::SigmaError;
use crate::mapping::parse_mapping;
use std::fs::read_to_string;
use std::io::{self, Write};
use std::process::ExitCode;


fn read_file(path: &str) -> Result<String, SigmaError> {
    read_to_string(path).map_err(|source| SigmaError::Read {
        path: path.to_string(),
        source,
    })
}


/// Compiles every rule file named after the mapping file and the table name, one `SELECT` per line on `out`.
pub fn run<Output: Write>(args: &[&str], out: &mut Output) -> Result<(), SigmaError> {
    match args {
        [mapping_path, table, rule_paths @ ..] if !rule_paths.is_empty() => {
            let mapping = parse_mapping(&read_file(mapping_path)?)?;
            let options = SqlOptions {
                table: (*table).to_string(),
                ..SqlOptions::default()
            };
            rule_paths.iter().try_for_each(|path| {
                let sql = compile_rule(&read_file(path)?, &mapping, &options)?;
                writeln!(out, "{sql}").map_err(SigmaError::from)
            })
        }
        _ => Err(SigmaError::Usage),
    }
}


/// Runs the command, writes the `Display` form of any error to `err` and maps the outcome to an exit code.
pub fn run_reporting<Output: Write, ErrorOutput: Write>(args: &[&str], out: &mut Output, err: &mut ErrorOutput) -> io::Result<ExitCode> {
    match run(args, out) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(err, "{error}").map(|()| ExitCode::FAILURE),
    }
}
