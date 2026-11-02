use crate::error::ConfigError;
use crate::load::{load_module, load_module_for_tenant, load_platform};
use crate::schema::write_schemas;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use thiserror::Error;


pub const USAGE: &str = "usage: schema <dir> | check platform <file> | check module <file> | check tenant <base> <tenant>";


#[derive(Debug, Error)]
pub enum CliError {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("cannot write output: {0}")]
    Output(#[from] io::Error),
}


/// Runs one command of the example binary: `schema <dir>` or `check <platform|module|tenant> <files>`.
pub fn run<W: Write>(args: &[&str], out: &mut W) -> Result<(), CliError> {
    match args {
        ["schema", dir] => write_schemas(Path::new(dir))?
            .iter()
            .try_for_each(|path| writeln!(out, "wrote {}", path.display()))
            .map_err(CliError::from),
        ["check", "platform", file] => {
            load_platform(Path::new(file))?;
            writeln!(out, "ok {file}").map_err(CliError::from)
        }
        ["check", "module", file] => {
            load_module(Path::new(file))?;
            writeln!(out, "ok {file}").map_err(CliError::from)
        }
        ["check", "tenant", base, tenant] => {
            load_module_for_tenant(Path::new(base), Path::new(tenant))?;
            writeln!(out, "ok {tenant}").map_err(CliError::from)
        }
        _ => Err(CliError::Usage),
    }
}


/// Runs the command, writes the `Display` form of any error to `err` and maps the outcome to an exit code.
pub fn run_reporting<W: Write, E: Write>(args: &[&str], out: &mut W, err: &mut E) -> io::Result<ExitCode> {
    match run(args, out) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(err, "{error}").map(|()| ExitCode::FAILURE),
    }
}
