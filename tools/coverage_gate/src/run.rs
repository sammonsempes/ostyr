use crate::check::check;
use crate::error::GateError;
use crate::export::parse_export;
use crate::scan::find_sources;
use std::fs::File;
use std::io::Write;
use std::path::Path;


const DEFAULT_ROOT: &str = ".";


const EXPORT_ARG: usize = 1;


const ROOT_ARG: usize = 2;


pub fn run<W: Write>(args: &[String], mut out: W) -> Result<bool, GateError> {
    let export_path = Path::new(args.get(EXPORT_ARG).ok_or(GateError::Usage)?);
    let root = Path::new(args.get(ROOT_ARG).map_or(DEFAULT_ROOT, String::as_str));
    let file = File::open(export_path).map_err(|source| GateError::Open {
        path: export_path.to_path_buf(),
        source,
    })?;
    let export = parse_export(file)?;
    let resolved = root.canonicalize().map_err(|source| GateError::Resolve {
        path: root.to_path_buf(),
        source,
    })?;
    let violations = check(&export, &find_sources(&resolved)?)?;
    violations
        .iter()
        .try_for_each(|violation| writeln!(out, "{violation}"))
        .map_err(GateError::Write)?;
    Ok(violations.is_empty())
}
