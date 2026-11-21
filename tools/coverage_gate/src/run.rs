use crate::check::check;
use crate::depinfo::{refuse_unchecked, Packages, DEPS_FLAG};
use crate::error::GateError;
use crate::export::parse_export;
use crate::manifest::kernel_declared;
use crate::metadata::{load_metadata, path_packages, refuse_excluded_packages, workspace_members};
use crate::scan::find_sources;
use crate::unscanned::refuse_unscanned;
use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};


const DEFAULT_ROOT: &str = ".";


const EXPORT_ARG: usize = 1;


const ROOT_ARG: usize = 2;


const FIRST_SCOPE_ARG: usize = 3;


/// Keeps the sources under one of the scope directories (relative to the root); no directory keeps all.
pub fn in_scope(sources: Vec<PathBuf>, root: &Path, scope: &[String]) -> Vec<PathBuf> {
    sources
        .into_iter()
        .filter(|source| scope.is_empty() || scope.iter().any(|dir| source.starts_with(root.join(dir))))
        .collect()
}


const DEPS_ENV: &str = "CARGO_LLVM_COV_TARGET_DIR";


/// The `--deps-dir` flags win; with none, the llvm-cov target directory the hook exports (an old hook copy may not pass the flag, T692A).
pub fn deps_directories(flagged: Vec<PathBuf>, from_env: Option<OsString>) -> Vec<PathBuf> {
    if flagged.is_empty() {
        from_env.filter(|value| !value.is_empty()).map(PathBuf::from).into_iter().collect()
    } else {
        flagged
    }
}


/// `--deps-dir=<dir>` arguments are the build directories holding the dep-info files; the other extra arguments are scope directories.
pub fn split_arguments(args: &[String]) -> (Vec<PathBuf>, Vec<String>) {
    let extra: Vec<&String> = args.iter().skip(FIRST_SCOPE_ARG).collect();
    let directories = extra.iter().filter_map(|arg| arg.strip_prefix(DEPS_FLAG)).map(PathBuf::from).collect();
    let scope = extra.iter().filter(|arg| !arg.starts_with(DEPS_FLAG)).map(|arg| (*arg).clone()).collect();
    (directories, scope)
}


const KERNEL_COMMAND: &str = "kernel-declared";


pub fn run<Output: Write>(args: &[String], mut out: Output) -> Result<bool, GateError> {
    run_dyn(args, &mut out)
}


pub fn run_dyn(args: &[String], out: &mut dyn Write) -> Result<bool, GateError> {
    match args.get(EXPORT_ARG).map(String::as_str) {
        Some(KERNEL_COMMAND) => print_kernel_answer(args, out),
        _ => run_gate(args, out),
    }
}


/// `coverage_gate kernel-declared [root]` answers `declared` or `absent`, or fails.
pub fn kernel_answer(args: &[String]) -> Result<&'static str, GateError> {
    let root = Path::new(args.get(ROOT_ARG).map_or(DEFAULT_ROOT, String::as_str));
    let declared = kernel_declared(root)?;
    Ok(if declared { "declared" } else { "absent" })
}


pub fn print_kernel_answer(args: &[String], out: &mut dyn Write) -> Result<bool, GateError> {
    let word = kernel_answer(args)?;
    writeln!(out, "{word}").map_err(GateError::Write)?;
    Ok(true)
}


pub fn run_gate(args: &[String], out: &mut dyn Write) -> Result<bool, GateError> {
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
    let (flagged, scope) = split_arguments(args);
    let directories = deps_directories(flagged, std::env::var_os(DEPS_ENV));
    let scanned = find_sources(&resolved)?;
    let metadata = load_metadata(&resolved)?;
    refuse_excluded_packages(&resolved, &metadata.packages)?;
    let members = workspace_members(&metadata);
    refuse_unscanned(&export, &resolved, &scanned, &members)?;
    let packages = Packages {
        members: &members,
        path: &path_packages(&metadata),
    };
    refuse_unchecked(&resolved, &scanned, &packages, &directories, &scope)?;
    let violations = check(&export, &resolved, &in_scope(scanned, &resolved, &scope))?;
    violations
        .iter()
        .try_for_each(|violation| writeln!(out, "{violation}"))
        .map_err(GateError::Write)?;
    Ok(violations.is_empty())
}
