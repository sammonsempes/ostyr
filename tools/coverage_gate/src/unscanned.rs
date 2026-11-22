use crate::error::GateError;
use crate::export::Export;
use crate::metadata::{has_build_script, Package};
use crate::scan::BUILD_DIR;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;


const OLD_OUT_TAIL: usize = 4;


const NEW_OUT_TAIL: usize = 5;


const HASH_LENGTH: usize = 16;


const GENERATED_EXTENSION: &str = "rs";


const PROTO_EXTENSION: &str = "proto";


const PROTO_PACKAGE_PREFIX: &str = "package ";


/// The canonical path of an export entry; a file that no longer exists keeps its path, so it can match nothing scanned.
pub fn canonical_entry(path: &Path) -> Result<PathBuf, GateError> {
    match path.canonicalize() {
        Ok(resolved) => Ok(resolved),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(source) => Err(GateError::Resolve {
            path: path.to_path_buf(),
            source,
        }),
    }
}


pub fn is_hash(name: &str) -> bool {
    name.len() == HASH_LENGTH && name.chars().all(|character| character.is_ascii_hexdigit())
}


pub fn package_of_build_dir(name: &str) -> Option<&str> {
    name.rsplit_once('-').filter(|(_, hash)| is_hash(hash)).map(|(package, _)| package)
}


/// `(package, file name)` for a build script `OUT_DIR` under `base`: `build/<package>-<hash>/out/<file>` (older cargo) or `build/<package>/<hash>/out/<file>` (current).
pub fn out_dir_file<'a>(base: &Path, file: &'a Path) -> Option<(&'a str, &'a str)> {
    let relative = file.strip_prefix(base).ok()?;
    let names: Vec<&str> = relative.components().map(|part| part.as_os_str().to_str().unwrap_or("")).collect();
    let old = names.len().checked_sub(OLD_OUT_TAIL).and_then(|start| names.get(start..));
    let new = names.len().checked_sub(NEW_OUT_TAIL).and_then(|start| names.get(start..));
    match (old, new) {
        (_, Some(["build", package, hash, "out", name])) if is_hash(hash) => Some((package, name)),
        (Some(["build", directory, "out", name]), _) => package_of_build_dir(directory).map(|package| (package, *name)),
        _ => None,
    }
}


pub fn proto_packages(directory: &Path) -> Result<Vec<String>, GateError> {
    let protos: Vec<PathBuf> = WalkDir::new(directory)
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != BUILD_DIR)
        .map(|walked| walked.map(walkdir::DirEntry::into_path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == PROTO_EXTENSION))
        .collect();
    let texts = protos
        .iter()
        .map(|path| std::fs::read_to_string(path).map_err(|source| GateError::ReadSource { path: path.clone(), source }))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(texts
        .iter()
        .flat_map(|text| text.lines())
        .filter_map(|line| line.trim().strip_prefix(PROTO_PACKAGE_PREFIX))
        .filter_map(|rest| rest.strip_suffix(';'))
        .map(|name| name.trim().to_string())
        .collect())
}


/// An `OUT_DIR` file of a workspace package is allowed only as `<proto package>.rs` in the `OUT_DIR` of a workspace package that has a build script and a `.proto` declaring that package.
pub fn out_dir_allowed(packages: &[&Package], package: &str, name: &str) -> Result<bool, GateError> {
    let owner = packages
        .iter()
        .find(|candidate| candidate.name == package && has_build_script(candidate))
        .copied();
    let stem = Path::new(name)
        .extension()
        .is_some_and(|extension| extension == GENERATED_EXTENSION)
        .then(|| Path::new(name).file_stem().and_then(|stem| stem.to_str()))
        .flatten();
    match (owner, stem) {
        (Some(found), Some(stem_name)) => {
            let directory = found.manifest_path.parent().ok_or_else(|| GateError::Resolve {
                path: found.manifest_path.clone(),
                source: std::io::Error::from(ErrorKind::NotFound),
            })?;
            proto_packages(directory).map(|declared| declared.iter().any(|declared_name| declared_name == stem_name))
        }
        _ => Ok(false),
    }
}


pub fn is_refused(root: &Path, scanned: &[PathBuf], packages: &[&Package], file: &Path) -> Result<bool, GateError> {
    let canonical = canonical_entry(file)?;
    match out_dir_file(&root.join(BUILD_DIR), &canonical) {
        _ if scanned.contains(&canonical) => Ok(false),
        Some((package, name)) => out_dir_allowed(packages, package, name).map(|allowed| !allowed),
        None => Ok(canonical.starts_with(root)),
    }
}


/// Rule 1 of T692A cycle 2: every export file under the workspace must be one the gate scanned, or generated protobuf in an `OUT_DIR`.
pub fn first_unscanned(export: &Export, root: &Path, scanned: &[PathBuf], packages: &[&Package]) -> Result<Option<PathBuf>, GateError> {
    export
        .data
        .iter()
        .flat_map(|data| &data.files)
        .map(|entry| is_refused(root, scanned, packages, &entry.filename).map(|refused| refused.then(|| entry.filename.clone())))
        .find_map(Result::transpose)
        .transpose()
}


pub fn refuse_unscanned(export: &Export, root: &Path, scanned: &[PathBuf], packages: &[&Package]) -> Result<(), GateError> {
    first_unscanned(export, root, scanned, packages)?.map_or(Ok(()), |path| Err(GateError::UnscannedExportFile { path }))
}
