use crate::error::GateError;
use crate::manifest::KERNEL_DIR;
use serde::Deserialize;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;


const MANIFEST: &str = "Cargo.toml";


const CARGO_VARIABLE: &str = "CARGO";


const CARGO_DEFAULT: &str = "cargo";


const BUILD_SCRIPT_KIND: &str = "custom-build";


const STDERR_LIMIT: usize = 2000;


#[derive(Debug, Deserialize)]
pub struct Metadata {
    pub packages: Vec<Package>,
}


#[derive(Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub manifest_path: PathBuf,
    pub dependencies: Vec<Dependency>,
    pub targets: Vec<Target>,
}


#[derive(Debug, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub path: Option<PathBuf>,
}


#[derive(Debug, Deserialize)]
pub struct Target {
    pub kind: Vec<String>,
}


pub fn parse_metadata(bytes: &[u8]) -> Result<Metadata, GateError> {
    serde_json::from_slice(bytes).map_err(GateError::MetadataParse)
}


/// The workspace members according to cargo itself (`cargo metadata --no-deps`); a root with no manifest has none.
pub fn workspace_packages(root: &Path) -> Result<Vec<Package>, GateError> {
    workspace_packages_with(&cargo_program(std::env::var_os(CARGO_VARIABLE)), root)
}


pub fn cargo_program(variable: Option<OsString>) -> OsString {
    variable.unwrap_or_else(|| OsString::from(CARGO_DEFAULT))
}


pub fn workspace_packages_with(cargo: &OsStr, root: &Path) -> Result<Vec<Package>, GateError> {
    let manifest = root.join(MANIFEST);
    let present = manifest.try_exists().map_err(|source| GateError::ReadManifest {
        path: manifest.clone(),
        source,
    })?;
    if present {
        let output = Command::new(cargo)
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--offline",
                "--locked",
                "--manifest-path",
            ])
            .arg(&manifest)
            .output()
            .map_err(GateError::MetadataRun)?;
        if output.status.success() {
            parse_metadata(&output.stdout).map(|metadata| metadata.packages)
        } else {
            Err(GateError::MetadataFailed {
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).chars().take(STDERR_LIMIT).collect(),
            })
        }
    } else {
        Ok(Vec::new())
    }
}


pub fn resolve(path: &Path) -> Result<PathBuf, GateError> {
    path.canonicalize().map_err(|source| GateError::Resolve {
        path: path.to_path_buf(),
        source,
    })
}


pub fn is_under_kernel(root: &Path, path: &Path) -> Result<bool, GateError> {
    resolve(path).map(|resolved| resolved.starts_with(root.join(KERNEL_DIR)))
}


pub fn excluded_package(root: &Path, package: &Package) -> Result<Option<String>, GateError> {
    let own = is_under_kernel(root, &package.manifest_path)?.then(|| package.name.clone());
    let linked = package
        .dependencies
        .iter()
        .filter_map(|dependency| dependency.path.as_ref().map(|path| (dependency, path)))
        .map(|(dependency, path)| is_under_kernel(root, path).map(|under| under.then(|| dependency.name.clone())))
        .find_map(Result::transpose)
        .transpose()?;
    Ok(own.or(linked))
}


/// Rule 2 of T692A cycle 2: no workspace member lives under, or depends by path on, the excluded kernel directory.
pub fn refuse_excluded_packages(root: &Path, packages: &[Package]) -> Result<(), GateError> {
    packages
        .iter()
        .map(|package| excluded_package(root, package))
        .find_map(Result::transpose)
        .transpose()?
        .map_or(Ok(()), |name| Err(GateError::ExcludedPackage { name }))
}


pub fn has_build_script(package: &Package) -> bool {
    package
        .targets
        .iter()
        .any(|target| target.kind.iter().any(|kind| kind == BUILD_SCRIPT_KIND))
}
