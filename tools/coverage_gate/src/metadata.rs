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


#[derive(Debug, Default, Deserialize)]
pub struct Metadata {
    pub packages: Vec<Package>,
    pub workspace_members: Vec<String>,
}


#[derive(Debug, Deserialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub manifest_path: PathBuf,
    pub targets: Vec<Target>,
    #[serde(default)]
    pub source: Option<String>,
}


#[derive(Debug, Deserialize)]
pub struct Target {
    pub name: String,
    pub kind: Vec<String>,
    pub src_path: PathBuf,
}


pub fn parse_metadata(bytes: &[u8]) -> Result<Metadata, GateError> {
    serde_json::from_slice(bytes).map_err(GateError::MetadataParse)
}


/// The resolved graph according to cargo itself (`cargo metadata --offline --locked`, no `--no-deps`: it sees `[patch]`); a root with no manifest has none.
pub fn load_metadata(root: &Path) -> Result<Metadata, GateError> {
    load_metadata_with(&cargo_program(std::env::var_os(CARGO_VARIABLE)), root)
}


pub fn workspace_members(metadata: &Metadata) -> Vec<&Package> {
    metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .collect()
}


/// Every package whose source is a path (members, path dependencies, `[patch]` to a path): cargo reports a null or absent `source`.
pub fn path_packages(metadata: &Metadata) -> Vec<&Package> {
    metadata.packages.iter().filter(|package| package.source.is_none()).collect()
}


pub fn cargo_program(variable: Option<OsString>) -> OsString {
    variable.unwrap_or_else(|| OsString::from(CARGO_DEFAULT))
}


pub fn load_metadata_with(cargo: &OsStr, root: &Path) -> Result<Metadata, GateError> {
    let manifest = root.join(MANIFEST);
    let present = manifest.try_exists().map_err(|source| GateError::ReadManifest {
        path: manifest.clone(),
        source,
    })?;
    if present {
        let output = Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--offline", "--locked", "--manifest-path"])
            .arg(&manifest)
            .output()
            .map_err(GateError::MetadataRun)?;
        if output.status.success() {
            parse_metadata(&output.stdout)
        } else {
            Err(GateError::MetadataFailed {
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).chars().take(STDERR_LIMIT).collect(),
            })
        }
    } else {
        Ok(Metadata::default())
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
    is_under_kernel(root, &package.manifest_path).map(|under| under.then(|| package.name.clone()))
}


/// Rule 2 of T692A: no package of the resolved graph (a `[patch]` or a git source patched to a path included) lives under the excluded kernel directory.
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
