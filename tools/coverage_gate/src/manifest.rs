use crate::error::GateError;
use serde::Deserialize;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};


const MANIFEST: &str = "Cargo.toml";


const KERNEL_DIR: &str = "crates/ebpf-probes/ebpf";


#[derive(Debug, Default, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub workspace: WorkspaceTable,
}


#[derive(Debug, Default, Deserialize)]
pub struct WorkspaceTable {
    #[serde(default)]
    pub exclude: Vec<String>,
}


pub fn parse_manifest(path: &Path, text: &str) -> Result<Manifest, GateError> {
    toml::from_str(text).map_err(|source| GateError::ParseManifest {
        path: path.to_path_buf(),
        source,
    })
}


pub fn read_manifest(root: &Path) -> Result<Manifest, GateError> {
    let path = root.join(MANIFEST);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_manifest(&path, &text),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(Manifest::default()),
        Err(source) => Err(GateError::ReadManifest { path, source }),
    }
}


/// The only exclude entry the gate accepts is the eBPF kernel crate directory, which cannot be built for the host.
pub fn is_boundary_entry(entry: &str) -> bool {
    Path::new(entry) == Path::new(KERNEL_DIR)
}


pub fn excluded_dirs(root: &Path) -> Result<Vec<PathBuf>, GateError> {
    read_manifest(root)?
        .workspace
        .exclude
        .iter()
        .map(|entry| {
            if is_boundary_entry(entry) {
                Ok(root.join(entry))
            } else {
                Err(GateError::ExcludeRefused { entry: entry.clone() })
            }
        })
        .collect()
}
