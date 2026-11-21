use std::io;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum GateError {
    #[error("usage: coverage_gate <llvm-cov-json> [workspace-root]")]
    Usage,
    #[error("cannot open {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read the coverage export")]
    Read(#[source] io::Error),
    #[error("malformed coverage export")]
    Parse(#[source] serde_json::Error),
    #[error("cannot resolve {path}")]
    Resolve {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read source {path}")]
    ReadSource {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot parse source {path}")]
    ParseSource {
        path: PathBuf,
        #[source]
        source: syn::Error,
    },
    #[error("cannot scan the workspace")]
    Walk(#[from] walkdir::Error),
    #[error("cannot read the workspace manifest {path}")]
    ReadManifest {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("malformed workspace manifest {path}")]
    ParseManifest {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("workspace.exclude entry {entry} is not crates/ebpf-probes/ebpf: an exclude cannot hide a crate from the gate")]
    ExcludeRefused { entry: String },
    #[error("{path} exists but the root workspace.exclude has no exact crates/ebpf-probes/ebpf entry: the kernel crate would escape the gate")]
    KernelUndeclared { path: PathBuf },
    #[error("{path} uses {form}, which the gate refuses: a skipped file could hide behind it")]
    HiddenInclude { path: PathBuf, form: &'static str },
    #[error("{path} declares a module with #[path]: the gate refuses it, a skipped file could hide behind it")]
    PathModule { path: PathBuf },
    #[error("cannot run cargo metadata")]
    MetadataRun(#[source] io::Error),
    #[error("cargo metadata failed ({status}): {stderr}")]
    MetadataFailed { status: String, stderr: String },
    #[error("malformed cargo metadata output")]
    MetadataParse(#[source] serde_json::Error),
    #[error("{path} is in the coverage export but the gate did not scan it: compiled code outside the scanned sources escapes the gate")]
    UnscannedExportFile { path: PathBuf },
    #[error("package {name} lies under or resolves into crates/ebpf-probes/ebpf: only the kernel crate itself lives there, outside the workspace")]
    ExcludedPackage { name: String },
    #[error("{path} was compiled into a workspace library or binary but the gate neither scanned it nor allowed it: compiled code outside the scanned sources escapes the gate")]
    UncheckedCompiledFile { path: PathBuf },
    #[error("no dep-info for {package} target {target}: what rustc compiled cannot be checked")]
    MissingDepInfo { package: String, target: String },
    #[error("cannot write the report")]
    Write(#[source] io::Error),
}
