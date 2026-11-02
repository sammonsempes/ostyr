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
    #[error("cannot write the report")]
    Write(#[source] io::Error),
}
