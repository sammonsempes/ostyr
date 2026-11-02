use std::{io, path::PathBuf, string::FromUtf8Error};
use thiserror::Error;


#[derive(Debug, Error)]
pub enum LintError {
    #[error("usage: custom_lint <workspace root>")]
    Usage,
    #[error("cannot read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not valid UTF-8", path.display())]
    Utf8 {
        path: PathBuf,
        #[source]
        source: FromUtf8Error,
    },
    #[error("{} is not valid Rust", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: syn::Error,
    },
    #[error("cannot walk the workspace")]
    Walk(#[from] walkdir::Error),
    #[error("cannot write the report")]
    Output(#[from] io::Error),
}
