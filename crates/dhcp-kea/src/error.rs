use std::io;
use std::str::Utf8Error;
use thiserror::Error;


#[derive(Debug, Error)]
pub enum HeaderError {
    #[error("the header has no `{0}` column")]
    Missing(&'static str),
    #[error("the header repeats the `{0}` column")]
    Duplicate(&'static str),
    #[error("the header has more than {max} columns")]
    TooManyColumns { max: usize },
    #[error("the header line is longer than the line cap")]
    TooLong,
    #[error("the header line is not valid UTF-8: {0}")]
    Utf8(#[from] Utf8Error),
}


#[derive(Debug, Error)]
pub enum RowError {
    #[error("column-count")]
    ColumnCount,
    #[error("address")]
    Address,
    #[error("hwaddr")]
    Mac,
    #[error("expire")]
    Expire,
    #[error("valid_lifetime")]
    Lifetime,
    #[error("lifetime-range")]
    Range,
    #[error("subnet_id")]
    Subnet,
    #[error("state")]
    State,
    #[error("line-too-long")]
    TooLong,
    #[error("not-utf8")]
    Utf8,
}


#[derive(Debug, Error)]
pub enum KeaError {
    #[error("refused lease file header: {0}")]
    Header(#[from] HeaderError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("the lease file is not a regular file")]
    NotRegular,
    #[error("cannot serialise the ECS event: {0}")]
    Export(#[from] core_export::error::ExportError),
    #[error("usage: kea_leases <csv> [--follow]")]
    Usage,
}
