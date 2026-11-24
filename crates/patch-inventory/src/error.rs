//! Errors that refuse a whole input.

use thiserror::Error;


#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("reading the package manager output failed")]
    Read(#[from] std::io::Error),
    #[error("input is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("input has more than {limit} lines")]
    TooManyLines { limit: usize },
}


#[derive(Debug, Error)]
pub enum WindowsError {
    #[error("reading the update search output failed")]
    Input(#[from] InventoryError),
    #[error("the update search output holds a byte outside printable ASCII")]
    NotAscii,
    #[error("the update search printed nothing")]
    NoOutput,
    #[error("the update search output is not the expected JSON envelope (line {line}, column {column})")]
    Malformed { line: usize, column: usize },
    #[error("the update search failed with result code {code}")]
    SearchFailed { code: i64 },
    #[error("the update search lists more than {limit} updates")]
    TooManyUpdates { limit: usize },
}


#[derive(Debug, Error)]
pub enum WingetError {
    #[error("reading the winget output failed")]
    Input(#[from] InventoryError),
    #[error("the winget output is not valid UTF-8")]
    Encoding,
    #[error("winget could not open its source")]
    SourceOpenFailed,
    #[error("winget exited with code {code}")]
    Exit { code: i32 },
    #[error("the winget output has no recognisable table")]
    UnrecognisedLayout,
    #[error("the winget output has more than {limit} tables")]
    TooManyTables { limit: usize },
    #[error("the winget output lists more than {limit} updates")]
    TooManyUpdates { limit: usize },
    #[error("a winget table ends with a line that holds no single number")]
    FooterUnreadable,
    #[error("a winget table with rows has no footer line")]
    FooterMissing,
    #[error("a line shaped like a package row follows the end of a winget table")]
    RowAfterTableEnd,
    #[error("a line break other than CR LF follows the first separator of a winget table")]
    LineBreakInTable,
    #[error("the number in a winget footer does not fit in 32 bits")]
    FooterTooLarge,
    #[error("a winget footer counts {footer} rows but the table has {rows}")]
    FooterMismatch { footer: u32, rows: usize },
}
