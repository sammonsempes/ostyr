use crate::recording::{Header, Trailer};
use crate::session::CloseReason;
use crate::types::ChainHash;


/// A bound value; the tenant is bound as `$1` by the executor, these start at `$2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Int(i64),
    Text(String),
    Bool(bool),
    Bytes(Vec<u8>),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
    Null,
    Unreadable,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub sql: &'static str,
    pub params: Vec<Param>,
}


/// What closes a session: the recording's header (checked against the row), its trailer and final hash, its frame count (header and trailer included) and its byte length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseRecord {
    pub header: Header,
    pub reason: CloseReason,
    pub trailer: Trailer,
    pub final_hash: ChainHash,
    pub frames: u64,
    pub bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub session_id: String,
    pub requester: String,
    pub asset: String,
    pub ticket: String,
    pub opened_at: i64,
    pub closed_at: Option<i64>,
    pub close_reason: Option<String>,
    pub recording_frames: Option<i64>,
    pub recording_hash: Option<Vec<u8>>,
    pub recording_bytes: Option<i64>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListFilter {
    pub asset: Option<String>,
    pub requester: Option<String>,
    pub open_only: bool,
}


/// The last row of the previous page: the next page starts strictly after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub opened_at: i64,
    pub session_id: String,
}


/// A served page: the rows that passed the serving check, the count of rows read and refused, and the cursor text of the next page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    pub rows: Vec<SessionRow>,
    pub skipped: usize,
    pub next_cursor: Option<String>,
}
