use crate::error::GateError;
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;


#[derive(Debug, Deserialize)]
pub struct Export {
    pub data: Vec<Data>,
}


#[derive(Debug, Deserialize)]
pub struct Data {
    pub files: Vec<FileEntry>,
}


#[derive(Debug, Deserialize)]
pub struct FileEntry {
    pub filename: PathBuf,
    pub summary: Summary,
}


#[derive(Debug, Deserialize)]
pub struct Summary {
    pub lines: Counts,
    pub branches: Counts,
}


#[derive(Debug, Deserialize)]
pub struct Counts {
    pub count: u64,
    pub covered: u64,
}


pub fn parse_export<Input: Read>(mut reader: Input) -> Result<Export, GateError> {
    let mut text = String::new();
    reader.read_to_string(&mut text).map_err(GateError::Read)?;
    serde_json::from_str(&text).map_err(GateError::Parse)
}
