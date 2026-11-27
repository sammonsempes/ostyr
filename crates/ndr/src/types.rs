use crate::error::NdrError;
use crate::model::Sighting;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;


/// Reads a pipe under a byte bound: the bytes and whether more was written.
pub type ReadFn = fn(&mut dyn Read, usize) -> io::Result<(Vec<u8>, bool)>;


/// The `fileinfo` lines of one tick, by the SHA-256 of the file they name.
pub type Groups = BTreeMap<String, Vec<Sighting>>;


/// Opens `eve.json`: the production open or a test double.
pub type OpenEveFn = fn(&Path) -> Result<Option<File>, NdrError>;
