use crate::model::Sighting;
use std::collections::BTreeMap;
use std::io::{self, Read};


/// Reads a pipe under a byte bound: the bytes and whether more was written.
pub type ReadFn = fn(&mut dyn Read, usize) -> io::Result<(Vec<u8>, bool)>;


/// The `fileinfo` lines of one tick, by the SHA-256 of the file they name.
pub type Groups = BTreeMap<String, Vec<Sighting>>;
