use std::io::{self, Read};


/// Reads a pipe under a byte bound: the bytes and whether more was written.
pub type ReadFn = fn(&mut dyn Read, usize) -> io::Result<(Vec<u8>, bool)>;
