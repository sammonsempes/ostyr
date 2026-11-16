use std::fs::{File, Metadata};
use std::io;
use zeroize::Zeroizing;


pub type ReadAtFn = fn(&File, u64) -> io::Result<Zeroizing<Vec<u8>>>;


pub type InspectFn = fn(&File) -> io::Result<Metadata>;
