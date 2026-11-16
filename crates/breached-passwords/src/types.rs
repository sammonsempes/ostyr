use std::fs::{File, Metadata};
use std::io;


pub type InspectFn = fn(&File) -> io::Result<Metadata>;
