use std::{io, path::Path};


pub type FileReader = fn(&Path) -> io::Result<Vec<u8>>;


pub type Position = (usize, usize);
