use std::{io, path::Path};


pub type FileReader = fn(&Path) -> io::Result<Vec<u8>>;


pub type Position = (usize, usize);


pub type CallGraph = std::collections::BTreeMap<String, std::collections::BTreeSet<String>>;
