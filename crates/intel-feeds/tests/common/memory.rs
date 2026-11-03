use std::collections::BTreeMap;
use std::io::{self, BufRead, Cursor, Write};
use std::path::Path;


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected"))
    }
}


pub fn open_from(files: &BTreeMap<&str, &str>, path: &Path) -> io::Result<Box<dyn BufRead>> {
    files
        .get(path.to_string_lossy().as_ref())
        .map(|text| Box::new(Cursor::new(text.as_bytes().to_vec())) as Box<dyn BufRead>)
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}
