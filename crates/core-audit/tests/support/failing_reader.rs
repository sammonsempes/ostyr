use std::io::{self, Cursor, Read};


pub struct FailingReader {
    pub inner: Cursor<Vec<u8>>,
    pub fail_at_end: bool,
}


pub fn flaky_reader(data: Vec<u8>, fail_at_end: bool) -> FailingReader {
    FailingReader {
        inner: Cursor::new(data),
        fail_at_end,
    }
}


impl Read for FailingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        if count == 0 && self.fail_at_end {
            Err(io::Error::other("injected read failure"))
        } else {
            Ok(count)
        }
    }
}
