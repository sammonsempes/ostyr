use std::io::{self, Write};


/// Accepts `remaining` bytes in total, then fails every write and flush.
pub struct LimitedWriter {
    pub remaining: usize,
}


impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            Err(io::Error::other("injected"))
        } else {
            self.remaining -= buffer.len();
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
