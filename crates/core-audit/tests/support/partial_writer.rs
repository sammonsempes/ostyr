use std::io::{self, Write};


pub const HALF_DIVISOR: usize = 2;


#[derive(Debug, Default)]
pub struct PartialWriter {
    pub written: Vec<u8>,
    pub failed_once: bool,
}


impl Write for PartialWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.failed_once {
            Ok(0)
        } else if self.written.is_empty() {
            let half = buffer.len() / HALF_DIVISOR;
            self.written.extend(buffer.iter().take(half));
            Ok(half)
        } else {
            self.failed_once = true;
            Err(io::Error::other("injected partial write failure"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
