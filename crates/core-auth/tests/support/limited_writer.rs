use std::io::{self, Write};


#[derive(Debug, Clone)]
pub struct LimitedWriter {
    pub operations_left: usize,
    pub bytes: Vec<u8>,
}


impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self.operations_left.checked_sub(1) {
            Some(left) => {
                self.operations_left = left;
                self.bytes.extend_from_slice(buffer);
                Ok(buffer.len())
            }
            None => Err(io::Error::other("injected write failure")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.operations_left.checked_sub(1) {
            Some(left) => {
                self.operations_left = left;
                Ok(())
            }
            None => Err(io::Error::other("injected flush failure")),
        }
    }
}
