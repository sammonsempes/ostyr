use std::io::{self, Write};


#[derive(Debug, Clone, Copy)]
pub struct FailingWriter {
    pub fail_write: bool,
    pub fail_flush: bool,
}


impl Write for FailingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            Err(io::Error::other("injected write failure"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}
