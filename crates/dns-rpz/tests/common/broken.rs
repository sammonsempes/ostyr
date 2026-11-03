use std::io::{self, Read};


pub struct BrokenReader;


impl Read for BrokenReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}
