use std::io;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


#[derive(Clone)]
pub struct Capture(pub Arc<Mutex<Vec<u8>>>);


impl io::Write for Capture {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|error| io::Error::other(error.to_string())).map(|mut inner| {
            inner.extend_from_slice(buffer);
            buffer.len()
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
