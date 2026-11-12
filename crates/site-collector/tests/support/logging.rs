use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use tracing::Dispatch;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


/// Runs `action` with a capturing subscriber and returns its value and everything it logged.
pub fn captured<Output>(action: impl FnOnce() -> Output) -> (Output, String) {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer_buffer = Arc::clone(&buffer);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || SharedBuffer(Arc::clone(&writer_buffer)))
            .finish(),
    );
    let value = tracing::dispatcher::with_default(&dispatch, action);
    let bytes = buffer.lock().unwrap_or_else(PoisonError::into_inner).clone();
    (value, String::from_utf8_lossy(&bytes).into_owned())
}
