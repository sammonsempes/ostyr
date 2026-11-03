use std::io;
use std::sync::OnceLock;
use tracing::Level;


static INSTALLED: OnceLock<()> = OnceLock::new();


/// Tracing macros skip their arguments when no subscriber listens: installing one makes the coverage of the logging calls honest.
pub fn init_logging() {
    INSTALLED.get_or_init(|| {
        tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(io::sink).init();
    });
}
