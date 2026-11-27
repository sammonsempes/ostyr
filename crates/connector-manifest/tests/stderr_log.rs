#![cfg(target_os = "linux")]

use connector_manifest::run::{log_reaping, pump_stderr, Event};
use std::error::Error;
use std::io::{self, Cursor, Write};
use std::sync::{Arc, Mutex};


const MARKER: &str = "CREDENTIAL-MARKER-9917 ";


const REPEATS: usize = 40;


pub struct Capture {
    pub bytes: Arc<Mutex<Vec<u8>>>,
}


impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.bytes.lock().map_err(|_| io::Error::other("poisoned"))?.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn stderr_bytes_are_counted_and_never_reach_a_log_line() -> Result<(), Box<dyn Error>> {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    tracing_log::LogTracer::init()?;
    let sink = bytes.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || Capture { bytes: sink.clone() })
        .finish();
    let mut events = Vec::new();
    tracing::subscriber::with_default(subscriber, || {
        log_reaping(Err(io::Error::other("kill")), Ok(std::os::unix::process::ExitStatusExt::from_raw(0)));
        pump_stderr(&mut Cursor::new(MARKER.repeat(REPEATS).into_bytes()), &mut |event| events.push(event));
    });
    let captured = String::from_utf8(bytes.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(captured.contains("could not be killed"), "the capture works: {captured}");
    assert!(!captured.contains("CREDENTIAL-MARKER"), "{captured}");
    assert!(matches!(events.as_slice(), [Event::Stderr(Ok(report))] if report.bytes == (MARKER.len() * REPEATS) as u64));
    Ok(())
}
