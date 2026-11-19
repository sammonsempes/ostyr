#[path = "common/types.rs"]
mod types;


use cert_inventory::alerting::{micros_of, MAX_CREATED_MICROS, MICROS_PER_SECOND};
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use types::TestResult;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


const NEGATIVE_SECONDS: i64 = -86_400;


struct CaptureWriter(Arc<Mutex<Vec<u8>>>);


impl Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut guard = self.0.lock().map_err(|_poisoned| std::io::Error::other("poisoned"))?;
        guard.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn captured<Output>(run: impl FnOnce() -> Output) -> Result<(Output, String), Box<dyn std::error::Error>> {
    LazyLock::force(&ANCHOR);
    let capture: Arc<Mutex<Vec<u8>>> = Arc::default();
    let sink = Arc::clone(&capture);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || CaptureWriter(Arc::clone(&sink)))
            .with_ansi(false)
            .finish(),
    );
    let value = tracing::dispatcher::with_default(&dispatch, run);
    let bytes = capture.lock().map_err(|_poisoned| std::io::Error::other("poisoned"))?.clone();
    Ok((value, String::from_utf8(bytes)?))
}


#[test]
fn a_negative_time_is_clamped_with_one_warning() -> TestResult {
    let (micros, log) = captured(|| micros_of(NEGATIVE_SECONDS))?;
    assert_eq!(micros, 0);
    assert_eq!(log.lines().count(), 1);
    assert!(log.contains("negative time clamped to zero"));
    assert!(log.contains(&NEGATIVE_SECONDS.to_string()));
    Ok(())
}


#[test]
fn a_valid_and_a_huge_time_log_nothing() -> TestResult {
    let (values, log) = captured(|| (micros_of(1), micros_of(i64::MAX)))?;
    assert_eq!(values, (MICROS_PER_SECOND, MAX_CREATED_MICROS));
    assert!(log.is_empty());
    Ok(())
}
