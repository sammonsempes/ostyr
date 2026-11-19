#[path = "common/record.rs"]
mod record;
#[path = "common/types.rs"]
mod types;


use cert_inventory::alerting::{expiry_alerts, micros_of, MAX_CREATED_MICROS, MICROS_PER_SECOND};
use cert_inventory::model::CertRecord;
use core_pg::scope::tenant_scope;
use record::record_with;
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use types::TestResult;


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


const NOW: i64 = 1_700_000_000;


const OLD_NOT_AFTER: i64 = -600_000_000;


const MANY: usize = 10_000;


const TWO: usize = 2;


const HEX_LENGTH: usize = 64;


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
fn micros_of_is_pure() -> TestResult {
    let (values, log) = captured(|| (micros_of(NEGATIVE_SECONDS), micros_of(1), micros_of(i64::MAX)))?;
    assert_eq!(values, (0, MICROS_PER_SECOND, MAX_CREATED_MICROS));
    assert!(log.is_empty());
    Ok(())
}


fn old_cert(index: usize, not_after: i64) -> CertRecord {
    let mut record = record_with(&[], not_after);
    record.fingerprint_sha256 = format!("{index:0>width$x}", width = HEX_LENGTH);
    record.subject = "CN=a.example.com".to_owned();
    record
}


#[test]
fn many_clamped_records_give_one_warning_with_the_count() -> TestResult {
    let scope = tenant_scope("acme")?;
    let records: Vec<CertRecord> = (0..MANY).map(|index| old_cert(index, OLD_NOT_AFTER)).collect();
    let (alerts, log) = captured(|| expiry_alerts(&scope, &records, NOW))?;
    assert_eq!(alerts.len(), MANY);
    assert!(alerts.iter().all(|alert| alert.event_time == "0"));
    assert_eq!(log.lines().count(), 1);
    assert!(log.contains(&format!("clamped={MANY}")));
    Ok(())
}


#[test]
fn positive_not_after_and_a_negative_now_give_no_clamp_count() -> TestResult {
    let scope = tenant_scope("acme")?;
    let fresh = vec![old_cert(1, NOW - 1)];
    let records = vec![old_cert(1, NOW - 1), old_cert(TWO, OLD_NOT_AFTER)];
    let (alerts, log) = captured(|| expiry_alerts(&scope, &fresh, NOW))?;
    assert_eq!(alerts.len(), 1);
    assert!(log.is_empty());
    let (none, negative_log) = captured(|| expiry_alerts(&scope, &records, NEGATIVE_SECONDS))?;
    assert!(none.is_empty());
    assert!(negative_log.contains("clamped=0"));
    Ok(())
}
