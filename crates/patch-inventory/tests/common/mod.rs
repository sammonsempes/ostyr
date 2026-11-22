use patch_inventory::limits::default_limits;
use patch_inventory::model::{Device, Limits};
use std::collections::BTreeMap;
use std::io::Read;


pub mod types;


pub use types::TestResult;


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected failure"))
    }
}


pub fn device() -> Device {
    Device {
        tenant: "tenant-a".to_string(),
        device_id: "device-1".to_string(),
    }
}


pub fn limits() -> Limits {
    default_limits()
}


pub fn skipped_count<Reason: Ord>(skipped: &BTreeMap<Reason, usize>, reason: Reason) -> usize {
    skipped.get(&reason).copied().unwrap_or(0)
}
