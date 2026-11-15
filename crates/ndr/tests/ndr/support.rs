pub use crate::types::TestResult;
use ndr::model::Limits;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use time::OffsetDateTime;


pub const SHA_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";


pub const SHA_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";


pub const SHA_C: &str = "cc00000000000000000000000000000000000000000000000000000000000000";


pub const SHA_D: &str = "dd00000000000000000000000000000000000000000000000000000000000000";


pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";


pub const EICAR_RULE: &str = "rule eicar { strings: $a = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\" condition: $a }";


pub const SECOND_RULE: &str = "rule marker { strings: $a = \"EICAR\" condition: $a }";


pub const SLOW_RULE: &str = "rule slow { condition: for any i in (0..2000000000) : ( uint8(i % 60) > 255 ) }";


pub const BAD_RULE: &str = "rule broken { condition: undefined_identifier }";


pub const TINY_LIMIT: u64 = 8;


pub const ONE_SECOND: u64 = 1;


pub const TWO: usize = 2;


pub const THREE: usize = 3;


pub const FOUR: u64 = 4;


/// Limits with a short scan timeout so the timeout test ends quickly; the outcome does not depend on speed, only on the rule running far longer.
pub fn quick_limits() -> Limits {
    Limits {
        scan_timeout: std::time::Duration::from_secs(ONE_SECOND),
        ..Limits::default()
    }
}


pub fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}


pub fn write_rule(dir: &Path, name: &str, text: &str) -> TestResult {
    fs::write(dir.join(name), text)?;
    Ok(())
}


pub fn store(root: &Path, sha256: &str, content: &[u8]) -> TestResult {
    let sub = root.join(sha256.get(..TWO).ok_or("short hash")?);
    fs::create_dir_all(&sub)?;
    fs::write(sub.join(sha256), content)?;
    Ok(())
}


pub fn fileinfo_line(sha256: &str) -> String {
    format!(
        "{{\"event_type\":\"fileinfo\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"10.0.0.2\",\"fileinfo\":{{\"sha256\":\"{sha256}\",\"stored\":true}}}}"
    )
}


pub fn field<'a>(json: &'a serde_json::Value, pointer: &str) -> Option<&'a str> {
    json.pointer(pointer).and_then(serde_json::Value::as_str)
}


static LOGGING: LazyLock<bool> =
    LazyLock::new(|| tracing::subscriber::set_global_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish()).is_ok());


/// A global subscriber that is always interested, so tracing fields are evaluated whatever the test order.
pub fn logging_on() -> bool {
    *LOGGING
}
