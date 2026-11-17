pub use crate::types::TestResult;
use ndr::model::{Limits, Yr};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use time::OffsetDateTime;


pub const SHA_A: &str = "aa00000000000000000000000000000000000000000000000000000000000000";


pub const SHA_B: &str = "bb00000000000000000000000000000000000000000000000000000000000000";


pub const SHA_C: &str = "cc00000000000000000000000000000000000000000000000000000000000000";


pub const SHA_D: &str = "dd00000000000000000000000000000000000000000000000000000000000000";


pub const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";


pub const EICAR_RULE: &str = "rule eicar { strings: $a = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\" condition: $a }";


pub const SECOND_RULE: &str = "rule marker { strings: $a = \"EICAR\" condition: $a }";


pub const BAD_RULE: &str = "rule broken { condition: undefined_identifier }";


pub const TINY_LIMIT: u64 = 8;


pub const TWO: usize = 2;


pub const THREE: usize = 3;


pub const FOUR: u64 = 4;


pub const QUICK_MILLIS: u64 = 300;


pub const MODE_EXECUTABLE: u32 = 0o755;


pub const FAKE_YR: &str = "fake";


pub const EMPTY: &str = "empty";


pub const EXIT_OK: &str = "exit_ok";


pub const EXIT_THREE: &str = "exit_three";


pub const ENV_ECHO: &str = "env_echo";


pub const SLEEP: &str = "sleep";


pub const CLOSE_FDS: &str = "close_fds";


pub const PID_FLOOD: &str = "pid_flood";


pub const PID_SLEEP: &str = "pid_sleep";


pub const HANG_SCAN: &str = "hang_scan";


pub const FLOOD_SCAN: &str = "flood_scan";


pub const STDERR_TIMEOUT: &str = "stderr_timeout";


pub const EXIT_ONE_SCAN: &str = "exit_one_scan";


pub const STAT_YR: &str = "stat_yr";


pub const GROUP_UMASK: u32 = 0o002;


const COMPILE_OK: &str = "compile) : > \"$3\"; exit 0;;";


const FAKE_SCRIPT_COUNT: usize = 14;


const FAKE_BODY: &str = r#"#!/bin/sh
case "$1" in
compile)
    out="$3"
    shift 4
    for source in "$@"; do
        if /bin/grep -q undefined_identifier "$source"; then
            echo "error: unknown identifier" >&2
            exit 1
        fi
    done
    : > "$out"
    exit 0
    ;;
scan)
    shift 11
    if /bin/grep -q EICAR-STANDARD "$1"; then
        echo '{"path":"p","rules":[{"identifier":"eicar"}]}'
    fi
    exit 0
    ;;
esac
exit 2
"#;


const STAT_BODY: &str = r#"#!/bin/sh
case "$1" in
compile)
    out="$3"
    ws="${out%/*}"
    shift 4
    /usr/bin/stat -c '%a %u' "$ws" "$@" > "${ws%/*}/report-compile"
    : > "$out"
    exit 0
    ;;
scan)
    shift 11
    ws="${1%/*}"
    /usr/bin/stat -c '%a %u' "$ws" "$1" > "${ws%/*}/report-scan"
    exit 0
    ;;
esac
exit 2
"#;


/// Every fake `yr`, written once before any test starts a child: writing an executable while another thread forks gives ETXTBSY.
const FAKE_SCRIPTS: [(&str, &str); FAKE_SCRIPT_COUNT] = [
    (FAKE_YR, FAKE_BODY),
    (EMPTY, "#!/bin/sh\n"),
    (EXIT_OK, "#!/bin/sh\nexit 0\n"),
    (EXIT_THREE, "#!/bin/sh\nexit 3\n"),
    (ENV_ECHO, "#!/bin/sh\necho \"out [${HOME:-unset}]\"\necho err >&2\n/bin/cat\n"),
    (SLEEP, "#!/bin/sh\nexec /bin/sleep 1000\n"),
    (CLOSE_FDS, "#!/bin/sh\nexec >&- 2>&-\nexec /bin/sleep 1000\n"),
    (PID_FLOOD, "#!/bin/sh\necho $$ > \"$1\"\nexec /usr/bin/yes aaaaaaaaaaaaaaaa\n"),
    (PID_SLEEP, "#!/bin/sh\necho $$ > \"$1\"\nexec /bin/sleep 1000\n"),
    (HANG_SCAN, "#!/bin/sh\ncase \"$1\" in\nCOMPILE_OK\nscan) exec /bin/sleep 1000;;\nesac\n"),
    (
        FLOOD_SCAN,
        "#!/bin/sh\ncase \"$1\" in\nCOMPILE_OK\nscan) exec /usr/bin/yes aaaaaaaaaaaaaaaa;;\nesac\n",
    ),
    (
        STDERR_TIMEOUT,
        "#!/bin/sh\ncase \"$1\" in\nCOMPILE_OK\nscan) echo 'error: scanning x: timeout' >&2; exit 0;;\nesac\n",
    ),
    (EXIT_ONE_SCAN, "#!/bin/sh\ncase \"$1\" in\nCOMPILE_OK\nscan) exit 1;;\nesac\n"),
    (STAT_YR, STAT_BODY),
];


static SHARED_DIR: LazyLock<Result<PathBuf, String>> = LazyLock::new(write_scripts);


pub fn write_scripts() -> Result<PathBuf, String> {
    let dir = tempfile::Builder::new()
        .prefix("fake-yr-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .map_err(|error| error.to_string())?
        .keep();
    FAKE_SCRIPTS.iter().try_for_each(|(name, text)| {
        let program = dir.join(name);
        fs::write(&program, text.replace("COMPILE_OK", COMPILE_OK)).map_err(|error| error.to_string())?;
        fs::set_permissions(&program, fs::Permissions::from_mode(MODE_EXECUTABLE)).map_err(|error| error.to_string())
    })?;
    Ok(dir)
}


/// Forces the one-time script write; every test that starts a child calls it (through `fixture`) first.
pub fn ready() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(SHARED_DIR.as_ref().map_err(|error| error.clone())?.clone())
}


/// Limits with a short deadline; the outcome does not depend on speed, only on the fake `yr` never ending.
pub fn quick_limits() -> Limits {
    Limits {
        scan_timeout: std::time::Duration::from_millis(QUICK_MILLIS),
        compile_timeout: std::time::Duration::from_millis(QUICK_MILLIS),
        ..Limits::default()
    }
}


pub fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}


/// A shared fake `yr` script by name and a private work directory, removed with the value.
pub struct Fixture {
    pub program_dir: PathBuf,
    pub work_dir: tempfile::TempDir,
    pub yr: Yr,
}


pub fn fixture(name: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let program_dir = ready()?;
    let work_dir = tempfile::tempdir()?;
    let yr = Yr {
        program: program_dir.join(name),
        work_dir: work_dir.path().to_path_buf(),
    };
    Ok(Fixture { program_dir, work_dir, yr })
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


static LOGGING: LazyLock<bool> = LazyLock::new(|| {
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .finish(),
    )
    .is_ok()
});


/// A global subscriber that is always interested, so tracing fields are evaluated whatever the test order.
pub fn logging_on() -> bool {
    *LOGGING
}
