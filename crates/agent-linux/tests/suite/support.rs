use agent_linux::cursor::open_state_dir;
use agent_linux::follow::poll;
use agent_linux::model::{Follower, Paths, Report, SourceSettings, StateDir};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use tempfile::{tempdir, TempDir};


pub const EXEC: &str = r#"{"process_exec":{"process":{"pid":42,"uid":1000,"cwd":"/home/alice","binary":"/usr/bin/curl","arguments":"-s"}},"node_name":"node-1","time":"2026-11-03T10:00:00Z"}"#;


pub const UNKNOWN: &str = r#"{"process_loader":{"process":{"pid":1,"binary":"/sbin/init"}},"node_name":"node-1","time":"2026-11-03T10:00:07Z"}"#;


pub const FOREIGN_TENANT: &str =
    r#"{"tenant":"other","process_exec":{"process":{"pid":43,"binary":"/bin/id"}},"node_name":"node-1","time":"2026-11-03T10:00:00Z"}"#;


pub const LINE_LIMIT: usize = 1_000_000;


pub struct Setup {
    pub dir: TempDir,
    pub paths: Paths,
    pub state: StateDir,
    pub follower: Follower,
}


pub fn setup() -> Result<Setup, Box<dyn Error>> {
    let dir = tempdir()?;
    let paths = Paths {
        export: dir.path().join("export.json"),
        cursor_file: dir.path().join("cursor"),
        spool: dir.path().join("spool"),
        sending: dir.path().join("spool.sending"),
    };
    let state = open_state_dir(&paths.cursor_file)?;
    Ok(Setup {
        dir,
        paths,
        state,
        follower: Follower::default(),
    })
}


pub fn append(path: &Path, text: &str) -> std::io::Result<()> {
    OpenOptions::new().append(true).create(true).open(path)?.write_all(text.as_bytes())
}


pub fn lines(path: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(fs::read_to_string(path)?.lines().map(str::to_owned).collect())
}


pub fn poll_default(setup: &mut Setup) -> Result<Report, Box<dyn Error>> {
    Ok(poll(
        &mut setup.follower,
        &setup.state,
        &setup.paths,
        &SourceSettings::default(),
        LINE_LIMIT,
    )?)
}


pub fn poll_with(setup: &mut Setup, settings: &SourceSettings, limit: usize) -> Result<Report, Box<dyn Error>> {
    Ok(poll(&mut setup.follower, &setup.state, &setup.paths, settings, limit)?)
}


pub fn scoped_logging() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish())
}


pub const TWO: u64 = 2;


pub const THREE: u64 = 3;


pub const LEN_TWO: usize = 2;


pub const LEN_THREE: usize = 3;


pub const LEN_FIVE: usize = 5;


pub const UNRELATED_OFFSET: u64 = 5_000;


pub const EXTRA_BYTES: usize = 50;


pub const SMALL_LINE_BYTES: u64 = 1_024;


pub const OVERLONG_BYTES: usize = 5_000;


pub const TINY_LINE_LIMIT: usize = 10;


pub const SETTING_COUNT: usize = 4;


pub const SENSOR_SETTING_COUNT: usize = 7;


pub const RELOADED_MILLIS: u64 = 7;
