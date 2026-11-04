use core_audit::log::{append, genesis_log};
use core_config::reload::ReloadContext;
use core_config::types::SharedAuditFn;
use serde_json::{json, Value};
use sigma_sql::error::SigmaError;
use sigma_sql::mapping::{parse_mapping, FieldMapping};
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use stream_correlation::cli::start_engine;
use stream_correlation::engine::{process_event, Engine};
use stream_correlation::error::CorrelationError;
use stream_correlation::reload::load_rules;
use stream_correlation::ruleset::{parse_ruleset, RuleSet};
use stream_correlation::types::RuleTexts;
use stream_correlation::window::Alert;
use tempfile::TempDir;
use tracing::Level;


pub const MAPPING: &str = include_str!("../../../sigma-sql/mappings/ecs.yaml");


pub const SECONDS_PER_MINUTE: i64 = 60;


pub const SEC_2: i64 = 2;


pub const SEC_3: i64 = 3;


pub const SEC_4: i64 = 4;


pub const SEC_5: i64 = 5;


pub const SEC_200: i64 = 200;


pub const SEC_400: i64 = 400;


pub const SEC_450: i64 = 450;


pub const TEST_PORT: u16 = 443;


pub const TEST_PID: u32 = 4242;


pub const LOGIN: &str = "title: Failed login
id: failed-login
name: failed_login
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: login failed
  condition: selection
";


pub const BEACON: &str = "title: Outbound beacon
id: outbound
logsource:
  category: network_connection
detection:
  selection:
    Image|endswith: /beacon
  condition: selection
";


pub const DOWNLOAD: &str = "title: Download tool
id: download
name: download_tool
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  condition: selection
";


pub const EXECUTE: &str = "title: Run payload
id: execute
name: run_payload
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /payload
  condition: selection
";


pub const BRUTE_FORCE: &str = "title: Brute force
id: brute-force
correlation:
  type: event_count
  rules:
    - failed-login
  group-by:
    - host.name
  timespan: 5m
  condition:
    gte: 3
";


pub const DISTINCT_DESTINATIONS: &str = "title: Scan
id: scan
correlation:
  type: value_count
  rules:
    - outbound
  group-by:
    - host.name
  timespan: 10m
  condition:
    gte: 3
    field: destination.ip
";


pub const DROPPER: &str = "title: Dropper
id: dropper
correlation:
  type: temporal_ordered
  rules:
    - download_tool
    - run_payload
  group-by:
    - host.name
  timespan: 2m
";


pub const ANY_ORDER: &str = "title: Any order
id: any-order
correlation:
  type: temporal
  rules:
    - download
    - execute
  group-by:
    - host.name
  timespan: 2m
";


static INSTALLED: OnceLock<()> = OnceLock::new();


/// Tracing macros skip their arguments when no subscriber listens: installing one makes the coverage of the logging calls honest.
pub fn init_logging() {
    INSTALLED.get_or_init(|| {
        tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(io::sink).init();
    });
}


pub fn join_documents(documents: &[&str]) -> String {
    documents.join("\n---\n")
}


pub fn mapping() -> Result<FieldMapping, SigmaError> {
    parse_mapping(MAPPING)
}


pub fn ruleset(documents: &[&str]) -> Result<RuleSet, CorrelationError> {
    let mut texts = RuleTexts::new();
    texts.insert("rules.yml".to_string(), join_documents(documents));
    parse_ruleset(&texts, &mapping()?)
}


pub fn stamp(second: i64) -> String {
    format!("2026-11-04T10:{:02}:{:02}.000Z", second / SECONDS_PER_MINUTE, second % SECONDS_PER_MINUTE)
}


pub fn process(second: i64, id: &str, host: &str, image: &str, command_line: &str) -> Value {
    json!({
        "@timestamp": stamp(second),
        "event": {"id": id, "category": ["process"], "type": ["start"]},
        "host": {"name": host, "os": {"type": "linux"}},
        "process": {"pid": TEST_PID, "executable": image, "command_line": command_line},
    })
}


pub fn connection(second: i64, id: &str, host: &str, destination_ip: &str) -> Value {
    json!({
        "@timestamp": stamp(second),
        "event": {"id": id, "category": ["network"]},
        "host": {"name": host, "os": {"type": "linux"}},
        "process": {"executable": "/opt/beacon"},
        "destination": {"ip": destination_ip, "port": TEST_PORT},
    })
}


pub fn failed_login(second: i64, id: &str, host: &str) -> Value {
    process(second, id, host, "/usr/sbin/sshd", "sshd: login failed")
}


pub fn audit() -> Box<SharedAuditFn> {
    let log = genesis_log(io::sink());
    Box::new(move |entry| append(&log, entry))
}


pub fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "test".to_owned(),
        tenant: "example".to_owned(),
        module: "stream-correlation".to_owned(),
        target: "rules.yml".to_owned(),
        request_id: "test-reload".to_owned(),
    }
}


pub fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


pub struct Bench {
    pub dir: TempDir,
    pub mapping_file: PathBuf,
    pub rule_file: PathBuf,
    pub checkpoint: PathBuf,
    pub engine: Engine,
}


pub fn bench(documents: &[&str]) -> Result<Bench, Box<dyn Error>> {
    init_logging();
    let dir = tempfile::tempdir()?;
    let mapping_file = dir.path().join("ecs.yaml");
    let rule_file = dir.path().join("rules.yml");
    let checkpoint = dir.path().join("checkpoint.json");
    fs::write(&mapping_file, MAPPING)?;
    fs::write(&rule_file, join_documents(documents))?;
    let engine = start_engine(mapping_file.clone(), vec![rule_file.clone()], &checkpoint, audit(), context())?;
    Ok(Bench {
        dir,
        mapping_file,
        rule_file,
        checkpoint,
        engine,
    })
}


pub fn restart(bench: &Bench) -> Result<Engine, CorrelationError> {
    start_engine(
        bench.mapping_file.clone(),
        vec![bench.rule_file.clone()],
        &bench.checkpoint,
        audit(),
        context(),
    )
}


pub fn feed(engine: &Engine, event: &Value) -> Vec<Alert> {
    let id = event
        .get("event")
        .and_then(|section| section.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("no-id");
    process_event(engine, id, event)
}


pub fn rules_error(mapping_file: &Path, rule_file: &Path) -> Result<String, Box<dyn Error>> {
    match load_rules(mapping_file, &[rule_file.to_path_buf()]) {
        Ok(_) => Err("rules were accepted".into()),
        Err(error) => Ok(error.to_string()),
    }
}


pub struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write refused"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush refused"))
    }
}


pub struct FlushFails;


impl Write for FlushFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush refused"))
    }
}


pub struct NewlineFails;


impl Write for NewlineFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.contains(&b'\n') {
            Err(io::Error::other("newline refused"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read refused"))
    }
}
