#![cfg(unix)]


#[path = "support/types.rs"]
mod types;


use ad_posture::limits::DEFAULT_MAX_BYTES;
use attack_paths::ad::node_id;
use attack_paths::error::{StoreError, TagsError, TenantError};
use attack_paths::model::{Limits, MAX_NODES};
use attack_paths::serve::{
    block_on_with_grace, compute, compute_with, failure_class, finish, listen_for_hangups, listen_for_signals, one_round, pause, report, report_gaps,
    report_tenant, run, run_rounds, run_until_interrupt, safe_text, serve_then_quiesce, start, store_cause, tenant_round, GraphGaps, ReloadThread,
    TenantReport, CLASS_FAILED, CLASS_INPUT_CHANGED, CLASS_INPUT_INCOMPLETE, CLASS_OUTCOME_UNKNOWN, CUT_MARKER, MAX_LOG_CHARS,
};
use attack_paths::settings::{
    boxed_reload_audit, load_settings, open_attack_settings, pg_digest, reload_context, settings_state, start_only_field, AttackSettings,
    TenantEntry, MAX_DEADLINE_SECONDS, MAX_INTERVAL_SECONDS, MAX_TENANTS, MIN_INTERVAL_SECONDS,
};
use attack_paths::store::StoreOutcome;
use attack_paths::tags::sealed_text;
use attack_paths::types::{Hangups, InterruptWait, ServiceFuture, StopWatchFn};
use core_audit::log::open_file_log;
use core_config::error::ConfigError;
use core_config::parse::MAX_FILE_BYTES;
use core_config::reload::{open_engine, reload, ReloadOutcome};
use core_pg::error::PgError;
use core_pg::settings::load_settings as load_pg_settings;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::collections::BTreeMap;
use std::fs;
use std::future::{pending, ready, Future};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, ChildStderr, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::runtime::Handle;
use tokio::sync::{Notify, Semaphore};
use tracing::dispatcher::{with_default, Dispatch};
use tracing::instrument::WithSubscriber;
use types::TestResult;


const PROGRAM: &str = env!("CARGO_BIN_EXE_ostyr-attack-paths");


const OWNER_ONLY: u32 = 0o600;


const JUNK_BYTES: usize = 10_240;


const CLOSED_PORT: u16 = 1;


const PG_PASSWORD: &str = "p";


const STORE_MARKER: &str = "FROM attack_path_report_store(";


const TWO_ROUNDS: u64 = 2;


const ONE_ROUND: u64 = 1;


const LIVE_INTERVAL: &str = "7200";


const MAX_POLLS: usize = 2_000;


const POLL_PAUSE: Duration = Duration::from_millis(10);


const MAX_DRAIN: usize = 10_000;


const MAX_LINES: usize = 1_000;


const HANG_GUARD: Duration = Duration::from_secs(60);


const NO_RETURN_WINDOW: Duration = Duration::from_secs(2);


const STORED_ID: i64 = 7;


const TENANT_COUNT: usize = 2;


const NODES: usize = 3;


const EDGES: usize = 2;


const SECOND_ID: i64 = 2;


const THIRD_ID: i64 = 3;


const OVER_TENANTS: usize = MAX_TENANTS + 1;


const WIDE_LIMIT: usize = 1_000;


const LONG_TEXT: usize = 5_000;


const TOUCH_SECONDS: u64 = 3_600;


const MODE_OTHER: u32 = 0o640;


const DEPTH: usize = 8;


const SNAPSHOT: &str = r#"[
{"distinguishedName":"CN=alice,DC=lab","objectClass":["top","person","user"],"memberOf":["CN=Ops,DC=lab"]},
{"distinguishedName":"CN=Ops,DC=lab","objectClass":["top","group"],"memberOf":["CN=Admins,DC=lab"]},
{"distinguishedName":"CN=Admins,DC=lab","objectClass":["top","group"]}
]"#;


const SNAPSHOT_WITH_UNREADABLE: &str = r#"[
{"distinguishedName":"CN=alice,DC=lab","objectClass":["top","user"],"memberOf":["CN=Admins,DC=lab"]},
{"distinguishedName":"CN=Admins,DC=lab","objectClass":["top","group"]},
{"distinguishedName":"CN=broken,DC=lab","objectClass":["top","user"],"memberOf":5}
]"#;


fn private_file(path: &Path, bytes: &[u8]) -> TestResult {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


fn tags_text() -> String {
    sealed_text(&format!("critical:\n  - \"{}\"\n", node_id("CN=Admins,DC=lab")))
}


fn tenants_block(dir: &Path, names: &[&str]) -> String {
    let entries: String = names
        .iter()
        .map(|name| {
            format!(
                "\n  - tenant: {name}\n    snapshot_file: {}\n    tags_file: {}",
                dir.join(format!("{name}.json")).display(),
                dir.join(format!("{name}.tags.yaml")).display()
            )
        })
        .collect();
    format!("{entries}\n")
}


fn settings_text(dir: &Path, overrides: &[(&str, String)]) -> String {
    let mut fields: BTreeMap<&str, String> = BTreeMap::from([
        ("pg_settings", dir.join("pg.yaml").display().to_string()),
        ("audit_file", dir.join("audit.log").display().to_string()),
        ("tenants", tenants_block(dir, &["acme", "beta"])),
        ("interval_seconds", MIN_INTERVAL_SECONDS.to_string()),
        ("deadline_seconds", "5".to_owned()),
        ("max_depth", DEPTH.to_string()),
        ("max_paths", "1000".to_owned()),
    ]);
    overrides.iter().for_each(|(key, value)| {
        fields.insert(key, value.clone());
    });
    fields.iter().map(|(key, value)| format!("{key}: {value}\n")).collect()
}


fn write_site(dir: &Path, port: u16, ca_pem: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    ["acme", "beta"].iter().try_for_each(|name| {
        fs::write(dir.join(format!("{name}.json")), SNAPSHOT)?;
        fs::write(dir.join(format!("{name}.tags.yaml")), tags_text())
    })?;
    let settings_file = dir.join("attack.yaml");
    fs::write(&settings_file, settings_text(dir, &[]))?;
    Ok(settings_file)
}


fn run_to_end(arguments: &[&Path]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(PROGRAM).args(arguments).stdin(Stdio::null()).output()?)
}


async fn fake_with(handler: Handler) -> Result<(Fake, String), Box<dyn std::error::Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


fn storing() -> Handler {
    Arc::new(|sql| {
        if sql.contains(STORE_MARKER) {
            Reply::Rows(vec![["stored", "1"].map(str::to_owned).to_vec()])
        } else {
            Reply::Done
        }
    })
}


fn wait_for(reader: &mut BufReader<ChildStderr>, marker: &str) -> TestResult {
    reader
        .by_ref()
        .lines()
        .take(MAX_LINES)
        .find_map(|line| line.map(|text| text.contains(marker).then_some(())).transpose())
        .ok_or("the child ended before the marker")??;
    Ok(())
}


fn wait_for_audit(path: &Path, marker: &str) -> TestResult {
    (0..MAX_POLLS)
        .find_map(|_attempt| {
            std::thread::sleep(POLL_PAUSE);
            fs::read_to_string(path).is_ok_and(|text| text.contains(marker)).then_some(())
        })
        .ok_or("the audit record never arrived")?;
    Ok(())
}


fn signal(child: &Child, name: &str) -> TestResult {
    let status = Command::new("kill").arg(name).arg(child.id().to_string()).status()?;
    assert!(status.success());
    Ok(())
}


struct Service {
    child: Child,
    reader: BufReader<ChildStderr>,
}


impl Drop for Service {
    fn drop(&mut self) {
        if self.child.kill().is_err() {
            tracing::debug!("the child had already exited");
        }
        if self.child.wait().is_err() {
            tracing::debug!("the child could not be reaped");
        }
    }
}


fn spawn_service(settings_file: &Path) -> Result<Service, Box<dyn std::error::Error>> {
    let mut child = Command::new(PROGRAM)
        .arg(settings_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let reader = BufReader::new(child.stderr.take().ok_or("no stderr")?);
    Ok(Service { child, reader })
}


fn finish_service(mut service: Service) -> TestResult {
    let mut rest = String::new();
    service.reader.read_to_string(&mut rest)?;
    let exit = service.child.wait()?;
    assert!(exit.success(), "{rest}");
    Ok(())
}


fn never() -> io::Result<InterruptWait> {
    Ok(Box::pin(pending()))
}


fn at_once() -> io::Result<InterruptWait> {
    Ok(Box::pin(ready(Ok(()))))
}


fn cannot_listen() -> io::Result<InterruptWait> {
    Err(io::Error::other("no handler"))
}


fn quiet_hangups() -> io::Result<Hangups> {
    listen_for_hangups()
}


fn cannot_hang_up() -> io::Result<Hangups> {
    Err(io::Error::other("no hangup stream"))
}


fn raising_hangups() -> io::Result<Hangups> {
    let stream = listen_for_hangups()?;
    signal_hook::low_level::raise(signal_hook::consts::SIGHUP)?;
    Ok(stream)
}


fn instant(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(ready(()))
}


fn forever(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(pending())
}


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().map_err(|_poisoned| io::Error::other("poisoned"))?.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn capturing() -> (Dispatch, Arc<Mutex<Vec<u8>>>) {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || Capture(Arc::clone(&writer)))
        .with_ansi(false)
        .finish();
    (Dispatch::new(subscriber), buffer)
}


fn text_of(buffer: &Arc<Mutex<Vec<u8>>>) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = buffer.lock().map_err(|_poisoned| "poisoned")?.clone();
    Ok(String::from_utf8(bytes)?)
}


fn captured(action: impl FnOnce()) -> Result<String, Box<dyn std::error::Error>> {
    let (dispatch, buffer) = capturing();
    with_default(&dispatch, action);
    text_of(&buffer)
}


async fn captured_async<Work: Future>(future: Work) -> Result<(Work::Output, String), Box<dyn std::error::Error>> {
    let (dispatch, buffer) = capturing();
    let output = future.with_subscriber(dispatch).await;
    Ok((output, text_of(&buffer)?))
}


fn bad_value(dir: &Path, overrides: &[(&str, String)]) -> Result<String, Box<dyn std::error::Error>> {
    let file = dir.join("bad.yaml");
    fs::write(&file, settings_text(dir, overrides))?;
    let refusal = load_settings(&file).err().ok_or("the file was accepted")?;
    Ok(refusal.to_string())
}


#[test]
fn every_out_of_bound_setting_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let numbered: String = (0..OVER_TENANTS)
        .map(|index| {
            format!(
                "\n  - tenant: t{index}\n    snapshot_file: {}\n    tags_file: {}",
                dir.path().join("s.json").display(),
                dir.path().join("t.yaml").display()
            )
        })
        .collect::<String>()
        + "\n";
    let doubled = tenants_block(dir.path(), &["acme", "acme"]);
    let relative = "\n  - tenant: acme\n    snapshot_file: s.json\n    tags_file: /t.yaml\n".to_owned();
    let relative_tags = "\n  - tenant: acme\n    snapshot_file: /s.json\n    tags_file: t.yaml\n".to_owned();
    let cases = [
        ("interval_seconds", (MIN_INTERVAL_SECONDS - 1).to_string(), "settings.interval_seconds"),
        ("interval_seconds", (MAX_INTERVAL_SECONDS + 1).to_string(), "settings.interval_seconds"),
        ("deadline_seconds", "0".to_owned(), "settings.deadline_seconds"),
        ("deadline_seconds", (MAX_DEADLINE_SECONDS + 1).to_string(), "settings.deadline_seconds"),
        ("max_depth", "0".to_owned(), "settings.max_depth"),
        ("max_depth", "17".to_owned(), "settings.max_depth"),
        ("max_paths", "0".to_owned(), "settings.max_paths"),
        ("max_paths", "100001".to_owned(), "settings.max_paths"),
        ("pg_settings", "relative.yaml".to_owned(), "settings.pg_settings"),
        ("audit_file", "relative.log".to_owned(), "settings.audit_file"),
        ("tenants", " []".to_owned(), "settings.tenants"),
        ("tenants", numbered, "settings.tenants"),
        ("tenants", tenants_block(dir.path(), &["-x"]), "settings.tenants"),
        ("tenants", doubled, "listed twice"),
        ("tenants", relative, "absolute"),
        ("tenants", relative_tags, "absolute"),
        ("extra", "1".to_owned(), "unknown field"),
    ];
    cases.iter().try_for_each(|(field, value, marker)| {
        let text = bad_value(dir.path(), &[(field, value.clone())])?;
        assert!(text.contains(marker), "{field}={value:?}: {text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


#[test]
fn the_boundary_values_are_accepted() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("edge.yaml");
    fs::write(
        &file,
        settings_text(
            dir.path(),
            &[
                ("interval_seconds", MAX_INTERVAL_SECONDS.to_string()),
                ("deadline_seconds", MAX_DEADLINE_SECONDS.to_string()),
                ("max_depth", "16".to_owned()),
                ("max_paths", "100000".to_owned()),
            ],
        ),
    )?;
    assert_eq!(load_settings(&file)?.tenants.len(), TENANT_COUNT);
    Ok(())
}


#[test]
fn only_the_live_values_may_change_on_a_reload() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("a.yaml");
    fs::write(&file, settings_text(dir.path(), &[]))?;
    let baseline = load_settings(&file)?;
    let live = [
        ("interval_seconds", LIVE_INTERVAL),
        ("deadline_seconds", "6"),
        ("max_depth", "5"),
        ("max_paths", "2000"),
    ];
    live.iter().try_for_each(|(field, value)| {
        fs::write(&file, settings_text(dir.path(), &[(field, (*value).to_owned())]))?;
        assert_eq!(start_only_field(&baseline, &load_settings(&file)?), None, "{field}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let fixed = [
        ("tenants", tenants_block(dir.path(), &["acme"])),
        ("pg_settings", dir.path().join("x.yaml").display().to_string()),
        ("audit_file", dir.path().join("x.log").display().to_string()),
    ];
    fixed.iter().try_for_each(|(field, value)| {
        fs::write(&file, settings_text(dir.path(), &[(field, value.clone())]))?;
        assert_eq!(start_only_field(&baseline, &load_settings(&file)?), Some(*field));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn the_settings_state_names_every_key() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("a.yaml");
    fs::write(&file, settings_text(dir.path(), &[]))?;
    let state = settings_state(&load_settings(&file)?);
    [
        "tenants",
        "pg_settings",
        "audit_file",
        "interval_seconds",
        "deadline_seconds",
        "max_depth",
        "max_paths",
    ]
    .iter()
    .for_each(|key| assert!(state.contains_key(*key), "{key}"));
    assert_eq!(reload_context(&file).tenant, "all");
    Ok(())
}


#[test]
fn the_reload_engine_applies_live_edits_and_denies_start_only_ones() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let file = dir.path().join("attack.yaml");
    let baseline = load_settings(&file)?;
    let pg_text = fs::read_to_string(dir.path().join("pg.yaml"))?;
    let engine = open_attack_settings(
        &file,
        baseline,
        pg_digest(&pg_text),
        boxed_reload_audit(open_file_log(&dir.path().join("audit.log"))?),
    )?;
    fs::write(&file, settings_text(dir.path(), &[("interval_seconds", LIVE_INTERVAL.to_owned())]))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    fs::write(&file, settings_text(dir.path(), &[("tenants", tenants_block(dir.path(), &["other"]))]))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("tenants changed")));
    fs::write(&file, settings_text(dir.path(), &[]))?;
    fs::write(dir.path().join("pg.yaml"), format!("{pg_text}\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("pg_settings")));
    Ok(())
}


fn entry_of(dir: &Path, name: &str) -> TenantEntry {
    TenantEntry {
        tenant: name.to_owned(),
        snapshot_file: dir.join(format!("{name}.json")),
        tags_file: dir.join(format!("{name}.tags.yaml")),
    }
}


const LIMITS: Limits = Limits {
    max_depth: DEPTH,
    max_paths: WIDE_LIMIT,
};


#[test]
fn a_tenant_is_computed_from_its_snapshot_and_tags() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let computed = compute(&entry_of(dir.path(), "acme"), LIMITS)?;
    assert_eq!(computed.found.paths.len(), 1);
    assert_eq!((computed.gaps.nodes, computed.gaps.edges), (NODES, EDGES));
    assert!(!computed.found.truncated && !computed.gaps.graph_truncated);
    assert_eq!((computed.gaps.skipped_tags, computed.gaps.incomplete_nodes), (0, 0));
    Ok(())
}


#[test]
fn an_unreadable_entry_marks_the_report_truncated() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    fs::write(dir.path().join("acme.json"), SNAPSHOT_WITH_UNREADABLE)?;
    let computed = compute(&entry_of(dir.path(), "acme"), LIMITS)?;
    assert!(computed.found.truncated && computed.gaps.graph_truncated);
    assert_eq!(computed.found.paths.len(), 1);
    Ok(())
}


#[test]
fn a_tag_naming_a_node_cut_at_the_node_cap_is_skipped_and_counted() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entries: Vec<String> = (0..=MAX_NODES)
        .map(|index| format!("{{\"distinguishedName\":\"CN=u{index},DC=lab\",\"objectClass\":[\"user\"]}}"))
        .collect();
    fs::write(dir.path().join("acme.json"), format!("[{}]", entries.join(",")))?;
    fs::write(
        dir.path().join("acme.tags.yaml"),
        sealed_text(&format!("critical:\n  - \"{}\"\n", node_id(&format!("CN=u{MAX_NODES},DC=lab")))),
    )?;
    let computed = compute(&entry_of(dir.path(), "acme"), LIMITS)?;
    assert_eq!(computed.gaps.skipped_tags, 1);
    assert!(computed.found.truncated);
    assert_eq!(computed.gaps.nodes, MAX_NODES);
    Ok(())
}


#[test]
fn a_missing_or_malformed_input_fails_that_tenant_by_name() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    fs::remove_file(&entry.snapshot_file)?;
    assert!(matches!(compute(&entry, LIMITS), Err(TenantError::File(ConfigError::Io { .. }))));
    fs::write(&entry.snapshot_file, "{")?;
    assert!(matches!(compute(&entry, LIMITS), Err(TenantError::Snapshot(_))));
    fs::write(&entry.snapshot_file, SNAPSHOT)?;
    fs::write(&entry.tags_file, sealed_text("critical:\n  - nowhere\n"))?;
    assert!(matches!(
        compute(&entry, LIMITS),
        Err(TenantError::Tags(TagsError::UnknownNode { index: 0 }))
    ));
    fs::write(&entry.tags_file, tags_text())?;
    let none = Limits { max_depth: 0, max_paths: 1 };
    assert!(matches!(compute(&entry, none), Err(TenantError::Paths(_))));
    Ok(())
}


#[test]
fn a_snapshot_over_its_byte_bound_is_a_named_failure() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    fs::File::create(&entry.snapshot_file)?.set_len(DEFAULT_MAX_BYTES + 1)?;
    let failure = compute(&entry, LIMITS).err().ok_or("expected a failure")?;
    assert!(matches!(failure, TenantError::SnapshotBound { bound: "bytes", .. }), "{failure}");
    assert!(failure.to_string().contains("bytes"));
    Ok(())
}


#[test]
fn a_tag_file_over_its_cap_is_a_named_failure() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    fs::File::create(&entry.tags_file)?.set_len(MAX_FILE_BYTES + 1)?;
    let failure = compute(&entry, LIMITS).err().ok_or("expected a failure")?;
    assert!(
        matches!(failure, TenantError::Tags(TagsError::Config(ConfigError::TooLarge { .. }))),
        "{failure}"
    );
    Ok(())
}


fn make_fifo(path: &Path) -> TestResult {
    assert!(Command::new("mkfifo").arg(path).status()?.success());
    Ok(())
}


fn guarded<Found: Send + 'static>(work: impl FnOnce() -> Found + Send + 'static) -> Result<Found, Box<dyn std::error::Error>> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || sender.send(work()));
    Ok(receiver.recv_timeout(HANG_GUARD)?)
}


#[test]
fn a_fifo_in_place_of_the_snapshot_is_refused_without_blocking() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    fs::remove_file(&entry.snapshot_file)?;
    make_fifo(&entry.snapshot_file)?;
    let outcome = guarded(move || compute(&entry, LIMITS))?;
    assert!(matches!(outcome, Err(TenantError::File(ConfigError::WatchedFile { .. }))));
    Ok(())
}


#[test]
fn a_symlink_in_place_of_either_input_is_refused_whatever_it_points_to() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    let pipe = dir.path().join("pipe");
    make_fifo(&pipe)?;
    fs::remove_file(&entry.tags_file)?;
    std::os::unix::fs::symlink(&pipe, &entry.tags_file)?;
    let blocked = entry.clone();
    let outcome = guarded(move || compute(&blocked, LIMITS))?;
    assert!(matches!(outcome, Err(TenantError::Tags(TagsError::Config(ConfigError::Io { .. })))));
    fs::remove_file(&entry.tags_file)?;
    fs::write(dir.path().join("real.tags.yaml"), tags_text())?;
    std::os::unix::fs::symlink(dir.path().join("real.tags.yaml"), &entry.tags_file)?;
    assert!(matches!(
        compute(&entry, LIMITS),
        Err(TenantError::Tags(TagsError::Config(ConfigError::Io { .. })))
    ));
    fs::remove_file(&entry.tags_file)?;
    fs::write(&entry.tags_file, tags_text())?;
    fs::write(dir.path().join("other.json"), SNAPSHOT)?;
    fs::remove_file(&entry.snapshot_file)?;
    std::os::unix::fs::symlink(dir.path().join("other.json"), &entry.snapshot_file)?;
    assert!(matches!(compute(&entry, LIMITS), Err(TenantError::File(ConfigError::Io { .. }))));
    Ok(())
}


fn is_tags(path: &Path) -> bool {
    path.to_string_lossy().ends_with(".tags.yaml")
}


fn truncate_tags(path: &Path) -> io::Result<()> {
    if is_tags(path) {
        let text = fs::read_to_string(path)?;
        fs::write(path, text.lines().take(1).collect::<Vec<_>>().join("\n"))?;
    }
    Ok(())
}


fn append_snapshot(path: &Path) -> io::Result<()> {
    if !is_tags(path) {
        fs::OpenOptions::new().append(true).open(path)?.write_all(b" ")?;
    }
    Ok(())
}


fn touch_snapshot(path: &Path) -> io::Result<()> {
    if !is_tags(path) {
        let later = std::time::SystemTime::now() + Duration::from_secs(TOUCH_SECONDS);
        fs::File::options().write(true).open(path)?.set_modified(later)?;
    }
    Ok(())
}


fn chmod_tags(path: &Path) -> io::Result<()> {
    if is_tags(path) {
        fs::set_permissions(path, fs::Permissions::from_mode(MODE_OTHER))?;
    }
    Ok(())
}


fn failing_hook(_path: &Path) -> io::Result<()> {
    Err(io::Error::other("hook"))
}


#[test]
fn a_tag_file_cut_while_it_was_read_is_refused_for_that_tenant_by_name() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    fs::write(&entry.tags_file, sealed_text("critical:\n  - nowhere\n"))?;
    let failure = compute_with(&entry, LIMITS, truncate_tags).err().ok_or("expected a failure")?;
    assert!(matches!(failure, TenantError::Tags(TagsError::Changed)), "{failure}");
    assert_eq!(failure_class(&failure), CLASS_INPUT_CHANGED);
    fs::write(&entry.tags_file, tags_text())?;
    assert_eq!(compute(&entry, LIMITS)?.found.paths.len(), 1);
    Ok(())
}


#[test]
fn a_tag_file_without_its_trailer_is_incomplete_for_that_tenant_by_name() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    let full = tags_text();
    let cut_at_line = full.lines().take(1).collect::<Vec<_>>().join("\n") + "\n";
    let no_newline = full.trim_end().to_string();
    let doubled = format!("{full}{full}");
    let legacy = "critical: []\ncomplete: true\n".to_string();
    [cut_at_line, no_newline, doubled, legacy].iter().try_for_each(|text| -> TestResult {
        fs::write(&entry.tags_file, text)?;
        let failure = compute(&entry, LIMITS).err().ok_or("expected a failure")?;
        assert_eq!(failure_class(&failure), CLASS_INPUT_INCOMPLETE, "{failure}");
        Ok(())
    })?;
    fs::write(&entry.tags_file, "critical:\n  - a\n")?;
    let missing = compute(&entry, LIMITS).err().ok_or("expected a failure")?;
    assert!(matches!(missing, TenantError::Tags(TagsError::Incomplete)), "{missing}");
    assert_eq!(failure_class(&missing), CLASS_INPUT_INCOMPLETE);
    fs::write(&entry.tags_file, tags_text())?;
    assert_eq!(compute(&entry, LIMITS)?.found.paths.len(), 1);
    Ok(())
}


#[test]
fn a_hostile_trailer_reaches_neither_the_error_nor_the_log() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    let junk = "J".repeat(JUNK_BYTES);
    fs::write(&entry.tags_file, format!("critical: []\ncomplete: sha256:\u{1b}[31m{junk}\n"))?;
    let failure = compute(&entry, LIMITS).err().ok_or("expected a failure")?;
    assert_eq!(failure_class(&failure), CLASS_INPUT_INCOMPLETE);
    let shown = [failure.to_string(), format!("{failure:?}")];
    assert!(shown.iter().all(|text| !text.contains('\u{1b}') && !text.contains("JJJJ")), "{shown:?}");
    let log = captured(|| report_tenant("acme", &Err(failure)))?;
    assert!(log.contains("acme") && log.contains(CLASS_INPUT_INCOMPLETE), "{log}");
    assert!(!log.contains('\u{1b}') && !log.contains("JJJJ"), "{log}");
    Ok(())
}


#[test]
fn a_tag_file_whose_change_time_moved_during_the_read_is_refused() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    let failure = compute_with(&entry, LIMITS, chmod_tags).err().ok_or("expected a failure")?;
    assert!(matches!(failure, TenantError::Tags(TagsError::Changed)), "{failure}");
    Ok(())
}


#[test]
fn a_snapshot_changed_while_it_was_read_is_refused_by_size_or_by_time() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    let grown = compute_with(&entry, LIMITS, append_snapshot).err().ok_or("expected a failure")?;
    assert!(matches!(grown, TenantError::SnapshotChanged), "{grown}");
    assert_eq!(failure_class(&grown), CLASS_INPUT_CHANGED);
    fs::write(&entry.snapshot_file, SNAPSHOT)?;
    let touched = compute_with(&entry, LIMITS, touch_snapshot).err().ok_or("expected a failure")?;
    assert!(matches!(touched, TenantError::SnapshotChanged), "{touched}");
    Ok(())
}


#[test]
fn a_failing_hook_is_a_named_file_error() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    assert!(matches!(
        compute_with(&entry, LIMITS, failing_hook),
        Err(TenantError::File(ConfigError::Io { .. }))
    ));
    Ok(())
}


#[test]
fn a_changed_input_fails_one_tenant_and_the_next_one_is_stored() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let first = entry_of(dir.path(), "acme");
    fs::write(&first.tags_file, sealed_text("critical:\n  - nowhere\n"))?;
    let second = entry_of(dir.path(), "beta");
    fs::write(&second.snapshot_file, SNAPSHOT)?;
    fs::write(&second.tags_file, tags_text())?;
    let refused = compute_with(&first, LIMITS, truncate_tags).err().ok_or("expected a failure")?;
    assert!(matches!(refused, TenantError::Tags(TagsError::Changed)), "{refused}");
    assert_eq!(compute_with(&second, LIMITS, truncate_tags_of_acme_only)?.found.paths.len(), 1);
    Ok(())
}


fn truncate_tags_of_acme_only(path: &Path) -> io::Result<()> {
    if path.to_string_lossy().ends_with("acme.tags.yaml") {
        truncate_tags(path)?;
    }
    Ok(())
}


fn stored_exec(_scope: core_pg::scope::TenantScope, _sql: &'static str, _params: Vec<String>) -> attack_paths::types::RowFuture<'static> {
    Box::pin(ready(Ok(vec![["stored", "7"].map(str::to_owned).to_vec()])))
}


fn deadline_exec(_scope: core_pg::scope::TenantScope, _sql: &'static str, _params: Vec<String>) -> attack_paths::types::RowFuture<'static> {
    Box::pin(ready(Err(PgError::ClientDeadline { seconds: 1 })))
}


#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_round_stores_one_report_through_the_executor() -> TestResult {
    let dir = tempdir()?;
    write_site(dir.path(), CLOSED_PORT, "")?;
    let entry = entry_of(dir.path(), "acme");
    let stored = tenant_round(&stored_exec, &entry, LIMITS).await?;
    assert_eq!(stored.outcome, StoreOutcome::Stored { id: STORED_ID });
    assert_eq!(stored.paths, 1);
    let failure = tenant_round(&deadline_exec, &entry, LIMITS).await.err().ok_or("expected a failure")?;
    assert_eq!(failure_class(&failure), CLASS_OUTCOME_UNKNOWN);
    Ok(())
}


fn store_failure(failure: PgError) -> TenantError {
    TenantError::Store(StoreError::Store(failure))
}


#[test]
fn only_a_failure_before_the_commit_is_a_plain_failure() -> TestResult {
    let server = store_failure(PgError::Server {
        code: "23505".to_owned(),
        class: "integrity",
    });
    let timeout = store_failure(PgError::StatementTimeout { seconds: 1 });
    let connect = store_failure(PgError::ConnectTimeout { seconds: 1 });
    let deadline = store_failure(PgError::ClientDeadline { seconds: 1 });
    let transport = store_failure(PgError::InvalidTenant);
    let bad_answer = TenantError::Store(StoreError::BadRow);
    let cap = TenantError::Store(StoreError::CapReached { max: 1 });
    [&deadline, &transport, &bad_answer]
        .iter()
        .for_each(|unknown| assert_eq!(failure_class(unknown), CLASS_OUTCOME_UNKNOWN));
    [&server, &timeout, &connect, &cap]
        .iter()
        .for_each(|known| assert_eq!(failure_class(known), CLASS_FAILED));
    let causes = [&server, &timeout, &connect, &deadline, &transport, &bad_answer, &cap].map(store_cause);
    assert_eq!(
        causes,
        [
            "server_error",
            "statement_timeout",
            "connect_timeout",
            "client_deadline",
            "database",
            "bad_answer",
            "none"
        ]
    );
    let text = captured(|| report_tenant("acme", &Err(deadline)))?;
    assert!(
        text.contains(CLASS_OUTCOME_UNKNOWN) && text.contains("client_deadline") && !text.contains("nothing was written"),
        "{text}"
    );
    Ok(())
}


#[test]
fn an_error_text_is_escaped_and_cut_before_it_reaches_a_log() -> TestResult {
    assert_eq!(safe_text(&"a\nb\u{1b}c"), "a\\nb\\u{1b}c");
    let cut = safe_text(&"x".repeat(LONG_TEXT));
    assert_eq!(cut.chars().count(), MAX_LOG_CHARS + CUT_MARKER.chars().count());
    assert!(cut.ends_with(CUT_MARKER));
    assert!(!safe_text(&"x".repeat(MAX_LOG_CHARS)).contains(CUT_MARKER));
    let newlines = safe_text(&"\n".repeat(MAX_LOG_CHARS));
    assert!(newlines.ends_with(CUT_MARKER));
    assert_eq!(newlines.chars().count(), MAX_LOG_CHARS + CUT_MARKER.chars().count());
    let forged = TenantError::File(ConfigError::Io {
        file: "/s/a\nWARN forged line".to_owned(),
        source: io::Error::other("x"),
    });
    let text = captured(|| report_tenant("acme", &Err(forged)))?;
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(!text.lines().any(|line| line.starts_with("WARN forged")), "{text}");
    Ok(())
}


fn done(outcome: StoreOutcome, gaps: GraphGaps) -> TenantReport {
    TenantReport { outcome, paths: 1, gaps }
}


fn clean() -> GraphGaps {
    GraphGaps {
        nodes: NODES,
        edges: EDGES,
        graph_truncated: false,
        incomplete_nodes: 0,
        skipped_tags: 0,
    }
}


#[test]
fn every_outcome_is_one_named_line() -> TestResult {
    let text = captured(|| {
        report_tenant("acme", &Ok(done(StoreOutcome::Stored { id: 1 }, clean())));
        report_tenant("beta", &Ok(done(StoreOutcome::AlreadyStored { id: SECOND_ID }, clean())));
        report(&Err(PgError::InvalidTenant));
        report(&Ok(vec![("gamma".to_owned(), Ok(done(StoreOutcome::Stored { id: THIRD_ID }, clean())))]));
    })?;
    assert!(
        text.contains("stored id=1") && text.contains("unchanged id=2") && text.contains("stored id=3"),
        "{text}"
    );
    assert!(text.contains("round failed before any tenant ran"), "{text}");
    assert!(!text.contains("incomplete"), "{text}");
    Ok(())
}


#[test]
fn each_kind_of_gap_makes_the_warning() -> TestResult {
    let truncated = GraphGaps {
        graph_truncated: true,
        ..clean()
    };
    let incomplete = GraphGaps {
        incomplete_nodes: 1,
        ..clean()
    };
    let skipped = GraphGaps { skipped_tags: 1, ..clean() };
    [truncated, incomplete, skipped].iter().try_for_each(|gaps| {
        let text = captured(|| report_gaps("acme", gaps))?;
        assert!(text.contains("marked truncated"), "{text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(captured(|| report_gaps("acme", &clean()))?.is_empty());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_tenant_does_not_stop_the_others_in_a_round() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::remove_file(dir.path().join("acme.json"))?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let runs = one_round(&pg, &live).await?;
    assert_eq!(runs.len(), TENANT_COUNT);
    let outcomes: Vec<(&str, bool)> = runs.iter().map(|(tenant, run)| (tenant.as_str(), run.is_ok())).collect();
    assert_eq!(outcomes, vec![("acme", false), ("beta", true)]);
    let text = captured(|| report(&Ok(runs)))?;
    assert!(text.contains("attack path report failed") && text.contains("stored id=1"), "{text}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_round_against_a_closed_port_is_a_database_error() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let live = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let failure = one_round(&pg, &live).await.err().ok_or("expected an error")?;
    assert!(captured(|| report(&Err(failure)))?.contains("round failed before any tenant ran"));
    Ok(())
}


async fn statements_after(mut fake: Fake) -> (usize, usize) {
    let mut stores = 0;
    let mut others = 0;
    let mut drained = 0;
    let mut empty = false;
    while !empty && drained < MAX_DRAIN {
        match fake.statements.try_recv() {
            Ok(sql) if sql.contains(STORE_MARKER) => stores += 1,
            Ok(_other) => others += 1,
            Err(_closed_or_empty) => empty = true,
        }
        drained += 1;
    }
    (stores, others)
}


#[tokio::test(flavor = "multi_thread")]
async fn two_rounds_store_every_tenant_twice_and_start_returns() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (outcome, log) = captured_async(start(&settings_file, TWO_ROUNDS, never, quiet_hangups, instant)).await?;
    outcome?;
    assert!(log.contains("serving") && log.contains("stored id=1"), "{log}");
    assert_eq!(statements_after(fake).await.0, TWO_ROUNDS as usize * TENANT_COUNT);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_production_wait_returns_after_its_duration() -> TestResult {
    pause(Duration::ZERO).await;
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, TWO_ROUNDS, never, quiet_hangups, pause_zero).await?;
    Ok(())
}


fn pause_zero(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    pause(Duration::ZERO)
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_during_the_migration_lets_it_finish_and_no_round_runs() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let (outcome, log) = captured_async(start(&settings_file, u64::MAX, at_once, quiet_hangups, instant)).await?;
    outcome?;
    assert!(log.contains("finishing the work in flight") && log.contains("migration"), "{log}");
    assert!(!log.contains("serving"), "{log}");
    let (stores, others) = statements_after(fake).await;
    assert_eq!(stores, 0);
    assert!(others > 0);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_migration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(Arc::new(|sql| {
        if sql.contains("CREATE TABLE IF NOT EXISTS public.schema_migrations") {
            Reply::Error("XX000")
        } else {
            Reply::Done
        }
    }))
    .await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let outcome = start(&settings_file, ONE_ROUND, never, quiet_hangups, instant).await;
    assert!(outcome.is_err());
    Ok(())
}


static SAW_INTERRUPT: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(0));


static SAW_HANGUP: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(0));


fn recording_interrupt() -> io::Result<InterruptWait> {
    SAW_INTERRUPT.add_permits(1);
    never()
}


fn recording_hangups() -> io::Result<Hangups> {
    SAW_HANGUP.add_permits(1);
    quiet_hangups()
}


#[tokio::test(flavor = "multi_thread")]
async fn the_interrupt_and_the_hangup_are_armed_before_the_first_file_is_read() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    let failure = start(&missing, ONE_ROUND, recording_interrupt, recording_hangups, instant).await;
    assert!(failure.is_err());
    assert_eq!(SAW_INTERRUPT.available_permits(), 1);
    assert_eq!(SAW_HANGUP.available_permits(), 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_signal_registration_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent.yaml");
    let interrupt = start(&missing, ONE_ROUND, cannot_listen, quiet_hangups, instant)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(interrupt.to_string().contains("no handler"));
    let hangup = start(&missing, ONE_ROUND, never, cannot_hang_up, instant)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(hangup.to_string().contains("no hangup stream"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_hangup_that_arrives_before_the_first_read_does_not_end_the_process() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    start(&settings_file, ONE_ROUND, never, raising_hangups, instant).await?;
    assert_eq!(statements_after(fake).await.0, TENANT_COUNT);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_or_invalid_settings_file_fails_the_start() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    fs::remove_file(dir.path().join("pg.yaml"))?;
    assert!(start(&settings_file, ONE_ROUND, never, quiet_hangups, instant).await.is_err());
    write_site(dir.path(), fake.port, &ca_pem)?;
    fs::write(dir.path().join("audit.log"), "")?;
    fs::remove_file(dir.path().join("audit.log"))?;
    fs::create_dir(dir.path().join("audit.log"))?;
    assert!(start(&settings_file, ONE_ROUND, never, quiet_hangups, instant).await.is_err());
    Ok(())
}


async fn engine_for(
    dir: &Path,
    port: u16,
    ca_pem: &str,
) -> Result<(core_config::reload::ReloadEngine<AttackSettings>, core_pg::settings::PgSettings), Box<dyn std::error::Error>> {
    let settings_file = write_site(dir, port, ca_pem)?;
    let baseline = load_settings(&settings_file)?;
    let pg_text = fs::read_to_string(dir.join("pg.yaml"))?;
    let engine = open_attack_settings(
        &settings_file,
        baseline,
        pg_digest(&pg_text),
        boxed_reload_audit(open_file_log(&dir.join("audit.log"))?),
    )?;
    Ok((engine, load_pg_settings(&dir.join("pg.yaml"))?))
}


static WAIT_ERR: LazyLock<Notify> = LazyLock::new(Notify::new);


static WAIT_OK: LazyLock<Notify> = LazyLock::new(Notify::new);


fn release_wait_error(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {
        WAIT_ERR.notify_one();
        pending::<()>().await;
    })
}


fn release_wait_end(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(async {
        WAIT_OK.notify_one();
        pending::<()>().await;
    })
}


fn interrupt_after(signal_notify: &'static LazyLock<Notify>, outcome: fn() -> io::Result<()>) -> InterruptWait {
    Box::pin(async move {
        signal_notify.notified().await;
        outcome()
    })
}


fn fine() -> io::Result<()> {
    Ok(())
}


fn broken() -> io::Result<()> {
    Err(io::Error::other("no signal"))
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_between_rounds_ends_the_service() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let (engine, pg) = engine_for(dir.path(), fake.port, &ca_pem).await?;
    let mut interrupted = interrupt_after(&WAIT_OK, fine);
    run_rounds(u64::MAX, &engine, &pg, release_wait_end, never, &mut interrupted).await?;
    assert_eq!(statements_after(fake).await.0, TENANT_COUNT);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_interrupt_wait_between_rounds_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let (engine, pg) = engine_for(dir.path(), fake.port, &ca_pem).await?;
    let mut interrupted = interrupt_after(&WAIT_ERR, broken);
    let failure = run_rounds(u64::MAX, &engine, &pg, release_wait_error, never, &mut interrupted)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(failure.to_string().contains("no signal"));
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_during_a_round_still_stores_it_and_then_stops() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let (engine, pg) = engine_for(dir.path(), fake.port, &ca_pem).await?;
    let mut interrupted: InterruptWait = Box::pin(ready(Ok(())));
    let (outcome, log) = captured_async(run_rounds(u64::MAX, &engine, &pg, forever, never, &mut interrupted)).await?;
    outcome?;
    assert!(log.contains("finishing the work in flight") && log.contains("stored id=1"), "{log}");
    assert_eq!(statements_after(fake).await.0, TENANT_COUNT);
    Ok(())
}


fn work_that_marks(marks: &Arc<AtomicUsize>, failing: bool) -> ServiceFuture<'static> {
    let seen = Arc::clone(marks);
    Box::pin(async move {
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        seen.fetch_add(1, Ordering::SeqCst);
        if failing {
            Err(io::Error::other("work failed").into())
        } else {
            Ok(())
        }
    })
}


#[tokio::test(flavor = "multi_thread")]
async fn work_that_ends_first_is_not_an_interrupt() -> TestResult {
    let marks = Arc::new(AtomicUsize::new(0));
    let mut interrupted: InterruptWait = Box::pin(pending());
    let stopped = run_until_interrupt("round", work_that_marks(&marks, false), never, &mut interrupted).await?;
    assert!(!stopped);
    assert_eq!(marks.load(Ordering::SeqCst), 1);
    let failed = run_until_interrupt("round", work_that_marks(&marks, true), never, &mut interrupted).await;
    assert!(failed.is_err());
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn an_interrupt_never_cuts_the_work_in_flight() -> TestResult {
    let marks = Arc::new(AtomicUsize::new(0));
    let mut interrupted: InterruptWait = Box::pin(ready(Ok(())));
    let (stopped, log) = captured_async(run_until_interrupt("round", work_that_marks(&marks, false), never, &mut interrupted)).await?;
    assert!(stopped?);
    assert_eq!(marks.load(Ordering::SeqCst), 1, "the work was cut: {log}");
    assert!(log.contains("finishing the work in flight"), "{log}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_second_interrupt_is_logged_and_the_work_still_finishes() -> TestResult {
    let marks = Arc::new(AtomicUsize::new(0));
    let mut interrupted: InterruptWait = Box::pin(ready(Ok(())));
    let (stopped, log) = captured_async(run_until_interrupt("round", work_that_marks(&marks, false), at_once, &mut interrupted)).await?;
    assert!(stopped?);
    assert_eq!(marks.load(Ordering::SeqCst), 1, "{log}");
    assert!(log.contains("stop already in progress"), "{log}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_second_interrupt_that_cannot_be_armed_leaves_the_work_to_finish() -> TestResult {
    let marks = Arc::new(AtomicUsize::new(0));
    let mut work = work_that_marks(&marks, false);
    let (outcome, log) = captured_async(finish("round", &mut work, cannot_listen)).await?;
    outcome?;
    assert_eq!(marks.load(Ordering::SeqCst), 1);
    assert!(log.contains("no second interrupt can be armed"), "{log}");
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn a_failing_interrupt_wait_still_lets_the_work_finish_and_is_an_error() -> TestResult {
    let marks = Arc::new(AtomicUsize::new(0));
    let mut interrupted: InterruptWait = Box::pin(ready(Err(io::Error::other("no signal"))));
    let failure = run_until_interrupt("round", work_that_marks(&marks, false), never, &mut interrupted)
        .await
        .err()
        .ok_or("expected an error")?;
    assert!(failure.to_string().contains("no signal"));
    assert_eq!(marks.load(Ordering::SeqCst), 1);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn work_that_fails_while_the_service_stops_is_an_error() -> TestResult {
    let marks = Arc::new(AtomicUsize::new(0));
    let mut interrupted: InterruptWait = Box::pin(ready(Ok(())));
    let failure = run_until_interrupt("migration", work_that_marks(&marks, true), never, &mut interrupted).await;
    assert!(failure.is_err());
    assert_eq!(marks.load(Ordering::SeqCst), 1);
    Ok(())
}


#[test]
fn a_reload_in_flight_ends_before_the_service_returns() -> TestResult {
    let dir = tempdir()?;
    let settings_file = write_site(dir.path(), CLOSED_PORT, "")?;
    let baseline = load_settings(&settings_file)?;
    let pg = load_pg_settings(&dir.path().join("pg.yaml"))?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (in_loader_tx, in_loader_rx) = channel();
    let (release_tx, release_receiver) = channel::<()>();
    let release_rx = Mutex::new(release_receiver);
    let counter = Arc::clone(&calls);
    let engine = Arc::new(open_engine(
        Box::new(move || {
            if counter.fetch_add(1, Ordering::SeqCst) > 0 {
                assert!(in_loader_tx.send(()).is_ok());
                release_rx
                    .lock()
                    .map_err(|_poisoned| ConfigError::Io {
                        file: "loader".to_owned(),
                        source: io::Error::other("poisoned"),
                    })?
                    .recv_timeout(HANG_GUARD)
                    .map_err(|_timeout| ConfigError::Io {
                        file: "loader".to_owned(),
                        source: io::Error::other("never released"),
                    })?;
            }
            Ok(baseline.clone())
        }),
        settings_state,
        Vec::new(),
        boxed_reload_audit(open_file_log(&dir.path().join("audit.log"))?),
        reload_context(&settings_file),
    )?);
    let reloading = Arc::clone(&engine);
    let reloader = std::thread::spawn(move || reload(&reloading));
    in_loader_rx.recv_timeout(HANG_GUARD)?;
    let (stopped_tx, stopped_rx) = channel();
    let (returned_tx, returned_rx) = channel();
    let serving = Arc::clone(&engine);
    let server = std::thread::spawn(move || {
        let stop_watch: StopWatchFn = Box::new(move || assert!(stopped_tx.send(()).is_ok()));
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
        let mut interrupted: InterruptWait = Box::pin(ready(Ok(())));
        let outcome =
            runtime.map(|current| current.block_on(serve_then_quiesce(stop_watch, ONE_ROUND, &serving, &pg, instant, never, &mut interrupted)));
        assert!(returned_tx.send(outcome.is_ok()).is_ok());
    });
    stopped_rx.recv_timeout(HANG_GUARD)?;
    assert!(
        returned_rx.recv_timeout(NO_RETURN_WINDOW).is_err(),
        "the service returned with a reload in flight"
    );
    release_tx.send(())?;
    assert!(returned_rx.recv_timeout(HANG_GUARD)?);
    server.join().map_err(|_panic| "server panicked")?;
    reloader.join().map_err(|_panic| "reloader panicked")?;
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_signal_futures_stay_pending_until_a_signal_arrives() -> TestResult {
    let waiting = listen_for_signals()?;
    assert!(tokio::time::timeout(Duration::ZERO, waiting).await.is_err());
    drop(listen_for_hangups()?);
    Ok(())
}


fn reload_guard(worker: Option<std::thread::JoinHandle<()>>) -> Result<ReloadThread, Box<dyn std::error::Error>> {
    let stream = listen_for_hangups()?;
    Ok(ReloadThread {
        handle: stream.handle(),
        worker,
    })
}


#[test]
fn a_reload_thread_that_panicked_is_logged_when_the_guard_drops() -> TestResult {
    let worker = std::thread::spawn(|| std::panic::resume_unwind(Box::new("reload thread")));
    let guard = reload_guard(Some(worker))?;
    let text = captured(move || drop(guard))?;
    assert!(text.contains("the reload thread panicked"), "{text}");
    let clean = reload_guard(Some(std::thread::spawn(|| ())))?;
    let absent = reload_guard(None)?;
    let quiet = captured(move || {
        drop(clean);
        drop(absent);
    })?;
    assert!(!quiet.contains("panicked"), "{quiet}");
    Ok(())
}


#[test]
fn a_blocking_task_that_never_ends_does_not_hold_the_runtime_past_the_grace() -> TestResult {
    let (release, held) = channel::<()>();
    let (started_tx, started_rx) = channel::<()>();
    let (done_tx, done_rx) = channel();
    let worker = std::thread::spawn(move || {
        let result = block_on_with_grace(
            Box::pin(async move {
                let blocking = tokio::task::spawn_blocking(move || {
                    assert!(started_tx.send(()).is_ok());
                    match held.recv() {
                        Ok(()) | Err(_) => (),
                    }
                });
                started_rx.recv_timeout(HANG_GUARD)?;
                drop(blocking);
                Ok(())
            }),
            Duration::ZERO,
        );
        assert!(done_tx.send(result.is_ok()).is_ok());
    });
    let finished = done_rx.recv_timeout(HANG_GUARD);
    release.send(())?;
    worker.join().map_err(|_panic| "worker panicked")?;
    assert!(finished?);
    Ok(())
}


#[tokio::test(flavor = "multi_thread")]
async fn run_refuses_a_missing_or_extra_argument() -> TestResult {
    let none = run(&[]).await.err().ok_or("expected an error")?;
    assert!(none.to_string().contains("usage: ostyr-attack-paths"));
    let two = run(&["a".to_owned(), "b".to_owned()]).await.err().ok_or("expected an error")?;
    assert!(two.to_string().contains("usage"));
    Ok(())
}


#[test]
fn the_binary_prints_the_usage_and_fails_on_a_missing_argument_or_file() -> TestResult {
    let dir = tempdir()?;
    let none = run_to_end(&[])?;
    assert!(!none.status.success());
    assert!(String::from_utf8(none.stderr)?.contains("usage"));
    let missing = run_to_end(&[&dir.path().join("absent.yaml")])?;
    assert!(!missing.status.success());
    assert!(!missing.stderr.is_empty());
    Ok(())
}


async fn serve_until_report(signal_name: &str) -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(storing()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let mut service = spawn_service(&settings_file)?;
    tokio::task::block_in_place(|| wait_for(&mut service.reader, "attack path report"))?;
    signal(&service.child, signal_name)?;
    tokio::task::block_in_place(|| finish_service(service))
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_stores_a_round_and_exits_zero_on_sigint() -> TestResult {
    serve_until_report("-INT").await
}


#[tokio::test(flavor = "multi_thread")]
async fn the_binary_exits_zero_on_sigterm() -> TestResult {
    serve_until_report("-TERM").await
}


static MIGRATION_SEEN: LazyLock<Notify> = LazyLock::new(Notify::new);


static MIGRATION_ACK: LazyLock<Notify> = LazyLock::new(Notify::new);


static HELD_ONCE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(1));


fn held_migration() -> Handler {
    Arc::new(|sql| {
        if sql.contains("pg_advisory_xact_lock") && HELD_ONCE.try_acquire().map(|permit| permit.forget()).is_ok() {
            MIGRATION_SEEN.notify_one();
            let acked = tokio::task::block_in_place(|| Handle::current().block_on(tokio::time::timeout(HANG_GUARD, MIGRATION_ACK.notified())));
            if acked.is_err() {
                tracing::debug!("the migration was never released");
            }
            Reply::Done
        } else if sql.contains(STORE_MARKER) {
            Reply::Rows(vec![["stored", "1"].map(str::to_owned).to_vec()])
        } else {
            Reply::Done
        }
    })
}


#[tokio::test(flavor = "multi_thread")]
async fn a_sighup_during_the_start_is_applied_audited_and_never_fatal() -> TestResult {
    let dir = tempdir()?;
    let (fake, ca_pem) = fake_with(held_migration()).await?;
    let settings_file = write_site(dir.path(), fake.port, &ca_pem)?;
    let mut service = spawn_service(&settings_file)?;
    tokio::time::timeout(HANG_GUARD, MIGRATION_SEEN.notified()).await?;
    fs::write(
        &settings_file,
        settings_text(dir.path(), &[("interval_seconds", LIVE_INTERVAL.to_owned())]),
    )?;
    signal(&service.child, "-HUP")?;
    tokio::task::block_in_place(|| wait_for_audit(&dir.path().join("audit.log"), LIVE_INTERVAL))?;
    MIGRATION_ACK.notify_one();
    tokio::task::block_in_place(|| wait_for(&mut service.reader, "attack path report"))?;
    fs::write(
        &settings_file,
        settings_text(dir.path(), &[("tenants", tenants_block(dir.path(), &["other"]))]),
    )?;
    signal(&service.child, "-HUP")?;
    tokio::task::block_in_place(|| wait_for_audit(&dir.path().join("audit.log"), "denied"))?;
    signal(&service.child, "-INT")?;
    tokio::task::block_in_place(|| finish_service(service))?;
    let audit = fs::read_to_string(dir.path().join("audit.log"))?;
    assert!(
        audit.lines().all(|line| line.contains("\"tenant\":\"all\"") && !line.contains("acme\"")),
        "{audit}"
    );
    assert!(audit.contains("tenants") && audit.contains("denied"), "{audit}");
    Ok(())
}
