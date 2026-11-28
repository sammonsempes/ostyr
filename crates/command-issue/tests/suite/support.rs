use crate::types::Hook;
use agent_command::model::{KeyClass, TrustedKey, TrustedKeys};
use agent_command::types::BoxError;
use arc_swap::ArcSwap;
use command_issue::issue::{IssueAction, IssueRequest, Issued, Issuer};
use command_issue::key::Pair;
use command_issue::limits::Limits;
use command_issue::queue::{open_command_dirs, sync_directory, unlink_name, CommandDirs};
use command_issue::sequence::{ALLOCATE_SQL, COUNT_SQL, LOCK_SQL, ROW_SQL};
use command_issue::types::{ClockFn, HookFn};
use core_pg::connect::connect;
use core_pg::settings::{parse_settings, PgSettings};
use ed25519_dalek::SigningKey;
use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, int8_cell, Fake, Mode, Reply, INT8_OID, TEXT_OID};
use rcgen::SanType;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Notify;
use tokio_postgres::Client;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;


pub const TENANT: &str = "acme";


pub const AGENT: &str = "agent1";


pub const KEY_ID: &str = "routine-1";


pub const START: u64 = 1_000_000;


pub const DEADLINE: Duration = Duration::from_secs(30);


pub const HANG_GUARD: Duration = Duration::from_secs(20);


pub const SEED_BYTE: u8 = 7;


pub const DRAIN_LIMIT: usize = 1_000;


pub const SECRET_MODE: u32 = 0o600;


pub const PERMISSIONS: u32 = 0o777;


pub const SECOND: u64 = 2;


pub const THIRD: u64 = 3;


pub const FOURTH: u64 = 4;


pub const SEED_LENGTH: usize = 32;


pub const ROW_COLUMNS: usize = 2;


pub const VALID_UNTIL_FACTOR: u64 = 10;


/// The fake server's memory: the agent row, the allocation counter, scripted failures, and one emulated advisory lock.
pub struct Script {
    pub row: Mutex<Option<(i64, i64)>>,
    pub count: AtomicI64,
    pub counter: AtomicI64,
    pub failing: Mutex<Vec<(&'static str, &'static str)>>,
    pub silent: Mutex<Vec<&'static str>>,
    pub on_commit: Mutex<Option<Arc<Hook>>>,
    pub held: Mutex<bool>,
    pub free: Condvar,
    pub waiting: Notify,
}


pub fn locked<Value>(mutex: &Mutex<Value>) -> MutexGuard<'_, Value> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn new_script() -> Arc<Script> {
    Arc::new(Script {
        row: Mutex::new(None),
        count: AtomicI64::new(0),
        counter: AtomicI64::new(0),
        failing: Mutex::new(Vec::new()),
        silent: Mutex::new(Vec::new()),
        on_commit: Mutex::new(None),
        held: Mutex::new(false),
        free: Condvar::new(),
        waiting: Notify::new(),
    })
}


pub fn release(script: &Script) {
    *locked(&script.held) = false;
    script.free.notify_all();
}


pub fn acquire(script: &Script) {
    let held = locked(&script.held);
    if *held {
        script.waiting.notify_one();
    }
    let (mut guard, _timeout) = script
        .free
        .wait_timeout_while(held, HANG_GUARD, |taken| *taken)
        .unwrap_or_else(PoisonError::into_inner);
    *guard = true;
}


pub fn rows_of(columns: usize, cells: Vec<i64>, parameters: Vec<i32>) -> Reply {
    Reply::Typed {
        parameters,
        columns: vec![INT8_OID; columns],
        rows: if cells.is_empty() {
            vec![]
        } else {
            vec![cells.into_iter().map(int8_cell).collect()]
        },
    }
}


pub fn allocate_reply(script: &Script) -> Reply {
    let last = script.counter.fetch_add(1, Ordering::SeqCst) + 1;
    let confirmed = locked(&script.row).map_or(0, |(_, confirmed)| confirmed);
    *locked(&script.row) = Some((last, confirmed));
    rows_of(1, vec![last], vec![TEXT_OID, TEXT_OID, INT8_OID])
}


pub fn answer(script: &Script, sql: &str) -> Reply {
    if sql == "COMMIT" || sql == "ROLLBACK" {
        release(script);
    }
    let on_commit = locked(&script.on_commit).clone();
    if let (true, Some(action)) = (sql == "COMMIT", on_commit) {
        action();
    }
    let failure = locked(&script.failing)
        .iter()
        .find(|(needle, _)| sql.contains(needle))
        .map(|(_, code)| *code);
    let silenced = locked(&script.silent).iter().any(|needle| sql.contains(needle));
    if let Some(code) = failure {
        Reply::Error(code)
    } else if silenced {
        rows_of(1, vec![], vec![TEXT_OID, TEXT_OID, INT8_OID])
    } else if sql.contains(LOCK_SQL) {
        acquire(script);
        Reply::Done
    } else if sql.contains(ROW_SQL) {
        let row = *locked(&script.row);
        rows_of(
            ROW_COLUMNS,
            row.map_or(vec![], |(last, confirmed)| vec![last, confirmed]),
            vec![TEXT_OID, TEXT_OID],
        )
    } else if sql.contains(COUNT_SQL) {
        rows_of(1, vec![script.count.load(Ordering::SeqCst)], vec![TEXT_OID])
    } else if sql.contains(ALLOCATE_SQL) {
        allocate_reply(script)
    } else {
        Reply::Done
    }
}


pub fn write_secret(path: &Path, text: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, text)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SECRET_MODE))?;
    Ok(())
}


pub fn settings_for(dir: &Path, port: u16, ca_pem: &str) -> Result<PgSettings, Box<dyn Error>> {
    let password_file = dir.join("pg.pass");
    let ca_file = dir.join("ca.pem");
    write_secret(&password_file, b"p")?;
    fs::write(&ca_file, ca_pem)?;
    let text = format!(
        "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
        password_file.display(),
        ca_file.display()
    );
    Ok(parse_settings(&text, "pg.yaml")?)
}


pub fn routine_key(public_key: ed25519_dalek::VerifyingKey) -> TrustedKey {
    TrustedKey {
        class: KeyClass::Routine,
        public_key,
        not_before: 0,
        not_after: START * VALID_UNTIL_FACTOR,
        revoked: false,
        actions: Some(BTreeSet::from(["ping".to_owned(), "collect_status".to_owned()])),
    }
}


pub fn pair_of(byte: u8, key_id: &str) -> Pair {
    let signing_key = SigningKey::from_bytes(&[byte; SEED_LENGTH]);
    Pair {
        key_id: key_id.to_owned(),
        public_key: signing_key.verifying_key(),
        signing_key,
    }
}


pub fn keys_for(pair: &Pair) -> TrustedKeys {
    TrustedKeys {
        keys: BTreeMap::from([(pair.key_id.clone(), routine_key(pair.public_key))]),
    }
}


pub struct Rig {
    pub fake: Fake,
    pub script: Arc<Script>,
    pub settings: PgSettings,
    pub client: Client,
    pub dirs: CommandDirs,
    pub keys: TrustedKeys,
    pub pairs: ArcSwap<Pair>,
    pub now: Arc<AtomicU64>,
    pub clock: Box<ClockFn>,
    pub hook: Box<HookFn>,
    pub refusals: AtomicU64,
    pub limits: Limits,
    pub root: PathBuf,
    pub _dir: TempDir,
}


pub fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}


pub async fn rig() -> Result<Rig, Box<dyn Error>> {
    let script = new_script();
    let handler_script = Arc::clone(&script);
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), "p", Arc::new(move |sql| answer(&handler_script, sql))).await?;
    let dir = tempdir()?;
    let settings = settings_for(dir.path(), fake.port, &pki.ca_pem)?;
    let client = connect(&settings).await?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let dirs = open_command_dirs(&root, own_uid())?;
    let pair = pair_of(SEED_BYTE, KEY_ID);
    let now = Arc::new(AtomicU64::new(START));
    let clock_source = Arc::clone(&now);
    Ok(Rig {
        fake,
        script,
        settings,
        client,
        dirs,
        keys: keys_for(&pair),
        pairs: ArcSwap::from_pointee(pair),
        now,
        clock: Box::new(move || clock_source.load(Ordering::SeqCst)),
        hook: Box::new(|_issued: &Issued| Ok(())),
        refusals: AtomicU64::new(0),
        limits: Limits::default(),
        root,
        _dir: dir,
    })
}


pub fn issuer_with<'a>(rig: &'a Rig, client: &'a Client, hook: &'a HookFn) -> Issuer<'a> {
    Issuer {
        client,
        dirs: &rig.dirs,
        keys: &rig.keys,
        pairs: &rig.pairs,
        limits: rig.limits,
        deadline: DEADLINE,
        clock: rig.clock.as_ref(),
        before_publish: hook,
        sync: sync_directory,
        unlink: unlink_name,
        agent_limit_refusals: &rig.refusals,
    }
}


pub fn issuer_of(rig: &Rig) -> Issuer<'_> {
    issuer_with(rig, &rig.client, rig.hook.as_ref())
}


pub fn request<'a>(agent: &'a str, action: IssueAction) -> IssueRequest<'a> {
    IssueRequest {
        tenant: TENANT,
        agent_id: agent,
        action,
    }
}


pub fn ping(agent: &str) -> IssueRequest<'_> {
    request(agent, IssueAction::Ping)
}


pub fn failing_hook(_issued: &Issued) -> Result<(), BoxError> {
    Err("hook refused".into())
}


pub fn names_in(directory: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = fs::read_dir(directory)?
        .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<String>, io::Error>>()?;
    names.sort();
    Ok(names)
}


pub fn agent_path(rig: &Rig, agent: &str) -> PathBuf {
    rig.root.join(format!("{TENANT}@{agent}"))
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}


pub fn count_of(statements: &[String], needle: &str) -> usize {
    statements.iter().filter(|statement| statement.contains(needle)).count()
}


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


pub struct Sink(pub Arc<Mutex<Vec<u8>>>);


impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        locked(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


pub fn capture() -> (Dispatch, Arc<Mutex<Vec<u8>>>) {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(BoxMakeWriter::new(move || Sink(Arc::clone(&writer))))
            .finish(),
    );
    (dispatch, buffer)
}


pub fn logged(buffer: &Mutex<Vec<u8>>) -> String {
    String::from_utf8_lossy(&locked(buffer)).into_owned()
}
