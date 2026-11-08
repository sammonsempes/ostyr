use core_api::config::DEFAULT_LOG_LEVEL;
use core_api::example::{example_access, example_document, example_router};
use core_api::model::{ApiConfig, Limits, TlsFiles};
use core_api::routes::build_router;
use core_api::server::serve;
use core_api::state::{build_state, MAX_TRACKED_ATTEMPTS, MAX_TRACKED_SOURCES, RATE_MAX_REQUESTS, RATE_WINDOW_SECONDS};
use core_api::types::{ServerHandle, SharedState};
use core_auth::cli::read_key_file;
use core_auth::model::Account;
use core_auth::password::hash_password;
use core_auth::random::os_random;
use core_auth::store::update_store_file;
use rcgen::generate_simple_self_signed;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use xdrctl::cli::run_reporting;
use xdrctl::types::SendFn;


pub mod types;


pub use types::{TestError, TestResult};


pub const PASSWORD: &str = "correct horse battery staple";


pub const USER: &str = "reader";


pub const OWNER_ONLY: u32 = 0o600;


#[cfg(unix)]
pub const MODE_MASK: u32 = 0o777;


pub const KEY_BYTES: usize = 32;


pub const KEY_FILL: u8 = 7;


pub const SERVER_TIMEOUT: Duration = Duration::from_secs(5);


pub const MAX_CONNECTIONS: usize = 16;


pub struct Live {
    pub dir: TempDir,
    pub url: String,
    pub ca_file: PathBuf,
    pub handle: ServerHandle,
}


impl Drop for Live {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}


pub struct Outcome {
    pub code: String,
    pub out: String,
    pub err: String,
}


pub struct BrokenRead;


impl Read for BrokenRead {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("input broken"))
    }
}


pub fn broken_input() -> BufReader<BrokenRead> {
    BufReader::new(BrokenRead)
}


pub struct BrokenOutput {
    pub fail_write: bool,
}


impl Write for BrokenOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_write {
            Err(io::Error::other("output broken"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush broken"))
    }
}


pub fn words(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}


#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}


#[cfg(not(unix))]
pub fn set_mode(_path: &Path, _mode: u32) -> TestResult {
    Ok(())
}


#[cfg(unix)]
pub fn mode_of(path: &Path) -> Result<u32, TestError> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(path)?.permissions().mode() & MODE_MASK)
}


#[cfg(not(unix))]
pub fn mode_of(_path: &Path) -> Result<u32, TestError> {
    Ok(OWNER_ONLY)
}


pub fn run_server(config: ApiConfig, handle: ServerHandle, sender: Sender<SocketAddr>) -> TestResult {
    let account = Account {
        username: USER.to_owned(),
        password_hash: hash_password(PASSWORD, os_random)?,
        roles: ["reader".to_owned()].into(),
        totp: None,
        sessions_valid_after: None,
    };
    update_store_file(&config.accounts_store, os_random, |accounts, _| {
        accounts.insert(USER.to_owned(), account);
        Ok(())
    })?
    .saved?;
    let state: SharedState = Arc::new(build_state(
        &config,
        Arc::new(read_key_file(&config.key_file)?),
        example_access(),
        vec![example_document()],
    )?);
    let router = build_router(state, example_router());
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let running = handle.clone();
        let server = tokio::spawn(async move { serve(&config, router, running).await });
        let address = handle.listening().await.ok_or("server did not start")?;
        sender.send(address)?;
        server.await??;
        Ok::<(), TestError>(())
    })
}


pub fn start_live() -> Result<Live, TestError> {
    let dir = tempdir()?;
    let generated = generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = dir.path().join("server.pem");
    let key = dir.path().join("server.key");
    fs::write(&certificate, generated.cert.pem())?;
    fs::write(&key, generated.signing_key.serialize_pem())?;
    set_mode(&key, OWNER_ONLY)?;
    let key_file = dir.path().join("store.key");
    fs::write(&key_file, [KEY_FILL; KEY_BYTES])?;
    set_mode(&key_file, OWNER_ONLY)?;
    let compromised_list = dir.path().join("compromised.txt");
    fs::write(&compromised_list, "passwordpassword\n")?;
    let config = ApiConfig {
        module: "example".to_owned(),
        tenant: "acme".to_owned(),
        address: "127.0.0.1:0".parse()?,
        tls: Some(TlsFiles {
            certificate: certificate.clone(),
            key,
        }),
        accounts_store: dir.path().join("accounts.json"),
        audit_log: dir.path().join("server-audit.log"),
        key_file: key_file.display().to_string(),
        compromised_list,
        header_read_timeout: SERVER_TIMEOUT,
        limits: Limits {
            rate_max_requests: RATE_MAX_REQUESTS,
            rate_window_seconds: RATE_WINDOW_SECONDS,
            max_sources: MAX_TRACKED_SOURCES,
            max_attempts: MAX_TRACKED_ATTEMPTS,
            body_read_timeout: SERVER_TIMEOUT,
            max_connections_per_source: MAX_CONNECTIONS,
        },
        log_level: DEFAULT_LOG_LEVEL,
        oidc: None,
    };
    let handle = ServerHandle::new();
    let (sender, receiver) = channel();
    let running = handle.clone();
    thread::spawn(move || run_server(config, running, sender).map_err(|error| error.to_string()));
    let address = receiver.recv()?;
    Ok(Live {
        dir,
        url: format!("https://localhost:{}", address.port()),
        ca_file: certificate,
        handle,
    })
}


pub fn config_dir(live: &Live) -> PathBuf {
    live.dir.path().join("client")
}


pub fn session_file(live: &Live) -> PathBuf {
    config_dir(live).join("session.json")
}


pub fn live_args(live: &Live, extra: &[&str]) -> Vec<String> {
    let mut args = words(&["xdrctl", "--server", &live.url]);
    args.extend(words(&["--ca-file", &live.ca_file.display().to_string()]));
    args.extend(words(&["--config-dir", &config_dir(live).display().to_string()]));
    args.extend(words(extra));
    args
}


pub fn offline_args(dir: &Path, extra: &[&str]) -> Vec<String> {
    let mut args = words(&["xdrctl", "--config-dir", &dir.display().to_string()]);
    args.extend(words(extra));
    args
}


pub fn invoke(args: &[String], input: &str, send: &SendFn) -> Result<Outcome, TestError> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_reporting(args, None, send, &mut input.as_bytes(), &mut out, &mut err)?;
    Ok(Outcome {
        code: format!("{code:?}"),
        out: String::from_utf8(out)?,
        err: String::from_utf8(err)?,
    })
}
