#[path = "support/types.rs"]
mod types;


use core_api::example::{example_access, example_document, example_router};
use core_api::logging::reloadable_dispatch;
use core_api::server::{listening_address, new_listener, run_module, stop_listener};
use notify::RecursiveMode;
use notify_debouncer_full::new_debouncer;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::mpsc::channel;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Duration;
use tempfile::tempdir;
use tracing::instrument::WithSubscriber;
use tracing::level_filters::LevelFilter;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::{TestError, TestResult};


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 7;


const OWNER_ONLY: u32 = 0o600;


const EVENT_COUNT: usize = 3;


const DEBOUNCE: Duration = Duration::from_millis(50);


const HANG_GUARD: Duration = Duration::from_secs(120);


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


struct SharedFile(Arc<File>);


impl Write for SharedFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}


#[cfg(unix)]
fn set_private(path: &std::path::Path) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


#[cfg(not(unix))]
fn set_private(_path: &std::path::Path) -> Result<(), TestError> {
    Ok(())
}


fn module_yaml(dir: &std::path::Path, extra: &str) -> Result<String, TestError> {
    let key_file = dir.join("store.key");
    fs::write(&key_file, [KEY_FILL; KEY_BYTES])?;
    set_private(&key_file)?;
    let compromised = dir.join("compromised.txt");
    fs::write(&compromised, "passwordpassword\n")?;
    let path = dir.join("module.yaml");
    fs::write(
        &path,
        format!(
            "name: example\nversion: 1.0.0\nlisten: \"127.0.0.1:0\"\nsettings:\n  accounts_store: {}\n  audit_log: {}\n  key_file: {}\n  compromised_list: {}\n{extra}",
            dir.join("accounts.json").display(),
            dir.join("audit.log").display(),
            key_file.display(),
            compromised.display(),
        ),
    )?;
    Ok(path.display().to_string())
}


#[tokio::test]
async fn a_module_starts_at_the_level_of_its_file() -> TestResult {
    LazyLock::force(&ANCHOR);
    let dir = tempdir()?;
    let path = module_yaml(dir.path(), "  log_level: debug\n")?;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let (dispatch, handle) = reloadable_dispatch(BoxMakeWriter::new(move || SharedBuffer(Arc::clone(&sink))), LevelFilter::INFO);
    let listener = new_listener();
    let running = listener.clone();
    let task = tokio::spawn(
        async move {
            run_module(
                &[path],
                example_router(),
                example_access(),
                vec![example_document()],
                &[],
                running,
                Some(handle),
            )
            .await
        }
        .with_subscriber(dispatch.clone()),
    );
    listening_address(&listener).await.ok_or("server did not start")?;
    tracing::dispatcher::with_default(&dispatch, || tracing::debug!("first record"));
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    let text = String::from_utf8(captured.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
    assert!(text.contains("first record"));
    Ok(())
}


#[test]
fn the_watcher_targets_never_log_below_info_so_they_cannot_feed_the_watch() -> TestResult {
    LazyLock::force(&ANCHOR);
    let dir = tempdir()?;
    let log_file = dir.path().join("out.log");
    let settings = dir.path().join("module.yaml");
    fs::write(&settings, "a")?;
    let output = Arc::new(OpenOptions::new().create(true).append(true).open(&log_file)?);
    let (dispatch, _handle) = reloadable_dispatch(BoxMakeWriter::new(move || SharedFile(Arc::clone(&output))), LevelFilter::DEBUG);
    let (sender, receiver) = channel();
    let inside = dispatch.clone();
    let mut debouncer = new_debouncer(DEBOUNCE, None, move |_result| {
        tracing::dispatcher::with_default(&inside, || {
            tracing::debug!(target: "notify", "watcher debug");
            tracing::debug!(target: "notify_debouncer_full", "debouncer debug");
            tracing::debug!(target: "inotify", "inotify debug");
            tracing::info!(target: "notify", "watcher info");
            tracing::debug!(target: "probe", "other debug");
        });
        sender.send(()).unwrap_or_else(|error| tracing::error!(%error, "receiver gone"));
    })?;
    debouncer.watch(dir.path(), RecursiveMode::NonRecursive)?;
    (0..EVENT_COUNT).try_for_each(|i| -> Result<(), TestError> {
        fs::write(&settings, format!("change {i}"))?;
        receiver.recv_timeout(HANG_GUARD)?;
        Ok(())
    })?;
    drop(debouncer);
    let text = fs::read_to_string(&log_file)?;
    assert!(!text.contains("watcher debug"));
    assert!(!text.contains("debouncer debug"));
    assert!(!text.contains("inotify debug"));
    assert!(text.contains("watcher info"));
    assert!(text.contains("other debug"));
    Ok(())
}
