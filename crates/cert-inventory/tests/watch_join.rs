#![cfg(target_os = "linux")]


#[path = "common/types.rs"]
mod types;


use cert_inventory::serve::start;
use cert_inventory::types::InterruptWait;
use std::fs;
use std::future::{ready, Future};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const OWNER_ONLY: u32 = 0o600;


const DEBOUNCER_THREAD_COMM: &str = "notify-rs debou";


fn at_once() -> io::Result<InterruptWait> {
    Ok(Box::pin(ready(Ok(()))))
}


fn instant(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(ready(()))
}


fn vanished(error: io::Error) -> io::Result<String> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(String::new())
    } else {
        Err(error)
    }
}


fn debouncer_threads() -> Result<usize, io::Error> {
    let comms = fs::read_dir("/proc/self/task")?
        .map(|entry| entry.and_then(|task| fs::read_to_string(task.path().join("comm")).or_else(vanished)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(comms.iter().filter(|comm| comm.trim_end() == DEBOUNCER_THREAD_COMM).count())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_production_stop_joins_the_watcher_thread_before_start_returns() -> TestResult {
    let dir = tempdir()?;
    let base = dir.path();
    fs::write(base.join("pg.pass"), "p")?;
    fs::set_permissions(base.join("pg.pass"), fs::Permissions::from_mode(OWNER_ONLY))?;
    fs::write(base.join("ca.pem"), "x")?;
    fs::write(
        base.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: 1\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            base.join("pg.pass").display(),
            base.join("ca.pem").display()
        ),
    )?;
    fs::create_dir_all(base.join("certs"))?;
    let settings_file = base.join("certs.yaml");
    fs::write(
        &settings_file,
        format!(
            "tenant: acme\npg_settings: {}\naudit_file: {}\nroots: [{}]\nhost: scanner-1.lab\ninterval_seconds: 3600\nmax_depth: 4\ndeadline_seconds: 5\nmax_certs: 1000\n",
            base.join("pg.yaml").display(),
            base.join("audit.log").display(),
            base.join("certs").display()
        ),
    )?;
    assert_eq!(debouncer_threads()?, 0, "a watcher thread existed before the service started");
    start(&settings_file, 1, at_once, instant).await?;
    assert_eq!(debouncer_threads()?, 0, "start returned while the watcher thread was alive");
    Ok(())
}
