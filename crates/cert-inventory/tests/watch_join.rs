#![cfg(target_os = "linux")]


#[path = "common/types.rs"]
mod types;


use cert_inventory::serve::start;
use cert_inventory::types::InterruptWait;
use std::fs;
use std::future::{ready, Future};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const OWNER_ONLY: u32 = 0o600;


const REPEATS: usize = 20;


fn at_once() -> io::Result<InterruptWait> {
    Ok(Box::pin(ready(Ok(()))))
}


fn instant(_duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
    Box::pin(ready(()))
}


fn vanished(error: io::Error) -> io::Result<PathBuf> {
    if error.kind() == io::ErrorKind::NotFound {
        Ok(PathBuf::new())
    } else {
        Err(error)
    }
}


fn open_handles_on(file: &Path) -> Result<usize, io::Error> {
    let links = fs::read_dir("/proc/self/fd")?
        .map(|entry| entry.and_then(|handle| fs::read_link(handle.path())).or_else(vanished))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(links.iter().filter(|link| link.as_path() == file).count())
}


#[tokio::test(flavor = "multi_thread")]
async fn the_production_stop_joins_the_watcher_so_the_audit_handle_is_released_before_start_returns() -> TestResult {
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
    let audit_file = base.join("audit.log");
    assert_eq!(open_handles_on(&audit_file)?, 0, "the audit log was open before the service started");
    for _ in 0..REPEATS {
        start(&settings_file, 1, at_once, instant).await?;
        assert_eq!(
            open_handles_on(&audit_file)?,
            0,
            "start returned while the watcher thread still held the audit log"
        );
    }
    Ok(())
}
