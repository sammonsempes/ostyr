use pg_fake::certs::{loopback, make_pki};
use pg_fake::fake::{self, Fake, Mode, Reply};
use pg_fake::types::Handler;
use rcgen::SanType;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;


pub const OWNER_ONLY: u32 = 0o600;


pub const PG_PASSWORD: &str = "p";


pub const TOKEN: &str = "auditor@pve!lab=0a1b2c3d-1111-2222-3333-444455556666";


pub const FETCH_TIMEOUT_MS: u64 = 5000;


pub const INTERVAL_SECONDS: u64 = 60;


pub struct Site {
    pub settings_file: PathBuf,
    pub audit_file: PathBuf,
}


pub fn private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


/// Every statement is accepted; the apply statement answers "applied, nothing refused, no cap".
pub fn applying() -> Handler {
    Arc::new(|sql| {
        if sql == cmdb::store::APPLY_SQL {
            Reply::Rows(vec![vec!["true".to_owned(), "[]".to_owned(), "[]".to_owned(), String::new()]])
        } else {
            Reply::Done
        }
    })
}


pub async fn pg_with(handler: Handler) -> Result<(Fake, String), Box<dyn Error>> {
    let pki = make_pki(SanType::IpAddress(loopback()))?;
    let fake = fake::start(Mode::Tls(pki.server), PG_PASSWORD, handler).await?;
    Ok((fake, pki.ca_pem))
}


/// The three settings files, the token, the CA of the Proxmox stand-in and the audit path; `extra` is appended to the service file.
pub fn write_site(dir: &Path, pg_port: u16, pg_ca: &str, api_port: u16, pve_ca: &str, extra: &str) -> Result<Site, Box<dyn Error>> {
    private_file(&dir.join("pg.pass"), PG_PASSWORD.as_bytes())?;
    private_file(&dir.join("token"), format!("{TOKEN}\n").as_bytes())?;
    fs::write(dir.join("pg-ca.pem"), pg_ca)?;
    fs::write(dir.join("pve-ca.pem"), pve_ca)?;
    fs::write(
        dir.join("pg.yaml"),
        format!(
            "host: 127.0.0.1\nport: {pg_port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("pg-ca.pem").display()
        ),
    )?;
    fs::write(
        dir.join("fetch.yaml"),
        format!(
            "api_url: https://localhost:{api_port}\nca_file: {}\ntoken_file: {}\ntenant: acme\ncluster: pve-1\ntimeout_ms: {FETCH_TIMEOUT_MS}\n",
            dir.join("pve-ca.pem").display(),
            dir.join("token").display()
        ),
    )?;
    let audit_file = dir.join("audit.log");
    let settings_file = dir.join("service.yaml");
    fs::write(
        &settings_file,
        format!(
            "fetch_settings: {}\npg_settings: {}\naudit_file: {}\ninterval_seconds: {INTERVAL_SECONDS}\n{extra}",
            dir.join("fetch.yaml").display(),
            dir.join("pg.yaml").display(),
            audit_file.display(),
        ),
    )?;
    Ok(Site { settings_file, audit_file })
}
