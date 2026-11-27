use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};


pub const TENANT: &str = "acme";


pub const MANUAL_ACME: &str =
    "evidence:\n  - tenant: acme\n    control: art21-2-a\n    owner: ciso\n    recorded_at: 2026-11-01T08:00:00Z\n    review_until: 2099-11-01T08:00:00Z\n";


pub const OWNER_ONLY: u32 = 0o600;


pub const INTERVAL: u64 = 300;


pub struct Site {
    pub dir: PathBuf,
    pub settings_file: PathBuf,
    pub pg_file: PathBuf,
    pub manual_file: PathBuf,
    pub indicators: PathBuf,
    pub audit_file: PathBuf,
}


pub fn settings_text(site: &Site, frameworks: &str, interval: u64) -> String {
    format!(
        "tenant: {TENANT}\npg_settings: {}\naudit_file: {}\nindicators_dir: {}\nmanual_file: {}\nframeworks: {frameworks}\ninterval_seconds: {interval}\nmax_reports: 1000\n",
        site.pg_file.display(),
        site.audit_file.display(),
        site.indicators.display(),
        site.manual_file.display(),
    )
}


pub fn pg_text(dir: &Path, port: u16, host: &str) -> String {
    format!(
        "host: {host}\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\nstatement_timeout_secs: 5\n",
        dir.join("pg.pass").display(),
        dir.join("ca.pem").display()
    )
}


pub fn write_site(dir: &Path, port: u16, ca_pem: &str, frameworks: &str) -> Result<Site, Box<dyn std::error::Error>> {
    fs::write(dir.join("pg.pass"), "p")?;
    fs::set_permissions(dir.join("pg.pass"), fs::Permissions::from_mode(OWNER_ONLY))?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::create_dir_all(dir.join("indicators"))?;
    let site = Site {
        dir: dir.to_path_buf(),
        settings_file: dir.join("service.yaml"),
        pg_file: dir.join("pg.yaml"),
        manual_file: dir.join("manual.yaml"),
        indicators: dir.join("indicators"),
        audit_file: dir.join("audit.log"),
    };
    fs::write(&site.pg_file, pg_text(dir, port, "127.0.0.1"))?;
    fs::write(&site.manual_file, MANUAL_ACME)?;
    fs::write(&site.settings_file, settings_text(&site, frameworks, INTERVAL))?;
    Ok(site)
}
