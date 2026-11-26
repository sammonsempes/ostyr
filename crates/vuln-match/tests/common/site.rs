use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};


pub const OWNER_ONLY: u32 = 0o600;


pub const ROUND_SECONDS: u64 = 10;


pub const OPEN: &str = "CC0-1.0";


pub const TENANT: &str = "acme";


pub const RECORD: &str = r#"{"id":"DSA-1","aliases":["CVE-2024-1234"],"affected":[{"package":{"ecosystem":"Debian:12","name":"curl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.88.1-11"}]}]}]}"#;


pub const KEV: &str = r#"{"catalogVersion":"1","dateReleased":"2026-01-01","count":1,"vulnerabilities":[{"cveID":"CVE-2024-1234","dateAdded":"2024-01-01","dueDate":"2024-02-01","knownRansomwareCampaignUse":"Unknown"}]}"#;


pub const EPSS: &str = "#model_version:v1,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.5,0.9\n";


pub const VULNERABLE: &str =
    r#"[{"ecosystem":"Debian:12","name":"curl","version":"7.88.1-10"},{"ecosystem":"Debian:12","name":"bash","version":"5.2"}]"#;


pub fn build_archive(records: &[(&str, &str)]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    records.iter().try_for_each(|(name, content)| -> Result<(), Box<dyn Error>> {
        writer.start_file(*name, options)?;
        writer.write_all(content.as_bytes())?;
        Ok(())
    })?;
    Ok(writer.finish()?.into_inner())
}


pub fn sha_of(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}


/// The paths of a site written in one directory.
pub struct Site {
    pub settings: PathBuf,
    pub inventory: PathBuf,
    pub archive: PathBuf,
    pub kev: PathBuf,
    pub epss: PathBuf,
    pub audit: PathBuf,
    pub pg: PathBuf,
}


pub fn write_site(dir: &Path, pg_port: u16, ca_pem: &str) -> Result<Site, Box<dyn Error>> {
    let site = Site {
        settings: dir.join("service.yaml"),
        inventory: dir.join("inventory"),
        archive: dir.join("osv.zip"),
        kev: dir.join("kev.json"),
        epss: dir.join("epss.csv"),
        audit: dir.join("audit.log"),
        pg: dir.join("pg.yaml"),
    };
    fs::create_dir_all(&site.inventory)?;
    let archive = build_archive(&[("DSA-1.json", RECORD)])?;
    fs::write(&site.archive, &archive)?;
    fs::write(&site.kev, KEV)?;
    fs::write(&site.epss, EPSS)?;
    fs::write(dir.join("pg.pass"), "p")?;
    fs::set_permissions(dir.join("pg.pass"), std::os::unix::fs::PermissionsExt::from_mode(OWNER_ONLY))?;
    fs::write(dir.join("ca.pem"), ca_pem)?;
    fs::write(
        &site.pg,
        format!(
            "host: 127.0.0.1\nport: {pg_port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            dir.join("pg.pass").display(),
            dir.join("ca.pem").display()
        ),
    )?;
    fs::write(&site.settings, settings_text(&site, &sha_of(&archive), ROUND_SECONDS))?;
    Ok(site)
}


pub fn settings_text(site: &Site, sha256: &str, round_seconds: u64) -> String {
    format!(
        "tenant: {TENANT}\npg_settings: {}\naudit_file: {}\ninventory_dir: {}\nosv_archive: {}\nkev_file: {}\nepss_file: {}\nround_seconds: {round_seconds}\n\
         feed:\n  sha256: {sha256}\n  prefix_licences:\n    \"DSA-\": {OPEN}\n  allowed_licences: [{OPEN}]\n",
        site.pg.display(),
        site.audit.display(),
        site.inventory.display(),
        site.archive.display(),
        site.kev.display(),
        site.epss.display(),
    )
}
