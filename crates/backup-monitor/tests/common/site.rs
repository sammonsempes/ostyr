use backup_monitor::restore::digest_hex;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;


pub const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-service-restic.sh");


pub const PRIVATE_DIRECTORY: u32 = 0o700;


pub const SECRET_FILE: u32 = 0o600;


pub const CONFIG_ID: &str = "8ff9e8256a6089f1357840c0fc88b498c541e8948af3317219d4117ce4243ab5";


pub const SNAPSHOT_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";


pub const CANARY: &str = "canary-v1\n";


pub const PG_PASSWORD: &str = "p";


pub struct Site {
    pub dir: TempDir,
    pub settings: PathBuf,
    pub declarations: PathBuf,
    pub restic: PathBuf,
    pub bin: PathBuf,
    pub audit: PathBuf,
    pub state: PathBuf,
    pub secrets: PathBuf,
    pub pg: PathBuf,
}


pub fn private_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    Ok(())
}


pub fn private_file(path: &Path, bytes: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SECRET_FILE))?;
    Ok(())
}


/// A declarations text for tenant `tenant` with the named restic repositories, the first `tested` of them with a restore test.
pub fn declarations_text(tenant: &str, names: &[&str], tested: usize) -> String {
    let digest = digest_hex(CANARY.as_bytes());
    let mut text = format!("tenant: {tenant}\ncritical:\n  - host: web1\n    max_age_hours: 8760\nrepositories:\n");
    names.iter().enumerate().for_each(|(index, name)| {
        text.push_str(&format!(
            "  - repository: {name}\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/{name}\n      password_file: password\n"
        ));
        if index < tested {
            text.push_str(&format!(
                "    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      sha256: {digest}\n      max_bytes: 100\n"
            ));
        }
    });
    text
}


pub fn site(port: u16, ca_pem: &str, declarations: &str) -> Result<Site, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let root = dir.path().to_path_buf();
    let (bin, state, secrets) = (root.join("bin"), root.join("state"), root.join("secrets"));
    [&bin, &state, &secrets].iter().try_for_each(|path| private_dir(path))?;
    private_file(&secrets.join("password"), "hunter2\n")?;
    let restic = bin.join("restic");
    let installed = Command::new("install").arg("-m").arg("755").arg(SCRIPT).arg(&restic).status()?;
    assert!(installed.success());
    fs::write(bin.join("canary"), CANARY)?;
    fs::write(bin.join("config.json"), format!("{{\"version\":2,\"id\":\"{CONFIG_ID}\"}}"))?;
    fs::write(
        bin.join("snapshots.json"),
        format!("[{{\"time\":\"2026-11-20T10:00:00Z\",\"paths\":[\"/data\"],\"hostname\":\"web1\",\"id\":\"{SNAPSHOT_ID}\",\"short_id\":\"x\"}}]"),
    )?;
    fs::write(bin.join("list.txt"), format!("{SNAPSHOT_ID}\n"))?;
    private_file(&root.join("pg.pass"), PG_PASSWORD)?;
    fs::write(root.join("ca.pem"), ca_pem)?;
    let pg = root.join("pg.yaml");
    fs::write(
        &pg,
        format!(
            "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\n",
            root.join("pg.pass").display(),
            root.join("ca.pem").display()
        ),
    )?;
    let declarations_path = root.join("declarations.yaml");
    fs::write(&declarations_path, declarations)?;
    let audit = root.join("audit.log");
    let settings = root.join("backup-monitor.yaml");
    fs::write(
        &settings,
        format!(
            "tenant: acme\ndeclarations_file: {}\nstate_dir: {}\nsecrets_dir: {}\npg_settings: {}\naudit_file: {}\ninterval_seconds: 3600\n\
             restore_interval_seconds: 3600\n",
            declarations_path.display(),
            state.display(),
            secrets.display(),
            pg.display(),
            audit.display()
        ),
    )?;
    Ok(Site {
        dir,
        settings,
        declarations: declarations_path,
        restic,
        bin,
        audit,
        state,
        secrets,
        pg,
    })
}
