#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use rustix::process::{kill_process, Pid, Signal};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::iter::from_fn;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread::{spawn, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempDir};
use types::TestResult;


const BINARY: &str = env!("CARGO_BIN_EXE_ostyr-intel");


const HANG_GUARD: Duration = Duration::from_secs(120);


const PASSWORD_MODE: u32 = 0o600;


const WORLD_READABLE_MODE: u32 = 0o644;


const INTERVAL_SECONDS: u64 = 60;


const AUDIT_LINES: usize = 3;


const REQUESTS_PER_ROUND: usize = 6;


const TAXII_PASSWORD: &str = "TAXIIPW-41d0be66";


const PASSWORD: &str = "BINARYPW-7f31c2a9";


struct Running {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}


impl Drop for Running {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            tracing::debug!(%error, "child already gone");
        }
        if let Err(error) = self.child.wait() {
            tracing::warn!(%error, "child not reaped");
        }
    }
}


fn start(settings: &Path) -> Result<Running, Box<dyn std::error::Error>> {
    let mut child = Command::new(BINARY).arg(settings).stderr(Stdio::piped()).spawn()?;
    let stderr = child.stderr.take().ok_or("no stderr")?;
    let (sender, lines) = channel();
    spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .for_each(|line| drop(sender.send(line)))
    });
    Ok(Running {
        child,
        lines,
        seen: Vec::new(),
    })
}


fn wait_for(running: &mut Running, wanted: &str) -> Result<String, Box<dyn std::error::Error>> {
    let known = running.seen.iter().find(|line| line.contains(wanted)).cloned();
    let deadline = Instant::now() + HANG_GUARD;
    let found = known.or_else(|| {
        from_fn(|| {
            deadline
                .checked_duration_since(Instant::now())
                .and_then(|left| running.lines.recv_timeout(left).ok())
        })
        .inspect(|line| running.seen.push(line.clone()))
        .find(|line| line.contains(wanted))
    });
    Ok(found.ok_or_else(|| format!("the line `{wanted}` never came"))?)
}


fn signal(running: &Running, which: Signal) -> TestResult {
    let pid = Pid::from_child(&running.child);
    Ok(kill_process(pid, which)?)
}


fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let lines: Vec<String> = from_fn(|| {
        let mut line = String::new();
        reader.read_line(&mut line).ok().filter(|count| *count > 0).map(|_| line)
    })
    .take_while(|line| line != "\r\n")
    .collect();
    let length = lines
        .iter()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
        .unwrap_or(0);
    let head = lines.concat();
    let mut body = String::new();
    reader.take(length).read_to_string(&mut body)?;
    Ok(format!("{head}\r\n\r\n{body}"))
}


fn serve(listener: TcpListener, count: usize) -> JoinHandle<io::Result<Vec<String>>> {
    spawn(move || {
        (0..count).try_fold(Vec::new(), |mut seen, _| {
            let (mut stream, _) = listener.accept()?;
            seen.push(read_request(&mut stream)?);
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
            Ok(seen)
        })
    })
}


struct Lab {
    dir: TempDir,
    listener: TcpListener,
}


fn lab() -> Result<Lab, Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let mut password = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PASSWORD_MODE)
        .open(dir.path().join("password"))?;
    writeln!(password, "{PASSWORD}")?;
    fs::write(dir.path().join("good.txt"), "192.0.2.1\n198.51.100.0/24\n")?;
    Ok(Lab { dir, listener })
}


fn feeds_text(lab: &Lab, tenant: &str, extra_feed: &str) -> Result<String, Box<dyn std::error::Error>> {
    let port = lab.listener.local_addr()?.port();
    Ok(format!(
        "feeds:\n  - name: good\n    format: crowdsec\n    path: good.txt\n    ttl_seconds: 4000000000\n  - name: gone\n    format: crowdsec\n    path: gone.txt\n\
         {extra_feed}clickhouse:\n  url: http://127.0.0.1:{port}\n  user: ostyr\n  password_file: {0}/password\n  database: d\n  table: t\n  dictionary: dd\n  tenant: {tenant}\n",
        lab.dir.path().display()
    ))
}


fn write_files(lab: &Lab, feeds: &str, interval: u64) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    fs::write(lab.dir.path().join("feeds.yaml"), feeds)?;
    let settings = lab.dir.path().join("settings.yaml");
    fs::write(
        &settings,
        format!(
            "feeds_file: {0}/feeds.yaml\naudit_file: {0}/audit.jsonl\ninterval_seconds: {interval}\n",
            lab.dir.path().display()
        ),
    )?;
    Ok(settings)
}


#[test]
fn a_bad_argument_or_settings_file_is_one_line_and_a_non_zero_exit() -> TestResult {
    let usage = Command::new(BINARY).output()?;
    assert!(!usage.status.success());
    assert!(String::from_utf8_lossy(&usage.stderr).contains("usage: ostyr-intel"));
    let missing = Command::new(BINARY).arg("/nonexistent/settings.yaml").output()?;
    assert!(!missing.status.success());
    assert_eq!(String::from_utf8_lossy(&missing.stderr).lines().count(), 1);
    Ok(())
}


#[test]
fn a_round_loads_the_feeds_then_a_reload_is_audited_and_sigterm_exits_zero() -> TestResult {
    let lab = lab()?;
    let feeds = feeds_text(&lab, "tenant-a", "")?;
    let settings = write_files(&lab, &feeds, INTERVAL_SECONDS)?;
    let listener = lab.listener.try_clone()?;
    let server = serve(listener, REQUESTS_PER_ROUND);
    let mut running = start(&settings)?;
    wait_for(&mut running, "intel service started")?;
    let failed = wait_for(&mut running, "intel round failed")?;
    assert!(failed.contains("names=\"gone\""));
    assert!(failed.contains("rows=2"));
    assert!(!running.seen.iter().any(|line| line.contains(PASSWORD)));
    let requests = server.join().map_err(|_| "server panicked")??;
    assert_eq!(requests.len(), REQUESTS_PER_ROUND);
    let insert = requests.last().ok_or("no request")?;
    assert!(insert.contains("192.0.2.1") && insert.contains("\"tenant\":\"tenant-a\""));
    let (head, body) = insert.split_once("\r\n\r\n").ok_or("no head")?;
    assert!(head.contains(PASSWORD) && !body.contains(PASSWORD));
    fs::write(
        lab.dir.path().join("feeds.yaml"),
        feeds_text(&lab, "tenant-a", "  - name: more\n    format: crowdsec\n    path: good.txt\n")?,
    )?;
    signal(&running, Signal::HUP)?;
    wait_for(&mut running, "configuration reloaded")?;
    fs::write(lab.dir.path().join("feeds.yaml"), feeds_text(&lab, "tenant-b", "")?)?;
    signal(&running, Signal::HUP)?;
    wait_for(&mut running, "configuration reload refused")?;
    let port = lab.listener.local_addr()?.port();
    let moved = feeds_text(&lab, "tenant-a", "")?.replace(&format!("127.0.0.1:{port}"), "127.0.0.1:9");
    fs::write(lab.dir.path().join("feeds.yaml"), moved)?;
    signal(&running, Signal::HUP)?;
    wait_for(&mut running, "clickhouse.url")?;
    signal(&running, Signal::TERM)?;
    let status = running.child.wait()?;
    assert!(status.success());
    let audit = fs::read_to_string(lab.dir.path().join("audit.jsonl"))?;
    assert_eq!(audit.lines().count(), AUDIT_LINES);
    assert!(audit.lines().all(|line| line.contains("\"tenant\":\"all\"")));
    assert!(audit.contains("\"result\":\"applied\"") && audit.contains("clickhouse.tenant") && audit.contains("clickhouse.url"));
    Ok(())
}


#[test]
fn a_taxii_feed_that_fails_is_named_and_no_secret_reaches_a_log_or_the_audit() -> TestResult {
    let lab = lab()?;
    let mut taxii_password = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(WORLD_READABLE_MODE)
        .open(lab.dir.path().join("taxii.pw"))?;
    writeln!(taxii_password, "{TAXII_PASSWORD}")?;
    let taxii = format!(
        "  - name: tx\n    format: taxii21\n    taxii:\n      api_root: http://127.0.0.1:9\n      collection: c1\n      user: u\n      password_file: {}/taxii.pw\n",
        lab.dir.path().display()
    );
    let settings = write_files(&lab, &feeds_text(&lab, "tenant-a", &taxii)?, INTERVAL_SECONDS)?;
    let server = serve(lab.listener.try_clone()?, REQUESTS_PER_ROUND);
    let mut running = start(&settings)?;
    let failed = wait_for(&mut running, "intel round failed")?;
    assert!(failed.contains("names=\"gone,tx\""));
    wait_for(&mut running, "the TAXII password file could not be used")?;
    signal(&running, Signal::INT)?;
    assert!(running.child.wait()?.success());
    server.join().map_err(|_| "server panicked")??;
    assert!(!running.seen.iter().any(|line| line.contains(TAXII_PASSWORD) || line.contains(PASSWORD)));
    assert!(!fs::read_to_string(lab.dir.path().join("audit.jsonl"))?.contains(TAXII_PASSWORD));
    Ok(())
}


#[test]
fn a_fifo_and_a_device_symlink_as_feed_files_are_named_failed_feeds_and_the_stop_is_honoured() -> TestResult {
    let lab = lab()?;
    assert!(Command::new("mkfifo").arg(lab.dir.path().join("fifo.txt")).status()?.success());
    std::os::unix::fs::symlink("/dev/zero", lab.dir.path().join("zero.txt"))?;
    let extra = "  - name: fifo\n    format: crowdsec\n    path: fifo.txt\n  - name: zero\n    format: crowdsec\n    path: zero.txt\n";
    let settings = write_files(&lab, &feeds_text(&lab, "tenant-a", extra)?, INTERVAL_SECONDS)?;
    let server = serve(lab.listener.try_clone()?, REQUESTS_PER_ROUND);
    let mut running = start(&settings)?;
    let failed = wait_for(&mut running, "intel round failed")?;
    assert!(failed.contains("names=\"gone,fifo,zero\""), "{failed}");
    assert!(failed.contains("rows=2"), "{failed}");
    signal(&running, Signal::TERM)?;
    assert!(running.child.wait()?.success());
    server.join().map_err(|_| "server panicked")??;
    Ok(())
}
