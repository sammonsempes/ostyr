#![cfg(unix)]

#[path = "common/logging.rs"]
mod logging;
#[path = "common/types.rs"]
mod types;


use dns_rpz::error::ServiceError;
use dns_rpz::model::LoopEnd;
use dns_rpz::process::{parse_args, run_service, signal_waiter};
use signal_hook::consts::{SIGINT, SIGTERM, SIGUSR2};
use signal_hook::low_level::raise;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;
use tempfile::tempdir;
use types::TestResult;


const INTERVAL: u64 = 60;


const LONG_WAIT: Duration = Duration::from_secs(30);


const ROUND_LINE: &str = "round finished";


const MAX_ROUNDS: u64 = 100;


const IOC: &str = "{\"ioc_type\":\"domain\",\"value\":\"evil.example.com\",\"sources\":[],\"first_seen\":\"2026-11-01T00:00:00Z\",\
\"last_seen\":\"2026-11-03T00:00:00Z\",\"confidence\":90,\"tlp\":\"amber\",\"expires_at\":null,\"tags\":{\"malware\":[],\"actor\":[],\"campaign\":[]}}\n";


const NO_RELOAD_POLICY: &str = "unbound:\n  command: /bin/true\n";


fn policy_text(extra: &str) -> String {
    format!("zone: rpz.example.org\nsoa:\n  mname: ns1.example.org\n  rname: hostmaster.example.org\nns: [ns1.example.org]\n{extra}")
}


fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let staging = path.with_extension("staging");
    fs::write(&staging, text)?;
    fs::rename(&staging, path)
}


struct KillOnDrop(Child);


impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            tracing::debug!(%error, "child already gone");
        }
    }
}


fn write_files(dir: &Path, audit_file: &str) -> TestResult {
    let base = dir.display();
    replace_file(&dir.join("policy.yaml"), &policy_text(NO_RELOAD_POLICY))?;
    replace_file(&dir.join("iocs.jsonl"), IOC)?;
    replace_file(
        &dir.join("service.yaml"),
        &format!(
            "policy_file: {base}/policy.yaml\naudit_file: {audit_file}\nioc_source: {base}/iocs.jsonl\ncounter_file: {base}/counter\n\
zone_file: {base}/zone.db\ninterval_seconds: {INTERVAL}\n"
        ),
    )?;
    Ok(())
}


fn service_arguments(dir: &Path) -> Vec<String> {
    vec![dir.join("service.yaml").display().to_string()]
}


#[test]
fn one_argument_is_required() -> TestResult {
    assert!(matches!(parse_args(&[]), Err(ServiceError::Usage)));
    assert!(matches!(parse_args(&["a".to_owned(), "b".to_owned()]), Err(ServiceError::Usage)));
    assert_eq!(parse_args(&["a".to_owned()])?, Path::new("a"));
    Ok(())
}


#[test]
fn a_service_starts_serves_one_round_and_stops() -> TestResult {
    logging::init_logging();
    let dir = tempdir()?;
    let audit_file = dir.path().join("audit.log");
    write_files(dir.path(), &audit_file.display().to_string())?;
    let mut report = Vec::new();
    let end = run_service(&service_arguments(dir.path()), &|_interval| true, MAX_ROUNDS, &mut report)?;
    assert_eq!(end, LoopEnd::Stopped);
    assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains("evil.example.com"));
    let audit = fs::read_to_string(&audit_file)?;
    assert!(audit.contains("dns-rpz.zone_reload"), "{audit}");
    assert!(String::from_utf8(report)?.contains("failed reload"));
    Ok(())
}


#[test]
fn startup_refusals_are_named() -> TestResult {
    logging::init_logging();
    let dir = tempdir()?;
    let audit_file = dir.path().join("audit.log");
    let args = service_arguments(dir.path());
    let wait = |_interval: Duration| true;
    let mut report = Vec::new();
    assert!(matches!(run_service(&[], &wait, MAX_ROUNDS, &mut report), Err(ServiceError::Usage)));
    assert!(matches!(
        run_service(&args, &wait, MAX_ROUNDS, &mut report),
        Err(ServiceError::Settings(_))
    ));
    write_files(dir.path(), "relative.log")?;
    assert!(matches!(
        run_service(&args, &wait, MAX_ROUNDS, &mut report),
        Err(ServiceError::Invalid(_))
    ));
    write_files(dir.path(), &dir.path().join("missing-directory").join("audit.log").display().to_string())?;
    assert!(matches!(run_service(&args, &wait, MAX_ROUNDS, &mut report), Err(ServiceError::Audit(_))));
    write_files(dir.path(), &audit_file.display().to_string())?;
    fs::remove_file(dir.path().join("policy.yaml"))?;
    assert!(matches!(run_service(&args, &wait, MAX_ROUNDS, &mut report), Err(ServiceError::Policy(_))));
    let text = fs::read_to_string(dir.path().join("service.yaml"))?;
    replace_file(&dir.path().join("service.yaml"), &text.replace("audit_file", "audit_path"))?;
    assert!(matches!(
        run_service(&args, &wait, MAX_ROUNDS, &mut report),
        Err(ServiceError::Settings(_))
    ));
    Ok(())
}


#[test]
fn a_stop_signal_ends_the_wait_and_a_quiet_wait_times_out() -> TestResult {
    let (wait, guard) = signal_waiter(&[SIGUSR2])?;
    assert!(!wait(Duration::ZERO));
    raise(SIGUSR2)?;
    assert!(wait(LONG_WAIT));
    drop(guard);
    assert!(wait(LONG_WAIT));
    Ok(())
}


fn spawn_service(dir: &Path) -> Result<(KillOnDrop, BufReader<std::process::ChildStderr>), std::io::Error> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ostyr-dns-rpz"))
        .arg(dir.join("service.yaml"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or_else(|| std::io::Error::other("no stderr"))?;
    Ok((KillOnDrop(child), BufReader::new(stderr)))
}


fn stop_with(dir: &Path, signal: &str) -> Result<(ExitStatus, String), Box<dyn std::error::Error>> {
    let (mut service, mut stderr) = spawn_service(dir)?;
    let mut seen = String::new();
    let mut line = String::new();
    while !seen.contains(ROUND_LINE) && stderr.read_line(&mut line)? > 0 {
        seen.push_str(&line);
        line.clear();
    }
    assert!(seen.contains(ROUND_LINE), "{seen}");
    let sent = Command::new("kill").arg(signal).arg(service.0.id().to_string()).status()?;
    assert!(sent.success());
    let mut rest = String::new();
    stderr.read_to_string(&mut rest)?;
    Ok((service.0.wait()?, seen))
}


#[test]
fn the_binary_stops_with_zero_on_sigterm_and_sigint() -> TestResult {
    for signal in [format!("-{SIGTERM}"), format!("-{SIGINT}")] {
        let dir = tempdir()?;
        write_files(dir.path(), &dir.path().join("audit.log").display().to_string())?;
        let (status, seen) = stop_with(dir.path(), &signal)?;
        assert!(status.success(), "{signal} {status:?} {seen}");
        assert!(fs::read_to_string(dir.path().join("zone.db"))?.contains("evil.example.com"));
    }
    Ok(())
}


#[test]
fn the_binary_refuses_a_missing_argument_and_a_bad_file() -> TestResult {
    let usage = Command::new(env!("CARGO_BIN_EXE_ostyr-dns-rpz")).stdin(Stdio::null()).output()?;
    assert!(!usage.status.success());
    assert!(String::from_utf8_lossy(&usage.stderr).contains("usage: ostyr-dns-rpz"));
    let dir = tempdir()?;
    replace_file(&dir.path().join("service.yaml"), "interval_seconds: 60\n")?;
    let bad = Command::new(env!("CARGO_BIN_EXE_ostyr-dns-rpz"))
        .arg(dir.path().join("service.yaml"))
        .stdin(Stdio::null())
        .output()?;
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("service file"));
    Ok(())
}
