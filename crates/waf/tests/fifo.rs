#![cfg(unix)]

use rustix::fs::{mknodat, FileType, Mode, CWD};
use rustix::io::Errno;
use rustix::process::{kill_process, Pid, Signal};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use waf::cli::render_to;
use waf::error::WafError;
use waf::tls::{check_ca_root, read_failure, NOT_REGULAR_FILE};


const FIFO_MODE: u32 = 0o600;


const HANG_GUARD: Duration = Duration::from_secs(900);


const CHILD_TEST: &str = "child_renders_the_routes_file";


const ROUTES_VARIABLE: &str = "WAF_FIFO_ROUTES";


const TARGET_DEPTH: usize = 3;


const DEVICES: [&str; 2] = ["/dev/null", "/dev/zero"];


fn target_directory() -> Result<PathBuf, Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    Ok(executable.ancestors().nth(TARGET_DEPTH).ok_or("no target directory")?.to_path_buf())
}


fn run_capped(routes: &Path) -> Result<bool, Box<dyn Error>> {
    let mut child = Command::new(std::env::current_exe()?)
        .args([CHILD_TEST, "--exact", "--test-threads", "1"])
        .env(ROUTES_VARIABLE, routes)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = Pid::from_child(&child);
    let (sender, receiver) = mpsc::channel();
    let waiter = std::thread::spawn(move || sender.send(child.wait()));
    let outcome = receiver.recv_timeout(HANG_GUARD);
    if outcome.is_err() {
        kill_process(pid, Signal::KILL)?;
    }
    waiter.join().map_err(|_| "waiter thread panicked")??;
    Ok(outcome.is_ok_and(|status| status.is_ok_and(|exit| exit.success())))
}


#[test]
fn a_fifo_is_refused_by_a_render_that_ends() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir_in(target_directory()?)?;
    let fifo = dir.path().join("root.pem");
    mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(FIFO_MODE), 0)?;
    let routes = dir.path().join("routes.yaml");
    let yaml = format!(
        concat!(
            "tls:\n  issuer: acme\n  directory: https://acme.example.test/dir\n  email: ops@example.test\n",
            "  ca_root_file: {}\n",
            "routes:\n  - hosts: [app.example.test]\n    backends: [\"127.0.0.1:9001\"]\n"
        ),
        fifo.display()
    );
    fs::write(&routes, yaml)?;
    assert!(run_capped(&routes)?);
    Ok(())
}


#[test]
fn child_renders_the_routes_file() -> Result<(), Box<dyn Error>> {
    if let Some(routes) = std::env::var_os(ROUTES_VARIABLE) {
        let out_dir = Path::new(&routes).parent().ok_or("no output directory")?;
        let mut input = fs::File::open(&routes)?;
        let result = render_to(&mut input, &mut Vec::new(), &mut Vec::new(), out_dir);
        assert!(matches!(result, Err(WafError::BadTls(reason)) if reason == NOT_REGULAR_FILE));
    }
    Ok(())
}


#[test]
fn a_device_is_refused_without_being_opened() -> Result<(), Box<dyn Error>> {
    DEVICES.iter().try_for_each(|device| -> Result<(), Box<dyn Error>> {
        let result = check_ca_root(device);
        assert!(matches!(result, Err(WafError::BadTls(reason)) if reason == NOT_REGULAR_FILE));
        Ok(())
    })
}


#[test]
fn a_fifo_is_refused_in_process() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir_in(target_directory()?)?;
    let fifo = dir.path().join("root.pem");
    mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(FIFO_MODE), 0)?;
    let result = check_ca_root(&fifo.to_string_lossy());
    assert!(matches!(result, Err(WafError::BadTls(reason)) if reason == NOT_REGULAR_FILE));
    Ok(())
}


#[test]
fn a_failed_system_call_names_the_ca_root_file() -> Result<(), Box<dyn Error>> {
    assert!(matches!(read_failure(Errno::IO), WafError::CaRoot(_)));
    Ok(())
}
