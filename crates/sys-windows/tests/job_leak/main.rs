#![cfg(windows)]
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};
use sys_windows::job_output::{drain_output, read_output, reader_count, DrainEnd, OutputRead, DRAIN_CHUNK_BYTES};
use sys_windows::job_spawn::{no_job_fault, no_window_action, spawn_in_job_hooked, terminate, JobOutput};
use sys_windows::types::SpawnHooks;


const WAIT_SECONDS: u64 = 120;


const SHORT_DEADLINE_MILLIS: u64 = 1_000;


fn system_directory() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{}\\System32", std::env::var("SystemRoot")?))
}


fn cmd_path() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{}\\cmd.exe", system_directory()?))
}


fn guarded<Delivered: Send + 'static>(work: impl FnOnce() -> Delivered + Send + 'static) -> Result<Delivered, Box<dyn std::error::Error>> {
    let (sender, receiver) = channel();
    std::thread::spawn(move || {
        let delivered = sender.send(work()).is_ok();
        std::hint::black_box(delivered);
    });
    Ok(receiver
        .recv_timeout(Duration::from_secs(WAIT_SECONDS))
        .map_err(|_| "the work never ended")?)
}


fn spawn_sibling() {
    let spawned = Command::new("ping").args(["-n", "11", "127.0.0.1"]).spawn();
    std::hint::black_box(spawned.is_ok());
}


fn spawn_with_sibling_after(after_create: fn(), after_clear: fn()) -> Result<JobOutput, Box<dyn std::error::Error>> {
    let root = std::env::var("SystemRoot")?;
    let hooks = SpawnHooks {
        assign: no_job_fault,
        after_create,
        after_clear,
    };
    Ok(spawn_in_job_hooked(
        &cmd_path()?,
        &["/D", "/C", "echo hello"],
        &[("SystemRoot", root.as_str())],
        &system_directory()?,
        hooks,
    )?)
}


fn bounded_after_terminate(spawned: JobOutput) -> Result<(OutputRead, DrainEnd, usize), Box<dyn std::error::Error>> {
    let JobOutput { child, output } = spawned;
    terminate(&child)?;
    let deadline = Instant::now() + Duration::from_millis(SHORT_DEADLINE_MILLIS);
    let found = guarded(move || {
        let mut buffer = [0; DRAIN_CHUNK_BYTES];
        let first = read_output(&output, &mut buffer, deadline).map_err(|error| error.to_string())?;
        let drained = drain_output(&output, deadline).map_err(|error| error.to_string())?;
        Ok::<_, String>((first, drained, reader_count(&output)))
    })?;
    Ok(found?)
}


#[test]
fn the_window_leak_is_bounded_and_clearing_the_flag_closes_it() -> Result<(), Box<dyn std::error::Error>> {
    let leaked = bounded_after_terminate(spawn_with_sibling_after(spawn_sibling, no_window_action)?)?;
    assert!(matches!(leaked.0, OutputRead::Bytes(_) | OutputRead::DeadlinePassed), "{:?}", leaked.0);
    assert_eq!(leaked.1, DrainEnd::DeadlinePassed);
    assert_eq!(leaked.2, 0);
    let cleared = bounded_after_terminate(spawn_with_sibling_after(no_window_action, spawn_sibling)?)?;
    assert_eq!(cleared.1, DrainEnd::Reached);
    assert_eq!(cleared.2, 0);
    Ok(())
}
