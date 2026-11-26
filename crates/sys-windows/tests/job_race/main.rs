#![cfg(windows)]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sys_windows::job_output::{drain_output, read_output, ChildOutput, OutputRead, DRAIN_CHUNK_BYTES};
use sys_windows::job_spawn::{spawn_in_job, terminate, JobOutput};


const WAIT_SECONDS: u64 = 120;


const READ_SECONDS: u64 = 30;


const SHORT_DEADLINE_MILLIS: u64 = 1_000;


const MAX_READS: u32 = 10_000;


const RACE_SPAWNS: usize = 60;


const RACE_THREADS: usize = 6;


fn system_directory() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{}\\System32", std::env::var("SystemRoot")?))
}


fn cmd_path() -> Result<String, Box<dyn std::error::Error>> {
    Ok(format!("{}\\cmd.exe", system_directory()?))
}


fn start(arguments: &[&str], extra: &[(&str, &str)]) -> Result<JobOutput, Box<dyn std::error::Error>> {
    let root = std::env::var("SystemRoot")?;
    let system = system_directory()?;
    let mut environment = vec![("SystemRoot", root.as_str())];
    environment.extend_from_slice(extra);
    Ok(spawn_in_job(&cmd_path()?, arguments, &environment, &system)?)
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


fn read_to_end(output: &ChildOutput, deadline: Instant) -> Result<(Vec<u8>, OutputRead), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; DRAIN_CHUNK_BYTES];
    let mut failure = None;
    let last = (0..MAX_READS).find_map(|_| match read_output(output, &mut buffer, deadline) {
        Ok(OutputRead::Bytes(count)) => {
            bytes.extend(buffer.iter().take(count));
            None
        }
        Ok(other) => Some(other),
        Err(error) => {
            failure = Some(error);
            Some(OutputRead::End)
        }
    });
    failure.map_or(Ok(()), Err)?;
    Ok((bytes, last.ok_or("the output never ended")?))
}


fn race_worker(count: usize) -> Result<usize, String> {
    (0..count).try_fold(0, |done, _| {
        let JobOutput { child, output } = start(&["/D", "/C", "echo race"], &[]).map_err(|error| error.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(READ_SECONDS);
        let (_, last) = read_to_end(&output, deadline).map_err(|error| error.to_string())?;
        terminate(&child).map_err(|error| error.to_string())?;
        let drained = drain_output(&output, Instant::now() + Duration::from_millis(SHORT_DEADLINE_MILLIS)).map_err(|error| error.to_string())?;
        std::hint::black_box((last, drained));
        Ok::<usize, String>(done + 1)
    })
}


fn interfere(stop: &AtomicBool) {
    (0..MAX_READS).find_map(|_| {
        stop.load(Ordering::SeqCst).then_some(()).or_else(|| {
            let status = Command::new("hostname").status();
            std::hint::black_box(status.is_ok());
            None
        })
    });
}


#[test]
fn sixty_spawns_against_concurrent_sibling_commands_never_hang() -> Result<(), Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let interferer_stop = Arc::clone(&stop);
    let interferer = std::thread::spawn(move || interfere(&interferer_stop));
    let workers = (0..RACE_THREADS)
        .map(|_| std::thread::spawn(move || race_worker(RACE_SPAWNS / RACE_THREADS)))
        .collect::<Vec<_>>();
    let counts = guarded(move || {
        workers
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "worker panicked".to_string()).and_then(std::convert::identity))
            .collect::<Result<Vec<usize>, String>>()
    });
    stop.store(true, Ordering::SeqCst);
    assert!(interferer.join().is_ok());
    assert_eq!(counts?.map_err(|error| error.to_string())?.iter().sum::<usize>(), RACE_SPAWNS);
    Ok(())
}
