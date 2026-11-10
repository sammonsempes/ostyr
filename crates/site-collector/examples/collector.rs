use core_audit::log::{append, open_file_log};
use core_config::reload::{current_config, ReloadContext};
use core_config::watch::watch_files;
use site_collector::listen::{open_runtime, run};
use site_collector::listen_model::Runtime;
use site_collector::listen_settings::open_listener_engine;
use site_collector::spool::{open_spool, read_from, spool_stats};
use site_collector::spool_model::SpoolConfig;
use std::error::Error;
use std::io::{stdin, stdout, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};


const DEBOUNCE: Duration = Duration::from_millis(300);


const SEGMENT_BYTES: u64 = 1 << 20;


const TOTAL_BYTES: u64 = 1 << 24;


const REPLAY_LIMIT: usize = 1_000_000;


const SECONDS_PER_YEAR: u64 = 31_556_952;


const FIRST_YEAR: i32 = 1970;


const USAGE: &str =
    "usage: collector <settings-file> <audit-file> <spool-dir>; stdin: quit (prints the counters and the spool); the settings file is watched";


fn current_year() -> i32 {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    FIRST_YEAR + i32::try_from(seconds / SECONDS_PER_YEAR).unwrap_or(0)
}


fn start(settings_file: &str, audit_file: &str, spool_dir: &str) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let context = ReloadContext {
        actor_id: "collector".to_owned(),
        tenant: "example".to_owned(),
        module: "site-collector".to_owned(),
        target: settings_file.to_owned(),
        request_id: "collector-example".to_owned(),
    };
    let (opened, shared) = open_listener_engine(PathBuf::from(settings_file), Box::new(move |entry| append(&log, entry)), context)?;
    let engine = Arc::new(opened);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(settings_file)], DEBOUNCE)?;
    let spool = open_spool(
        Path::new(spool_dir),
        SpoolConfig {
            segment_max_bytes: SEGMENT_BYTES,
            total_max_bytes: TOTAL_BYTES,
        },
    )?;
    let mut runtime = open_runtime(current_config(&engine), spool)?;
    let shutdown = AtomicBool::new(false);
    let started = Instant::now();
    let now = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let finished = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            run(&mut runtime, &engine, &shared, &shutdown, &now, &current_year);
            runtime
        });
        stdin().lock().lines().map_while(Result::ok).any(|command| command.trim() == "quit");
        shutdown.store(true, Ordering::Relaxed);
        worker.join().map_err(|_| "the receive thread panicked")
    })?;
    report(&finished)
}


fn report(runtime: &Runtime) -> Result<(), Box<dyn Error>> {
    let mut out = stdout();
    writeln!(out, "{:?}", runtime.stats)?;
    writeln!(out, "{:?}", spool_stats(&runtime.spool))?;
    read_from(&runtime.spool, 0, REPLAY_LIMIT)?
        .iter()
        .try_for_each(|record| writeln!(out, "{} {}", record.sequence, String::from_utf8_lossy(&record.payload)))?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, audit, spool] => start(settings, audit, spool),
        _ => Err(USAGE.into()),
    }
}
