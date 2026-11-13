use core_audit::log::{append, open_file_log};
use core_config::reload::{current_config, ReloadContext, ReloadEngine};
use core_config::watch::watch_files;
use site_collector::forward::{forward_once, write_cursor};
use site_collector::forward_model::{ForwardLimits, ForwardReport, MAX_AGENT_SPOOL_BYTES};
use site_collector::listen::{open_runtime, receive_buffer_len, receive_cycle};
use site_collector::listen_model::{ListenerSettings, Runtime, SharedSocket, MAX_CYCLES};
use site_collector::listen_settings::open_listener_engine;
use site_collector::spool::{open_spool, read_from, spool_stats, sync_range};
use site_collector::spool_model::SpoolConfig;
use std::error::Error;
use std::io::{stdin, stdout, BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;


const DEBOUNCE: Duration = Duration::from_millis(300);


const SEGMENT_BYTES: u64 = 1 << 20;


const TOTAL_BYTES: u64 = 1 << 24;


const REPLAY_LIMIT: usize = 1_000_000;


const SECONDS_PER_YEAR: u64 = 31_556_952;


const FIRST_YEAR: i32 = 1970;


const FORWARD_INTERVAL_MS: u64 = 1000;


const USAGE: &str =
    "usage: collector <settings-file> <audit-file> <spool-dir> [agent-spool-file]; with the last one, admitted records are forwarded every second; stdin: quit (prints the counters and the spool); the settings file is watched";


fn error_chain(error: &dyn Error) -> String {
    std::iter::successors(Some(error), |current| (*current).source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}


fn current_year() -> i32 {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    FIRST_YEAR + i32::try_from(seconds / SECONDS_PER_YEAR).unwrap_or(0)
}


fn receive_and_forward(
    runtime: &mut Runtime,
    engine: &ReloadEngine<ListenerSettings>,
    shared: &SharedSocket,
    shutdown: &AtomicBool,
    agent_spool: Option<&Path>,
) {
    let started = Instant::now();
    let now = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut buffer = vec![0u8; receive_buffer_len(runtime.applied.kind)];
    let mut recv = |target: &mut [u8]| shared.bound.load().socket.recv_from(target);
    let mut last_forward = 0;
    (0..MAX_CYCLES).take_while(|_| !shutdown.load(Ordering::Relaxed)).for_each(|_| {
        receive_cycle(runtime, engine, &mut buffer, &mut recv, &now, &current_year);
        let due = now().saturating_sub(last_forward) >= FORWARD_INTERVAL_MS;
        if let (true, Some(path)) = (due, agent_spool) {
            last_forward = now();
            let limits = ForwardLimits {
                kind: runtime.applied.kind,
                max_records: current_config(engine).forward_batch_records,
                agent_spool_max_bytes: MAX_AGENT_SPOOL_BYTES,
            };
            let line = match forward_once(&mut runtime.spool, path, &limits, OffsetDateTime::now_utc(), write_cursor, sync_range) {
                Ok(report) if report == ForwardReport::default() => String::new(),
                Ok(report) => format!("forward {report:?}"),
                Err(error) => format!("forward failed: {}", error_chain(&error)),
            };
            if let Err(error) = (!line.is_empty()).then(|| writeln!(stdout(), "{line}")).transpose() {
                tracing::error!(%error, "cannot write the forward line");
            }
        }
    });
}


fn start(settings_file: &str, audit_file: &str, spool_dir: &str, agent_spool: Option<&Path>) -> Result<(), Box<dyn Error>> {
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
    let finished = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            receive_and_forward(&mut runtime, &engine, &shared, &shutdown, agent_spool);
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
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, audit, spool] => start(settings, audit, spool, None),
        [settings, audit, spool, agent_spool] => start(settings, audit, spool, Some(Path::new(agent_spool))),
        _ => Err(USAGE.into()),
    }
}
