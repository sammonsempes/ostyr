use alerts::pg::pg_executor;
use alerts::store::{insert_alerts, MIGRATIONS, MIGRATION_NAMESPACE};
use core_audit::log::{append, open_file_log};
use core_config::reload::{current_config, ReloadContext};
use core_config::watch::watch_files;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::settings::parse_settings;
use intel_feeds::config::open_feeds;
use intel_feeds::retro::run_retro;
use intel_feeds::retro_schedule::{run_schedule, Hooks, RoundOutcome};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;


const USAGE: &str = "usage: retro_schedule <feeds-file> <audit-file> <max-passes>";


const DEBOUNCE: Duration = Duration::from_millis(300);


const DEADLINE: Duration = Duration::from_secs(30);


fn chain<'a>(error: &'a (dyn Error + 'a)) -> String {
    std::iter::successors(Some(error), |current| (*current).source())
        .map(ToString::to_string)
        .collect::<Vec<String>>()
        .join(": ")
}


fn show(outcome: &RoundOutcome) {
    let line = match outcome {
        RoundOutcome::Done { summary, report } => format!(
            "done groups={} not_an_ip={} truncated={} gap={} built={} refused={} inserted={} known={}",
            summary.groups,
            summary.not_an_ip,
            summary.truncated,
            summary.gap.is_some(),
            report.built,
            report.refused,
            report.inserted,
            report.known
        ),
        RoundOutcome::Failed(failure) => format!("failed {}", chain(failure)),
    };
    if let Err(error) = writeln!(stdout(), "{line}") {
        tracing::error!(%error, "stdout closed");
    }
}


fn start(feeds_file: &str, audit_file: &str, max_passes: u64) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let context = ReloadContext {
        actor_id: "retro_schedule".to_owned(),
        tenant: "example".to_owned(),
        module: "intel-feeds".to_owned(),
        target: feeds_file.to_owned(),
        request_id: "intel-feeds-reload".to_owned(),
    };
    let engine = Arc::new(open_feeds(
        PathBuf::from(feeds_file),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(feeds_file)], DEBOUNCE)?;
    let pg_file = current_config(&engine)
        .retro
        .as_ref()
        .ok_or("the feeds file has no retro section")?
        .pg_settings
        .clone();
    let pg_settings = parse_settings(&std::fs::read_to_string(&pg_file)?, &pg_file.display().to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let client = runtime.block_on(connect(&pg_settings))?;
    runtime.block_on(migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE))?;
    let exec = pg_executor(&client, DEADLINE);
    let snapshot = || Some(current_config(&engine));
    let clock = OffsetDateTime::now_utc;
    let wait = std::thread::sleep;
    let stop = || false;
    let run = |settings: &_, start, end, previous| {
        let started = Instant::now();
        run_retro(settings, start, end, previous, &|| started.elapsed())
    };
    let insert = |scope: &_, batch: &_| runtime.block_on(insert_alerts(&exec, scope, batch));
    let hooks = Hooks {
        snapshot: &snapshot,
        clock: &clock,
        wait: &wait,
        stop: &stop,
        run: &run,
        insert: &insert,
    };
    run_schedule(&hooks, max_passes, &mut show);
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [feeds_file, audit_file, passes] => start(feeds_file, audit_file, passes.parse()?),
        _ => Err(USAGE.into()),
    }
}
