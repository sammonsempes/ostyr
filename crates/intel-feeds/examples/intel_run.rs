use core_audit::log::{append, open_file_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_config::watch::watch_files;
use intel_feeds::cli::{run_session, Session};
use intel_feeds::config::{open_feeds, FeedsFile};
use intel_feeds::load::load_iocs;
use intel_feeds::run::open_file;
use std::error::Error;
use std::io::{self, stderr, stdin, stdout};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const DEBOUNCE: Duration = Duration::from_millis(300);


#[cfg(unix)]
fn keep_signals(engine: Arc<ReloadEngine<FeedsFile>>) -> io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_engine: Arc<ReloadEngine<FeedsFile>>) -> io::Result<impl Sized> {
    Ok(())
}


fn start(feeds_file: &str, audit_file: &str, fixed_now: Option<&String>) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let context = ReloadContext {
        actor_id: "intel_run".to_owned(),
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
    let _signals = keep_signals(Arc::clone(&engine))?;
    let base = PathBuf::from(feeds_file).parent().map(Path::to_path_buf).unwrap_or_else(PathBuf::new);
    let fixed = fixed_now.map(|text| OffsetDateTime::parse(text, &Rfc3339)).transpose()?;
    let clock = move || fixed.unwrap_or_else(OffsetDateTime::now_utc);
    let open = move |path: &Path| open_file(&base.join(path));
    let load = |config: &_, iocs: &_, feeds: &_, now| {
        let started = Instant::now();
        load_iocs(config, iocs, feeds, now, &|| started.elapsed())
    };
    let mut out = stdout();
    let mut report = stderr();
    let mut session = Session {
        engine: &engine,
        clock: &clock,
        open: &open,
        load: &load,
        out: &mut out,
        report: &mut report,
    };
    run_session(&mut session, &mut stdin().lock())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [feeds_file, audit_file] => start(feeds_file, audit_file, None),
        [feeds_file, audit_file, fixed_now] => start(feeds_file, audit_file, Some(fixed_now)),
        _ => Err("usage: intel_run <feeds-file> <audit-file> [fixed-now-rfc3339]; commands on stdin: run, reload, feeds, quit".into()),
    }
}
