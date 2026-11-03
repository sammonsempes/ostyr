use core_audit::log::{append, open_file_log};
use core_config::reload::{ReloadContext, ReloadEngine};
use core_config::watch::watch_files;
use dns_rpz::cli::{run_session, Session};
use dns_rpz::policy::{open_policy, Policy};
use dns_rpz::run::open_file;
use std::error::Error;
use std::io::{self, stderr, stdin};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const DEBOUNCE: Duration = Duration::from_millis(300);


const USAGE: &str = "usage: rpz_run <policy> <audit> <iocs> <counter> <zone> [fixed-now-rfc3339]; stdin commands: run, reload, quit";


#[cfg(unix)]
fn keep_signals(engine: Arc<ReloadEngine<Policy>>) -> io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_engine: Arc<ReloadEngine<Policy>>) -> io::Result<impl Sized> {
    Ok(())
}


struct Arguments<'a> {
    policy_file: &'a str,
    audit_file: &'a str,
    ioc_file: &'a str,
    counter_file: &'a str,
    zone_file: &'a str,
    fixed_now: Option<&'a String>,
}


fn start(arguments: &Arguments) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(arguments.audit_file))?;
    let context = ReloadContext {
        actor_id: "rpz_run".to_owned(),
        tenant: "example".to_owned(),
        module: "dns-rpz".to_owned(),
        target: arguments.policy_file.to_owned(),
        request_id: "dns-rpz-reload".to_owned(),
    };
    let engine = Arc::new(open_policy(
        PathBuf::from(arguments.policy_file),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?);
    let _watcher = watch_files(Arc::clone(&engine), &[PathBuf::from(arguments.policy_file)], DEBOUNCE)?;
    let _signals = keep_signals(Arc::clone(&engine))?;
    let fixed = arguments.fixed_now.map(|text| OffsetDateTime::parse(text, &Rfc3339)).transpose()?;
    let clock = move || fixed.unwrap_or_else(OffsetDateTime::now_utc);
    let ioc_path = PathBuf::from(arguments.ioc_file);
    let open = move || open_file(&ioc_path);
    let mut report = stderr();
    let mut session = Session {
        engine: &engine,
        clock: &clock,
        open: &open,
        counter: Path::new(arguments.counter_file),
        output: Path::new(arguments.zone_file),
        report: &mut report,
    };
    run_session(&mut session, &mut stdin().lock())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [policy_file, audit_file, ioc_file, counter_file, zone_file] => start(&Arguments {
            policy_file,
            audit_file,
            ioc_file,
            counter_file,
            zone_file,
            fixed_now: None,
        }),
        [policy_file, audit_file, ioc_file, counter_file, zone_file, fixed_now] => start(&Arguments {
            policy_file,
            audit_file,
            ioc_file,
            counter_file,
            zone_file,
            fixed_now: Some(fixed_now),
        }),
        _ => Err(USAGE.into()),
    }
}
