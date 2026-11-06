use core_audit::log::{append, open_file_log};
use core_config::reload::ReloadContext;
use core_config::watch::watch_files;
use std::error::Error;
use std::io::{stdin, stdout};
use std::path::{Path, PathBuf};
use std::time::Duration;
use stream_correlation::cli::{run_stream, start_engine, CHECKPOINT_EVERY};


const DEBOUNCE: Duration = Duration::from_millis(300);


#[cfg(unix)]
fn keep_signals(engine: std::sync::Arc<core_config::reload::ReloadEngine<stream_correlation::ruleset::RuleSet>>) -> std::io::Result<impl Sized> {
    core_config::signal::reload_on_signals(engine, &[signal_hook::consts::SIGHUP])
}


#[cfg(not(unix))]
fn keep_signals(_engine: std::sync::Arc<core_config::reload::ReloadEngine<stream_correlation::ruleset::RuleSet>>) -> std::io::Result<impl Sized> {
    Ok(())
}


fn start(mapping_file: &str, checkpoint: &str, audit_file: &str, rule_files: &[String]) -> Result<(), Box<dyn Error>> {
    let log = open_file_log(Path::new(audit_file))?;
    let context = ReloadContext {
        actor_id: "correlate".to_owned(),
        tenant: "example".to_owned(),
        module: "stream-correlation".to_owned(),
        target: mapping_file.to_owned(),
        request_id: "correlate-reload".to_owned(),
    };
    let rule_paths: Vec<PathBuf> = rule_files.iter().map(PathBuf::from).collect();
    let engine = start_engine(
        PathBuf::from(mapping_file),
        rule_paths.clone(),
        Path::new(checkpoint),
        Box::new(move |entry| append(&log, entry)),
        context,
    )?;
    let watched: Vec<PathBuf> = rule_paths.into_iter().chain([PathBuf::from(mapping_file)]).collect();
    let _watcher = watch_files(std::sync::Arc::clone(&engine.rules), &watched, DEBOUNCE)?;
    let _signals = keep_signals(std::sync::Arc::clone(&engine.rules))?;
    run_stream(&engine, &mut stdin().lock(), &mut stdout(), Path::new(checkpoint), CHECKPOINT_EVERY)?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mapping_file, checkpoint, audit_file, rule_files @ ..] if !rule_files.is_empty() => start(mapping_file, checkpoint, audit_file, rule_files),
        _ => Err("usage: correlate <mapping.yaml> <checkpoint> <audit-file> <rule-file>...".into()),
    }
}
