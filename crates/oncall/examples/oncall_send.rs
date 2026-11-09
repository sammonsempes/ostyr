use core_audit::log::{append, genesis_log};
use core_config::reload::ReloadContext;
use oncall::channel::load_channel;
use oncall::model::AlertNotice;
use oncall::notify::notify;
use oncall::settings::open_settings_engine;
use oncall::transport::https_sender;
use std::collections::BTreeMap;
use std::io::{sink, stderr, Write};
use std::path::Path;
use std::process::ExitCode;


const USAGE: &str = "usage: oncall_send <settings.yaml> <channel.yaml>";


fn run(settings: &Path, channel_file: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let log = genesis_log(sink());
    let context = ReloadContext {
        actor_id: "example".to_string(),
        tenant: "acme".to_string(),
        module: "oncall".to_string(),
        target: settings.display().to_string(),
        request_id: "example".to_string(),
    };
    let engine = open_settings_engine(settings, Box::new(move |entry| append(&log, entry)), context)?;
    let channel = load_channel(channel_file)?;
    let alert = AlertNotice {
        tenant: channel.tenant.clone(),
        name: "lab proof".to_string(),
        labels: BTreeMap::from([("host".to_string(), "lab-1".to_string())]),
        annotations: BTreeMap::new(),
    };
    let mut sender = https_sender(&engine);
    Ok(notify(&alert, &[channel], &mut sender)?.len())
}


fn main() -> std::io::Result<ExitCode> {
    tracing_subscriber::fmt().with_writer(stderr).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, channel] => match run(Path::new(settings), Path::new(channel)) {
            Ok(0) => Ok(ExitCode::SUCCESS),
            Ok(count) => writeln!(stderr(), "{count} channel(s) failed").map(|()| ExitCode::FAILURE),
            Err(error) => writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE),
        },
        _ => writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE),
    }
}
