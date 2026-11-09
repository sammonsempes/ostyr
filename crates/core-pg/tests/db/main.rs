mod certs;
mod connect;
mod fake;
mod migrate;
mod query;
mod types;


use core_pg::settings::{parse_settings, PgSettings};
use std::error::Error;
use std::fs;
use std::path::Path;
use tokio::sync::mpsc::UnboundedReceiver;


pub const DRAIN_LIMIT: usize = 100;


pub fn settings_for(dir: &Path, port: u16, ca_pem: &str, password: &str, connect_timeout: u64) -> Result<PgSettings, Box<dyn Error>> {
    let password_file = dir.join("pg.pass");
    let ca_file = dir.join("ca.pem");
    fs::write(&password_file, password)?;
    fs::write(&ca_file, ca_pem)?;
    let text = format!(
        "host: 127.0.0.1\nport: {port}\ndatabase: ostyr\nuser: ostyr\npassword_file: {}\nca_file: {}\nconnect_timeout_secs: {connect_timeout}\n",
        password_file.display(),
        ca_file.display()
    );
    Ok(parse_settings(&text, "pg.yaml")?)
}


pub fn drain(receiver: &mut UnboundedReceiver<String>) -> Vec<String> {
    std::iter::repeat_with(|| receiver.try_recv())
        .take(DRAIN_LIMIT)
        .take_while(Result::is_ok)
        .flatten()
        .collect()
}
