//! Live proof: `kea_history <pg.yaml> <leases.csv> <tenant> [lookup <ip> <rfc3339>]` stores the leases file in the history, or prints the intervals holding the address at that time as JSON lines.

use alerts::pg::pg_executor;
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use dhcp_kea::cursor::{MIGRATIONS, MIGRATION_NAMESPACE};
use dhcp_kea::header::parse_header;
use dhcp_kea::history::{lease_at, store_history, HistorySettings};
use dhcp_kea::row::convert_row;
use serde_json::json;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str = "usage: kea_history <pg.yaml> <leases.csv> <tenant> [lookup <ip> <rfc3339>]";


const DEADLINE: Duration = Duration::from_secs(60);


async fn scenario(settings_file: &Path, leases_file: &Path, tenant: &str, lookup: Option<(&str, &str)>) -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let scope = tenant_scope(tenant)?;
    let exec = pg_executor(&client, DEADLINE);
    match lookup {
        Some((address, at_text)) => {
            let at = OffsetDateTime::parse(at_text, &Rfc3339)?.unix_timestamp();
            let found = lease_at(&exec, &scope, address, at).await?;
            found.intervals.iter().try_for_each(|interval| {
                writeln!(
                    stdout(),
                    "{}",
                    json!({"address": interval.address, "mac": interval.mac, "hostname": interval.hostname, "starts": interval.starts,
                           "ends": interval.ends, "action": interval.action, "subnet_id": interval.subnet_id})
                )
            })?;
            writeln!(stdout(), "intervals={} truncated={}", found.intervals.len(), found.truncated)?;
        }
        None => {
            let text = std::fs::read_to_string(leases_file)?;
            let mut lines = text.lines();
            let columns = parse_header(lines.next().unwrap_or(""))?;
            let (converted, malformed): (Vec<_>, Vec<_>) = lines.map(|line| convert_row(&columns, line)).partition(Result::is_ok);
            let leases: Vec<_> = converted.into_iter().flatten().collect();
            let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
            let counts = store_history(&exec, &scope, &HistorySettings::default(), now, &leases).await?;
            writeln!(stdout(), "leases={} bad_rows={} {counts:?}", leases.len(), malformed.len())?;
        }
    }
    Ok(())
}


fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(stderr).try_init()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match args.as_slice() {
        [settings, leases, tenant] => Some((settings, leases, tenant, None)),
        [settings, leases, tenant, word, address, at] if word == "lookup" => Some((settings, leases, tenant, Some((address.as_str(), at.as_str())))),
        _ => None,
    };
    match parsed {
        Some((settings, leases, tenant, lookup)) => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), Path::new(leases), tenant, lookup)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => Ok(writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE)?),
            }
        }
        None => Ok(writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE)?),
    }
}
