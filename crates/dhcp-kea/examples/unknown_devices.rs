//! Live proof: `unknown_devices <pg.yaml> <leases.csv> <known.txt> <tenant>` stores one alert per unknown MAC of the leases file.

use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use dhcp_kea::alerting::{alerted_macs, candidate_macs, store_unknown_device_alerts, unknown_device_alerts};
use dhcp_kea::header::parse_header;
use dhcp_kea::row::convert_row;
use std::collections::BTreeSet;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


const USAGE: &str = "usage: unknown_devices <pg.yaml> <leases.csv> <known.txt> <tenant>";


const DEADLINE: Duration = Duration::from_secs(30);


async fn scenario(settings_file: &Path, leases_file: &Path, known_file: &Path, tenant: &str) -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let text = std::fs::read_to_string(leases_file)?;
    let mut lines = text.lines();
    let columns = parse_header(lines.next().unwrap_or(""))?;
    let (converted, malformed): (Vec<_>, Vec<_>) = lines.map(|line| convert_row(&columns, line)).partition(Result::is_ok);
    let leases: Vec<_> = converted.into_iter().flatten().collect();
    let bad_rows = malformed.len();
    let known: BTreeSet<String> = std::fs::read_to_string(known_file)?.lines().map(str::to_owned).collect();
    let scope = tenant_scope(tenant)?;
    let exec = pg_executor(&client, DEADLINE);
    let alerted = alerted_macs(&exec, &scope, &candidate_macs(&leases, &known)).await;
    let skipped = alerted.len();
    let known_or_alerted: BTreeSet<String> = known.union(&alerted).cloned().collect();
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let (alerts, rejected) = unknown_device_alerts(&scope, &leases, &known_or_alerted, now);
    let inserted = store_unknown_device_alerts(&exec, &scope, &alerts).await?;
    writeln!(
        stdout(),
        "leases={} bad_rows={bad_rows} already_alerted={skipped} alerts={} inserted={inserted} no_mac={} bad_known={}",
        leases.len(),
        alerts.len(),
        rejected.no_mac,
        rejected.bad_known
    )?;
    Ok(())
}


fn main() -> Result<ExitCode, Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt().with_writer(stderr).try_init()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [settings, leases, known, tenant] => {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            match runtime.block_on(scenario(Path::new(settings), Path::new(leases), Path::new(known), tenant)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => Ok(writeln!(stderr(), "{error}").map(|()| ExitCode::FAILURE)?),
            }
        }
        _ => Ok(writeln!(stderr(), "{USAGE}").map(|()| ExitCode::FAILURE)?),
    }
}
