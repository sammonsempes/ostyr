use alerts::pg::pg_executor;
use alerts::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::scope::tenant_scope;
use core_pg::settings::parse_settings;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use synthetic_checks::alerting::{outage_alerts, store_outage_alerts, Outage};
use synthetic_checks::model::CheckKind;


const USAGE: &str = "usage: outage_store <pg.yaml> <tenant-a> <tenant-b>";


const DEADLINE: Duration = Duration::from_secs(30);


const SINCE: u64 = 1_700_000_000;


const INJECTION: &str = "'); DROP TABLE alerts; --";


const MANY_LOCATIONS: usize = 1000;


fn outage(tenant: &str, check: &str, since: u64) -> Outage {
    Outage {
        tenant: tenant.to_owned(),
        check: check.to_owned(),
        kind: CheckKind::Http,
        failing_locations: (0..MANY_LOCATIONS).map(|index| format!("loc{index}")).collect(),
        since,
    }
}


async fn scenario(settings_file: &Path, tenant_a: &str, tenant_b: &str) -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(&std::fs::read_to_string(settings_file)?, &settings_file.display().to_string())?;
    let client = connect(&settings).await?;
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, DEADLINE).await?;
    let exec = pg_executor(&client, DEADLINE);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut out = stdout();
    let scope_a = tenant_scope(tenant_a)?;
    let scope_b = tenant_scope(tenant_b)?;
    let checks = ["web", "a\nb", "-rf", INJECTION];
    for (tenant, scope) in [(tenant_a, &scope_a), (tenant_b, &scope_b)] {
        let outages: Vec<Outage> = checks.iter().map(|check| outage(tenant, check, SINCE)).collect();
        let alerts = outage_alerts(scope, &outages, now);
        let first = store_outage_alerts(&exec, scope, &alerts).await?;
        let rerun = store_outage_alerts(&exec, scope, &outage_alerts(scope, &outages, now + 1)).await?;
        writeln!(out, "tenant {tenant}: alerts {} inserted {first} rerun {rerun}", alerts.len())?;
    }
    let foreign = outage_alerts(&scope_a, &[outage(tenant_b, "foreign-check", SINCE)], now);
    let stored = store_outage_alerts(&exec, &scope_a, &foreign).await?;
    writeln!(
        out,
        "outage of {tenant_b} under scope {tenant_a}: alerts {} stored {stored}",
        foreign.len()
    )?;
    let forced = outage_alerts(&scope_b, &[outage(tenant_b, "forced-check", SINCE)], now);
    let refused = store_outage_alerts(&exec, &scope_a, &forced).await;
    writeln!(out, "alert of {tenant_b} stored under scope {tenant_a}: {refused:?}")?;
    let huge = outage_alerts(&scope_a, &[outage(tenant_a, "huge-since", u64::MAX)], now);
    writeln!(out, "since u64::MAX: alerts {}", huge.len())?;
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (settings, tenant_a, tenant_b) = match arguments.as_slice() {
        [settings, tenant_a, tenant_b] => Ok((settings, tenant_a, tenant_b)),
        _ => Err(USAGE),
    }?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(scenario(Path::new(settings), tenant_a, tenant_b))
}
