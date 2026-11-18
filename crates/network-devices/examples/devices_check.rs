use alerts::backend::{lease, MAX_CONNECTIONS};
use alerts::settings::open_pg_engine_from;
use alerts::store::{MIGRATIONS as ALERT_MIGRATIONS, MIGRATION_NAMESPACE as ALERT_NAMESPACE};
use cmdb::backend::ACTOR;
use cmdb::model::Limits;
use cmdb::pg::pg_executor;
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_config::load::load_module;
use core_pg::migrate::migrate;
use network_devices::cmdb_write::write_devices;
use network_devices::load::load_devices;
use network_devices::model::Device;
use network_devices::plan::polling_plan;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;


const USAGE: &str = "usage: devices_check <directory> [--cmdb <module.yaml>]";


const CMDB_FLAG: &str = "--cmdb";


async fn write_cmdb(module_file: &str, devices: &[Device]) -> Result<usize, Box<dyn Error>> {
    let loaded = load_module(Path::new(module_file))?;
    let (opened, _pg_file) = open_pg_engine_from(Path::new(module_file), &loaded, core_api::server::new_listener(), ACTOR)?;
    let engine = Arc::new(opened);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let held = lease(&engine, &permits).await?;
    migrate(&held.client, ALERT_NAMESPACE, &ALERT_MIGRATIONS, held.deadline).await?;
    migrate(&held.client, MIGRATION_NAMESPACE, &MIGRATIONS, held.deadline).await?;
    let executor = pg_executor(&held.client, held.deadline);
    let now_micros = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let report = write_devices(&executor, devices, &Default::default(), &Limits::default(), now_micros).await;
    let mut out = stdout();
    for (tenant, tenant_report) in &report.tenants {
        writeln!(
            out,
            "cmdb tenant {tenant}: created {} updated {} unchanged {} refused {} alerts {} failed {}",
            tenant_report.created,
            tenant_report.updated,
            tenant_report.unchanged,
            tenant_report.refused,
            tenant_report.alerts_inserted,
            tenant_report.failed.unwrap_or("no")
        )?;
        for name in &tenant_report.agent_hosts {
            writeln!(
                out,
                "warning: tenant {tenant} device {name} is declared without an agent but a CMDB host reports its address"
            )?;
        }
    }
    Ok(report.tenants.values().filter(|tenant_report| tenant_report.failed.is_some()).count())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_writer(stderr)
        .try_init()
        .map_err(|error| error.to_string())?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (directory, module) = match arguments.as_slice() {
        [directory] => Ok((directory, None)),
        [directory, flag, module] if flag == CMDB_FLAG => Ok((directory, Some(module))),
        _ => Err(USAGE),
    }?;
    let loaded = load_devices(Path::new(directory))?;
    let mut out = stdout();
    for device in &loaded.devices {
        writeln!(
            out,
            "device {} tenant {} kind {:?} addresses {:?} agent {}",
            device.name, device.tenant, device.kind, device.addresses, device.agent_managed
        )?;
    }
    for warning in &loaded.warnings {
        writeln!(out, "warning: {warning}")?;
    }
    for entry in polling_plan(&loaded.devices) {
        writeln!(
            out,
            "poll {} {} {:?} credentials {}",
            entry.tenant, entry.name, entry.version, entry.credentials
        )?;
    }
    let failed = match module {
        Some(module_file) => write_cmdb(module_file, &loaded.devices).await?,
        None => 0,
    };
    if failed == 0 {
        Ok(())
    } else {
        Err(format!("{failed} tenant(s) not fully written").into())
    }
}
