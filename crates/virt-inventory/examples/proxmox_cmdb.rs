//! Usage: `proxmox_cmdb <fetch-settings.yaml> <pg-settings.yaml>`. Fetches the Proxmox inventory (read-only token check first) and syncs it into the tenant's CMDB.
use cmdb::model::Limits;
use cmdb::pg::pg_executor;
use cmdb::store::{MIGRATIONS, MIGRATION_NAMESPACE};
use core_pg::connect::connect;
use core_pg::migrate::migrate;
use core_pg::settings::load_settings as load_pg_settings;
use std::error::Error;
use std::io::{stderr, stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use virt_inventory::cmdb_sync::sync;
use virt_inventory::fetch::fetch_inventory;
use virt_inventory::inventory::{inventory_items, inventory_skipped};
use virt_inventory::model::Parsed;
use virt_inventory::settings::load_settings;


const PG_ARGUMENT: usize = 1;


const STATEMENT_DEADLINE_SECONDS: u64 = 30;


const USAGE: &str = "usage: proxmox_cmdb <fetch-settings.yaml> <pg-settings.yaml>";


async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let fetch_file = arguments.first().ok_or(USAGE)?;
    let pg_file = arguments.get(PG_ARGUMENT).ok_or(USAGE)?;
    let settings = load_settings(Path::new(fetch_file))?;
    let inventory = fetch_inventory(&settings)?;
    let parsed = Parsed {
        items: inventory_items(&inventory).to_vec(),
        skipped: inventory_skipped(&inventory).clone(),
    };
    let client = connect(&load_pg_settings(Path::new(pg_file))?).await?;
    let deadline = Duration::from_secs(STATEMENT_DEADLINE_SECONDS);
    migrate(&client, MIGRATION_NAMESPACE, &MIGRATIONS, deadline).await?;
    let executor = pg_executor(&client, deadline);
    let report = sync(&executor, &settings, &parsed, &Default::default(), &Limits::default()).await?;
    writeln!(stdout(), "{report:?}")?;
    Ok(())
}


#[tokio::main]
async fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments).await {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(error) => writeln!(stderr(), "refused: {error}").map(|()| ExitCode::FAILURE),
    }
}
