//! Usage: `backup_indicators <pg.yaml> <declarations.yaml> <tenant> [now-unix-seconds]` (Unix only); prints the GRC indicator file (a JSON array) on stdout.

#[cfg(unix)]
mod run {
    use backup_monitor::declarations::load_declarations;
    use backup_monitor::indicator::{indicator_json, restore_indicator};
    use backup_monitor::types::RowFuture;
    use core_config::parse::read_file;
    use core_pg::connect::connect;
    use core_pg::error::PgError;
    use core_pg::query::{column_text, scoped_query};
    use core_pg::scope::TenantScope;
    use core_pg::settings::load_settings;
    use core_pg::types::SqlParameter;
    use std::error::Error;
    use std::io::{stdout, Write};
    use std::path::Path;
    use std::time::Duration;
    use time::OffsetDateTime;
    use tokio_postgres::Client;


    const ARGUMENT_PG: usize = 1;


    const ARGUMENT_DECLARATIONS: usize = 2;


    const ARGUMENT_TENANT: usize = 3;


    const ARGUMENT_NOW: usize = 4;


    const STORE_DEADLINE_SECONDS: u64 = 30;


    const USAGE: &str = "usage: backup_indicators <pg.yaml> <declarations.yaml> <tenant> [now-unix-seconds]";


    async fn pg_rows(client: &Client, scope: TenantScope, sql: &'static str, params: Vec<String>) -> Result<Vec<Vec<String>>, PgError> {
        let bound: Vec<SqlParameter<'_>> = params.iter().map(|param| param as SqlParameter<'_>).collect();
        let rows = scoped_query(client, &scope, sql, &bound, Duration::from_secs(STORE_DEADLINE_SECONDS)).await?;
        rows.iter()
            .map(|row| (0..row.len()).map(|index| column_text(row, index)).collect())
            .collect()
    }


    pub fn execute() -> Result<(), Box<dyn Error>> {
        let arguments: Vec<String> = std::env::args().collect();
        let pg_path = arguments.get(ARGUMENT_PG).ok_or(USAGE)?;
        let declarations_path = arguments.get(ARGUMENT_DECLARATIONS).ok_or(USAGE)?;
        let tenant = arguments.get(ARGUMENT_TENANT).ok_or(USAGE)?;
        let now = match arguments.get(ARGUMENT_NOW) {
            Some(text) => OffsetDateTime::from_unix_timestamp(text.parse()?)?,
            None => OffsetDateTime::now_utc(),
        };
        let text = read_file(Path::new(declarations_path))?;
        let declarations = load_declarations(&text, declarations_path)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let row = runtime.block_on(async {
            let client = connect(&load_settings(Path::new(pg_path))?).await?;
            let exec =
                |scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'_> { Box::pin(pg_rows(&client, scope, sql, params)) };
            Ok::<_, Box<dyn Error>>(restore_indicator(&exec, &declarations, tenant, now).await?)
        })?;
        writeln!(stdout(), "{}", indicator_json(row.as_ref()))?;
        Ok(())
    }
}


#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run::execute()
}


#[cfg(not(unix))]
fn main() {}
