//! Lab tool. `deadline_probe <pg.yaml>`: a second connection holds a row lock, releases it just after the client deadline, and the first runs the write.

use core_pg::connect::connect;
use core_pg::query::global_query;
use core_pg::settings::load_settings;
use std::io::{stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;


const USAGE: &str = "usage: deadline_probe <pg.yaml>";


const DEADLINE: Duration = Duration::from_secs(2);


const RELEASE_AFTER_DEADLINE: Duration = Duration::from_millis(100);


const PREPARE: &str = "DROP TABLE IF EXISTS probe_t; CREATE TABLE probe_t (id int PRIMARY KEY, v text); INSERT INTO probe_t VALUES (1, 'old')";


const WRITE: &str = "UPDATE probe_t SET v = 'done' WHERE id = 1 RETURNING id::text";


async fn run_command(arguments: &[String]) -> Result<String, String> {
    let settings = load_settings(Path::new(arguments.get(1).ok_or(USAGE)?)).map_err(|error| error.to_string())?;
    let holder = connect(&settings).await.map_err(|error| error.to_string())?;
    let writer = connect(&settings).await.map_err(|error| error.to_string())?;
    holder.batch_execute(PREPARE).await.map_err(|error| error.to_string())?;
    holder
        .batch_execute("BEGIN; SELECT 1 FROM probe_t WHERE id = 1 FOR UPDATE")
        .await
        .map_err(|error| error.to_string())?;
    let release = async {
        tokio::time::sleep(DEADLINE + RELEASE_AFTER_DEADLINE).await;
        holder.batch_execute("COMMIT").await.map_err(|error| error.to_string())
    };
    let write = async {
        let start = std::time::Instant::now();
        let outcome = global_query(&writer, WRITE, DEADLINE).await;
        (outcome, start.elapsed().as_millis())
    };
    let ((written, elapsed), released) = tokio::join!(write, release);
    released?;
    Ok(format!("{:?} after {elapsed} ms", written.map(|rows| rows.len())))
}


fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
    let outcome = runtime
        .map_err(|error| error.to_string())
        .and_then(|built| built.block_on(run_command(&arguments)));
    let line = outcome.unwrap_or_else(|error| format!("error: {error}"));
    let written = writeln!(stdout(), "{line}");
    ExitCode::from(u8::from(written.is_err()))
}
