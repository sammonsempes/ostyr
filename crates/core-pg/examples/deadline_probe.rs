//! Lab tool. `deadline_probe <pg.yaml> <two-phase|held>`: locks held by other connections while the first runs a write with a deadline.

use core_pg::connect::connect;
use core_pg::query::global_query;
use core_pg::settings::load_settings;
use std::io::{stdout, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio_postgres::Client;


const USAGE: &str = "usage: deadline_probe <pg.yaml> <two-phase|held>";


const TWO_PHASE_DEADLINE: Duration = Duration::from_secs(8);


const TABLE_LOCK_RELEASE: Duration = Duration::from_millis(7500);


const MODE_ARGUMENT: usize = 2;


const QUEUE_DELAY: Duration = Duration::from_millis(200);


const ROW_LOCK_HOLD: Duration = Duration::from_millis(7500);


const HELD_DEADLINE: Duration = Duration::from_secs(4);


const HELD_RELEASE: Duration = Duration::from_secs(12);


const PREPARE: &str = "DROP TABLE IF EXISTS probe_t; CREATE TABLE probe_t (id int PRIMARY KEY, v text); INSERT INTO probe_t VALUES (1, 'old')";


const WRITE: &str = "UPDATE probe_t SET v = 'done' WHERE id = 1 RETURNING id::text";


const TABLE_LOCK: &str = "BEGIN; LOCK TABLE probe_t IN ACCESS EXCLUSIVE MODE";


const ROW_LOCK: &str = "BEGIN; SELECT 1 FROM probe_t WHERE id = 1 FOR UPDATE";


async fn release_after(holder: &Client, wait: Duration) -> Result<(), String> {
    tokio::time::sleep(wait).await;
    holder.batch_execute("COMMIT").await.map_err(|error| error.to_string())
}


async fn queue_row_lock(holder: &Client) -> Result<(), String> {
    holder.batch_execute(ROW_LOCK).await.map_err(|error| error.to_string())?;
    release_after(holder, ROW_LOCK_HOLD).await
}


async fn run_command(arguments: &[String]) -> Result<String, String> {
    let settings = load_settings(Path::new(arguments.get(1).ok_or(USAGE)?)).map_err(|error| error.to_string())?;
    let held = arguments.get(MODE_ARGUMENT).ok_or(USAGE)?.as_str() == "held";
    let first = connect(&settings).await.map_err(|error| error.to_string())?;
    let second = connect(&settings).await.map_err(|error| error.to_string())?;
    let writer = connect(&settings).await.map_err(|error| error.to_string())?;
    first.batch_execute(PREPARE).await.map_err(|error| error.to_string())?;
    let deadline = if held { HELD_DEADLINE } else { TWO_PHASE_DEADLINE };
    first
        .batch_execute(if held { ROW_LOCK } else { TABLE_LOCK })
        .await
        .map_err(|error| error.to_string())?;
    let write = async {
        let start = std::time::Instant::now();
        let outcome = global_query(&writer, WRITE, deadline).await;
        (outcome, start.elapsed().as_millis())
    };
    let first_release = release_after(&first, if held { HELD_RELEASE } else { TABLE_LOCK_RELEASE });
    let second_lock = async {
        if held {
            Ok(())
        } else {
            tokio::time::sleep(QUEUE_DELAY).await;
            queue_row_lock(&second).await
        }
    };
    let ((written, elapsed), released_first, released_second) = tokio::join!(write, first_release, second_lock);
    released_first?;
    released_second?;
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
