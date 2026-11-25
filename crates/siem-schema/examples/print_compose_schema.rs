use siem_schema::create::render_create_table;
use siem_schema::metrics::{render_metrics_ddl, MetricsRetention};
use siem_schema::schema::default_columns;
use siem_schema::traces::{render_traces_ddl, TracesRetention};
use siem_schema::ttl::TtlSettings;
use std::io::Write;


const EVENTS_TABLE: &str = "events";


const EVENTS_DAYS: u32 = 90;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = TtlSettings {
        default_days: EVENTS_DAYS,
        default_move_after_days: None,
        tiers: vec![],
        storage_policy: None,
        cold_volume: None,
    };
    let events = render_create_table(EVENTS_TABLE, &default_columns(), &settings)?;
    let metrics = render_metrics_ddl(&MetricsRetention::default())?;
    let traces = render_traces_ddl(&TracesRetention::default())?;
    let mut stdout = std::io::stdout();
    std::iter::once(events)
        .chain(metrics)
        .chain(std::iter::once(traces))
        .map(|statement| {
            statement
                .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
                .replacen("CREATE MATERIALIZED VIEW ", "CREATE MATERIALIZED VIEW IF NOT EXISTS ", 1)
                .replacen(" AS\nSELECT", " DEFINER = schema SQL SECURITY DEFINER AS\nSELECT", 1)
        })
        .try_for_each(|statement| writeln!(stdout, "{statement};"))?;
    Ok(())
}
