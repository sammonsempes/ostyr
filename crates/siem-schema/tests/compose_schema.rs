use siem_schema::create::render_create_table;
use siem_schema::error::SchemaError;
use siem_schema::metrics::{render_metrics_ddl, MetricsRetention};
use siem_schema::schema::default_columns;
use siem_schema::traces::{render_traces_ddl, TracesRetention};
use siem_schema::ttl::TtlSettings;


const COMPOSE_SCHEMA: &str = include_str!("../../../deploy/compose/config/clickhouse-schema.sql");


const EVENTS_DAYS: u32 = 90;


const STATEMENTS: usize = 9;


#[test]
fn compose_schema_file_matches_the_renderer() -> Result<(), SchemaError> {
    let settings = TtlSettings {
        default_days: EVENTS_DAYS,
        default_move_after_days: None,
        tiers: vec![],
        storage_policy: None,
        cold_volume: None,
    };
    let events = render_create_table("events", &default_columns(), &settings)?;
    let metrics = render_metrics_ddl(&MetricsRetention::default())?;
    let traces = render_traces_ddl(&TracesRetention::default())?;
    let expected: String = std::iter::once(events)
        .chain(metrics)
        .chain(std::iter::once(traces))
        .map(|statement| {
            let guarded = statement
                .replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
                .replacen("CREATE MATERIALIZED VIEW ", "CREATE MATERIALIZED VIEW IF NOT EXISTS ", 1)
                .replacen(" AS\nSELECT", " DEFINER = schema SQL SECURITY DEFINER AS\nSELECT", 1);
            format!("{guarded};\n")
        })
        .collect();
    assert_eq!(expected, COMPOSE_SCHEMA);
    assert_eq!(STATEMENTS, COMPOSE_SCHEMA.lines().filter(|line| *line == ";").count());
    Ok(())
}
