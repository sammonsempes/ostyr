mod common;


use common::types::TestResult;
use hunt_packs::model::Source;
use hunt_packs::packs::load_packs;
use siem_ingest::settings::DEFAULT_CLICKHOUSE_TABLE;
use siem_schema::create::render_create_table;
use siem_schema::schema::default_columns;
use siem_schema::ttl::TtlSettings;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;


const RETENTION_DAYS: u32 = 30;


const SAMPLE_QUERIES: usize = 2;


const QUOTE_PERIOD: usize = 2;


pub fn backquoted_names(text: &str) -> BTreeSet<String> {
    text.split('`').skip(1).step_by(QUOTE_PERIOD).map(str::to_owned).collect()
}


pub fn events_ddl() -> Result<String, Box<dyn Error>> {
    let ttl = TtlSettings {
        default_days: RETENTION_DAYS,
        default_move_after_days: None,
        tiers: Vec::new(),
        storage_policy: None,
        cold_volume: None,
    };
    Ok(render_create_table(DEFAULT_CLICKHOUSE_TABLE, &default_columns(), &ttl)?)
}


pub fn unknown_names(query: &str, ddl: &str) -> Vec<String> {
    let known = backquoted_names(ddl);
    backquoted_names(query).into_iter().filter(|name| !known.contains(name)).collect()
}


pub fn sample_queries() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join("packs");
    Ok(load_packs(&samples)?
        .into_iter()
        .filter(|loaded| loaded.pack.source == Source::Clickhouse)
        .map(|loaded| (loaded.pack.id, loaded.pack.query))
        .collect())
}


#[test]
fn every_column_a_sample_pack_names_is_in_the_generated_ddl() -> TestResult {
    let ddl = events_ddl()?;
    let queries = sample_queries()?;
    assert_eq!(queries.len(), SAMPLE_QUERIES);
    queries.iter().for_each(|(id, query)| {
        assert_eq!(unknown_names(query, &ddl), Vec::<String>::new(), "pack {id}");
        assert!(
            query.contains(&format!("FROM {DEFAULT_CLICKHOUSE_TABLE} ")),
            "pack {id} reads another table"
        );
    });
    Ok(())
}


#[test]
fn an_unknown_column_is_found() -> TestResult {
    let ddl = events_ddl()?;
    assert_eq!(unknown_names("SELECT `ts`, `@timestamp` FROM events", &ddl), vec!["ts".to_string()]);
    assert!(backquoted_names("no names here").is_empty());
    Ok(())
}
