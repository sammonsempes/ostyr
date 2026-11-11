use crate::error::RuleError;
use crate::fetch::{agent_for, fetch_points, load_fetch_settings, read_key, FetchError};
use crate::query::{parse_tenant_id, rule_sql};
use crate::rules::load_rules;
use siem_schema::metrics::MetricsRetention;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;


pub const USAGE: &str = "usage: metric_fetch <settings.yaml> <rules.yaml> <tenant>";


#[derive(Debug, Error)]
pub enum FetchCliError {
    #[error("{USAGE}")]
    Usage,
    #[error(transparent)]
    Rule(#[from] RuleError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("the report could not be written")]
    Output(#[from] io::Error),
}


/// Runs every rule of the file for the tenant and prints `rule<TAB>ts<TAB>value` per point.
pub fn run_files(settings: &str, rules: &str, tenant: &str, now: u64, out: &mut dyn Write) -> Result<(), FetchCliError> {
    let fetch_settings = load_fetch_settings(Path::new(settings))?;
    let agent = agent_for(&fetch_settings)?;
    let password = read_key(&fetch_settings)?;
    let scope = parse_tenant_id(tenant)?;
    let remaining = Duration::from_millis(fetch_settings.timeout_ms);
    load_rules(Path::new(rules))?.rules.iter().try_for_each(|rule| {
        let query = rule_sql(rule, &scope, now, &MetricsRetention::default())?;
        fetch_points(&agent, &fetch_settings, &password, &query, remaining)?
            .iter()
            .try_for_each(|(timestamp, value)| writeln!(out, "{}\t{timestamp}\t{value}", rule.id).map_err(FetchCliError::from))
    })
}


pub fn run_cli(args: &[String], now: u64, out: &mut dyn Write) -> Result<(), FetchCliError> {
    match args {
        [settings, rules, tenant] => run_files(settings, rules, tenant, now, out),
        _ => Err(FetchCliError::Usage),
    }
}
