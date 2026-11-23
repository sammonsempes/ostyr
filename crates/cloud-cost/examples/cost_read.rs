//! Usage: cost_read <clickhouse.yaml> <tenant> <from> <to> <dimension> [account]. Reads the stored daily costs back and prints one line per row.

use cloud_cost::read::{parse_day_text, parse_dimension, printable, read_daily, DailyQuery};
use cloud_cost::settings::{validate_config, CostLoadConfig};
use core_config::load::load_file;
use std::error::Error;
use std::io::{stdout, Write};


const ARGUMENT_SETTINGS: usize = 1;


const ARGUMENT_TENANT: usize = 2;


const ARGUMENT_FROM: usize = 3;


const ARGUMENT_TO: usize = 4;


const ARGUMENT_DIMENSION: usize = 5;


const ARGUMENT_ACCOUNT: usize = 6;


const USAGE: &str = "usage: cost_read <clickhouse.yaml> <tenant> <from YYYY-MM-DD> <to YYYY-MM-DD> <total|account_service|tag> [account]";


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let argument = |index: usize| arguments.get(index).ok_or(USAGE);
    let config: CostLoadConfig = load_file(argument(ARGUMENT_SETTINGS)?.as_ref())?;
    validate_config(&config)?;
    let query = DailyQuery {
        from: parse_day_text(argument(ARGUMENT_FROM)?).ok_or(USAGE)?,
        to: parse_day_text(argument(ARGUMENT_TO)?).ok_or(USAGE)?,
        dimension: parse_dimension(argument(ARGUMENT_DIMENSION)?).ok_or(USAGE)?,
        account: arguments.get(ARGUMENT_ACCOUNT).cloned(),
    };
    let rows = read_daily(&config, argument(ARGUMENT_TENANT)?, &query)?;
    let mut out = stdout();
    rows.iter().try_for_each(|row| {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.day,
            printable(&row.account),
            printable(&row.source),
            row.dimension,
            printable(&row.key1),
            printable(&row.key2),
            row.cost,
            printable(&row.currency)
        )
    })?;
    writeln!(out, "rows {}", rows.len())?;
    Ok(())
}
