//! Usage: cost_report <export.csv> <budgets.yaml> <YYYY-MM> [tenant]. Prints totals, skip counts and budget alerts.

use cloud_cost::budget::{load_budgets, parse_month};
use cloud_cost::evaluate::evaluate_budgets;
use cloud_cost::focus::read_focus;
use cloud_cost::model::{AlertKind, Limits};
use core_pg::scope::tenant_of;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Read, Write};


const DEFAULT_TENANT: &str = "example";


const MAX_BUDGET_FILE_BYTES: u64 = 1_048_576;


const ARGUMENT_EXPORT: usize = 1;


const ARGUMENT_BUDGETS: usize = 2;


const ARGUMENT_MONTH: usize = 3;


const ARGUMENT_TENANT: usize = 4;


const USAGE: &str = "usage: cost_report <export.csv> <budgets.yaml> <YYYY-MM> [tenant]";


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let export = arguments.get(ARGUMENT_EXPORT).ok_or(USAGE)?;
    let budgets_path = arguments.get(ARGUMENT_BUDGETS).ok_or(USAGE)?;
    let month_text = arguments.get(ARGUMENT_MONTH).ok_or(USAGE)?;
    let tenant = arguments.get(ARGUMENT_TENANT).map_or(DEFAULT_TENANT, String::as_str);
    let mut budget_text = String::new();
    File::open(budgets_path)?.take(MAX_BUDGET_FILE_BYTES).read_to_string(&mut budget_text)?;
    let budgets = load_budgets(&budget_text, budgets_path)?;
    let table = read_focus(File::open(export)?, &Limits::default(), tenant)?;
    let alerts = evaluate_budgets(&table, &budgets, &parse_month(month_text)?)?;
    let mut out = stdout();
    writeln!(out, "tenant {}", tenant_of(&table.tenant))?;
    writeln!(out, "currency {}", table.currency.as_deref().unwrap_or("none"))?;
    writeln!(out, "accepted rows {}", table.accepted)?;
    writeln!(out, "days {}", table.day_totals.len())?;
    writeln!(out, "other rows {} cost {}", table.other.count, table.other.cost)?;
    writeln!(out, "other tag pairs {} cost {}", table.tag_other.count, table.tag_other.cost)?;
    table
        .skipped
        .iter()
        .try_for_each(|(reason, count)| writeln!(out, "skipped {reason:?} {count}"))?;
    alerts.iter().try_for_each(|alert| match &alert.kind {
        AlertKind::Threshold { percent, spent, limit } => writeln!(out, "alert {} threshold {percent}% spent {spent} of {limit}", alert.budget),
        AlertKind::AbnormalDay { day, cost, median } => writeln!(out, "alert {} abnormal day {day} cost {cost} median {median}", alert.budget),
    })?;
    Ok(())
}
