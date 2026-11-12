use crate::error::CostError;
use crate::focus::{has_forbidden, is_label, parse_amount};
use crate::model::{Budget, Budgets, MonthKey, Scope};
use core_config::parse::parse_document;
use rust_decimal::Decimal;
use serde::de::{Deserializer, Error as DeserializeError};
use serde::Deserialize;
use time::Month;


pub const MAX_BUDGETS: usize = 256;


pub const MAX_THRESHOLDS: usize = 8;


pub const MAX_THRESHOLD_PERCENT: u32 = 1000;


pub const MAX_NAME_BYTES: usize = 128;


pub const MAX_CURRENCY_BYTES: usize = 16;


pub const MAX_SCOPE_BYTES: usize = 256;


pub const MAX_AMOUNT: Decimal = Decimal::from_parts(2_764_472_320, 232_830, 0, false, 0);


pub const MAX_FACTOR: Decimal = Decimal::from_parts(1_000_000, 0, 0, false, 0);


pub const MONTH_DIGITS: usize = 2;


pub fn amount_field<'de, Source: Deserializer<'de>>(source: Source) -> Result<Decimal, Source::Error> {
    let text = String::deserialize(source)?;
    parse_amount(&text).ok_or_else(|| Source::Error::custom("invalid decimal amount"))
}


pub fn short_label(text: &str, max_bytes: usize) -> bool {
    is_label(text) && text.len() <= max_bytes
}


pub fn scope_valid(scope: &Scope) -> bool {
    match scope {
        Scope::All => true,
        Scope::Account(id) => short_label(id, MAX_SCOPE_BYTES),
        Scope::Service(name) => short_label(name, MAX_SCOPE_BYTES),
        Scope::Tag(tag) => short_label(&tag.key, MAX_SCOPE_BYTES) && !has_forbidden(&tag.value) && tag.value.len() <= MAX_SCOPE_BYTES,
    }
}


pub fn thresholds_valid(thresholds: &[u32]) -> bool {
    thresholds.len() <= MAX_THRESHOLDS && thresholds.iter().all(|percent| (1..=MAX_THRESHOLD_PERCENT).contains(percent))
}


/// The first invalid field of a budget, or `None`.
pub fn budget_problem(budget: &Budget) -> Option<&'static str> {
    if !short_label(&budget.name, MAX_NAME_BYTES) {
        Some("name")
    } else if !scope_valid(&budget.scope) {
        Some("scope")
    } else if budget.monthly <= Decimal::ZERO || budget.monthly > MAX_AMOUNT {
        Some("monthly")
    } else if !short_label(&budget.currency, MAX_CURRENCY_BYTES) {
        Some("currency")
    } else if !thresholds_valid(&budget.thresholds) {
        Some("thresholds")
    } else if budget.daily_change.factor <= Decimal::ONE || budget.daily_change.factor > MAX_FACTOR {
        Some("factor")
    } else if budget.daily_change.min_amount < Decimal::ZERO || budget.daily_change.min_amount > MAX_AMOUNT {
        Some("min_amount")
    } else {
        None
    }
}


pub fn validate_budgets(budgets: &Budgets) -> Result<(), CostError> {
    if budgets.budgets.len() > MAX_BUDGETS {
        Err(CostError::TooManyBudgets { limit: MAX_BUDGETS })
    } else {
        budgets
            .budgets
            .iter()
            .enumerate()
            .try_for_each(|(index, budget)| budget_problem(budget).map_or(Ok(()), |field| Err(CostError::InvalidBudget { index, field })))
    }
}


/// Parses and validates a budget file; `file` only labels parse errors.
pub fn load_budgets(text: &str, file: &str) -> Result<Budgets, CostError> {
    let budgets: Budgets = parse_document(text, file)?;
    validate_budgets(&budgets)?;
    Ok(budgets)
}


pub fn parse_month(text: &str) -> Result<MonthKey, CostError> {
    let (year_text, month_text) = text.split_once('-').ok_or(CostError::BadMonth)?;
    let digits_only = year_text.chars().chain(month_text.chars()).all(|character| character.is_ascii_digit());
    let well_formed = month_text.len() == MONTH_DIGITS && digits_only;
    let year = year_text.parse::<i32>().map_err(|_| CostError::BadMonth)?;
    let number = month_text.parse::<u8>().map_err(|_| CostError::BadMonth)?;
    let month = Month::try_from(number).map_err(|_| CostError::BadMonth)?;
    if well_formed {
        Ok(MonthKey { year, month })
    } else {
        Err(CostError::BadMonth)
    }
}
