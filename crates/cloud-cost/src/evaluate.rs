use crate::budget::validate_budgets;
use crate::error::CostError;
use crate::focus::add_cost;
use crate::model::{AlertKind, Budget, Budgets, CostAlert, CostTable, MonthKey, Scope};
use crate::types::{CostKey, CostMap, DayMap};
use rust_decimal::Decimal;
use time::{Date, Duration};


pub const PREVIOUS_DAYS: i64 = 7;


pub const MEDIAN_INDEX: usize = 3;


pub const PERCENT: Decimal = Decimal::from_parts(100, 0, 0, false, 0);


pub fn in_month(day: Date, month: &MonthKey) -> bool {
    day.year() == month.year && day.month() == month.month
}


pub fn matches_scope(key: &CostKey, scope: &Scope) -> bool {
    match scope {
        Scope::All => true,
        Scope::Account(id) => key.1 == *id,
        Scope::Service(name) => key.2 == *name,
        Scope::Tag(tag) => key.1 == tag.key && key.2 == tag.value,
    }
}


pub fn sum_matching(map: &CostMap, scope: &Scope) -> Result<DayMap, CostError> {
    map.iter()
        .filter(|(key, _)| matches_scope(key, scope))
        .try_fold(DayMap::new(), |mut series, (key, amount)| {
            add_cost(series.entry(key.0).or_insert(Decimal::ZERO), *amount)?;
            Ok(series)
        })
}


/// Daily cost of one budget scope; the `other` buckets are not part of an account, service or tag series.
pub fn daily_series(table: &CostTable, scope: &Scope) -> Result<DayMap, CostError> {
    match scope {
        Scope::All => Ok(table.day_totals.clone()),
        Scope::Tag(_) => sum_matching(&table.by_tag, scope),
        Scope::Account(_) | Scope::Service(_) => sum_matching(&table.by_account_service, scope),
    }
}


pub fn month_to_date(series: &DayMap, month: &MonthKey) -> Result<Decimal, CostError> {
    series
        .iter()
        .filter(|(day, _)| in_month(**day, month))
        .try_fold(Decimal::ZERO, |mut spent, (_, amount)| {
            add_cost(&mut spent, *amount)?;
            Ok(spent)
        })
}


pub fn threshold_alerts(table: &CostTable, budget: &Budget, series: &DayMap, month: &MonthKey) -> Result<Vec<CostAlert>, CostError> {
    let spent = month_to_date(series, month)?;
    Ok(budget
        .thresholds
        .iter()
        .map(|percent| (*percent, budget.monthly * Decimal::from(*percent) / PERCENT))
        .filter(|(_, limit)| spent >= *limit)
        .map(|(percent, limit)| CostAlert {
            tenant: table.tenant.clone(),
            budget: budget.name.clone(),
            kind: AlertKind::Threshold { percent, spent, limit },
        })
        .collect())
}


/// Median of the seven calendar days before `day`; `None` unless all seven are present.
pub fn previous_median(series: &DayMap, day: Date) -> Option<Decimal> {
    let previous = (1..=PREVIOUS_DAYS)
        .map(|offset| day.checked_sub(Duration::days(offset)).and_then(|earlier| series.get(&earlier).copied()))
        .collect::<Option<Vec<Decimal>>>();
    previous.and_then(|mut values| {
        values.sort();
        values.get(MEDIAN_INDEX).copied()
    })
}


pub fn is_abnormal(cost: Decimal, median: Decimal, budget: &Budget) -> bool {
    let change = &budget.daily_change;
    cost > change.min_amount && median.checked_mul(change.factor).is_some_and(|limit| cost > limit)
}


pub fn abnormal_alerts(table: &CostTable, budget: &Budget, series: &DayMap, month: &MonthKey) -> Vec<CostAlert> {
    series
        .iter()
        .filter(|(day, _)| in_month(**day, month))
        .filter_map(|(day, cost)| {
            previous_median(series, *day)
                .filter(|median| is_abnormal(*cost, *median, budget))
                .map(|median| CostAlert {
                    tenant: table.tenant.clone(),
                    budget: budget.name.clone(),
                    kind: AlertKind::AbnormalDay {
                        day: *day,
                        cost: *cost,
                        median,
                    },
                })
        })
        .collect()
}


pub fn evaluate_budget(table: &CostTable, budget: &Budget, month: &MonthKey) -> Result<Vec<CostAlert>, CostError> {
    if table.currency.as_ref().is_some_and(|currency| *currency != budget.currency) {
        Err(CostError::CurrencyMismatch { budget: budget.name.clone() })
    } else {
        let series = daily_series(table, &budget.scope)?;
        let mut alerts = threshold_alerts(table, budget, &series, month)?;
        alerts.extend(abnormal_alerts(table, budget, &series, month));
        Ok(alerts)
    }
}


/// Thresholds of the month to date and abnormal days; a currency mismatch is an error naming the budget.
pub fn evaluate_budgets(table: &CostTable, budgets: &Budgets, month: &MonthKey) -> Result<Vec<CostAlert>, CostError> {
    validate_budgets(budgets)?;
    budgets.budgets.iter().try_fold(Vec::new(), |mut alerts, budget| {
        alerts.extend(evaluate_budget(table, budget, month)?);
        Ok(alerts)
    })
}
