use cloud_cost::budget::{
    amount_field, budget_problem, load_budgets, parse_month, validate_budgets, MAX_AMOUNT, MAX_BUDGETS, MAX_FACTOR, MAX_NAME_BYTES, MAX_SCOPE_BYTES,
    MAX_THRESHOLDS, MAX_THRESHOLD_PERCENT,
};
use cloud_cost::error::CostError;
use cloud_cost::evaluate::{evaluate_budgets, matches_scope};
use cloud_cost::focus::read_focus;
use cloud_cost::model::{AlertKind, Budget, Budgets, CostAlert, CostTable, DailyChange, Limits, MonthKey, Scope, TagScope};
use core_pg::scope::tenant_of;
use rust_decimal::Decimal;
use serde::de::value::{Error as ValueError, StrDeserializer};
use serde::de::IntoDeserializer;
use std::error::Error;
use std::str::FromStr;
use time::{Date, Duration, Month};


const TENANT: &str = "acme";


const YEAR: i32 = 2026;


const WEEK: usize = 7;


const SIX_DAYS: usize = 6;


const HALF: u32 = 50;


const MOST: u32 = 80;


const FULL: u32 = 100;


const BUDGET_FILE_COUNT: usize = 4;


const THREE_ALERTS: usize = 3;


const DECIMAL_MAX: &str = "79228162514264337593543950335";


const DECIMAL_MIN: &str = "-79228162514264337593543950335";


const FIRST_OF_OCTOBER_WEEK: u8 = 25;


const EIGHTH_DAY: u8 = 8;


const FIRST_BUDGET_INDEX: usize = 0;


const SECOND_BUDGET_INDEX: usize = 1;


const FLAT_WEEK: [&str; WEEK] = ["10", "10", "10", "10", "10", "200", "200"];


fn dec(text: &str) -> Result<Decimal, Box<dyn Error>> {
    Ok(Decimal::from_str(text)?)
}


fn date(month: Month, number: u8) -> Result<Date, Box<dyn Error>> {
    Ok(Date::from_calendar_date(YEAR, month, number)?)
}


fn november() -> MonthKey {
    MonthKey {
        year: YEAR,
        month: Month::November,
    }
}


fn line(cost: &str, account: &str, day: Date, service: &str, tags: &str) -> String {
    format!("{cost},USD,{account},{day}T00:00:00Z,{service},\"{}\"", tags.replace('"', "\"\""))
}


fn table_of(rows: &[String]) -> Result<CostTable, Box<dyn Error>> {
    let text = format!(
        "BilledCost,BillingCurrency,BillingAccountId,ChargePeriodStart,ServiceName,Tags\n{}",
        rows.join("\n")
    );
    Ok(read_focus(text.as_bytes(), &Limits::default(), TENANT)?)
}


fn daily(first: Date, costs: &[&str]) -> Vec<String> {
    costs
        .iter()
        .enumerate()
        .map(|(offset, cost)| line(cost, "acct1", first + Duration::days(offset as i64), "Compute", ""))
        .collect()
}


fn budget(scope: Scope) -> Result<Budget, Box<dyn Error>> {
    Ok(Budget {
        name: "prod".to_string(),
        scope,
        monthly: dec("100")?,
        currency: "USD".to_string(),
        thresholds: vec![HALF, MOST, FULL],
        daily_change: DailyChange {
            factor: dec("3")?,
            min_amount: dec("10")?,
        },
    })
}


fn evaluate(table: &CostTable, scope: Scope) -> Result<Vec<CostAlert>, Box<dyn Error>> {
    Ok(evaluate_budgets(
        table,
        &Budgets {
            budgets: vec![budget(scope)?],
        },
        &november(),
    )?)
}


fn percents(alerts: &[CostAlert]) -> Vec<u32> {
    alerts
        .iter()
        .filter_map(|alert| match alert.kind {
            AlertKind::Threshold { percent, .. } => Some(percent),
            AlertKind::AbnormalDay { .. } => None,
        })
        .collect()
}


fn abnormal(alerts: &[CostAlert]) -> Vec<(Date, Decimal, Decimal)> {
    alerts
        .iter()
        .filter_map(|alert| match alert.kind {
            AlertKind::AbnormalDay { day, cost, median } => Some((day, cost, median)),
            AlertKind::Threshold { .. } => None,
        })
        .collect()
}


#[test]
fn thresholds_fire_when_crossed_and_not_before() -> Result<(), Box<dyn Error>> {
    let below = table_of(&[line("49.99", "acct1", date(Month::November, 1)?, "Compute", "")])?;
    assert!(evaluate(&below, Scope::All)?.is_empty());
    let half = table_of(&[line("50", "acct1", date(Month::November, 1)?, "Compute", "")])?;
    assert_eq!(percents(&evaluate(&half, Scope::All)?), vec![HALF]);
    let most = table_of(&[line("85", "acct1", date(Month::November, 1)?, "Compute", "")])?;
    assert_eq!(percents(&evaluate(&most, Scope::All)?), vec![HALF, MOST]);
    let all = table_of(&[line("100", "acct1", date(Month::November, 1)?, "Compute", "")])?;
    let alerts = evaluate(&all, Scope::All)?;
    assert_eq!(alerts.len(), THREE_ALERTS);
    let first = alerts.first().ok_or("no alert")?;
    assert_eq!(tenant_of(&first.tenant), TENANT);
    assert_eq!(first.budget, "prod");
    assert_eq!(
        first.kind,
        AlertKind::Threshold {
            percent: HALF,
            spent: dec("100")?,
            limit: dec("50")?
        }
    );
    Ok(())
}


#[test]
fn only_the_month_to_date_counts() -> Result<(), Box<dyn Error>> {
    let table = table_of(&[line("500", "acct1", date(Month::October, FIRST_OF_OCTOBER_WEEK)?, "Compute", "")])?;
    let last_year = Date::from_calendar_date(YEAR - 1, Month::November, 1)?;
    let old = table_of(&[line("500", "acct1", last_year, "Compute", "")])?;
    assert!(evaluate(&old, Scope::All)?.is_empty());
    assert!(matches_scope(&(last_year, String::new(), String::new()), &Scope::All));
    assert!(evaluate(&table, Scope::All)?.is_empty());
    Ok(())
}


#[test]
fn scopes_select_their_own_series() -> Result<(), Box<dyn Error>> {
    let day = date(Month::November, 1)?;
    let table = table_of(&[
        line("90", "acct1", day, "Compute", r#"{"team":"a"}"#),
        line("10", "acct2", day, "Storage", r#"{"team":"b"}"#),
    ])?;
    assert_eq!(percents(&evaluate(&table, Scope::Account("acct1".to_string()))?), vec![HALF, MOST]);
    assert_eq!(percents(&evaluate(&table, Scope::Account("acct2".to_string()))?), Vec::<u32>::new());
    assert_eq!(percents(&evaluate(&table, Scope::Service("Compute".to_string()))?), vec![HALF, MOST]);
    assert_eq!(percents(&evaluate(&table, Scope::Service("Storage".to_string()))?), Vec::<u32>::new());
    let team_a = Scope::Tag(TagScope {
        key: "team".to_string(),
        value: "a".to_string(),
    });
    assert_eq!(percents(&evaluate(&table, team_a)?), vec![HALF, MOST]);
    let team_b = Scope::Tag(TagScope {
        key: "team".to_string(),
        value: "b".to_string(),
    });
    assert!(evaluate(&table, team_b)?.is_empty());
    let other_key = Scope::Tag(TagScope {
        key: "env".to_string(),
        value: "a".to_string(),
    });
    assert!(evaluate(&table, other_key)?.is_empty());
    assert_eq!(percents(&evaluate(&table, Scope::All)?), vec![HALF, MOST, FULL]);
    Ok(())
}


#[test]
fn abnormal_day_needs_seven_previous_days() -> Result<(), Box<dyn Error>> {
    let first = date(Month::November, 1)?;
    let mut costs = FLAT_WEEK.to_vec();
    costs.push("40");
    let seven = table_of(&daily(first, &costs))?;
    let alerts = evaluate(&seven, Scope::All)?;
    let found = abnormal(&alerts);
    assert_eq!(found, vec![(date(Month::November, EIGHTH_DAY)?, dec("40")?, dec("10")?)]);
    Ok(())
}


#[test]
fn abnormal_day_with_exactly_six_previous_days_is_silent() -> Result<(), Box<dyn Error>> {
    let mut costs = FLAT_WEEK.to_vec();
    costs.truncate(SIX_DAYS);
    costs.push("40");
    let table = table_of(&daily(date(Month::November, 1)?, &costs))?;
    assert!(abnormal(&evaluate(&table, Scope::All)?).is_empty());
    Ok(())
}


#[test]
fn abnormal_day_respects_factor_and_minimum() -> Result<(), Box<dyn Error>> {
    let mut costs = FLAT_WEEK.to_vec();
    costs.push("30");
    let at_factor = table_of(&daily(date(Month::November, 1)?, &costs))?;
    assert!(abnormal(&evaluate(&at_factor, Scope::All)?).is_empty());
    let mut high_floor = FLAT_WEEK.to_vec();
    high_floor.push("40");
    let table = table_of(&daily(date(Month::November, 1)?, &high_floor))?;
    let strict = Budget {
        daily_change: DailyChange {
            factor: dec("3")?,
            min_amount: dec("40")?,
        },
        ..budget(Scope::All)?
    };
    let alerts = evaluate_budgets(&table, &Budgets { budgets: vec![strict] }, &november())?;
    assert!(abnormal(&alerts).is_empty());
    Ok(())
}


#[test]
fn previous_month_days_count_as_history() -> Result<(), Box<dyn Error>> {
    let mut costs = FLAT_WEEK.to_vec();
    costs.push("90");
    let table = table_of(&daily(date(Month::October, FIRST_OF_OCTOBER_WEEK)?, &costs))?;
    let alerts = evaluate(&table, Scope::All)?;
    assert_eq!(abnormal(&alerts), vec![(date(Month::November, 1)?, dec("90")?, dec("10")?)]);
    Ok(())
}


#[test]
fn a_median_product_that_overflows_raises_no_alert() -> Result<(), Box<dyn Error>> {
    let mut costs = vec![DECIMAL_MAX; WEEK];
    costs.push(DECIMAL_MAX);
    let table = table_of(&daily(date(Month::October, FIRST_OF_OCTOBER_WEEK)?, &costs))?;
    let alerts = evaluate(&table, Scope::All)?;
    assert!(abnormal(&alerts).is_empty());
    Ok(())
}


#[test]
fn a_currency_mismatch_is_an_error_naming_the_budget() -> Result<(), Box<dyn Error>> {
    let table = table_of(&[line("1", "acct1", date(Month::November, 1)?, "Compute", "")])?;
    let euro = Budget {
        currency: "EUR".to_string(),
        ..budget(Scope::All)?
    };
    let outcome = evaluate_budgets(&table, &Budgets { budgets: vec![euro.clone()] }, &november());
    assert!(matches!(outcome, Err(CostError::CurrencyMismatch { ref budget }) if budget == "prod"));
    let empty = table_of(&[])?;
    assert!(evaluate_budgets(&empty, &Budgets { budgets: vec![euro] }, &november())?.is_empty());
    Ok(())
}


#[test]
fn sums_that_overflow_are_errors() -> Result<(), Box<dyn Error>> {
    let two_days = table_of(&daily(date(Month::November, 1)?, &[DECIMAL_MAX, DECIMAL_MAX]))?;
    assert!(evaluate(&two_days, Scope::All).is_err());
    let day = date(Month::November, 1)?;
    let table = table_of(&[
        line(DECIMAL_MAX, "acct1", day, "s1", ""),
        line(DECIMAL_MIN, "acct2", day, "s3", ""),
        line(DECIMAL_MAX, "acct1", day, "s2", ""),
    ])?;
    assert!(evaluate(&table, Scope::Account("acct1".to_string())).is_err());
    assert_eq!(percents(&evaluate(&table, Scope::Account("acct2".to_string()))?), Vec::<u32>::new());
    Ok(())
}


#[test]
fn evaluation_refuses_an_invalid_budget() -> Result<(), Box<dyn Error>> {
    let table = table_of(&[])?;
    let broken = Budget {
        monthly: Decimal::ZERO,
        ..budget(Scope::All)?
    };
    let outcome = evaluate_budgets(&table, &Budgets { budgets: vec![broken] }, &november());
    assert!(matches!(
        outcome,
        Err(CostError::InvalidBudget {
            index: FIRST_BUDGET_INDEX,
            field: "monthly"
        })
    ));
    Ok(())
}


#[test]
fn every_invalid_field_is_named() -> Result<(), Box<dyn Error>> {
    let tag = |key: &str, value: &str| {
        Scope::Tag(TagScope {
            key: key.to_string(),
            value: value.to_string(),
        })
    };
    let long = "x".repeat(MAX_SCOPE_BYTES + 1);
    let scopes = [
        (Scope::Account(String::new()), "scope"),
        (Scope::Account(long.clone()), "scope"),
        (Scope::Service(String::new()), "scope"),
        (tag("", "v"), "scope"),
        (tag("k", "v\u{202e}"), "scope"),
        (tag("k", &long), "scope"),
    ];
    scopes.iter().try_for_each(|(scope, field)| -> Result<(), Box<dyn Error>> {
        assert_eq!(budget_problem(&budget(scope.clone())?), Some(*field));
        Ok(())
    })?;
    let valid_scopes = [
        Scope::All,
        Scope::Service("Compute".to_string()),
        tag("k", ""),
        Scope::Account("a".to_string()),
    ];
    valid_scopes.iter().try_for_each(|scope| -> Result<(), Box<dyn Error>> {
        assert_eq!(budget_problem(&budget(scope.clone())?), None);
        Ok(())
    })?;
    let base = budget(Scope::All)?;
    let mutants = [
        (
            Budget {
                name: String::new(),
                ..base.clone()
            },
            "name",
        ),
        (
            Budget {
                name: "n".repeat(MAX_NAME_BYTES + 1),
                ..base.clone()
            },
            "name",
        ),
        (
            Budget {
                monthly: Decimal::ZERO,
                ..base.clone()
            },
            "monthly",
        ),
        (
            Budget {
                monthly: MAX_AMOUNT + Decimal::ONE,
                ..base.clone()
            },
            "monthly",
        ),
        (
            Budget {
                currency: String::new(),
                ..base.clone()
            },
            "currency",
        ),
        (
            Budget {
                thresholds: vec![0],
                ..base.clone()
            },
            "thresholds",
        ),
        (
            Budget {
                thresholds: vec![MAX_THRESHOLD_PERCENT + 1],
                ..base.clone()
            },
            "thresholds",
        ),
        (
            Budget {
                thresholds: vec![1; MAX_THRESHOLDS + 1],
                ..base.clone()
            },
            "thresholds",
        ),
        (
            Budget {
                daily_change: DailyChange {
                    factor: Decimal::ONE,
                    min_amount: Decimal::ZERO,
                },
                ..base.clone()
            },
            "factor",
        ),
        (
            Budget {
                daily_change: DailyChange {
                    factor: MAX_FACTOR + Decimal::ONE,
                    min_amount: Decimal::ZERO,
                },
                ..base.clone()
            },
            "factor",
        ),
        (
            Budget {
                daily_change: DailyChange {
                    factor: dec("2")?,
                    min_amount: dec("-1")?,
                },
                ..base.clone()
            },
            "min_amount",
        ),
        (
            Budget {
                daily_change: DailyChange {
                    factor: dec("2")?,
                    min_amount: MAX_AMOUNT + Decimal::ONE,
                },
                ..base.clone()
            },
            "min_amount",
        ),
    ];
    mutants.iter().try_for_each(|(mutant, field)| -> Result<(), Box<dyn Error>> {
        assert_eq!(budget_problem(mutant), Some(*field));
        Ok(())
    })?;
    let thresholds_ok = Budget {
        thresholds: vec![1, MAX_THRESHOLD_PERCENT],
        ..base.clone()
    };
    assert_eq!(budget_problem(&thresholds_ok), None);
    let list = Budgets {
        budgets: vec![base.clone(), Budget { name: String::new(), ..base }],
    };
    assert!(matches!(
        validate_budgets(&list),
        Err(CostError::InvalidBudget {
            index: SECOND_BUDGET_INDEX,
            field: "name"
        })
    ));
    Ok(())
}


#[test]
fn the_budget_count_is_capped_at_exactly_the_limit() -> Result<(), Box<dyn Error>> {
    let base = budget(Scope::All)?;
    let exact = Budgets {
        budgets: vec![base.clone(); MAX_BUDGETS],
    };
    assert!(validate_budgets(&exact).is_ok());
    let over = Budgets {
        budgets: vec![base; MAX_BUDGETS + 1],
    };
    assert!(matches!(validate_budgets(&over), Err(CostError::TooManyBudgets { limit: MAX_BUDGETS })));
    Ok(())
}


#[test]
fn budget_files_load_with_every_scope_shape() -> Result<(), Box<dyn Error>> {
    let text = [
        "budgets:",
        "  - name: prod",
        "    scope: all",
        "    monthly: \"1000.50\"",
        "    currency: USD",
        "    thresholds: [50, 100]",
        "    daily_change: {factor: \"3\", min_amount: 10}",
        "  - name: team",
        "    scope: {tag: {key: team, value: a}}",
        "    monthly: 200",
        "    currency: USD",
        "    thresholds: []",
        "    daily_change: {factor: 2.5, min_amount: 0}",
        "  - name: acct",
        "    scope: {account: \"123456789012\"}",
        "    monthly: 5",
        "    currency: USD",
        "    thresholds: [100]",
        "    daily_change: {factor: 2, min_amount: 1}",
        "  - name: svc",
        "    scope: {service: Compute}",
        "    monthly: 5",
        "    currency: USD",
        "    thresholds: [100]",
        "    daily_change: {factor: 2, min_amount: 1}",
    ]
    .join("\n");
    let budgets = load_budgets(&text, "budgets.yaml")?;
    assert_eq!(budgets.budgets.len(), BUDGET_FILE_COUNT);
    let first = budgets.budgets.first().ok_or("no budget")?;
    assert_eq!(first.scope, Scope::All);
    assert_eq!(first.monthly, dec("1000.5")?);
    assert_eq!(first.thresholds, vec![HALF, FULL]);
    assert_eq!(first.daily_change.min_amount, dec("10")?);
    let scopes = budgets.budgets.iter().map(|each| each.scope.clone()).collect::<Vec<_>>();
    assert!(scopes.contains(&Scope::Tag(TagScope {
        key: "team".to_string(),
        value: "a".to_string()
    })));
    assert!(scopes.contains(&Scope::Account("123456789012".to_string())));
    assert!(scopes.contains(&Scope::Service("Compute".to_string())));
    Ok(())
}


#[test]
fn budget_files_are_strict() -> Result<(), Box<dyn Error>> {
    let valid = "budgets:\n  - name: a\n    scope: all\n    monthly: 1\n    currency: USD\n    thresholds: [1]\n    daily_change: {factor: 2, min_amount: 0}\n";
    assert!(load_budgets(valid, "b.yaml").is_ok());
    let unknown = format!("{valid}    extra: 1\n");
    assert!(matches!(load_budgets(&unknown, "b.yaml"), Err(CostError::Budgets(_))));
    let exponent = valid.replace("monthly: 1", "monthly: \"1e3\"");
    assert!(matches!(load_budgets(&exponent, "b.yaml"), Err(CostError::Budgets(_))));
    let invalid = valid.replace("monthly: 1", "monthly: 0");
    assert!(matches!(
        load_budgets(&invalid, "b.yaml"),
        Err(CostError::InvalidBudget { field: "monthly", .. })
    ));
    Ok(())
}


#[test]
fn amount_field_refuses_non_decimal_text() -> Result<(), Box<dyn Error>> {
    let good: StrDeserializer<ValueError> = "12.5".into_deserializer();
    assert_eq!(amount_field(good)?, dec("12.5")?);
    let bad: StrDeserializer<ValueError> = "1e3".into_deserializer();
    assert!(amount_field(bad).is_err());
    Ok(())
}


#[test]
fn months_are_written_year_dash_month() -> Result<(), Box<dyn Error>> {
    assert_eq!(parse_month("2026-11")?, november());
    ["2026", "abcd-11", "2026-ab", "2026-13", "2026-1", "+026-11", "2026-+1", "2026-00"]
        .iter()
        .try_for_each(|text| -> Result<(), Box<dyn Error>> {
            assert!(matches!(parse_month(text), Err(CostError::BadMonth)), "{text}");
            Ok(())
        })?;
    Ok(())
}
