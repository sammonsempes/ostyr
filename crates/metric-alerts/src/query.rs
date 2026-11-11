use crate::error::RuleError;
use crate::evaluate::ABSENCE_INTERVALS;
use crate::model::{Capacity, Condition, Direction, Rule};
use crate::rules::MAX_LABELS;
use crate::types::{Point, QueryParams};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use siem_schema::identifier::{quote_identifier, validate_identifier};
use siem_schema::metrics::{pick_table, table_name, MetricsRetention, MetricsTable, BUCKET_COLUMN};
use siem_schema::schema::{TENANT_COLUMN, TIMESTAMP_COLUMN};


/// Evaluation step of threshold and rate rules, in seconds.
pub const EVALUATION_STEP_SECONDS: u64 = 60;


/// Margin of a rate rule beyond the hold time, as a multiple of the step.
pub const RATE_MARGIN_STEPS: u64 = 2;


/// A query with its named parameters, sent to ClickHouse as `param_<name>` values; no value is ever spliced into the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricQuery {
    pub sql: String,
    pub params: QueryParams,
    pub table: MetricsTable,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregate {
    Max,
    Min,
    Last,
}


/// A tenant id in core-pg's grammar, never a local copy of it.
pub fn parse_tenant_id(text: &str) -> Result<TenantScope, RuleError> {
    tenant_scope(text).map_err(RuleError::InvalidTenant)
}


/// Window and step in seconds that the evaluator needs for the condition.
pub fn window_and_step(rule: &Rule) -> (u64, u64) {
    match &rule.condition {
        Condition::Threshold { .. } => (rule.hold_for.saturating_add(EVALUATION_STEP_SECONDS), EVALUATION_STEP_SECONDS),
        Condition::Rate { .. } => (
            rule.hold_for.saturating_add(EVALUATION_STEP_SECONDS.saturating_mul(RATE_MARGIN_STEPS)),
            EVALUATION_STEP_SECONDS,
        ),
        Condition::Absence { interval } => (interval.saturating_mul(ABSENCE_INTERVALS.saturating_add(1)), (*interval).max(1)),
        Condition::Forecast { window, min_points, .. } => (*window, window.checked_div(*min_points as u64).unwrap_or(*window).max(1)),
    }
}


/// Which value of a bucket the evaluator wants.
pub fn aggregate_of(condition: &Condition) -> Aggregate {
    match condition {
        Condition::Threshold {
            direction: Direction::Above, ..
        } => Aggregate::Max,
        Condition::Threshold {
            direction: Direction::Below, ..
        } => Aggregate::Min,
        Condition::Rate { .. } | Condition::Absence { .. } | Condition::Forecast { .. } => Aggregate::Last,
    }
}


/// Expression over the table columns: the raw table aggregates `value`, a rollup merges its stored aggregate.
pub fn value_expression(table: MetricsTable, aggregate: Aggregate) -> &'static str {
    match (table, aggregate) {
        (MetricsTable::Raw, Aggregate::Max) => "max(`value`)",
        (MetricsTable::Raw, Aggregate::Min) => "min(`value`)",
        (MetricsTable::Raw, Aggregate::Last) => "anyLast(`value`)",
        (_, Aggregate::Max) => "max(`value_max`)",
        (_, Aggregate::Min) => "min(`value_min`)",
        (_, Aggregate::Last) => "anyLast(`value_last`)",
    }
}


/// Time column of the table.
pub fn time_column(table: MetricsTable) -> &'static str {
    match table {
        MetricsTable::Raw => TIMESTAMP_COLUMN,
        MetricsTable::Minute | MetricsTable::Hour | MetricsTable::Day => BUCKET_COLUMN,
    }
}


/// One condition and two parameters per selector label; a name that is not a valid identifier is refused.
pub fn selector_clauses(rule: &Rule) -> Result<(Vec<String>, QueryParams), RuleError> {
    if rule.selector.len() > MAX_LABELS {
        Err(RuleError::TooManySelectors {
            rule: rule.id.clone(),
            count: rule.selector.len(),
        })
    } else {
        let checked = rule
            .selector
            .iter()
            .enumerate()
            .map(|(index, (name, value))| {
                validate_identifier(name)?;
                let clause = format!("    AND `labels`[{{label_name_{index}:String}}] = {{label_value_{index}:String}}\n");
                let params = vec![
                    (format!("label_name_{index}"), name.clone()),
                    (format!("label_value_{index}"), value.clone()),
                ];
                Ok::<_, RuleError>((clause, params))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let clauses = checked.iter().map(|(clause, _)| clause.clone()).collect();
        let params = checked.into_iter().flat_map(|(_, params)| params).collect();
        Ok((clauses, params))
    }
}


/// Compiles the rule to one parameterised query over `[now - window, now]` returning rows `(ts, value)` in ascending order.
pub fn rule_sql(rule: &Rule, tenant: &TenantScope, now: u64, settings: &MetricsRetention) -> Result<MetricQuery, RuleError> {
    metric_sql(rule, tenant, now, settings, &rule.metric, aggregate_of(&rule.condition))
}


/// The shared query builder: the rule's window, table and selector over `metric` with `aggregate`, always filtered on the tenant.
pub fn metric_sql(
    rule: &Rule,
    tenant: &TenantScope,
    now: u64,
    settings: &MetricsRetention,
    metric: &str,
    aggregate: Aggregate,
) -> Result<MetricQuery, RuleError> {
    let (window, step) = window_and_step(rule);
    let table = pick_table(settings, window, step)?;
    let (clauses, label_params) = selector_clauses(rule)?;
    let from = now.saturating_sub(window);
    let name = quote_identifier(table_name(table))?;
    let time = quote_identifier(time_column(table))?;
    let tenant_column = quote_identifier(TENANT_COLUMN)?;
    let value = value_expression(table, aggregate);
    let sql = format!(
        "SELECT toUnixTimestamp({time}) AS `ts`, {value} AS `value`\nFROM {name}\nWHERE {tenant_column} = {{tenant:String}}\n    AND `metric` = {{metric:String}}\n    AND {time} >= toDateTime64({{from:UInt64}}, 3, 'UTC')\n    AND {time} <= toDateTime64({{to:UInt64}}, 3, 'UTC')\n{}GROUP BY `ts`\nORDER BY `ts` ASC\n",
        clauses.concat()
    );
    let base = vec![
        ("tenant".to_string(), tenant_of(tenant).to_owned()),
        ("metric".to_string(), metric.to_owned()),
        ("from".to_string(), from.to_string()),
        ("to".to_string(), now.to_string()),
    ];
    Ok(MetricQuery {
        sql,
        params: [base, label_params].concat(),
        table,
    })
}


/// Query of the latest capacity of a forecast whose capacity is a metric; `None` for every other rule.
pub fn capacity_sql(rule: &Rule, tenant: &TenantScope, now: u64, settings: &MetricsRetention) -> Result<Option<MetricQuery>, RuleError> {
    match &rule.condition {
        Condition::Forecast {
            capacity: Capacity::Metric { name },
            ..
        } => metric_sql(rule, tenant, now, settings, name, Aggregate::Last).map(Some),
        _ => Ok(None),
    }
}


/// The value of the greatest timestamp.
pub fn latest_value(rows: &[Point]) -> Option<f64> {
    rows.iter().max_by_key(|(timestamp, _)| *timestamp).map(|(_, value)| *value)
}
