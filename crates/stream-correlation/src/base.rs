use crate::condition::{evaluate, to_steps, Step};
use crate::error::{redacted, CorrelationError};
use crate::field::field_texts;
use crate::selection::{compile_selection, selection_matches};
use crate::types::{Selection, SelectionResults};
use serde_json::Value;
use sigma_sql::condition::{compile_condition, tokenize};
use sigma_sql::error::SigmaError;
use sigma_sql::mapping::FieldMapping;
use sigma_sql::rule::{parse_rule, Rule};
use sigma_sql::types::SelectionSql;
use std::collections::BTreeMap;


pub const CATEGORY_FIELD: &str = "event.category";


pub const OS_FIELD: &str = "host.os.type";


pub const VALIDATION_STUB: &str = "x";


/// A single-event Sigma rule compiled for in-memory evaluation.
#[derive(Debug, Clone)]
pub struct BaseRule {
    pub title: String,
    pub id: Option<String>,
    pub name: Option<String>,
    pub source: String,
    pub event_category: String,
    pub os: Option<String>,
    pub selections: BTreeMap<String, Selection>,
    pub steps: Vec<Step>,
}


fn unsupported(rule: &Rule, construct: String) -> SigmaError {
    SigmaError::Unsupported {
        rule: rule.title.clone(),
        construct,
    }
}


fn os_filter(rule: &Rule, mapping: &FieldMapping) -> Result<Option<String>, SigmaError> {
    rule.logsource
        .product
        .as_deref()
        .map(|product| {
            mapping
                .products
                .get(product)
                .cloned()
                .ok_or_else(|| unsupported(rule, "logsource product".to_string()))
        })
        .transpose()
}


/// Compiles the text of one Sigma rule; `name` is the rule's `name` key, which the SQL parser drops.
pub fn compile_base(text: &str, name: Option<String>, mapping: &FieldMapping) -> Result<BaseRule, CorrelationError> {
    let rule = parse_rule(text).map_err(redacted)?;
    let category = rule
        .logsource
        .category
        .as_deref()
        .ok_or_else(|| unsupported(&rule, "logsource without category".to_string()))?;
    let category_mapping = mapping
        .categories
        .get(category)
        .ok_or_else(|| unsupported(&rule, "logsource category".to_string()))?;
    match rule.logsource.service {
        Some(_) => Err(unsupported(&rule, "logsource service".to_string())),
        None => Ok(()),
    }?;
    let selections = rule
        .selections
        .iter()
        .map(|(key, value)| compile_selection(&rule.title, category, category_mapping, value).map(|compiled| (key.clone(), compiled)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let stubs: SelectionSql = selections.keys().map(|key| (key.clone(), VALIDATION_STUB.to_string())).collect();
    compile_condition(&rule.title, &rule.condition, &stubs)?;
    let names: Vec<String> = selections.keys().cloned().collect();
    let steps = to_steps(&tokenize(&rule.title, &rule.condition)?, &names);
    Ok(BaseRule {
        os: os_filter(&rule, mapping)?,
        title: rule.title,
        id: rule.id,
        name,
        source: text.to_string(),
        event_category: category_mapping.event_category.clone(),
        selections,
        steps,
    })
}


fn has_value(event: &Value, path: &str, expected: &str) -> bool {
    field_texts(event, path).is_some_and(|texts| texts.iter().any(|text| text == expected))
}


/// True when the event is in the rule's logsource and its detection condition holds.
pub fn base_matches(rule: &BaseRule, event: &Value) -> bool {
    let in_logsource = has_value(event, CATEGORY_FIELD, &rule.event_category) && rule.os.as_ref().is_none_or(|os| has_value(event, OS_FIELD, os));
    in_logsource && {
        let results: SelectionResults = rule
            .selections
            .iter()
            .map(|(key, selection)| (key.clone(), selection_matches(selection, event)))
            .collect();
        evaluate(&rule.steps, &results)
    }
}
