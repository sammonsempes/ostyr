use crate::check::{check_matches, item_check, Check};
use crate::field::field_texts;
use crate::types::Selection;
use serde_json::{Map, Value};
use sigma_sql::error::SigmaError;
use sigma_sql::modifier::parse_field_key;
use sigma_sql::types::FieldTable;


/// All checks of one field; `all` means every check must hold, otherwise one is enough.
#[derive(Debug, Clone)]
pub struct FieldTest {
    pub path: String,
    pub all: bool,
    pub checks: Vec<Check>,
}


fn unsupported(rule: &str, construct: &str) -> SigmaError {
    SigmaError::Unsupported {
        rule: rule.to_string(),
        construct: construct.to_string(),
    }
}


pub const EVENT_CODE_PATH: &str = "event.code";


pub const EVENT_CODE_REASON: &str = "an event code is an integer or a string";


/// The event code is text in the event: an integer in a rule becomes its text, a float, boolean or null is refused like in the SQL compiler.
fn event_code_value(rule: &str, field: &str, item: &Value) -> Result<Value, SigmaError> {
    match item {
        Value::Number(number) if !number.is_f64() => Ok(Value::String(number.to_string())),
        Value::String(_) => Ok(item.clone()),
        _ => Err(SigmaError::BadValue {
            rule: rule.to_string(),
            field: field.to_string(),
            reason: EVENT_CODE_REASON.to_string(),
        }),
    }
}


fn non_empty<Item>(rule: &str, parts: Vec<Item>) -> Result<Vec<Item>, SigmaError> {
    if parts.is_empty() {
        Err(unsupported(rule, "empty selection or value list"))
    } else {
        Ok(parts)
    }
}


fn compile_field(rule: &str, category: &str, fields: &FieldTable, key: &str, value: &Value) -> Result<FieldTest, SigmaError> {
    let (field, modifiers) = parse_field_key(rule, key)?;
    let path = fields.get(&field).ok_or_else(|| SigmaError::UnmappedField {
        rule: rule.to_string(),
        field: field.clone(),
        category: category.to_string(),
    })?;
    let raw_items: Vec<&Value> = match value {
        Value::Array(list) => list.iter().collect(),
        single => vec![single],
    };
    let items: Vec<Value> = non_empty(rule, raw_items)?
        .into_iter()
        .map(|item| {
            if path == EVENT_CODE_PATH {
                event_code_value(rule, &field, item)
            } else {
                Ok(item.clone())
            }
        })
        .collect::<Result<_, _>>()?;
    let checks = items
        .iter()
        .map(|item| item_check(rule, &field, modifiers, item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FieldTest {
        path: path.clone(),
        all: modifiers.all,
        checks,
    })
}


fn compile_map(rule: &str, category: &str, fields: &FieldTable, map: &Map<String, Value>) -> Result<Vec<FieldTest>, SigmaError> {
    let tests = map
        .iter()
        .map(|(key, value)| compile_field(rule, category, fields, key, value))
        .collect::<Result<Vec<_>, _>>()?;
    non_empty(rule, tests)
}


fn compile_item(rule: &str, category: &str, fields: &FieldTable, item: &Value) -> Result<Vec<FieldTest>, SigmaError> {
    match item {
        Value::Object(map) => compile_map(rule, category, fields, map),
        _ => Err(unsupported(rule, "keyword selection")),
    }
}


/// A map is an AND of fields, a list of maps an OR of maps; keyword selections are refused like in the SQL compiler.
pub fn compile_selection(rule: &str, category: &str, fields: &FieldTable, value: &Value) -> Result<Selection, SigmaError> {
    match value {
        Value::Object(map) => Ok(vec![compile_map(rule, category, fields, map)?]),
        Value::Array(items) => non_empty(
            rule,
            items
                .iter()
                .map(|item| compile_item(rule, category, fields, item))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => Err(unsupported(rule, "keyword selection")),
    }
}


pub fn field_test_matches(test: &FieldTest, event: &Value) -> bool {
    let texts = field_texts(event, &test.path);
    if test.all {
        test.checks.iter().all(|check| check_matches(check, texts.as_ref()))
    } else {
        test.checks.iter().any(|check| check_matches(check, texts.as_ref()))
    }
}


pub fn selection_matches(selection: &Selection, event: &Value) -> bool {
    selection.iter().any(|tests| tests.iter().all(|test| field_test_matches(test, event)))
}
