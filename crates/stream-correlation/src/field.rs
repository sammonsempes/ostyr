use crate::error::CorrelationError;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const TIMESTAMP_FIELD: &str = "@timestamp";


pub const MILLIS_PER_SECOND: i64 = 1000;


pub const GROUP_SEPARATOR: &str = "\u{1f}";


pub const VALUE_SEPARATOR: &str = ",";


/// Finds a dotted ECS path in a nested event, or the flat key with dots when the event is not nested; JSON `null` counts as absent.
pub fn lookup<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    let nested = path.split('.').try_fold(event, |current, key| current.get(key));
    nested.or_else(|| event.get(path)).filter(|value| !value.is_null())
}


pub fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}


/// The scalar texts of a field (an array gives one text per scalar element); `None` when the field is absent.
pub fn field_texts(event: &Value, path: &str) -> Option<Vec<String>> {
    lookup(event, path).map(|value| match value {
        Value::Array(items) => items.iter().filter_map(scalar_text).collect(),
        single => scalar_text(single).into_iter().collect(),
    })
}


/// Event time in milliseconds since the epoch, from the RFC 3339 `@timestamp`.
pub fn event_time_ms(event: &Value) -> Result<i64, CorrelationError> {
    let text = event
        .get(TIMESTAMP_FIELD)
        .and_then(Value::as_str)
        .ok_or(CorrelationError::MissingTimestamp)?;
    let parsed = OffsetDateTime::parse(text, &Rfc3339).map_err(|source| CorrelationError::BadTimestamp {
        value: text.to_string(),
        source,
    })?;
    Ok(parsed.unix_timestamp() * MILLIS_PER_SECOND + i64::from(parsed.millisecond()))
}


/// The values of every `group-by` field joined into one key; `None` when the event lacks one of them.
pub fn group_key(event: &Value, fields: &[String]) -> Option<String> {
    fields
        .iter()
        .map(|field| field_texts(event, field).map(|texts| texts.join(VALUE_SEPARATOR)))
        .collect::<Option<Vec<String>>>()
        .map(|values| values.join(GROUP_SEPARATOR))
}
