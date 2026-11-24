use crate::batch::{classify, Line};
use alerts::model::{Alert, Summary};
use serde_json::{json, Value};


/// The summary parsed as an object when it is whole and passes the JSONL reader's bounds, else its text.
pub fn summary_value(summary: &Summary) -> Value {
    let parsed = (!summary.truncated).then(|| classify(summary.text.as_bytes(), false));
    match parsed {
        Some(Line::Alert(value)) => value,
        _other => Value::String(summary.text.clone()),
    }
}


/// The playbook alert of a stored alert: store columns under fixed keys, the tenant from the scope, the summary only under `summary`.
pub fn alert_json(tenant: &str, alert: &Alert) -> Value {
    let named = [("host", &alert.host_name), ("user", &alert.user_name)]
        .into_iter()
        .filter_map(|(key, name)| name.as_ref().map(|value| (key, json!({ "value": value }))));
    let fixed = [
        ("id", json!(alert.id)),
        ("tenant", json!(tenant)),
        ("rule_id", json!(alert.rule_id)),
        ("rule_title", json!(alert.rule_title)),
        ("severity", json!(alert.severity.to_string())),
        ("event_time", json!(alert.event_time)),
        ("created", json!(alert.created_micros)),
        ("summary", summary_value(&alert.summary)),
    ];
    Value::Object(fixed.into_iter().chain(named).map(|(key, value)| (key.to_owned(), value)).collect())
}
