use crate::defender::{is_guid, is_utc_time, CONTROLLED_FOLDER_ACCESS, MAX_ACTION, MAX_ASR_RULES, MAX_TEXT_BYTES, STATUS_FIELDS};
use crate::model::{DefenderRefusal, Kind, Spec};
use crate::types::Sections;
use serde_json::{json, Map, Value};
use tracing::warn;


pub const MISSING: &str = "missing";


pub const WRONG_TYPE: &str = "wrong_type";


pub const REFUSED: &str = "refused";


pub const IDS_KEY: &str = "AttackSurfaceReductionRules_Ids";


pub const ACTIONS_KEY: &str = "AttackSurfaceReductionRules_Actions";


pub const ACTION_OFF: u64 = 0;


pub const ACTION_BLOCK: u64 = 1;


pub const ACTION_AUDIT: u64 = 2;


pub const ACTION_NOT_CONFIGURED: u64 = 5;


pub const ACTION_WARN: u64 = 6;


pub const BOM: char = '\u{feff}';


pub fn refusal_reason(refusal: DefenderRefusal) -> &'static str {
    match refusal {
        DefenderRefusal::Unavailable => "defender_unavailable",
        DefenderRefusal::Malformed => "malformed",
        DefenderRefusal::Undecodable => "undecodable",
    }
}


pub fn action_name(action: u64) -> &'static str {
    match action {
        ACTION_OFF => "off",
        ACTION_BLOCK => "block",
        ACTION_AUDIT => "audit",
        ACTION_NOT_CONFIGURED => "not_configured",
        ACTION_WARN => "warn",
        _ => "unknown",
    }
}


pub fn folder_access_name(mode: u64) -> &'static str {
    match mode {
        ACTION_OFF => "disabled",
        ACTION_BLOCK => "enabled",
        ACTION_AUDIT => "audit_mode",
        _ => "unknown",
    }
}


pub fn is_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_TEXT_BYTES && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || b" -_".contains(&byte))
}


pub fn convert(value: &Value, kind: Kind) -> Result<Value, &'static str> {
    match (value, kind) {
        (Value::Null, _) => Err(MISSING),
        (Value::Bool(_), Kind::Flag) => Ok(value.clone()),
        (Value::Number(number), Kind::Count) => number
            .as_u64()
            .filter(|count| *count <= u64::from(u32::MAX))
            .map(Value::from)
            .ok_or(REFUSED),
        (Value::String(text), Kind::Text) => is_text(text).then(|| value.clone()).ok_or(REFUSED),
        (Value::String(text), Kind::Time) => is_utc_time(text).then(|| value.clone()).ok_or(REFUSED),
        _ => Err(WRONG_TYPE),
    }
}


pub fn collect_fields(source: &Map<String, Value>, specs: &[Spec], out: &mut Map<String, Value>, unknown: &mut Vec<Value>) {
    specs.iter().for_each(|spec| {
        match source.get(spec.source).ok_or(MISSING).and_then(|value| convert(value, spec.kind)) {
            Ok(value) => {
                out.insert(spec.name.to_string(), value);
            }
            Err(reason) => unknown.push(json!({"field": spec.name, "reason": reason})),
        };
    });
}


pub fn array_of<'a>(source: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], &'static str> {
    match source.get(key) {
        None => Err(MISSING),
        Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items.as_slice()),
        Some(_) => Err(WRONG_TYPE),
    }
}


pub fn asr_arrays(preference: &Map<String, Value>) -> Result<(&[Value], &[Value]), &'static str> {
    array_of(preference, IDS_KEY).and_then(|ids| array_of(preference, ACTIONS_KEY).map(|actions| (ids, actions)))
}


pub fn asr_rule((id, action): (&Value, &Value)) -> Option<Value> {
    id.as_str()
        .filter(|text| is_guid(text))
        .zip(action.as_u64().filter(|number| *number <= MAX_ACTION))
        .map(|(guid, number)| json!({"id": guid.to_ascii_lowercase(), "action": number, "action_name": action_name(number)}))
}


pub fn collect_asr(preference: &Map<String, Value>, out: &mut Map<String, Value>, unknown: &mut Vec<Value>, findings: &mut Vec<&'static str>) {
    match asr_arrays(preference) {
        Err(reason) => unknown.push(json!({"field": "asr_rules", "reason": reason})),
        Ok((ids, actions)) if ids.len() != actions.len() => findings.push("asr_arrays_mismatch"),
        Ok((ids, actions)) => {
            let rules: Vec<Value> = ids.iter().zip(actions).take(MAX_ASR_RULES).filter_map(asr_rule).collect();
            let taken = ids.len().min(MAX_ASR_RULES);
            let over = ids.len() - taken;
            let refused = taken - rules.len();
            findings.extend((over > 0).then_some("asr_rules_over_limit"));
            findings.extend((refused > 0).then_some("asr_rules_refused"));
            out.insert("asr_rules".to_string(), Value::Array(rules));
            out.insert("asr_rules_over_limit".to_string(), Value::from(over));
            out.insert("asr_rules_refused".to_string(), Value::from(refused));
        }
    }
}


pub fn parse_root(text: &str) -> Result<Value, DefenderRefusal> {
    let body = text.strip_prefix(BOM).unwrap_or(text).trim();
    if body.is_empty() {
        Err(DefenderRefusal::Unavailable)
    } else {
        serde_json::from_str(body).map_err(|error| {
            let category = error.classify();
            warn!(category = ?category, "defender output is not JSON");
            DefenderRefusal::Malformed
        })
    }
}


pub fn sections(root: &Value) -> Result<Sections<'_>, DefenderRefusal> {
    let object = root.as_object().ok_or(DefenderRefusal::Malformed)?;
    let status = match object.get("status") {
        None | Some(Value::Null) => Err(DefenderRefusal::Unavailable),
        Some(Value::Object(status)) => Ok(status),
        Some(_) => Err(DefenderRefusal::Malformed),
    }?;
    Ok((status, object.get("preference").and_then(Value::as_object)))
}


pub fn parse_defender(output: &[u8]) -> Result<Map<String, Value>, DefenderRefusal> {
    let text = std::str::from_utf8(output).map_err(|error| {
        let valid_up_to = error.valid_up_to();
        warn!(valid_up_to, "defender output is not UTF-8");
        DefenderRefusal::Undecodable
    })?;
    let root = parse_root(text)?;
    let (status, preference) = sections(&root)?;
    let empty = Map::new();
    let chosen = preference.unwrap_or(&empty);
    let mut out = Map::new();
    let mut unknown: Vec<Value> = Vec::new();
    let mut findings: Vec<&'static str> = Vec::new();
    collect_fields(status, &STATUS_FIELDS, &mut out, &mut unknown);
    collect_fields(chosen, &[CONTROLLED_FOLDER_ACCESS], &mut out, &mut unknown);
    let folder_name = out.get(CONTROLLED_FOLDER_ACCESS.name).and_then(Value::as_u64).map(folder_access_name);
    out.extend(folder_name.map(|name| ("controlled_folder_access_name".to_string(), Value::from(name))));
    collect_asr(chosen, &mut out, &mut unknown, &mut findings);
    out.insert("unknown".to_string(), Value::Array(unknown));
    out.insert("findings".to_string(), json!(findings));
    Ok(out)
}
