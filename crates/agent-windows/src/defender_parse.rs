use crate::defender::{is_guid, is_utc_time, CONTROLLED_FOLDER_ACCESS, MAX_ACTION, MAX_ASR_RULES, MAX_TEXT_BYTES, STATUS_FIELDS};
use crate::model::{DefenderRefusal, Kind, Spec};
use crate::types::Raw;
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
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


pub fn keep_null<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<Option<Raw>, Source::Error> {
    Raw::deserialize(deserializer).map(Some)
}


#[derive(Deserialize)]
pub struct RootShape {
    pub status: Option<Value>,
    pub preference: Option<Raw>,
}


#[derive(Deserialize)]
pub struct PreferenceShape {
    #[serde(rename = "AttackSurfaceReductionRules_Ids", default, deserialize_with = "keep_null")]
    pub ids: Option<Raw>,
    #[serde(rename = "AttackSurfaceReductionRules_Actions", default, deserialize_with = "keep_null")]
    pub actions: Option<Raw>,
    #[serde(rename = "EnableControlledFolderAccess")]
    pub folder: Option<Value>,
}


pub fn count_items(raw: &RawValue) -> Result<usize, &'static str> {
    serde_json::from_str::<Option<Vec<IgnoredAny>>>(raw.get())
        .map(|items| items.map_or(0, |list| list.len()))
        .map_err(|_| WRONG_TYPE)
}


pub fn list_of(raw: &RawValue) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(raw.get()).unwrap_or_else(|_| Vec::new())
}


pub fn counted(raw: &Option<Raw>) -> Result<usize, &'static str> {
    raw.as_deref().ok_or(MISSING).and_then(count_items)
}


pub fn raw_rules(raw: &Option<Raw>) -> Vec<Value> {
    raw.as_deref().map_or_else(Vec::new, list_of)
}


pub fn asr_rule((id, action): (&Value, &Value)) -> Option<Value> {
    id.as_str()
        .filter(|text| is_guid(text))
        .zip(action.as_u64().filter(|number| *number <= MAX_ACTION))
        .map(|(guid, number)| json!({"id": guid.to_ascii_lowercase(), "action": number, "action_name": action_name(number)}))
}


pub fn collect_asr(shape: &PreferenceShape, out: &mut Map<String, Value>, unknown: &mut Vec<Value>, findings: &mut Vec<&'static str>) {
    match counted(&shape.ids).and_then(|ids| counted(&shape.actions).map(|actions| (ids, actions))) {
        Err(reason) => unknown.push(json!({"field": "asr_rules", "reason": reason})),
        Ok((ids, actions)) if ids != actions => findings.push("asr_arrays_mismatch"),
        Ok((total, _)) if total > MAX_ASR_RULES => {
            findings.push("asr_rules_over_limit");
            out.insert("asr_rules_over_limit".to_string(), Value::from(total));
        }
        Ok((total, _)) => {
            let ids = raw_rules(&shape.ids);
            let actions = raw_rules(&shape.actions);
            let rules: Vec<Value> = ids.iter().zip(&actions).filter_map(asr_rule).collect();
            let refused = total - rules.len();
            findings.extend((refused > 0).then_some("asr_rules_refused"));
            out.insert("asr_rules".to_string(), Value::Array(rules));
            out.insert("asr_rules_over_limit".to_string(), Value::from(0));
            out.insert("asr_rules_refused".to_string(), Value::from(refused));
        }
    }
}


pub fn parse_root(text: &str) -> Result<RootShape, DefenderRefusal> {
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


pub fn status_of(root: &RootShape) -> Result<&Map<String, Value>, DefenderRefusal> {
    match &root.status {
        None => Err(DefenderRefusal::Unavailable),
        Some(Value::Object(status)) if STATUS_FIELDS.iter().all(|spec| !status.contains_key(spec.source)) => Err(DefenderRefusal::Unavailable),
        Some(Value::Object(status)) => Ok(status),
        Some(_) => Err(DefenderRefusal::Malformed),
    }
}


pub fn preference_of(root: &RootShape) -> Result<PreferenceShape, &'static str> {
    match root.preference.as_deref() {
        None => Err(MISSING),
        Some(raw) if !raw.get().starts_with('{') => Err(WRONG_TYPE),
        Some(raw) => serde_json::from_str(raw.get()).map_err(|_| WRONG_TYPE),
    }
}


pub fn collect_preference(root: &RootShape, out: &mut Map<String, Value>, unknown: &mut Vec<Value>, findings: &mut Vec<&'static str>) {
    match preference_of(root) {
        Ok(shape) => {
            let mut source = Map::new();
            source.extend(shape.folder.clone().map(|value| (CONTROLLED_FOLDER_ACCESS.source.to_string(), value)));
            collect_fields(&source, &[CONTROLLED_FOLDER_ACCESS], out, unknown);
            collect_asr(&shape, out, unknown, findings);
        }
        Err(reason) => {
            unknown.push(json!({"field": CONTROLLED_FOLDER_ACCESS.name, "reason": reason}));
            unknown.push(json!({"field": "asr_rules", "reason": reason}));
        }
    }
}


pub fn parse_defender(output: &[u8]) -> Result<Map<String, Value>, DefenderRefusal> {
    let text = std::str::from_utf8(output).map_err(|error| {
        let valid_up_to = error.valid_up_to();
        warn!(valid_up_to, "defender output is not UTF-8");
        DefenderRefusal::Undecodable
    })?;
    let root = parse_root(text)?;
    let status = status_of(&root)?;
    let mut out = Map::new();
    let mut unknown: Vec<Value> = Vec::new();
    let mut findings: Vec<&'static str> = Vec::new();
    collect_fields(status, &STATUS_FIELDS, &mut out, &mut unknown);
    collect_preference(&root, &mut out, &mut unknown, &mut findings);
    let folder_name = out.get(CONTROLLED_FOLDER_ACCESS.name).and_then(Value::as_u64).map(folder_access_name);
    out.extend(folder_name.map(|name| ("controlled_folder_access_name".to_string(), Value::from(name))));
    out.insert("unknown".to_string(), Value::Array(unknown));
    out.insert("findings".to_string(), json!(findings));
    Ok(out)
}
