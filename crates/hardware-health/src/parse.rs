//! Bounded, strict parse of the smartctl JSON.

use crate::error::SmartError;
use crate::grammar::is_clean_ident;
use crate::model::{Attribute, Limits, NvmeHealth, Protocol, SmartReport, WhenFailed};
use serde_json::Value;
use std::io::Read;


const FORMAT_VERSION_LEN: usize = 2;


pub fn parse_smartctl<Input: Read>(mut reader: Input, limits: &Limits) -> Result<SmartReport, SmartError> {
    let bytes = read_bounded(&mut reader, limits.max_bytes)?;
    let root: Value = serde_json::from_slice(&bytes)?;
    if root.is_object() {
        Ok(assemble(&root, limits))
    } else {
        Err(SmartError::NotAnObject)
    }
}


fn read_bounded(reader: &mut dyn Read, max_bytes: u64) -> Result<Vec<u8>, SmartError> {
    let mut bytes = Vec::new();
    reader.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        Err(SmartError::Oversized { limit: max_bytes })
    } else {
        Ok(bytes)
    }
}


fn lookup<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(root, |node, key| node.get(*key))
}


fn accepted<'a>(found: Option<&'a Value>, rejected: &mut usize, matches: fn(&Value) -> bool) -> Option<&'a Value> {
    let kept = found.filter(|value| matches(value));
    if found.is_some() && kept.is_none() {
        *rejected += 1;
    }
    kept
}


fn unsigned(found: Option<&Value>, rejected: &mut usize) -> Option<u64> {
    accepted(found, rejected, Value::is_u64).and_then(Value::as_u64)
}


fn text(found: Option<&Value>, rejected: &mut usize) -> Option<String> {
    let candidate = accepted(found, rejected, Value::is_string).and_then(Value::as_str);
    let clean = candidate.filter(|content| is_clean_ident(content));
    if candidate.is_some() && clean.is_none() {
        *rejected += 1;
    }
    clean.map(str::to_string)
}


fn flag_unreadable(unreadable: &mut Vec<String>, name: String, found: Option<&Value>, parsed_is_none: bool) {
    if found.is_some() && parsed_is_none {
        unreadable.push(name);
    }
}


fn format_major(root: &Value, rejected: &mut usize) -> Option<u64> {
    let versions = accepted(root.get("json_format_version"), rejected, Value::is_array).and_then(Value::as_array);
    let numbers: Option<Vec<u64>> = versions.and_then(|items| items.iter().map(Value::as_u64).collect());
    let major = numbers
        .filter(|items| items.len() == FORMAT_VERSION_LEN)
        .and_then(|items| items.first().copied());
    if versions.is_some() && major.is_none() {
        *rejected += 1;
    }
    major
}


fn exit_status(root: &Value, rejected: &mut usize) -> Option<u8> {
    let wide = unsigned(lookup(root, &["smartctl", "exit_status"]), rejected);
    let narrow = wide.and_then(|value| u8::try_from(value).ok());
    if wide.is_some() && narrow.is_none() {
        *rejected += 1;
    }
    narrow
}


fn protocol(root: &Value, rejected: &mut usize) -> Option<Protocol> {
    text(lookup(root, &["device", "protocol"]), rejected).map(|name| match name.as_str() {
        "ATA" => Protocol::Ata,
        "NVMe" => Protocol::Nvme,
        "SCSI" => Protocol::Scsi,
        _ => Protocol::Other(name),
    })
}


fn is_nvme_lookalike(kind: &Option<Protocol>) -> bool {
    matches!(kind, Some(Protocol::Other(name)) if name.eq_ignore_ascii_case("NVMe"))
}


fn when_failed(row: &Value, rejected: &mut usize) -> Option<WhenFailed> {
    let label = accepted(row.get("when_failed"), rejected, Value::is_string).and_then(Value::as_str);
    let parsed = label.and_then(|name| match name {
        "now" => Some(WhenFailed::Now),
        "past" => Some(WhenFailed::Past),
        "" => Some(WhenFailed::Never),
        _ => None,
    });
    if label.is_some() && parsed.is_none() {
        *rejected += 1;
    }
    parsed
}


fn attribute(row: &Value, rejected: &mut usize, unreadable: &mut Vec<String>) -> Option<Attribute> {
    row.get("id").and_then(Value::as_u64).map(|id| {
        let when = when_failed(row, rejected);
        let value = unsigned(row.get("value"), rejected);
        let threshold = unsigned(row.get("thresh"), rejected);
        let prefailure_node = lookup(row, &["flags", "prefailure"]);
        let flags_unusable = row.get("flags").is_some_and(|node| !node.is_object());
        let failing_without_flag = when == Some(WhenFailed::Now) && prefailure_node.is_none();
        if flags_unusable || failing_without_flag {
            unreadable.push(format!("attribute {id} flags"));
        }
        let prefailure = accepted(prefailure_node, rejected, Value::is_boolean).and_then(Value::as_bool);
        let mut flagged = vec![
            ("prefailure", prefailure_node, prefailure.is_none()),
            ("when_failed", row.get("when_failed"), when.is_none()),
        ];
        if prefailure != Some(false) {
            flagged.extend([
                ("value", row.get("value"), value.is_none()),
                ("thresh", row.get("thresh"), threshold.is_none()),
            ]);
        }
        flagged
            .into_iter()
            .for_each(|(field, node, absent)| flag_unreadable(unreadable, format!("attribute {id} {field}"), node, absent));
        Attribute {
            id,
            name: text(row.get("name"), rejected),
            value,
            worst: unsigned(row.get("worst"), rejected),
            threshold,
            when_failed: when,
            prefailure,
            raw_value: unsigned(lookup(row, &["raw", "value"]), rejected),
        }
    })
}


fn attributes(root: &Value, limits: &Limits, rejected: &mut usize, unreadable: &mut Vec<String>) -> (Vec<Attribute>, usize) {
    let container_bad = root.get("ata_smart_attributes").is_some_and(|node| !node.is_object());
    let table_node = lookup(root, &["ata_smart_attributes", "table"]);
    let table = accepted(table_node, rejected, Value::is_array).and_then(Value::as_array);
    if container_bad || (table_node.is_some() && table.is_none()) {
        unreadable.push("attribute table".to_string());
    }
    let rows = table.map_or(&[][..], Vec::as_slice);
    let kept = rows
        .iter()
        .take(limits.max_attributes)
        .enumerate()
        .filter_map(|(index, row)| {
            let parsed = attribute(row, rejected, unreadable);
            if parsed.is_none() {
                *rejected += 1;
                unreadable.push(format!("attribute row {index}"));
            }
            parsed
        })
        .collect();
    (kept, rows.len().saturating_sub(limits.max_attributes))
}


fn nvme(root: &Value, rejected: &mut usize, unreadable: &mut Vec<String>) -> Option<NvmeHealth> {
    root.get("nvme_smart_health_information_log").map(|log| {
        if !log.is_object() {
            unreadable.push("nvme log".to_string());
        }
        if log.is_object() && log.get("critical_warning").is_none() {
            unreadable.push("nvme critical_warning".to_string());
        }
        let mut field = |name: &str| {
            let parsed = unsigned(log.get(name), rejected);
            flag_unreadable(unreadable, format!("nvme {name}"), log.get(name), parsed.is_none());
            parsed
        };
        NvmeHealth {
            critical_warning: field("critical_warning"),
            available_spare: field("available_spare"),
            available_spare_threshold: field("available_spare_threshold"),
            percentage_used: field("percentage_used"),
            media_errors: field("media_errors"),
        }
    })
}


fn assemble(root: &Value, limits: &Limits) -> SmartReport {
    let mut rejected = 0;
    let device_name = text(lookup(root, &["device", "name"]), &mut rejected);
    let protocol_kind = protocol(root, &mut rejected);
    let model = text(root.get("model_name"), &mut rejected);
    let serial = text(root.get("serial_number"), &mut rejected);
    let exit = exit_status(root, &mut rejected);
    let smart_passed = accepted(lookup(root, &["smart_status", "passed"]), &mut rejected, Value::is_boolean).and_then(Value::as_bool);
    let temperature_celsius = accepted(lookup(root, &["temperature", "current"]), &mut rejected, Value::is_i64).and_then(Value::as_i64);
    let power_on_hours = unsigned(lookup(root, &["power_on_time", "hours"]), &mut rejected);
    let format = format_major(root, &mut rejected);
    let mut unreadable = Vec::new();
    flag_unreadable(
        &mut unreadable,
        "smart_status.passed".to_string(),
        lookup(root, &["smart_status", "passed"]),
        smart_passed.is_none(),
    );
    flag_unreadable(
        &mut unreadable,
        "exit_status".to_string(),
        lookup(root, &["smartctl", "exit_status"]),
        exit.is_none(),
    );
    let (attribute_list, omitted_attributes) = attributes(root, limits, &mut rejected, &mut unreadable);
    let is_nvme = protocol_kind == Some(Protocol::Nvme);
    let nvme_health = nvme(root, &mut rejected, &mut unreadable);
    if is_nvme && nvme_health.is_none() {
        unreadable.push("nvme log".to_string());
    }
    flag_unreadable(
        &mut unreadable,
        "device.protocol".to_string(),
        lookup(root, &["device", "protocol"]),
        (protocol_kind.is_none() || is_nvme_lookalike(&protocol_kind)) && nvme_health.is_none(),
    );
    SmartReport {
        device_name,
        protocol: protocol_kind,
        model,
        serial,
        exit_status: exit,
        smart_passed,
        temperature_celsius,
        power_on_hours,
        attributes: attribute_list,
        omitted_attributes,
        nvme: nvme_health,
        rejected_fields: rejected,
        format_major: format,
        unreadable_health: unreadable,
    }
}
