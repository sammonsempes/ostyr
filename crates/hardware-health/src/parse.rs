//! Bounded, strict parse of the smartctl JSON.

use crate::error::SmartError;
use crate::grammar::is_clean_ident;
use crate::model::{Attribute, Limits, NvmeHealth, Protocol, SmartReport, WhenFailed};
use serde_json::Value;
use std::io::Read;


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


fn attribute(row: &Value, rejected: &mut usize) -> Option<Attribute> {
    row.get("id").and_then(Value::as_u64).map(|id| Attribute {
        id,
        name: text(row.get("name"), rejected),
        value: unsigned(row.get("value"), rejected),
        worst: unsigned(row.get("worst"), rejected),
        threshold: unsigned(row.get("thresh"), rejected),
        when_failed: when_failed(row, rejected),
        prefailure: accepted(lookup(row, &["flags", "prefailure"]), rejected, Value::is_boolean).and_then(Value::as_bool),
        raw_value: unsigned(lookup(row, &["raw", "value"]), rejected),
    })
}


fn attributes(root: &Value, limits: &Limits, rejected: &mut usize) -> (Vec<Attribute>, usize) {
    let table = accepted(lookup(root, &["ata_smart_attributes", "table"]), rejected, Value::is_array).and_then(Value::as_array);
    let rows = table.map_or(&[][..], Vec::as_slice);
    let kept = rows
        .iter()
        .take(limits.max_attributes)
        .filter_map(|row| {
            let parsed = attribute(row, rejected);
            if parsed.is_none() {
                *rejected += 1;
            }
            parsed
        })
        .collect();
    (kept, rows.len().saturating_sub(limits.max_attributes))
}


fn nvme(root: &Value, rejected: &mut usize) -> Option<NvmeHealth> {
    root.get("nvme_smart_health_information_log").map(|log| NvmeHealth {
        critical_warning: unsigned(log.get("critical_warning"), rejected),
        available_spare: unsigned(log.get("available_spare"), rejected),
        available_spare_threshold: unsigned(log.get("available_spare_threshold"), rejected),
        percentage_used: unsigned(log.get("percentage_used"), rejected),
        media_errors: unsigned(log.get("media_errors"), rejected),
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
    let (attribute_list, omitted_attributes) = attributes(root, limits, &mut rejected);
    let nvme_health = nvme(root, &mut rejected);
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
    }
}
