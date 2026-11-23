use crate::error::RenderError;
use crate::evaluate::is_live;
use crate::limits::{
    ALLOW_DEVICE_IDS, ALLOW_INSTANCE_IDS, DEFAULT_BLOCK_VALUE, DENY_DEVICE_IDS, ENABLED, LAYERED_VALUE, REASON_CLASS, REASON_NO_DEVICE_ID,
    REASON_PRECEDENCE, REASON_SERIAL_CASE, RESTRICTIONS_KEY,
};
use crate::model::{Action, Mode, Policy, RegistryKind, RegistryValue, Rule, WindowsPolicy};
use crate::types::Entry;
use std::collections::BTreeSet;
use time::OffsetDateTime;


/// `USB\VID_VVVV&PID_PPPP` in uppercase, or `None` for a rule that names no vendor and product.
pub fn device_id(rule: &Rule) -> Option<String> {
    rule.vendor
        .as_ref()
        .zip(rule.product.as_ref())
        .map(|(vendor, product)| format!("USB\\VID_{}&PID_{}", vendor.0.to_ascii_uppercase(), product.0.to_ascii_uppercase()))
}


/// Windows compares a serial case-insensitively (live, T784): a serial with a letter would also admit another letter case, which `evaluate` blocks.
pub fn serial_has_letter(rule: &Rule) -> bool {
    rule.serial
        .as_ref()
        .is_some_and(|serial| serial.0.chars().any(|character| character.is_ascii_alphabetic()))
}


pub fn same_device(left: &Rule, right: &Rule) -> bool {
    left.vendor == right.vendor && left.product == right.product
}


/// The fixed reason a rule has no Windows form whose meaning equals `evaluate`, alone or next to the other live entries.
pub fn no_equivalent_reason(entry: &Entry, entries: &[Entry]) -> Option<&'static str> {
    let (_, rule, exception) = *entry;
    let block_on_device = entries
        .iter()
        .any(|(_, other, _)| other.action == Action::Block && same_device(rule, other));
    let instance_allow_on_device = entries
        .iter()
        .any(|(_, other, _)| other.action == Action::Allow && other.serial.is_some() && same_device(rule, other));
    let precedence = match (rule.action, exception, rule.serial.is_some()) {
        (Action::Allow, true, false) | (Action::Allow, false, true) => block_on_device,
        (Action::Block, true, _) => instance_allow_on_device,
        _ => false,
    };
    [
        (rule.class.is_some(), REASON_CLASS),
        (device_id(rule).is_none(), REASON_NO_DEVICE_ID),
        (serial_has_letter(rule), REASON_SERIAL_CASE),
        (precedence, REASON_PRECEDENCE),
    ]
    .iter()
    .find(|(applies, _)| *applies)
    .map(|(_, reason)| *reason)
}


/// Rules first, then live exceptions numbered after the rules (expired exceptions keep their number).
pub fn live_entries(policy: &Policy, now: OffsetDateTime) -> Vec<Entry<'_>> {
    let rules = policy.rules.iter().enumerate().map(|(index, rule)| (index, rule, false));
    let exceptions = policy
        .exceptions
        .iter()
        .enumerate()
        .filter(|(_, exception)| is_live(exception, now))
        .map(|(index, exception)| (policy.rules.len() + index, &exception.rule, true));
    rules.chain(exceptions).collect()
}


pub fn dword(key: &str, name: &str) -> RegistryValue {
    RegistryValue {
        key: key.to_string(),
        name: name.to_string(),
        kind: RegistryKind::Dword,
        data: ENABLED.to_string(),
    }
}


/// The enabling value in the restrictions key, then the list under its own key with values `1` to `n`.
pub fn list_values(name: &str, ids: &BTreeSet<String>) -> Vec<RegistryValue> {
    let list_key = format!("{RESTRICTIONS_KEY}\\{name}");
    let enable = (!ids.is_empty()).then(|| dword(RESTRICTIONS_KEY, name));
    let items = ids.iter().enumerate().map(|(index, id)| RegistryValue {
        key: list_key.clone(),
        name: (index + 1).to_string(),
        kind: RegistryKind::Text,
        data: id.clone(),
    });
    enable.into_iter().chain(items).collect()
}


pub fn instance_id(rule: &Rule, device: &str) -> Option<String> {
    rule.serial.as_ref().map(|serial| format!("{device}\\{}", serial.0))
}


/// The entry named by its own list's index: exceptions are numbered after the rules in `live_entries`.
pub fn refusal(number: usize, is_exception: bool, rule_count: usize, reason: &'static str) -> RenderError {
    let (kind, index) = match is_exception {
        true => ("exception", number.saturating_sub(rule_count)),
        false => ("rule", number),
    };
    RenderError::NoWindowsEquivalent { kind, index, reason }
}


/// Device installation restrictions, layered: only the forms whose Windows meaning equals `evaluate` are written, any other is `NoWindowsEquivalent`.
pub fn render_windows(policy: &Policy, now: OffsetDateTime) -> Result<WindowsPolicy, RenderError> {
    match policy.mode {
        Mode::Audit => Err(RenderError::AuditMode),
        Mode::Enforce => {
            let entries = live_entries(policy, now);
            match entries
                .iter()
                .find_map(|entry| no_equivalent_reason(entry, &entries).map(|reason| (entry, reason)))
            {
                Some(((index, _, is_exception), reason)) => Err(refusal(*index, *is_exception, policy.rules.len(), reason)),
                None => Ok(build(policy, &entries)),
            }
        }
    }
}


/// The artefact as text: `owned <key>` lines, then `<key>\t<name>\t<REG_DWORD|REG_SZ>\t<data>` lines, in artefact order.
pub fn format_windows(policy: &WindowsPolicy) -> String {
    let owned = policy.owned_keys.iter().map(|key| format!("owned\t{key}\n"));
    let values = policy.values.iter().map(|value| {
        let kind = match value.kind {
            RegistryKind::Dword => "REG_DWORD",
            RegistryKind::Text => "REG_SZ",
        };
        format!("{}\t{}\t{kind}\t{}\n", value.key, value.name, value.data)
    });
    owned.chain(values).collect()
}


pub fn build(policy: &Policy, entries: &[Entry]) -> WindowsPolicy {
    let ids = |action: Action, with_serial: bool| -> BTreeSet<String> {
        entries
            .iter()
            .filter(|(_, rule, _)| rule.action == action && rule.serial.is_some() == with_serial)
            .filter_map(|(_, rule, _)| device_id(rule).and_then(|device| instance_id(rule, &device).or(Some(device))))
            .collect()
    };
    let default_block = (policy.default == Action::Block).then(|| dword(RESTRICTIONS_KEY, DEFAULT_BLOCK_VALUE));
    let denied = ids(Action::Block, false);
    let unshadowed: BTreeSet<String> = ids(Action::Allow, false).difference(&denied).cloned().collect();
    let values = std::iter::once(dword(RESTRICTIONS_KEY, LAYERED_VALUE))
        .chain(default_block)
        .chain(list_values(DENY_DEVICE_IDS, &denied))
        .chain(list_values(ALLOW_DEVICE_IDS, &unshadowed))
        .chain(list_values(ALLOW_INSTANCE_IDS, &ids(Action::Allow, true)))
        .collect();
    let owned_keys: Vec<String> = [DENY_DEVICE_IDS, ALLOW_DEVICE_IDS, ALLOW_INSTANCE_IDS]
        .iter()
        .map(|name| format!("{RESTRICTIONS_KEY}\\{name}"))
        .collect();
    WindowsPolicy {
        owned_keys: std::iter::once(RESTRICTIONS_KEY.to_string()).chain(owned_keys).collect(),
        values,
    }
}
