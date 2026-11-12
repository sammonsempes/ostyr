use crate::limits::{CLASS_DIGITS, ID_DIGITS, MAX_INTERFACES, STORAGE_CLASS};
use crate::model::{Action, Decision, Exception, Matched, Mode, Policy, Rule, UsbDevice};
use crate::types::InterfaceTriple;
use crate::validate::is_lower_hex;
use time::OffsetDateTime;


pub fn rule_matches(rule: &Rule, device: &UsbDevice) -> bool {
    let class_ok = rule
        .class
        .as_ref()
        .is_none_or(|class| device.interfaces.iter().any(|(code, _, _)| *code == class.0));
    let vendor_ok = rule.vendor.as_ref().is_none_or(|vendor| vendor.0 == device.vendor);
    let product_ok = rule.product.as_ref().is_none_or(|product| product.0 == device.product);
    let serial_ok = rule
        .serial
        .as_ref()
        .is_none_or(|serial| device.serial.as_deref() == Some(serial.0.as_str()));
    [class_ok, vendor_ok, product_ok, serial_ok].into_iter().all(|ok| ok)
}


pub fn first_rule(policy: &Policy, device: &UsbDevice, action: Action) -> Option<(Action, Matched)> {
    policy
        .rules
        .iter()
        .enumerate()
        .find(|(_, rule)| rule.action == action && rule_matches(rule, device))
        .map(|(index, _)| (action, Matched::Rule(index)))
}


pub fn is_live(exception: &Exception, now: OffsetDateTime) -> bool {
    exception.expires > now
}


pub fn first_exception(policy: &Policy, device: &UsbDevice, now: OffsetDateTime) -> Option<(Action, Matched)> {
    policy
        .exceptions
        .iter()
        .enumerate()
        .find(|(_, exception)| is_live(exception, now) && rule_matches(&exception.rule, device))
        .map(|(index, exception)| (exception.rule.action, Matched::Exception(index)))
}


/// Lowercases the hexadecimal fields (Windows reports `VID_0781`) and returns `None` when vendor, product or a class is invalid or there is no interface.
pub fn normalise_device(device: &UsbDevice) -> Option<UsbDevice> {
    let vendor = device.vendor.to_ascii_lowercase();
    let product = device.product.to_ascii_lowercase();
    let interfaces: Vec<InterfaceTriple> = device
        .interfaces
        .iter()
        .map(|(class, subclass, protocol)| (class.to_ascii_lowercase(), subclass.clone(), protocol.clone()))
        .collect();
    let valid = [
        !interfaces.is_empty(),
        is_lower_hex(&vendor, ID_DIGITS),
        is_lower_hex(&product, ID_DIGITS),
    ]
    .into_iter()
    .chain(interfaces.iter().map(|(class, _, _)| is_lower_hex(class, CLASS_DIGITS)))
    .all(|ok| ok);
    valid.then(|| UsbDevice {
        vendor,
        product,
        serial: device.serial.clone(),
        interfaces,
    })
}


pub fn decide_valid(policy: &Policy, device: &UsbDevice, now: OffsetDateTime) -> (Action, Matched) {
    first_exception(policy, device, now)
        .or_else(|| first_rule(policy, device, Action::Block))
        .or_else(|| first_rule(policy, device, Action::Allow))
        .unwrap_or((policy.default, Matched::Default))
}


pub fn decide(policy: &Policy, device: &UsbDevice, now: OffsetDateTime) -> (Action, Matched) {
    if device.interfaces.len() > MAX_INTERFACES {
        (Action::Block, Matched::Oversized)
    } else {
        normalise_device(device).map_or((Action::Block, Matched::InvalidDevice), |valid| decide_valid(policy, &valid, now))
    }
}


/// The nearest future expiry: the moment the agent re-renders, since a rendered file carries no expiry.
pub fn next_change(policy: &Policy, now: OffsetDateTime) -> Option<OffsetDateTime> {
    policy
        .exceptions
        .iter()
        .map(|exception| exception.expires)
        .filter(|expires| *expires > now)
        .min()
}


/// Precedence: a live exception, the first matching block rule, the first matching allow rule, the default; audit mode never blocks.
pub fn evaluate(policy: &Policy, device: &UsbDevice, now: OffsetDateTime) -> Decision {
    let (action, rule) = decide(policy, device, now);
    match (policy.mode, action) {
        (Mode::Audit, would) => Decision::Audit { would, rule },
        (Mode::Enforce, Action::Allow) => Decision::Allow { rule },
        (Mode::Enforce, Action::Block) => Decision::Block { rule },
    }
}


pub fn expired_exceptions(policy: &Policy, now: OffsetDateTime) -> Vec<&Exception> {
    policy.exceptions.iter().filter(|exception| !is_live(exception, now)).collect()
}


/// True for an allow rule that matches on a class alone.
pub fn is_class_only_allow(rule: &Rule) -> bool {
    rule.action == Action::Allow && rule.class.is_some() && rule.vendor.is_none() && rule.product.is_none() && rule.serial.is_none()
}


/// Class-only allow rules (when no block on class `08` alone exists) and every live class-only allow exception, which wins over any block.
pub fn class_only_allows(policy: &Policy, now: OffsetDateTime) -> Vec<Matched> {
    let storage_blocked = policy
        .rules
        .iter()
        .any(|rule| rule.action == Action::Block && rule.class.as_ref().is_some_and(|class| class.0 == STORAGE_CLASS) && rule.vendor.is_none());
    let rules = policy
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| !storage_blocked && is_class_only_allow(rule))
        .map(|(index, _)| Matched::Rule(index));
    let exceptions = policy
        .exceptions
        .iter()
        .enumerate()
        .filter(|(_, exception)| is_live(exception, now) && is_class_only_allow(&exception.rule))
        .map(|(index, _)| Matched::Exception(index));
    rules.chain(exceptions).collect()
}
