use crate::limits::MAX_INTERFACES;
use crate::model::{Action, Decision, Exception, Matched, Mode, Policy, Rule, UsbDevice};
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


pub fn decide(policy: &Policy, device: &UsbDevice, now: OffsetDateTime) -> (Action, Matched) {
    if device.interfaces.len() > MAX_INTERFACES {
        (Action::Block, Matched::Oversized)
    } else {
        first_exception(policy, device, now)
            .or_else(|| first_rule(policy, device, Action::Block))
            .or_else(|| first_rule(policy, device, Action::Allow))
            .unwrap_or((policy.default, Matched::Default))
    }
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
