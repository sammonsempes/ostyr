use crate::error::RenderError;
use crate::evaluate::{expired_exceptions, is_live};
use crate::model::{Action, Mode, Policy, Rule, RuleFile};
use time::OffsetDateTime;


/// USBGuard refuses `*:*:*` and `equals { }`, so a device with no interface is matched by `none-of` over all 256 classes.
pub fn no_interface_rule() -> String {
    let classes: String = (0..=u8::MAX).map(|class| format!(" {class:02x}:*:*")).collect();
    format!("block with-interface none-of {{{classes} }}\n")
}


pub fn target(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Block => "block",
    }
}


/// Ids are `VVVV:PPPP`, `VVVV:*` or absent (USBGuard refuses `*:PPPP`); every value is validated, so nothing is escaped.
pub fn rule_line(rule: &Rule) -> String {
    let identity = rule.vendor.as_ref().map(|vendor| {
        let product = rule.product.as_ref().map_or("*", |id| id.0.as_str());
        format!("id {}:{product}", vendor.0)
    });
    let serial = rule.serial.as_ref().map(|serial| format!("serial \"{}\"", serial.0));
    let interface = rule.class.as_ref().map(|class| format!("with-interface one-of {{ {}:*:* }}", class.0));
    [Some(target(rule.action).to_string()), identity, serial, interface]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
}


/// A leading rule blocks a device with no interface, as `evaluate` does, whatever `default`. Live exceptions next, then block rules, then allow rules, in file order; USBGuard applies the first matching line.
pub fn render_usbguard(policy: &Policy, now: OffsetDateTime) -> Result<RuleFile, RenderError> {
    match policy.mode {
        Mode::Audit => Err(RenderError::AuditMode),
        Mode::Enforce => {
            let exceptions = policy
                .exceptions
                .iter()
                .filter(|exception| is_live(exception, now))
                .map(|exception| &exception.rule);
            let blocks = policy.rules.iter().filter(|rule| rule.action == Action::Block);
            let allows = policy.rules.iter().filter(|rule| rule.action == Action::Allow);
            let body: String = exceptions
                .chain(blocks)
                .chain(allows)
                .map(|rule| format!("{}\n", rule_line(rule)))
                .collect();
            let rules = format!("{}{body}", no_interface_rule());
            Ok(RuleFile {
                rules,
                implicit_target: policy.default,
            })
        }
    }
}


pub fn summarize(policy: &Policy, now: OffsetDateTime) -> String {
    format!(
        "mode={:?} default={:?} rules={} exceptions={} expired={}",
        policy.mode,
        policy.default,
        policy.rules.len(),
        policy.exceptions.len(),
        expired_exceptions(policy, now).len()
    )
}
