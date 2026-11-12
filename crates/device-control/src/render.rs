use crate::error::RenderError;
use crate::evaluate::{expired_exceptions, is_live};
use crate::model::{Action, Mode, Policy, Rule, RuleFile};
use time::OffsetDateTime;


pub fn target(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Block => "block",
    }
}


/// Every value comes from a validated grammar, so none can hold a quote, a backslash or a newline and nothing is escaped.
pub fn rule_line(rule: &Rule) -> String {
    let identity = (rule.vendor.is_some() || rule.product.is_some()).then(|| {
        let vendor = rule.vendor.as_ref().map_or("*", |id| id.0.as_str());
        let product = rule.product.as_ref().map_or("*", |id| id.0.as_str());
        format!("id {vendor}:{product}")
    });
    let serial = rule.serial.as_ref().map(|serial| format!("serial \"{}\"", serial.0));
    let interface = rule.class.as_ref().map(|class| format!("with-interface one-of {{ {}:*:* }}", class.0));
    [Some(target(rule.action).to_string()), identity, serial, interface]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
}


/// Live exceptions first, then block rules, then allow rules, in file order; USBGuard applies the first matching line.
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
            let rules = exceptions
                .chain(blocks)
                .chain(allows)
                .map(|rule| format!("{}\n", rule_line(rule)))
                .collect();
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
