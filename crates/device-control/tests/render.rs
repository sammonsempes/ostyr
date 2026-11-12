use device_control::error::RenderError;
use device_control::limits::ID_DIGITS;
use device_control::model::{Action, Policy};
use device_control::parse::parse_policy;
use device_control::render::{render_usbguard, summarize};
use std::error::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


fn policy(text: &str) -> Result<Policy, Box<dyn Error>> {
    Ok(parse_policy(&mut text.as_bytes(), "policy.yaml")?)
}


fn at(text: &str) -> Result<OffsetDateTime, Box<dyn Error>> {
    Ok(OffsetDateTime::parse(text, &Rfc3339)?)
}


const LINES_WITHOUT_EXCEPTION: usize = 6;


const ENFORCE: &str = "mode: enforce
default: block
rules:
  - {action: allow, vendor: \"1d6b\", product: \"0002\"}
  - {action: block, class: \"08\"}
  - {action: allow, vendor: \"9999\", product: \"0001\"}
  - {action: allow, vendor: \"0781\", serial: \"S-1.2:x\"}
  - {action: block, vendor: \"dead\"}
  - {action: allow, class: \"03\", vendor: \"046d\", product: \"c52b\", serial: \"AB\"}
exceptions:
  - rule: {action: allow, class: \"08\"}
    owner: alice
    expires: 2030-01-01T00:00:00Z
    reason: firmware stick
  - rule: {action: block, vendor: \"beef\"}
    owner: bob
    expires: 2020-01-01T00:00:00Z
    reason: old
";


const EXPECTED: &str = "allow with-interface one-of { 08:*:* }
block with-interface one-of { 08:*:* }
block id dead:*
allow id 1d6b:0002
allow id 9999:0001
allow id 0781:* serial \"S-1.2:x\"
allow id 046d:c52b serial \"AB\" with-interface one-of { 03:*:* }
";


#[test]
fn exceptions_first_then_blocks_then_allows() -> Result<(), Box<dyn Error>> {
    let file = render_usbguard(&policy(ENFORCE)?, at("2029-01-01T00:00:00Z")?)?;
    assert_eq!(file.rules, EXPECTED);
    assert_eq!(file.implicit_target, Action::Block);
    Ok(())
}


#[test]
fn an_expired_exception_is_omitted_and_expiry_is_exclusive() -> Result<(), Box<dyn Error>> {
    let omitted = render_usbguard(&policy(ENFORCE)?, at("2030-01-01T00:00:00Z")?)?;
    assert!(omitted.rules.starts_with("block with-interface"));
    assert_eq!(omitted.rules.lines().count(), LINES_WITHOUT_EXCEPTION);
    Ok(())
}


#[test]
fn rendering_is_deterministic() -> Result<(), Box<dyn Error>> {
    let now = at("2029-01-01T00:00:00Z")?;
    let first = render_usbguard(&policy(ENFORCE)?, now)?;
    let second = render_usbguard(&policy(ENFORCE)?, now)?;
    assert_eq!(first, second);
    Ok(())
}


#[test]
fn the_default_becomes_the_implicit_target() -> Result<(), Box<dyn Error>> {
    let file = render_usbguard(&policy("mode: enforce\ndefault: allow\n")?, at("2029-01-01T00:00:00Z")?)?;
    assert_eq!(file.rules, "");
    assert_eq!(file.implicit_target, Action::Allow);
    Ok(())
}


#[test]
fn audit_mode_is_not_rendered() -> Result<(), Box<dyn Error>> {
    let result = render_usbguard(&policy("default: allow\n")?, at("2029-01-01T00:00:00Z")?);
    assert!(matches!(result, Err(RenderError::AuditMode)));
    Ok(())
}


#[test]
fn the_summary_counts_expired_exceptions() -> Result<(), Box<dyn Error>> {
    let summary = summarize(&policy(ENFORCE)?, at("2029-01-01T00:00:00Z")?);
    assert_eq!(summary, "mode=Enforce default=Block rules=6 exceptions=2 expired=1");
    Ok(())
}


#[test]
fn every_rendered_id_is_a_form_usbguard_accepts() -> Result<(), Box<dyn Error>> {
    let file = render_usbguard(&policy(ENFORCE)?, at("2029-01-01T00:00:00Z")?)?;
    let ids: Vec<&str> = file
        .rules
        .lines()
        .flat_map(|line| line.split(' ').skip_while(|word| *word != "id").nth(1))
        .collect();
    assert_eq!(ids, ["dead:*", "1d6b:0002", "9999:0001", "0781:*", "046d:c52b"]);
    let well_formed = ids.iter().all(|id| {
        let (vendor, product) = id.split_once(':').unwrap_or(("", ""));
        vendor.len() == ID_DIGITS && !vendor.contains('*') && (product == "*" || product.len() == ID_DIGITS)
    });
    assert!(well_formed);
    Ok(())
}
