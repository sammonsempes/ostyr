use device_control::evaluate::{evaluate, expired_exceptions, next_change};
use device_control::limits::MAX_INTERFACES;
use device_control::model::{Action, Decision, Matched, Policy, UsbDevice};
use device_control::parse::parse_policy;
use std::error::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const RULE_VENDOR_ONLY: usize = 2;


const RULE_PRODUCT_ONLY: usize = 3;


const RULE_SERIAL: usize = 4;


const RULE_CLASS_ONLY: usize = 5;


const BOTH_EXPIRED: usize = 2;


const BEFORE_EXPIRY: &str = "2029-12-31T23:59:59Z";


const FIRST_EXPIRY: &str = "2030-01-01T00:00:00Z";


const AFTER_EXPIRY: &str = "2030-01-01T00:00:01Z";


const SECOND_EXPIRY: &str = "2030-06-01T00:00:00Z";


const LONG_AFTER: &str = "2031-01-01T00:00:00Z";


fn policy(mode: &str) -> Result<Policy, Box<dyn Error>> {
    let text = format!(
        "mode: {mode}
default: block
rules:
  - {{action: block, class: \"08\"}}
  - {{action: allow, vendor: \"046d\", product: \"c52b\"}}
  - {{action: allow, vendor: \"1d6b\"}}
  - {{action: allow, vendor: \"9999\", product: \"0001\"}}
  - {{action: allow, vendor: \"0781\", serial: \"S1\"}}
  - {{action: allow, class: \"03\"}}
exceptions:
  - rule: {{action: allow, vendor: \"0781\", product: \"5567\"}}
    owner: alice
    expires: {FIRST_EXPIRY}
    reason: firmware stick
  - rule: {{action: block, vendor: \"046d\", product: \"c52b\"}}
    owner: bob
    expires: {SECOND_EXPIRY}
    reason: recalled receiver
"
    );
    Ok(parse_policy(&mut text.as_bytes(), "policy.yaml")?)
}


fn device(vendor: &str, product: &str, serial: Option<&str>, classes: &[&str]) -> UsbDevice {
    UsbDevice {
        vendor: vendor.to_string(),
        product: product.to_string(),
        serial: serial.map(str::to_string),
        interfaces: classes
            .iter()
            .map(|class| (class.to_string(), "00".to_string(), "00".to_string()))
            .collect(),
    }
}


fn at(text: &str) -> Result<OffsetDateTime, Box<dyn Error>> {
    Ok(OffsetDateTime::parse(text, &Rfc3339)?)
}


#[test]
fn a_live_exception_wins_over_a_block_rule() -> Result<(), Box<dyn Error>> {
    let storage = device("0781", "5567", None, &["08"]);
    let decision = evaluate(&policy("enforce")?, &storage, at(BEFORE_EXPIRY)?);
    assert_eq!(decision, Decision::Allow { rule: Matched::Exception(0) });
    Ok(())
}


#[test]
fn an_exception_expiring_exactly_now_no_longer_matches() -> Result<(), Box<dyn Error>> {
    let storage = device("0781", "5567", None, &["08"]);
    let decision = evaluate(&policy("enforce")?, &storage, at(FIRST_EXPIRY)?);
    assert_eq!(decision, Decision::Block { rule: Matched::Rule(0) });
    let later = evaluate(&policy("enforce")?, &storage, at(AFTER_EXPIRY)?);
    assert_eq!(later, Decision::Block { rule: Matched::Rule(0) });
    Ok(())
}


#[test]
fn a_block_exception_beats_an_allow_rule_until_it_expires() -> Result<(), Box<dyn Error>> {
    let receiver = device("046d", "c52b", None, &["03"]);
    let live = evaluate(&policy("enforce")?, &receiver, at(BEFORE_EXPIRY)?);
    assert_eq!(live, Decision::Block { rule: Matched::Exception(1) });
    let expired = evaluate(&policy("enforce")?, &receiver, at(SECOND_EXPIRY)?);
    assert_eq!(expired, Decision::Allow { rule: Matched::Rule(1) });
    Ok(())
}


#[test]
fn a_composite_device_with_a_storage_interface_is_blocked() -> Result<(), Box<dyn Error>> {
    let composite = device("046d", "c52b", None, &["03", "08"]);
    let decision = evaluate(&policy("enforce")?, &composite, at(LONG_AFTER)?);
    assert_eq!(decision, Decision::Block { rule: Matched::Rule(0) });
    Ok(())
}


#[test]
fn matching_is_exact_on_every_attribute() -> Result<(), Box<dyn Error>> {
    let now = at(LONG_AFTER)?;
    let enforce = policy("enforce")?;
    let cases = [
        (
            device("1d6b", "0002", None, &["09"]),
            Decision::Allow {
                rule: Matched::Rule(RULE_VENDOR_ONLY),
            },
        ),
        (
            device("9999", "0001", None, &["09"]),
            Decision::Allow {
                rule: Matched::Rule(RULE_PRODUCT_ONLY),
            },
        ),
        (
            device("0781", "9999", Some("S1"), &["09"]),
            Decision::Allow {
                rule: Matched::Rule(RULE_SERIAL),
            },
        ),
        (device("0781", "9999", Some("S2"), &["09"]), Decision::Block { rule: Matched::Default }),
        (device("0781", "9999", None, &["09"]), Decision::Block { rule: Matched::Default }),
        (
            device("046d", "9999", None, &["03"]),
            Decision::Allow {
                rule: Matched::Rule(RULE_CLASS_ONLY),
            },
        ),
        (device("046d", "c52b", None, &["09"]), Decision::Allow { rule: Matched::Rule(1) }),
        (device("046d", "c52c", None, &["09"]), Decision::Block { rule: Matched::Default }),
        (device("1d6c", "0002", None, &[]), Decision::Block { rule: Matched::Default }),
    ];
    cases.iter().try_for_each(|(usb, expected)| {
        assert_eq!(evaluate(&enforce, usb, now), *expected);
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn audit_mode_reports_what_would_happen_and_blocks_nothing() -> Result<(), Box<dyn Error>> {
    let audit = policy("audit")?;
    let now = at(LONG_AFTER)?;
    let blocked = evaluate(&audit, &device("046d", "c52b", None, &["08"]), now);
    assert_eq!(
        blocked,
        Decision::Audit {
            would: Action::Block,
            rule: Matched::Rule(0)
        }
    );
    let allowed = evaluate(&audit, &device("1d6b", "0002", None, &["09"]), now);
    assert_eq!(
        allowed,
        Decision::Audit {
            would: Action::Allow,
            rule: Matched::Rule(RULE_VENDOR_ONLY)
        }
    );
    Ok(())
}


#[test]
fn a_device_with_too_many_interfaces_is_blocked_with_bounded_work() -> Result<(), Box<dyn Error>> {
    let now = at(LONG_AFTER)?;
    let accepted = device("1d6b", "0002", None, &vec!["09"; MAX_INTERFACES]);
    assert_eq!(
        evaluate(&policy("enforce")?, &accepted, now),
        Decision::Allow {
            rule: Matched::Rule(RULE_VENDOR_ONLY)
        }
    );
    let oversized = device("1d6b", "0002", None, &vec!["09"; MAX_INTERFACES + 1]);
    assert_eq!(
        evaluate(&policy("enforce")?, &oversized, now),
        Decision::Block { rule: Matched::Oversized }
    );
    assert_eq!(
        evaluate(&policy("audit")?, &oversized, now),
        Decision::Audit {
            would: Action::Block,
            rule: Matched::Oversized
        }
    );
    Ok(())
}


#[test]
fn expired_exceptions_are_reported() -> Result<(), Box<dyn Error>> {
    let subject = policy("enforce")?;
    assert_eq!(expired_exceptions(&subject, at(BEFORE_EXPIRY)?).len(), 0);
    assert_eq!(expired_exceptions(&subject, at(FIRST_EXPIRY)?).len(), 1);
    assert_eq!(expired_exceptions(&subject, at(SECOND_EXPIRY)?).len(), BOTH_EXPIRED);
    Ok(())
}


#[test]
fn a_device_report_in_uppercase_hex_cannot_dodge_a_block() -> Result<(), Box<dyn Error>> {
    let now = at(LONG_AFTER)?;
    let enforce = policy("enforce")?;
    let shouting = UsbDevice {
        vendor: "046D".to_string(),
        product: "C52B".to_string(),
        serial: None,
        interfaces: vec![
            ("08".to_string(), "06".to_string(), "50".to_string()),
            ("0A".to_string(), "00".to_string(), "00".to_string()),
        ],
    };
    assert_eq!(evaluate(&enforce, &shouting, now), Decision::Block { rule: Matched::Rule(0) });
    let mixed = device("046D", "C52B", None, &["03"]);
    assert_eq!(evaluate(&enforce, &mixed, now), Decision::Allow { rule: Matched::Rule(1) });
    Ok(())
}


#[test]
fn an_invalid_device_is_blocked_never_allowed() -> Result<(), Box<dyn Error>> {
    let now = at(LONG_AFTER)?;
    let allow_all = parse_policy(
        &mut "mode: enforce\ndefault: allow\nrules:\n  - {action: allow, class: \"03\"}\n".as_bytes(),
        "p.yaml",
    )?;
    let invalid = [
        device("VID_0781", "5567", None, &["03"]),
        device("0781", "55", None, &["03"]),
        device("0781", "5567", None, &["xyz"]),
        device("0781", "5567", None, &["03", ""]),
        device("", "", None, &[]),
    ];
    invalid.iter().for_each(|usb| {
        assert_eq!(
            evaluate(&allow_all, usb, now),
            Decision::Block {
                rule: Matched::InvalidDevice
            }
        );
    });
    let audit = parse_policy(&mut "default: allow\n".as_bytes(), "p.yaml")?;
    assert_eq!(
        evaluate(&audit, &invalid[0], now),
        Decision::Audit {
            would: Action::Block,
            rule: Matched::InvalidDevice
        }
    );
    Ok(())
}


#[test]
fn next_change_is_the_nearest_future_expiry() -> Result<(), Box<dyn Error>> {
    let subject = policy("enforce")?;
    assert_eq!(next_change(&subject, at(BEFORE_EXPIRY)?), Some(at(FIRST_EXPIRY)?));
    assert_eq!(next_change(&subject, at(FIRST_EXPIRY)?), Some(at(SECOND_EXPIRY)?));
    assert_eq!(next_change(&subject, at(SECOND_EXPIRY)?), None);
    Ok(())
}
