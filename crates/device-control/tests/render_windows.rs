use device_control::error::RenderError;
use device_control::evaluate::evaluate;
use device_control::model::{
    Action, ClassCode, Decision, Devnode, Exception, Mode, Owner, Policy, Reason, RegistryKind, Rule, Serial, UsbDevice, UsbId, WindowsPolicy,
};
use device_control::parse::parse_policy;
use device_control::render_windows::{build, format_windows, live_entries, render_windows};
use device_control::windows_model::{chain_nodes, function_installed, windows_installs};
use std::error::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const FIXTURE: &str = include_str!("fixtures/windows.yaml");


const GOLDEN: &str = include_str!("fixtures/windows.golden");


const NOW: &str = "2029-01-01T00:00:00Z";


const LIVE_UNTIL: &str = "2030-01-01T00:00:00Z";


const EXPIRED: &str = "2020-01-01T00:00:00Z";


const MAX_CANDIDATES: usize = 6;


const CHAIN_WITHOUT_FUNCTION: usize = 2;


fn at(text: &str) -> Result<OffsetDateTime, Box<dyn Error>> {
    Ok(OffsetDateTime::parse(text, &Rfc3339)?)
}


fn rule(action: Action, product: &str, serial: Option<&str>) -> Rule {
    Rule {
        action,
        class: None,
        vendor: Some(UsbId("dead".to_string())),
        product: Some(UsbId(product.to_string())),
        serial: serial.map(|text| Serial(text.to_string())),
    }
}


fn exception(rule: Rule, expires: &str) -> Result<Exception, Box<dyn Error>> {
    Ok(Exception {
        rule,
        owner: Owner("alice".to_string()),
        expires: at(expires)?,
        reason: Reason("test".to_string()),
    })
}


fn policy(default: Action, rules: Vec<Rule>, exceptions: Vec<Exception>) -> Policy {
    Policy {
        mode: Mode::Enforce,
        default,
        rules,
        exceptions,
    }
}


fn refused_index(policy: &Policy) -> Result<Option<usize>, Box<dyn Error>> {
    Ok(match render_windows(policy, at(NOW)?) {
        Err(RenderError::NoWindowsEquivalent { index }) => Some(index),
        Err(other) => Err(other)?,
        Ok(_) => None,
    })
}


#[test]
fn the_fixture_renders_to_the_golden() -> Result<(), Box<dyn Error>> {
    let parsed = parse_policy(&mut FIXTURE.as_bytes(), "windows.yaml")?;
    let rendered = format_windows(&render_windows(&parsed, at(NOW)?)?);
    assert_eq!(rendered, GOLDEN);
    assert_eq!(rendered, format_windows(&render_windows(&parsed, at(NOW)?)?));
    Ok(())
}


#[test]
fn every_rendered_data_is_a_registry_safe_text() -> Result<(), Box<dyn Error>> {
    let parsed = parse_policy(&mut FIXTURE.as_bytes(), "windows.yaml")?;
    let artefact = render_windows(&parsed, at(NOW)?)?;
    let safe = |text: &str| {
        text.chars()
            .all(|character| character.is_ascii_alphanumeric() || "_&\\.:-".contains(character))
    };
    assert!(artefact
        .values
        .iter()
        .all(|value| safe(&value.data) && safe(&value.name) && safe(&value.key)));
    assert!(artefact.values.iter().any(|value| value.kind == RegistryKind::Text));
    assert!(artefact.values.iter().all(|value| !value.data.contains(['*', '?'])));
    Ok(())
}


#[test]
fn an_audit_policy_is_refused() -> Result<(), Box<dyn Error>> {
    let mut audit = policy(Action::Allow, vec![], vec![]);
    audit.mode = Mode::Audit;
    assert!(matches!(render_windows(&audit, at(NOW)?), Err(RenderError::AuditMode)));
    Ok(())
}


#[test]
fn the_default_maps_to_the_removable_devices_value() -> Result<(), Box<dyn Error>> {
    let block = format_windows(&render_windows(&policy(Action::Block, vec![], vec![]), at(NOW)?)?);
    let allow = format_windows(&render_windows(&policy(Action::Allow, vec![], vec![]), at(NOW)?)?);
    assert!(block.contains("\tDenyRemovableDevices\tREG_DWORD\t1\n"));
    assert!(!allow.contains("DenyRemovableDevices"));
    assert!(allow.contains("\tAllowDenyLayered\tREG_DWORD\t1\n"));
    assert!(!allow.contains("DenyUnspecified") && !block.contains("AllowAdminInstall"));
    Ok(())
}


#[test]
fn a_class_rule_is_never_rendered_as_nothing() -> Result<(), Box<dyn Error>> {
    let class = |action| Rule {
        action,
        class: Some(ClassCode("03".to_string())),
        vendor: None,
        product: None,
        serial: None,
    };
    assert_eq!(refused_index(&policy(Action::Block, vec![class(Action::Block)], vec![]))?, Some(0));
    assert_eq!(refused_index(&policy(Action::Block, vec![class(Action::Allow)], vec![]))?, Some(0));
    let with_vendor = Rule {
        vendor: Some(UsbId("dead".to_string())),
        ..class(Action::Block)
    };
    assert_eq!(refused_index(&policy(Action::Allow, vec![with_vendor], vec![]))?, Some(0));
    let in_exception = vec![exception(class(Action::Allow), LIVE_UNTIL)?];
    let ok_rule = rule(Action::Block, "beef", None);
    assert_eq!(refused_index(&policy(Action::Block, vec![ok_rule], in_exception))?, Some(1));
    Ok(())
}


#[test]
fn a_vendor_only_form_is_refused() -> Result<(), Box<dyn Error>> {
    let vendor_only = |action, serial: Option<&str>| Rule {
        product: None,
        serial: serial.map(|text| Serial(text.to_string())),
        ..rule(action, "beef", None)
    };
    assert_eq!(
        refused_index(&policy(Action::Allow, vec![vendor_only(Action::Block, None)], vec![]))?,
        Some(0)
    );
    assert_eq!(
        refused_index(&policy(Action::Block, vec![vendor_only(Action::Allow, Some("1"))], vec![]))?,
        Some(0)
    );
    Ok(())
}


#[test]
fn a_serial_with_a_letter_is_refused_because_windows_ignores_case() -> Result<(), Box<dyn Error>> {
    let lettered = policy(Action::Block, vec![rule(Action::Allow, "beef", Some("AB"))], vec![]);
    assert_eq!(refused_index(&lettered)?, Some(0));
    let digits = policy(Action::Block, vec![rule(Action::Allow, "beef", Some("1234.5-6:7"))], vec![]);
    assert_eq!(refused_index(&digits)?, None);
    let rendered = format_windows(&render_windows(&digits, at(NOW)?)?);
    assert!(rendered.contains("\t1\tREG_SZ\tUSB\\VID_DEAD&PID_BEEF\\1234.5-6:7\n"));
    Ok(())
}


#[test]
fn an_allow_exception_without_serial_next_to_a_block_is_refused_in_either_order() -> Result<(), Box<dyn Error>> {
    let allow = || exception(rule(Action::Allow, "beef", None), LIVE_UNTIL);
    let block = || exception(rule(Action::Block, "beef", None), LIVE_UNTIL);
    let block_rule = policy(Action::Allow, vec![rule(Action::Block, "beef", None)], vec![allow()?]);
    assert_eq!(refused_index(&block_rule)?, Some(1));
    let allow_first = policy(Action::Allow, vec![], vec![allow()?, block()?]);
    assert_eq!(refused_index(&allow_first)?, Some(0));
    let block_first = policy(Action::Allow, vec![], vec![block()?, allow()?]);
    assert_eq!(refused_index(&block_first)?, Some(1));
    Ok(())
}


#[test]
fn an_expired_exception_is_not_counted_in_a_refusal() -> Result<(), Box<dyn Error>> {
    let expired_allow = exception(rule(Action::Allow, "beef", None), EXPIRED)?;
    let live_block = exception(rule(Action::Block, "beef", None), LIVE_UNTIL)?;
    assert_eq!(refused_index(&policy(Action::Allow, vec![], vec![expired_allow, live_block]))?, None);
    let expired_block = exception(rule(Action::Block, "beef", None), EXPIRED)?;
    let serial_allow = rule(Action::Allow, "beef", Some("1"));
    assert_eq!(refused_index(&policy(Action::Block, vec![serial_allow], vec![expired_block]))?, None);
    Ok(())
}


#[test]
fn an_allow_rule_with_serial_next_to_a_block_is_refused() -> Result<(), Box<dyn Error>> {
    let serial_allow = rule(Action::Allow, "beef", Some("1"));
    let block_rule = policy(Action::Block, vec![serial_allow.clone(), rule(Action::Block, "beef", None)], vec![]);
    assert_eq!(refused_index(&block_rule)?, Some(0));
    let block_exception = policy(
        Action::Block,
        vec![serial_allow],
        vec![exception(rule(Action::Block, "beef", None), LIVE_UNTIL)?],
    );
    assert_eq!(refused_index(&block_exception)?, Some(0));
    Ok(())
}


#[test]
fn a_block_exception_next_to_an_instance_allow_is_refused() -> Result<(), Box<dyn Error>> {
    let block = exception(rule(Action::Block, "beef", None), LIVE_UNTIL)?;
    let allow_exception = exception(rule(Action::Allow, "beef", Some("1")), LIVE_UNTIL)?;
    assert_eq!(refused_index(&policy(Action::Block, vec![], vec![allow_exception, block]))?, Some(1));
    let other_device = exception(rule(Action::Allow, "0001", Some("1")), LIVE_UNTIL)?;
    let block_again = exception(rule(Action::Block, "beef", None), LIVE_UNTIL)?;
    assert_eq!(refused_index(&policy(Action::Block, vec![], vec![other_device, block_again]))?, None);
    Ok(())
}


#[test]
fn the_consistent_pairs_render() -> Result<(), Box<dyn Error>> {
    let block = || rule(Action::Block, "beef", None);
    let allow = || rule(Action::Allow, "beef", None);
    let instance = || exception(rule(Action::Allow, "beef", Some("1")), LIVE_UNTIL);
    assert_eq!(refused_index(&policy(Action::Allow, vec![block(), allow()], vec![]))?, None);
    assert_eq!(refused_index(&policy(Action::Allow, vec![block()], vec![instance()?]))?, None);
    let block_exception = exception(block(), LIVE_UNTIL)?;
    assert_eq!(refused_index(&policy(Action::Allow, vec![allow()], vec![block_exception]))?, None);
    Ok(())
}


fn candidates() -> Result<Vec<(bool, Rule)>, Box<dyn Error>> {
    Ok(vec![
        (false, rule(Action::Block, "beef", None)),
        (false, rule(Action::Allow, "beef", None)),
        (false, rule(Action::Allow, "beef", Some("1"))),
        (true, rule(Action::Allow, "beef", None)),
        (true, rule(Action::Allow, "beef", Some("1"))),
        (true, rule(Action::Block, "beef", None)),
    ])
}


fn policy_from_mask(mask: usize, default: Action) -> Result<Policy, Box<dyn Error>> {
    let picked: Vec<(bool, Rule)> = candidates()?
        .into_iter()
        .enumerate()
        .filter(|(position, _)| mask >> position & 1 == 1)
        .map(|(_, candidate)| candidate)
        .collect();
    let rules = picked
        .iter()
        .filter(|(is_exception, _)| !is_exception)
        .map(|(_, picked_rule)| picked_rule.clone())
        .collect();
    let exceptions = picked
        .iter()
        .filter(|(is_exception, _)| *is_exception)
        .map(|(_, picked_rule)| exception(picked_rule.clone(), LIVE_UNTIL))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(policy(default, rules, exceptions))
}


fn device(product: &str, serial: Option<&str>, classes: &[&str]) -> UsbDevice {
    UsbDevice {
        vendor: "dead".to_string(),
        product: product.to_string(),
        serial: serial.map(str::to_string),
        interfaces: classes
            .iter()
            .map(|class| (class.to_string(), "00".to_string(), "00".to_string()))
            .collect(),
    }
}


fn matrix() -> Vec<(UsbDevice, bool)> {
    let class_sets: Vec<&[&str]> = vec![
        &["08"],
        &["03"],
        &["03", "08"],
        &["08", "08"],
        &["ff"],
        &["03", "03"],
        &["08", "03", "ff"],
    ];
    let serials = [None, Some("1"), Some("2")];
    ["beef", "0001"]
        .into_iter()
        .flat_map(|product| serials.into_iter().map(move |serial| (product, serial)))
        .flat_map(|(product, serial)| class_sets.iter().map(move |classes| device(product, serial, classes)))
        .flat_map(|candidate| [true, false].map(|composite| (candidate.clone(), composite)))
        .collect()
}


fn allowed(policy: &Policy, device: &UsbDevice) -> Result<bool, Box<dyn Error>> {
    Ok(matches!(evaluate(policy, device, at(NOW)?), Decision::Allow { .. }))
}


fn first_node(device: &UsbDevice) -> Result<Devnode, Box<dyn Error>> {
    Ok(chain_nodes(device, 0, false, false).into_iter().next().ok_or("no parent")?)
}


fn installed_functions(candidate: &Policy, artefact: &WindowsPolicy) -> Result<usize, Box<dyn Error>> {
    let mut installed = 0;
    for (device, composite) in matrix() {
        let admitted = allowed(candidate, &device)?;
        assert_eq!(
            windows_installs(artefact, &first_node(&device)?),
            admitted,
            "parent of {device:?} under {candidate:?}"
        );
        for child_removable in [true, false] {
            for index in 0..device.interfaces.len() {
                if function_installed(artefact, &chain_nodes(&device, index, composite, child_removable)) {
                    installed += 1;
                    assert!(admitted, "function {index} of {device:?} under {candidate:?}");
                }
            }
        }
    }
    Ok(installed)
}


#[test]
fn every_function_windows_installs_is_admitted_by_evaluate() -> Result<(), Box<dyn Error>> {
    let (mut rendered, mut refused, mut installed) = (0, 0, 0);
    for mask in 0..1usize << MAX_CANDIDATES {
        for default in [Action::Allow, Action::Block] {
            let candidate = policy_from_mask(mask, default)?;
            match render_windows(&candidate, at(NOW)?) {
                Err(_) => refused += 1,
                Ok(artefact) => {
                    rendered += 1;
                    installed += installed_functions(&candidate, &artefact)?;
                }
            }
        }
    }
    assert!(rendered > 0 && refused > 0 && installed > 0);
    Ok(())
}


#[test]
fn each_refused_pair_would_diverge_from_evaluate_if_rendered() -> Result<(), Box<dyn Error>> {
    let serial_allow = rule(Action::Allow, "beef", Some("1"));
    let pairs = [
        policy(
            Action::Allow,
            vec![rule(Action::Block, "beef", None)],
            vec![exception(rule(Action::Allow, "beef", None), LIVE_UNTIL)?],
        ),
        policy(Action::Allow, vec![rule(Action::Block, "beef", None), serial_allow.clone()], vec![]),
        policy(
            Action::Allow,
            vec![serial_allow],
            vec![exception(rule(Action::Block, "beef", None), LIVE_UNTIL)?],
        ),
    ];
    for refused in pairs {
        assert!(refused_index(&refused)?.is_some());
        let artefact = build(&refused, &live_entries(&refused, at(NOW)?));
        let diverges = matrix().iter().any(|(device, _)| {
            let parent = first_node(device).ok();
            let admitted = allowed(&refused, device).ok();
            parent.map(|node| windows_installs(&artefact, &node)) != admitted
        });
        assert!(diverges);
    }
    Ok(())
}


#[test]
fn a_non_removable_parent_escapes_default_block_and_stays_a_named_residual() -> Result<(), Box<dyn Error>> {
    let blocking = policy(Action::Block, vec![], vec![]);
    let artefact = render_windows(&blocking, at(NOW)?)?;
    let device = matrix().into_iter().next().ok_or("no device")?.0;
    let mut parent = chain_nodes(&device, 0, false, false).into_iter().next().ok_or("no parent")?;
    assert!(!windows_installs(&artefact, &parent));
    parent.removable = false;
    assert!(windows_installs(&artefact, &parent));
    Ok(())
}


#[test]
fn a_device_with_no_interface_has_no_function_outside_the_proof() -> Result<(), Box<dyn Error>> {
    let device = UsbDevice {
        vendor: "dead".to_string(),
        product: "beef".to_string(),
        serial: None,
        interfaces: vec![],
    };
    let allow_all = policy(Action::Allow, vec![], vec![]);
    assert!(!allowed(&allow_all, &device)?);
    let artefact = render_windows(&allow_all, at(NOW)?)?;
    let parent = chain_nodes(&device, 0, false, false).into_iter().next().ok_or("no parent")?;
    assert!(windows_installs(&artefact, &parent));
    assert_eq!(chain_nodes(&device, 0, true, true).len(), CHAIN_WITHOUT_FUNCTION);
    Ok(())
}


#[test]
fn a_flag_that_is_not_one_does_not_enable_the_default() -> Result<(), Box<dyn Error>> {
    let mut artefact = render_windows(&policy(Action::Block, vec![], vec![]), at(NOW)?)?;
    let device = matrix().into_iter().next().ok_or("no device")?.0;
    let parent = first_node(&device)?;
    assert!(!windows_installs(&artefact, &parent));
    for value in artefact.values.iter_mut().filter(|value| value.name == "DenyRemovableDevices") {
        value.data = "0".to_string();
    }
    assert!(windows_installs(&artefact, &parent));
    Ok(())
}
