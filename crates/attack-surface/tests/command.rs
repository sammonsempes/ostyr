use attack_surface::command::{naabu_args, ports_text, MAX_VALUE_BYTES};
use attack_surface::error::CommandError;
use attack_surface::model::{PortRange, Scope, ScopeKind};
use attack_surface::scope::parse_scope;
use std::error::Error;
use std::ffi::OsString;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const SCOPE_TEXT: &str = "kind: external
rate_per_second: 100
ports: [22, 80, \"8000-8100\"]
targets:
  - value: 8.8.8.0/24
    ownership: {method: dns_txt, reference: TICKET-1}
  - value: 2606:4700::/48
    ownership: {method: attestation, reference: TICKET-2}
  - value: app.example.org
    ownership: {method: dns_txt, reference: TICKET-3}
";


const HAND_RATE: u32 = 5;


const SSH: u16 = 22;


const HTTP: u16 = 80;


const HTTP_END: u16 = 90;


fn scope_of(text: &str) -> Result<Scope, Box<dyn Error>> {
    let mut bytes = text.as_bytes();
    Ok(parse_scope(&mut bytes, "scope.yaml")?)
}


fn hand_scope(target: &str, ports: Vec<PortRange>) -> Scope {
    Scope {
        kind: ScopeKind::External,
        rate_per_second: HAND_RATE,
        ports,
        ranges: Vec::new(),
        hostnames: Vec::new(),
        targets: vec![target.to_string()],
    }
}


fn strings(args: &[OsString]) -> Vec<String> {
    args.iter().map(|value| value.to_string_lossy().into_owned()).collect()
}


#[test]
fn the_argument_vector_is_exact_for_each_kind_of_target() -> TestResult {
    let scope = scope_of(SCOPE_TEXT)?;
    let expected = |target: &str| {
        vec!["-json", "-silent", "-rate", "100", "-p", "22,80,8000-8100", "-host", target]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    };
    ["8.8.8.0/24", "2606:4700::/48", "app.example.org"]
        .iter()
        .try_for_each(|target| -> TestResult {
            assert_eq!(strings(&naabu_args(&scope, target)?), expected(target));
            Ok(())
        })
}


#[test]
fn a_target_outside_the_scope_has_no_argument_vector() -> TestResult {
    let scope = scope_of(SCOPE_TEXT)?;
    ["-iL /etc/shadow", "--config", "8.8.9.0/24", "", "8.8.8.0/24 -iL x"]
        .iter()
        .try_for_each(|target| -> TestResult {
            let error = naabu_args(&scope, target).err().ok_or("a vector was built")?;
            assert!(matches!(error, CommandError::UnknownTarget { .. }), "{target}");
            assert!(error.to_string().contains("not listed"), "{error}");
            Ok(())
        })
}


#[test]
fn a_hand_built_scope_cannot_smuggle_an_option_or_a_hidden_character() -> TestResult {
    let ports = vec![PortRange { first: SSH, last: SSH }];
    ["-iL", "a b", "evil\u{202e}", "", "tab\there"]
        .iter()
        .try_for_each(|target| -> TestResult {
            let error = naabu_args(&hand_scope(target, ports.clone()), target).err().ok_or("a vector was built")?;
            assert!(matches!(error, CommandError::BadValue { .. }), "{target}");
            assert!(error.to_string().contains("refused"), "{error}");
            Ok(())
        })?;
    let no_ports = naabu_args(&hand_scope("8.8.8.8/32", Vec::new()), "8.8.8.8/32")
        .err()
        .ok_or("a vector was built")?;
    assert!(matches!(no_ports, CommandError::BadValue { .. }));
    let overlong = "a".repeat(MAX_VALUE_BYTES + 1);
    let long = naabu_args(&hand_scope(&overlong, ports), &overlong).err().ok_or("a vector was built")?;
    assert!(matches!(long, CommandError::BadValue { .. }));
    Ok(())
}


#[test]
fn ports_are_written_in_naabu_syntax() -> TestResult {
    let ranges = [PortRange { first: SSH, last: SSH }, PortRange { first: HTTP, last: HTTP_END }];
    assert_eq!(ports_text(&ranges), "22,80-90");
    assert_eq!(ports_text(&[]), "");
    Ok(())
}
