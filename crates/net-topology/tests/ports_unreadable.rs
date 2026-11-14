#[path = "common/types.rs"]
mod types;


use net_topology::limits::Limits;
use net_topology::ports::parse_ports;
use types::TestResult;


const TWO_UNREADABLE: usize = 2;


#[test]
fn an_unreadable_entry_is_a_counted_refusal() -> TestResult {
    let text = r#"{"lldp":[{"interface":[5,"x",{"name":"eth0"},{"via":"unknown"}]}]}"#;
    let list = parse_ports(text.as_bytes(), &Limits::default())?;
    assert_eq!(list.ports, vec!["eth0".to_string()]);
    assert_eq!(list.unreadable_ports, TWO_UNREADABLE);
    assert_eq!(list.invalid_ports, 1);
    Ok(())
}
