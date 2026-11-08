mod common;


use cases::model::{Case, CaseStatus, IocStatus, Observable, ObservableKind, Pap, Severity, Tlp};
use cases::observable::{already_seen, normalise_value, AlreadySeen};
use common::types::TestResult;


fn observable(kind: ObservableKind, value: &str) -> Observable {
    Observable {
        kind,
        value: value.to_string(),
        tlp: Tlp::Amber,
        pap: Pap::Green,
        ioc: IocStatus::Suspected,
        source: "edr".to_string(),
    }
}


fn case(id: &str, tenant: &str, observables: Vec<Observable>) -> Case {
    Case {
        id: id.to_string(),
        tenant: tenant.to_string(),
        title: "t".to_string(),
        description: None,
        severity: Severity::Low,
        status: CaseStatus::New,
        resolution: None,
        assignee: None,
        template: None,
        case_type: None,
        created_at: 0,
        updated_at: 0,
        tasks: Vec::new(),
        observables,
        comments: Vec::new(),
        history: Vec::new(),
    }
}


#[test]
fn values_are_normalised_by_kind() -> TestResult {
    assert_eq!(normalise_value(ObservableKind::Domain, "  Evil.Example.COM. "), "evil.example.com");
    assert_eq!(normalise_value(ObservableKind::Ip, " 2001:DB8::1 "), "2001:db8::1");
    assert_eq!(normalise_value(ObservableKind::Hash, "ABCDEF"), "abcdef");
    assert_eq!(normalise_value(ObservableKind::Email, "A@B.org"), "a@b.org");
    assert_eq!(normalise_value(ObservableKind::Url, " http://A/B "), "http://A/B");
    assert_eq!(normalise_value(ObservableKind::Filename, "Run.EXE"), "Run.EXE");
    assert_eq!(normalise_value(ObservableKind::Other, " X "), "X");
    Ok(())
}


#[test]
fn shared_observables_are_found_after_normalisation() -> TestResult {
    let current = case(
        "c1",
        "acme",
        vec![
            observable(ObservableKind::Domain, "evil.example.com"),
            observable(ObservableKind::Ip, "10.0.0.1"),
        ],
    );
    let others = vec![
        case("c2", "acme", vec![observable(ObservableKind::Domain, "EVIL.example.com.")]),
        case("c3", "acme", vec![observable(ObservableKind::Domain, "other.example.com")]),
        case(
            "c4",
            "acme",
            vec![observable(ObservableKind::Ip, "10.0.0.1"), observable(ObservableKind::Ip, "10.0.0.1")],
        ),
        case("c1", "acme", vec![observable(ObservableKind::Ip, "10.0.0.1")]),
    ];
    let seen = already_seen(&current, &others);
    assert_eq!(
        seen,
        vec![
            AlreadySeen {
                case_id: "c2".to_string(),
                shared: vec![(ObservableKind::Domain, "evil.example.com".to_string())],
            },
            AlreadySeen {
                case_id: "c4".to_string(),
                shared: vec![(ObservableKind::Ip, "10.0.0.1".to_string())],
            },
        ]
    );
    Ok(())
}


#[test]
fn another_tenant_is_never_matched() -> TestResult {
    let current = case("c1", "acme", vec![observable(ObservableKind::Ip, "10.0.0.1")]);
    let others = vec![case("c2", "globex", vec![observable(ObservableKind::Ip, "10.0.0.1")])];
    assert_eq!(already_seen(&current, &others), Vec::new());
    Ok(())
}


#[test]
fn the_same_value_of_another_kind_is_not_shared() -> TestResult {
    let current = case("c1", "acme", vec![observable(ObservableKind::Filename, "x")]);
    let others = vec![case("c2", "acme", vec![observable(ObservableKind::Other, "x")])];
    assert_eq!(already_seen(&current, &others), Vec::new());
    Ok(())
}
