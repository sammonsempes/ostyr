#[path = "common/types.rs"]
mod types;


use cmdb::impact::{impacted_assets, impacted_services, propagates, BUSINESS_SERVICE_ATTRIBUTE, MAX_IMPACT_DEPTH};
use cmdb::model::{Asset, AssetKind, Attribute, Lifecycle, RelationKind, Relationship};
use std::collections::BTreeMap;
use types::TestResult;


fn edge(from: &str, kind: RelationKind, to: &str) -> Relationship {
    Relationship {
        from: from.to_string(),
        kind,
        to: to.to_string(),
    }
}


fn service_asset(id: &str, service: Option<&str>) -> Asset {
    Asset {
        id: id.to_string(),
        kind: AssetKind::Server,
        lifecycle: Lifecycle::InService,
        keys: BTreeMap::new(),
        attributes: service
            .map(|name| {
                (
                    BUSINESS_SERVICE_ATTRIBUTE.to_string(),
                    Attribute {
                        value: name.to_string(),
                        source: "declared".to_string(),
                    },
                )
            })
            .into_iter()
            .collect(),
    }
}


fn chain(length: usize) -> Vec<Relationship> {
    (0..length)
        .map(|i| edge(&format!("n{}", i + 1), RelationKind::DependsOn, &format!("n{i}")))
        .collect()
}


#[test]
fn member_of_does_not_propagate() -> TestResult {
    assert!(propagates(RelationKind::DependsOn));
    assert!(propagates(RelationKind::RunsOn));
    assert!(!propagates(RelationKind::MemberOf));
    let reached = impacted_assets("db", &[edge("group", RelationKind::MemberOf, "db")]);
    assert_eq!(reached.len(), 1);
    Ok(())
}


#[test]
fn cycle_terminates() -> TestResult {
    let edges = vec![
        edge("a", RelationKind::DependsOn, "b"),
        edge("b", RelationKind::RunsOn, "c"),
        edge("c", RelationKind::DependsOn, "a"),
    ];
    let reached = impacted_assets("a", &edges);
    assert_eq!(reached.into_iter().collect::<Vec<_>>(), vec!["a", "b", "c"]);
    Ok(())
}


#[test]
fn depth_bound_is_inclusive() -> TestResult {
    let edges = chain(MAX_IMPACT_DEPTH + 1);
    let reached = impacted_assets("n0", &edges);
    assert!(reached.contains(&format!("n{MAX_IMPACT_DEPTH}")));
    assert!(!reached.contains(&format!("n{}", MAX_IMPACT_DEPTH + 1)));
    assert_eq!(reached.len(), MAX_IMPACT_DEPTH + 1);
    Ok(())
}


#[test]
fn services_of_impacted_assets() -> TestResult {
    let assets = vec![
        service_asset("db", Some("billing")),
        service_asset("app", Some("portal")),
        service_asset("web", None),
        service_asset("other", Some("hr")),
    ];
    let edges = vec![edge("app", RelationKind::DependsOn, "db"), edge("web", RelationKind::RunsOn, "app")];
    let services = impacted_services("db", &assets, &edges);
    assert_eq!(services.into_iter().collect::<Vec<_>>(), vec!["billing", "portal"]);
    Ok(())
}
