#[path = "common/types.rs"]
mod types;


use cmdb::config::{DECLARED_SOURCE, OWNER_ATTRIBUTE};
use cmdb::grc_indicator::{indicator_json, is_in_service, is_owned, owned_ratio, Ratio, INDICATOR_NAME};
use cmdb::model::{Asset, AssetKind, Attribute, Lifecycle, Snapshot};
use cmdb::types::TruthMap;
use serde_json::Value;
use std::collections::BTreeMap;
use types::TestResult;


const OWNED_FIVE: usize = 3;


const TOTAL_FIVE: usize = 5;


const OWNED_FOUR: usize = 3;


const TOTAL_FOUR: usize = 4;


const FIXTURE: &str = r#"[{"tenant":"acme","name":"assets.owned_ratio","value":0.75,"observed_at":"2026-11-12T10:00:00Z","source":"cmdb:acme"}]"#;


fn asset(id: &str, lifecycle: Lifecycle, owner: Option<&str>) -> Asset {
    Asset {
        id: id.to_string(),
        kind: AssetKind::Server,
        lifecycle,
        keys: BTreeMap::new(),
        attributes: owner
            .map(|name| {
                (
                    OWNER_ATTRIBUTE.to_string(),
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


fn snapshot(assets: Vec<Asset>) -> Snapshot {
    Snapshot {
        assets,
        versions: BTreeMap::new(),
    }
}


#[test]
fn counts_owned_unowned_retired_and_blank() -> TestResult {
    let ratio = owned_ratio(
        &snapshot(vec![
            asset("a", Lifecycle::InService, Some("alice")),
            asset("b", Lifecycle::InService, Some("bob")),
            asset("c", Lifecycle::InService, Some("carol")),
            asset("d", Lifecycle::InService, None),
            asset("e", Lifecycle::InService, Some("  ")),
            asset("f", Lifecycle::Retired, Some("dave")),
            asset("g", Lifecycle::Destroyed, None),
        ]),
        &TruthMap::new(),
    );
    assert_eq!(
        ratio,
        Ratio {
            owned: OWNED_FIVE,
            total: TOTAL_FIVE
        }
    );
    assert!(is_in_service(&asset("a", Lifecycle::InService, None)));
    assert!(!is_in_service(&asset("a", Lifecycle::Ordered, None)));
    assert!(!is_owned(&asset("a", Lifecycle::InService, Some("")), &TruthMap::new()));
    Ok(())
}


#[test]
fn empty_inventory_gives_no_value() -> TestResult {
    let ratio = owned_ratio(&snapshot(vec![asset("f", Lifecycle::Retired, Some("dave"))]), &TruthMap::new());
    assert_eq!(ratio, Ratio { owned: 0, total: 0 });
    assert_eq!(indicator_json("acme", &ratio, "2026-11-12T10:00:00Z", "cmdb:acme"), "[]");
    Ok(())
}


#[test]
fn json_matches_the_grc_format() -> TestResult {
    let text = indicator_json(
        "acme",
        &Ratio {
            owned: OWNED_FOUR,
            total: TOTAL_FOUR,
        },
        "2026-11-12T10:00:00Z",
        "cmdb:acme",
    );
    let produced: Value = serde_json::from_str(&text)?;
    let expected: Value = serde_json::from_str(FIXTURE)?;
    assert_eq!(produced, expected);
    assert_eq!(INDICATOR_NAME, "assets.owned_ratio");
    Ok(())
}


fn from_source(owner: &str, source: &str) -> Asset {
    let mut built = asset("a", Lifecycle::InService, Some(owner));
    built.attributes.insert(
        OWNER_ATTRIBUTE.to_string(),
        Attribute {
            value: owner.to_string(),
            source: source.to_string(),
        },
    );
    built
}


#[test]
fn only_trusted_sources_count() -> TestResult {
    let truth: TruthMap = [(OWNER_ATTRIBUTE.to_string(), "directory".to_string())].into_iter().collect();
    assert!(is_owned(&from_source("alice", DECLARED_SOURCE), &TruthMap::new()));
    assert!(is_owned(&from_source("alice", "directory"), &truth));
    assert!(!is_owned(&from_source("alice", "directory"), &TruthMap::new()));
    assert!(!is_owned(&from_source("alice", "scanner"), &truth));
    assert!(!is_owned(&from_source("alice", "Declared"), &truth));
    Ok(())
}


#[test]
fn invisible_and_ambiguous_owners_do_not_count() -> TestResult {
    let truth = TruthMap::new();
    ["\u{1D159}", "\u{3164}", " ", "a  b", "\u{200B}a", "\u{00A0}", "\u{200B}"]
        .iter()
        .for_each(|owner| assert!(!is_owned(&from_source(owner, DECLARED_SOURCE), &truth), "{owner:?}"));
    ["alice", "\u{C9}quipe 7"]
        .iter()
        .for_each(|owner| assert!(is_owned(&from_source(owner, DECLARED_SOURCE), &truth)));
    Ok(())
}
