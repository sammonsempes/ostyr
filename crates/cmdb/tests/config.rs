#[path = "common/types.rs"]
mod types;


use cmdb::config::{declared_assets, load_cmdb, to_asset, DECLARED_SOURCE};
use cmdb::error::CmdbConfigError;
use cmdb::model::{AssetKind, IdentityKey, Lifecycle, RelationKind};
use cmdb::summary::MAX_ID_BYTES;
use core_config::error::ConfigError;
use types::TestResult;


const VALID: &str = "sources_of_truth:
  owner: declared
assets:
  - id: web1
    kind: server
    lifecycle: in_service
    keys:
      serial_number: SN1
      name: web1
    owner: alice
    criticality: critical
    business_service: portal
    environment: prod
    location: paris
  - id: bare
    kind: printer
    lifecycle: ordered
relationships:
  - from: web1
    kind: runs_on
    to: bare
";


const DECLARED_COUNT: usize = 2;


const FULL_ATTRIBUTES: usize = 5;


fn write_config(text: &str) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("cmdb.yaml");
    std::fs::write(&path, text)?;
    Ok((dir, path))
}


#[test]
fn valid_file_loads_into_assets() -> TestResult {
    let (_dir, path) = write_config(VALID)?;
    let config = load_cmdb(&path)?;
    assert_eq!(config.sources_of_truth.get("owner"), Some(&"declared".to_string()));
    assert_eq!(config.relationships.first().map(|edge| edge.kind), Some(RelationKind::RunsOn));
    let assets = declared_assets(&config);
    assert_eq!(assets.len(), DECLARED_COUNT);
    let web = assets.first().ok_or("missing")?;
    assert_eq!(web.kind, AssetKind::Server);
    assert_eq!(web.lifecycle, Lifecycle::InService);
    assert_eq!(web.keys.get(&IdentityKey::SerialNumber), Some(&"SN1".to_string()));
    assert_eq!(web.attributes.len(), FULL_ATTRIBUTES);
    let criticality = web.attributes.get("criticality").ok_or("no criticality")?;
    assert_eq!(criticality.value, "critical");
    assert_eq!(criticality.source, DECLARED_SOURCE);
    let bare = assets.get(1).ok_or("missing")?;
    assert!(bare.attributes.is_empty());
    assert_eq!(to_asset(config.assets.first().ok_or("missing")?), *web);
    Ok(())
}


#[test]
fn every_criticality_and_key_has_a_label() -> TestResult {
    let text = ["low", "medium", "high", "critical"]
        .iter()
        .enumerate()
        .map(|(i, level)| {
            format!("  - id: a{i}\n    kind: server\n    lifecycle: retired\n    criticality: {level}\n    keys:\n      mac: m{i}\n      cloud_id: c{i}\n")
        })
        .collect::<String>();
    let (_dir, path) = write_config(&format!("assets:\n{text}"))?;
    let assets = declared_assets(&load_cmdb(&path)?);
    let labels: Vec<String> = assets
        .iter()
        .filter_map(|asset| asset.attributes.get("criticality").map(|level| level.value.clone()))
        .collect();
    assert_eq!(labels, vec!["low", "medium", "high", "critical"]);
    assert_eq!(IdentityKey::SerialNumber.to_string(), "serial_number");
    assert_eq!(IdentityKey::Mac.to_string(), "mac");
    assert_eq!(IdentityKey::CloudId.to_string(), "cloud_id");
    assert_eq!(IdentityKey::Name.to_string(), "name");
    Ok(())
}


#[test]
fn unknown_field_reports_file_and_line() -> TestResult {
    let (_dir, path) = write_config("assets:\n  - id: a\n    kind: server\n    lifecycle: retired\n    colour: red\n")?;
    let error = load_cmdb(&path).err().ok_or("accepted")?;
    let text = error.to_string();
    assert!(matches!(error, CmdbConfigError::Load(ConfigError::Parse { .. })));
    assert!(text.contains("cmdb.yaml:5:"), "{text}");
    Ok(())
}


#[test]
fn bad_enum_value_names_field_path() -> TestResult {
    let (_dir, path) = write_config("assets:\n  - id: a\n    kind: toaster\n    lifecycle: retired\n")?;
    let text = load_cmdb(&path).err().ok_or("accepted")?.to_string();
    assert!(text.contains("assets[0].kind"), "{text}");
    Ok(())
}


#[test]
fn missing_file_is_io_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let error = load_cmdb(&dir.path().join("absent.yaml")).err().ok_or("accepted")?;
    assert!(matches!(error, CmdbConfigError::Load(ConfigError::Io { .. })));
    Ok(())
}


const VALUE_CAP: usize = 4_096;


fn declared_with(id: &str, owner: &str, mac: &str) -> String {
    format!("assets:\n  - id: \"{id}\"\n    kind: server\n    lifecycle: in_service\n    owner: \"{owner}\"\n    keys:\n      mac: \"{mac}\"\n")
}


#[test]
fn declared_assets_over_a_cap_or_with_invisible_text_are_refused_at_load() -> TestResult {
    let long_id = "i".repeat(MAX_ID_BYTES + 1);
    let long_owner = "o".repeat(VALUE_CAP + 1);
    let cases = [
        (declared_with(&long_id, "ann", "m1"), "asset id"),
        (declared_with("a1", &long_owner, "m1"), "attribute value"),
        (declared_with("a1", "an\\u202en", "m1"), "attribute value"),
        (declared_with("a\\u200b1", "ann", "m1"), "asset id"),
        (declared_with("a1", "ann", "m\\u2066"), "keys"),
    ];
    cases.iter().try_for_each(|(text, field)| -> TestResult {
        let (_dir, path) = write_config(text)?;
        let error = load_cmdb(&path).err().ok_or("accepted")?;
        let message = error.to_string();
        assert!(
            matches!(&error, CmdbConfigError::Declared { index: 0, source, .. } if source.to_string().contains(field)),
            "{message}"
        );
        assert!(message.contains("cmdb.yaml"), "{message}");
        assert!(!message.contains(&long_id) && !message.contains(&long_owner), "value echoed");
        Ok(())
    })?;
    let (_dir, path) = write_config(&declared_with(&"i".repeat(MAX_ID_BYTES), &"o".repeat(VALUE_CAP), "m1"))?;
    assert_eq!(load_cmdb(&path)?.assets.len(), 1);
    Ok(())
}
