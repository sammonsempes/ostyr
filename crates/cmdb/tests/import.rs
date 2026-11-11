#[path = "common/types.rs"]
mod types;


use cmdb::error::ImportError;
use cmdb::import::{import_file, import_reader, load_mapping, ImportFormat, ImportMapping, ImportReport, RejectedRow};
use cmdb::model::{Asset, AssetKind, Attribute, IdentityKey, Lifecycle, Resolution};
use cmdb::types::TruthMap;
use std::collections::BTreeMap;
use std::io::Read;
use types::TestResult;


const OVERSIZED_VALUE: usize = 5_000;


const SMALL_BYTES: u64 = 10;


const SMALL_ROWS: usize = 2;


const NOT_SCALAR_INDEX: usize = 2;


const NO_IDENTITY_INDEX: usize = 3;


const CSV_ROWS: usize = 2;


const INVALID_BYTES: [u8; 3] = [0xff, 0xfe, 0xfd];


const THIRD_LINE: u64 = 3;


const FOURTH_LINE: u64 = 4;


const SECOND_LINE: u64 = 2;


const CSV_TEXT: &str = "\u{feff}serial,owner,site\nSN1,\"Smith, Alice\",paris\nSN2,bob,\"lyon\"\n";


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("boom"))
    }
}


fn mapping(format: ImportFormat) -> ImportMapping {
    ImportMapping {
        format,
        source: "legacy".to_string(),
        kind: AssetKind::Server,
        keys: BTreeMap::from([(IdentityKey::SerialNumber, "serial".to_string())]),
        attributes: BTreeMap::from([("owner".to_string(), "owner".to_string()), ("location".to_string(), "site".to_string())]),
        max_bytes: None,
        max_rows: None,
    }
}


fn run(text: &str, format: ImportFormat, inventory: &[Asset], truth: &TruthMap) -> Result<ImportReport, ImportError> {
    import_reader(text.as_bytes(), &mapping(format), inventory, truth)
}


fn owner_of(report: &ImportReport, id: &str) -> Option<Attribute> {
    report
        .inventory
        .iter()
        .find(|asset| asset.id == id)
        .and_then(|asset| asset.attributes.get("owner").cloned())
}


fn existing(id: &str, serial: &str, lifecycle: Lifecycle, owner: Option<(&str, &str)>) -> Asset {
    Asset {
        id: id.to_string(),
        kind: AssetKind::Server,
        lifecycle,
        keys: BTreeMap::from([(IdentityKey::SerialNumber, serial.to_string())]),
        attributes: owner
            .map(|(value, source)| {
                (
                    "owner".to_string(),
                    Attribute {
                        value: value.to_string(),
                        source: source.to_string(),
                    },
                )
            })
            .into_iter()
            .collect(),
    }
}


#[test]
fn csv_with_bom_and_quoted_fields() -> TestResult {
    let report = run(CSV_TEXT, ImportFormat::Csv, &[], &TruthMap::new())?;
    assert_eq!(report.created, vec!["serial_number:SN1", "serial_number:SN2"]);
    assert_eq!(
        owner_of(&report, "serial_number:SN1").map(|attribute| attribute.value),
        Some("Smith, Alice".to_string())
    );
    assert!(report.rejected.is_empty());
    Ok(())
}


#[test]
fn reimport_is_idempotent() -> TestResult {
    let first = run(CSV_TEXT, ImportFormat::Csv, &[], &TruthMap::new())?;
    let second = run(CSV_TEXT, ImportFormat::Csv, &first.inventory, &TruthMap::new())?;
    assert_eq!(second.inventory, first.inventory);
    assert_eq!(second.unchanged, first.created);
    assert!(second.created.is_empty() && second.updated.is_empty() && second.conflicts.is_empty());
    Ok(())
}


#[test]
fn json_lines_with_scalars_nulls_and_blank_lines() -> TestResult {
    let text = "{\"serial\": 42, \"owner\": \"amy\", \"site\": null}\n\n{\"serial\": true, \"owner\": 7}\n";
    let report = run(text, ImportFormat::JsonLines, &[], &TruthMap::new())?;
    assert_eq!(report.created, vec!["serial_number:42", "serial_number:true"]);
    assert_eq!(
        owner_of(&report, "serial_number:true").map(|attribute| attribute.value),
        Some("7".to_string())
    );
    Ok(())
}


#[test]
fn malformed_json_rows_are_rejected_with_line_numbers() -> TestResult {
    let text = "{\"serial\": \"A\"}\nnot json\n[1]\n{\"serial\": [1]}\n{\"owner\": \"x\"}\n";
    let report = run(text, ImportFormat::JsonLines, &[], &TruthMap::new())?;
    assert_eq!(report.created, vec!["serial_number:A"]);
    let lines: Vec<u64> = report.rejected.iter().map(|row| row.line).collect();
    assert_eq!(lines, vec![SECOND_LINE, THIRD_LINE, FOURTH_LINE, FOURTH_LINE + 1]);
    assert_eq!(report.rejected.get(1).map(|row| row.reason.as_str()), Some("line is not a JSON object"));
    assert_eq!(
        report.rejected.get(NOT_SCALAR_INDEX).map(|row| row.reason.as_str()),
        Some("field is not a scalar")
    );
    assert_eq!(
        report.rejected.get(NO_IDENTITY_INDEX),
        Some(&RejectedRow {
            line: FOURTH_LINE + 1,
            reason: "observation from `legacy` carries no identity key".to_string()
        })
    );
    Ok(())
}


#[test]
fn ragged_csv_row_is_rejected_and_skipped() -> TestResult {
    let text = "serial,owner,site\nSN1,a,b\nSN2,a\nSN3,c,d\n";
    let report = run(text, ImportFormat::Csv, &[], &TruthMap::new())?;
    assert_eq!(report.created, vec!["serial_number:SN1", "serial_number:SN3"]);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected.first().map(|row| row.line), Some(THIRD_LINE));
    Ok(())
}


#[test]
fn missing_mapped_column_fails_the_file() -> TestResult {
    let result = run("serial,owner\nSN1,a\n", ImportFormat::Csv, &[], &TruthMap::new());
    assert!(matches!(result, Err(ImportError::MissingColumn { ref column }) if column == "site"));
    Ok(())
}


#[test]
fn size_bound_is_enforced() -> TestResult {
    let mut small = mapping(ImportFormat::Csv);
    small.max_bytes = Some(SMALL_BYTES);
    let result = import_reader(CSV_TEXT.as_bytes(), &small, &[], &TruthMap::new());
    assert!(matches!(result, Err(ImportError::TooLarge { limit: SMALL_BYTES })));
    Ok(())
}


#[test]
fn row_bound_is_enforced_for_both_formats() -> TestResult {
    let mut csv_mapping = mapping(ImportFormat::Csv);
    csv_mapping.max_rows = Some(1);
    let csv_result = import_reader(CSV_TEXT.as_bytes(), &csv_mapping, &[], &TruthMap::new());
    assert!(matches!(csv_result, Err(ImportError::TooManyRows { limit: 1 })));
    let mut json_mapping = mapping(ImportFormat::JsonLines);
    json_mapping.max_rows = Some(SMALL_ROWS);
    let text = "{\"serial\":\"1\"}\n{\"serial\":\"2\"}\n{\"serial\":\"3\"}\n";
    let json_result = import_reader(text.as_bytes(), &json_mapping, &[], &TruthMap::new());
    assert!(matches!(json_result, Err(ImportError::TooManyRows { limit: SMALL_ROWS })));
    let two = "{\"serial\":\"1\"}\n{\"serial\":\"2\"}\n";
    let exact = import_reader(two.as_bytes(), &json_mapping, &[], &TruthMap::new());
    assert!(exact.is_ok());
    Ok(())
}


#[test]
fn conflict_is_surfaced_through_reconciliation() -> TestResult {
    let inventory = vec![existing("srv", "SN1", Lifecycle::InService, Some(("carol", "rmm")))];
    let report = run(CSV_TEXT, ImportFormat::Csv, &inventory, &TruthMap::new())?;
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts.first().map(|conflict| conflict.resolution), Some(Resolution::Undecided));
    assert_eq!(owner_of(&report, "srv").map(|attribute| attribute.value), Some("carol".to_string()));
    assert!(report.updated.contains(&"srv".to_string()));
    Ok(())
}


#[test]
fn conflict_only_row_is_unchanged() -> TestResult {
    let inventory = vec![existing("srv", "SN1", Lifecycle::InService, Some(("carol", "rmm")))];
    let text = "serial,owner,site\nSN1,\"Smith, Alice\",\n";
    let report = run(text, ImportFormat::Csv, &inventory, &TruthMap::new())?;
    assert_eq!(report.unchanged, vec!["srv"]);
    assert_eq!(report.conflicts.len(), 1);
    Ok(())
}


#[test]
fn created_then_updated_and_unchanged_then_updated_in_one_file() -> TestResult {
    let inventory = vec![existing("old", "SN9", Lifecycle::Retired, Some(("zed", "legacy")))];
    let text = "serial,owner,site\nN1,a,\nN1,b,\nSN9,zed,\nSN9,yan,\nN2,c,\nN2,c,\n";
    let report = run(text, ImportFormat::Csv, &inventory, &TruthMap::new())?;
    assert_eq!(report.created, vec!["serial_number:N1", "serial_number:N2"]);
    assert_eq!(report.updated, vec!["old"]);
    assert!(report.unchanged.is_empty());
    assert_eq!(
        owner_of(&report, "serial_number:N1").map(|attribute| attribute.value),
        Some("b".to_string())
    );
    Ok(())
}


#[test]
fn unchanged_asset_is_listed_once() -> TestResult {
    let inventory = vec![existing("old", "SN9", Lifecycle::InService, Some(("zed", "legacy")))];
    let report = run("serial,owner,site\nSN9,zed,\nSN9,zed,\n", ImportFormat::Csv, &inventory, &TruthMap::new())?;
    assert_eq!(report.unchanged, vec!["old"]);
    Ok(())
}


#[test]
fn reader_and_encoding_failures_are_reported() -> TestResult {
    let failing = import_reader(FailingReader, &mapping(ImportFormat::Csv), &[], &TruthMap::new());
    assert!(matches!(failing, Err(ImportError::Io(_))));
    let bad_bytes: &[u8] = &INVALID_BYTES;
    let invalid = import_reader(bad_bytes, &mapping(ImportFormat::Csv), &[], &TruthMap::new());
    assert!(matches!(invalid, Err(ImportError::NotUtf8(_))));
    Ok(())
}


#[test]
fn reserved_source_and_attribute_prefix_are_refused_naming_the_field_only() -> TestResult {
    let mut reserved_source = mapping(ImportFormat::Csv);
    reserved_source.source = " CMDB ".to_string();
    let refused_source = import_reader(CSV_TEXT.as_bytes(), &reserved_source, &[], &TruthMap::new())
        .err()
        .ok_or("accepted")?;
    assert!(matches!(refused_source, ImportError::ReservedName { field: "source" }));
    assert!(!refused_source.to_string().contains("CMDB"));
    let mut reserved_attribute = mapping(ImportFormat::Csv);
    reserved_attribute.attributes.insert("Key:mac".to_string(), "site".to_string());
    let refused_attribute = import_reader(CSV_TEXT.as_bytes(), &reserved_attribute, &[], &TruthMap::new())
        .err()
        .ok_or("accepted")?;
    assert!(matches!(refused_attribute, ImportError::ReservedName { field: "attributes" }));
    assert!(!refused_attribute.to_string().contains("mac"));
    Ok(())
}


#[test]
fn oversized_value_rejects_that_row_only() -> TestResult {
    let long = "v".repeat(OVERSIZED_VALUE);
    let text = format!("serial,owner,site\nSN1,{long},paris\nSN2,bob,lyon\n");
    let report = run(&text, ImportFormat::Csv, &[], &TruthMap::new())?;
    assert_eq!(report.created.len(), 1);
    assert_eq!(report.rejected.len(), 1);
    assert!(report
        .rejected
        .iter()
        .all(|row| row.reason.contains("attribute value") && !row.reason.contains(&long)));
    Ok(())
}


#[test]
fn reserved_names_are_refused_when_the_mapping_loads() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mapping.yaml");
    std::fs::write(&path, "format: csv\nsource: cmdb\nkind: server\nkeys:\n  serial_number: serial\n")?;
    assert!(matches!(load_mapping(&path), Err(ImportError::ReservedName { field: "source" })));
    std::fs::write(
        &path,
        "format: csv\nsource: legacy\nkind: server\nkeys:\n  serial_number: serial\nattributes:\n  \"key:serial_number\": owner\n",
    )?;
    assert!(matches!(load_mapping(&path), Err(ImportError::ReservedName { field: "attributes" })));
    Ok(())
}


#[test]
fn files_and_mapping_load_from_disk() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mapping_path = dir.path().join("mapping.yaml");
    std::fs::write(
        &mapping_path,
        "format: csv\nsource: legacy\nkind: server\nkeys:\n  serial_number: serial\nattributes:\n  owner: owner\n  location: site\n",
    )?;
    let loaded = load_mapping(&mapping_path)?;
    assert_eq!(loaded, mapping(ImportFormat::Csv));
    let data_path = dir.path().join("export.csv");
    std::fs::write(&data_path, CSV_TEXT)?;
    let report = import_file(&data_path, &loaded, &[], &TruthMap::new())?;
    assert_eq!(report.created.len(), CSV_ROWS);
    let missing = import_file(&dir.path().join("absent.csv"), &loaded, &[], &TruthMap::new());
    assert!(matches!(missing, Err(ImportError::Io(_))));
    std::fs::write(&mapping_path, "format: xml\n")?;
    assert!(load_mapping(&mapping_path).is_err());
    Ok(())
}
