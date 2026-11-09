#[path = "common/types.rs"]
mod types;


use std::io::Write;
use time::macros::date;
use time::Date;
use types::TestResult;
use vuln_match::eol::{eol_findings, load_eol_table, parse_eol_table};
use vuln_match::error::EolError;
use vuln_match::limits::MAX_EOL_ENTRIES;
use vuln_match::model::Package;


const TABLE: &str =
    "entries:\n  - product: python\n    cycle: \"3.8\"\n    end_date: 2024-10-07\n  - product: nginx\n    cycle: \"1.2\"\n    end_date: 2030-01-01\n";


const DAY_BEFORE: Date = date!(2024 - 10 - 06);


const END_DAY: Date = date!(2024 - 10 - 07);


const DAY_AFTER: Date = date!(2024 - 10 - 08);


const LATER: Date = date!(2025 - 01 - 01);


const TWO_ENTRIES: usize = 2;


const BAD_DATE: &str = "entries:\n  - product: a\n    cycle: b\n    end_date: nope\n";


fn package(name: &str, version: &str) -> Package {
    Package {
        ecosystem: "Debian".into(),
        name: name.into(),
        version: version.into(),
    }
}


#[test]
fn date_boundary() -> TestResult {
    let table = parse_eol_table(TABLE, "eol.yaml")?;
    let packages = [package("python", "3.8.10")];
    assert!(eol_findings(&packages, &table, DAY_BEFORE).is_empty());
    let on_date = eol_findings(&packages, &table, END_DAY);
    assert_eq!(on_date.len(), 1);
    assert_eq!(on_date.first().map(|finding| finding.cycle.as_str()), Some("3.8"));
    assert_eq!(eol_findings(&packages, &table, DAY_AFTER).len(), 1);
    Ok(())
}


#[test]
fn cycle_and_product_must_match() -> TestResult {
    let table = parse_eol_table(TABLE, "eol.yaml")?;
    let packages = [
        package("python", "3.8"),
        package("python", "3.80.1"),
        package("python", "3.9.1"),
        package("ruby", "3.8.1"),
        package("nginx", "1.2.3"),
        package("python", "3.8"),
    ];
    assert_eq!(eol_findings(&packages, &table, LATER).len(), 1);
    Ok(())
}


#[test]
fn load_from_file_and_errors() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("eol.yaml");
    std::fs::File::create(&path)?.write_all(TABLE.as_bytes())?;
    assert_eq!(load_eol_table(&path)?.entries.len(), TWO_ENTRIES);
    assert!(matches!(load_eol_table(&directory.path().join("missing.yaml")), Err(EolError::Config(_))));
    assert!(matches!(parse_eol_table(BAD_DATE, "x"), Err(EolError::Config(_))));
    assert!(matches!(parse_eol_table("unknown: 1\n", "x"), Err(EolError::Config(_))));
    assert!(parse_eol_table("{}", "x")?.entries.is_empty());
    Ok(())
}


#[test]
fn entry_count_is_capped() -> TestResult {
    let row = "  - {product: a, cycle: b, end_date: 2024-01-01}\n";
    let over = parse_eol_table(&format!("entries:\n{}", row.repeat(MAX_EOL_ENTRIES + 1)), "x");
    assert!(matches!(over, Err(EolError::TooMany { .. })));
    assert!(over.err().is_some_and(|error| error.to_string().contains("exceed")));
    assert_eq!(
        parse_eol_table(&format!("entries:\n{}", row.repeat(MAX_EOL_ENTRIES)), "x")?.entries.len(),
        MAX_EOL_ENTRIES
    );
    Ok(())
}
