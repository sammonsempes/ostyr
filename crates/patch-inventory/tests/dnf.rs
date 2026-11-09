mod common;


use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::dnf::{parse_dnf, split_nevra};
use patch_inventory::error::InventoryError;
use patch_inventory::model::{Limits, SkipReason};


const UPDATEINFO: &[u8] = include_bytes!("fixtures/dnf-updateinfo.txt");


const CHECK_UPDATE: &[u8] = include_bytes!("fixtures/dnf-check-update.txt");


const EMPTY: &[u8] = b"";


const TINY_BYTES: usize = 4;


const UNKNOWN_INDEX: usize = 4;


const TZDATA_INDEX: usize = 3;


const CHECK_UPDATE_COUNT: usize = 5;


const BOTH_READERS_MALFORMED: usize = 10;


#[test]
fn fixtures_are_merged() -> TestResult {
    let inventory = parse_dnf(&device(), UPDATEINFO, CHECK_UPDATE, &limits())?;
    assert!(inventory.skipped.is_empty());
    let rows: Vec<(&str, &str, &str, bool)> = inventory
        .updates
        .iter()
        .map(|update| {
            (
                update.package.as_str(),
                update.architecture.as_str(),
                update.candidate_version.as_str(),
                update.security,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("kernel", "x86_64", "5.14.0-503.15.1.el9_5", true),
            ("openssl", "x86_64", "1:3.2.2-6.el9_5.1", true),
            ("openssl-libs", "x86_64", "1:3.2.2-6.el9_5.1", true),
            ("tzdata", "noarch", "2025b-1.el9", false),
            ("unknown-pkg", "noarch", "2.0-1.el9", true),
            ("vim-minimal", "x86_64", "2:8.2.2637-21.el9", false),
        ]
    );
    let kernel = inventory.updates.first().ok_or("none")?;
    assert_eq!(kernel.advisory_id.as_deref(), Some("RLSA-2026:1002"));
    assert_eq!(kernel.severity.as_deref(), Some("moderate"));
    assert_eq!(kernel.origin.as_deref(), Some("baseos"));
    assert_eq!(kernel.installed_version, None);
    assert!(inventory
        .updates
        .iter()
        .all(|update| update.tenant == "tenant-a" && update.device_id == "device-1"));
    let unknown = inventory.updates.get(UNKNOWN_INDEX).ok_or("none")?;
    assert_eq!(unknown.severity, None);
    assert_eq!(unknown.origin, None);
    let tzdata = inventory.updates.get(TZDATA_INDEX).ok_or("none")?;
    assert_eq!(tzdata.advisory_id.as_deref(), Some("RLBA-2026:2001"));
    Ok(())
}


#[test]
fn check_update_alone_has_no_advisory() -> TestResult {
    let inventory = parse_dnf(&device(), EMPTY, CHECK_UPDATE, &limits())?;
    assert_eq!(inventory.updates.len(), CHECK_UPDATE_COUNT);
    assert!(inventory.updates.iter().all(|update| !update.security && update.advisory_id.is_none()));
    assert!(inventory
        .updates
        .iter()
        .all(|update| update.package != "newpkg" && update.package != "oldpkg"));
    Ok(())
}


#[test]
fn security_advisory_beats_bugfix_for_one_package() -> TestResult {
    let updateinfo = "RLBA-1 bugfix pkg-1.0-1.el9.x86_64\nRLSA-2 security pkg-1.0-1.el9.x86_64\nRLSA-3 Low/Sec. pkg-1.0-1.el9.x86_64\nRLBA-4 bugfix pkg-1.0-1.el9.x86_64\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), EMPTY, &limits())?;
    assert_eq!(inventory.updates.len(), 1);
    let update = inventory.updates.first().ok_or("none")?;
    assert!(update.security);
    assert_eq!(update.advisory_id.as_deref(), Some("RLSA-2"));
    assert_eq!(update.severity, None);
    Ok(())
}


#[test]
fn malformed_lines_of_both_readers_are_added() -> TestResult {
    let updateinfo = "one two\nRLSA-1 bugfix nonevra\nRLSA-1 bugfix a-1.0.x86_64\nRLSA-1 bugfix -1.0-1.x86_64\nRLSA-1 bugfix a-1.0-1.\n";
    let check = "bad line\nnodot 1.0 repo\n.x86_64 1.0 repo\npkg. 1.0 repo\nSecurity: foo is an installed security update\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), check.as_bytes(), &limits())?;
    assert!(inventory.updates.is_empty());
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::Malformed), BOTH_READERS_MALFORMED);
    Ok(())
}


#[test]
fn nevra_is_split_from_the_right() -> TestResult {
    assert_eq!(
        split_nevra("openssl-libs-1:3.2.2-6.el9.x86_64"),
        Some(("openssl-libs", "1:3.2.2-6.el9", "x86_64"))
    );
    assert_eq!(split_nevra("a-1-2.noarch"), Some(("a", "1-2", "noarch")));
    assert_eq!(split_nevra("a-1-2."), None);
    Ok(())
}


#[test]
fn control_characters_and_unparsable_versions_are_counted() -> TestResult {
    let check = "pkg.x86_64 bad!ver repo\nok.x86_64 1.0-1 repo\nevil.x86_64 1.0\u{1b}[0m repo\n";
    let inventory = parse_dnf(&device(), EMPTY, check.as_bytes(), &limits())?;
    assert_eq!(inventory.updates.len(), 1);
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::UnparsableVersion), 1);
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::ControlCharacters), 1);
    Ok(())
}


#[test]
fn caps_apply_to_each_reader() -> TestResult {
    let tiny = Limits {
        max_bytes: TINY_BYTES,
        ..limits()
    };
    assert!(matches!(
        parse_dnf(&device(), UPDATEINFO, EMPTY, &tiny),
        Err(InventoryError::TooLarge { .. })
    ));
    assert!(matches!(
        parse_dnf(&device(), EMPTY, CHECK_UPDATE, &tiny),
        Err(InventoryError::TooLarge { .. })
    ));
    let few = Limits { max_lines: 1, ..limits() };
    assert!(matches!(
        parse_dnf(&device(), UPDATEINFO, EMPTY, &few),
        Err(InventoryError::TooManyLines { .. })
    ));
    assert!(matches!(
        parse_dnf(&device(), EMPTY, CHECK_UPDATE, &few),
        Err(InventoryError::TooManyLines { .. })
    ));
    Ok(())
}


#[test]
fn read_failures_are_errors() -> TestResult {
    assert!(matches!(
        parse_dnf(&device(), FailingReader, EMPTY, &limits()),
        Err(InventoryError::Read(_))
    ));
    assert!(matches!(
        parse_dnf(&device(), EMPTY, FailingReader, &limits()),
        Err(InventoryError::Read(_))
    ));
    Ok(())
}
