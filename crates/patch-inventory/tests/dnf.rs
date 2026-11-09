mod common;


use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::dnf::{bare_update, parse_dnf, split_nevra};
use patch_inventory::error::InventoryError;
use patch_inventory::finish::finish;
use patch_inventory::model::{Limits, SkipReason, Update};
use patch_inventory::types::SkipCounts;
use vuln_match::model::Family;


const UPDATEINFO: &[u8] = include_bytes!("fixtures/dnf-updateinfo.txt");


const CHECK_UPDATE: &[u8] = include_bytes!("fixtures/dnf-check-update.txt");


const EMPTY: &[u8] = b"";


const TINY_BYTES: usize = 4;


const SUDO_INDEX: usize = 2;


const VIM_INDEX: usize = 4;


const LOOKALIKE_COUNT: usize = 6;


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
            ("curl", "x86_64", "7.76.1-40.el9_8.9", true),
            ("libcurl", "x86_64", "7.76.1-40.el9_8.9", true),
            ("sudo", "x86_64", "1.9.17p2-3.el9_8.3", true),
            ("tzdata", "noarch", "2026f-1.el9_8", false),
            ("vim-minimal", "x86_64", "2:8.2.2637-26.el9_8.23", true),
        ]
    );
    let curl = inventory.updates.first().ok_or("none")?;
    assert_eq!(curl.advisory_id.as_deref(), Some("RLSA-2026:92907"));
    assert_eq!(curl.severity.as_deref(), Some("moderate"));
    let sudo = inventory.updates.get(SUDO_INDEX).ok_or("none")?;
    assert_eq!(sudo.advisory_id.as_deref(), Some("RLSA-2026:75571"));
    assert_eq!(sudo.severity.as_deref(), Some("important"));
    let vim = inventory.updates.get(VIM_INDEX).ok_or("none")?;
    assert_eq!(vim.advisory_id.as_deref(), Some("RLSA-2026:75768"));
    assert_eq!(curl.origin.as_deref(), Some("zzbase"));
    assert_eq!(curl.installed_version, None);
    assert!(inventory
        .updates
        .iter()
        .all(|update| update.tenant == "tenant-a" && update.device_id == "device-1"));
    let tzdata = inventory.updates.get(TZDATA_INDEX).ok_or("none")?;
    assert_eq!(tzdata.advisory_id, None);
    assert_eq!(tzdata.severity, None);
    Ok(())
}


#[test]
fn obsoleting_section_and_advisory_kinds_are_handled() -> TestResult {
    let updateinfo = "RLSA-1 unknown/Sec. a-1.0-1.el9.noarch\nRLBA-2 bugfix b-1.0-1.el9.noarch\nRLEA-3 enhancement c-1.0-1.el9.noarch\n";
    let check = "a.noarch 1.0-1.el9 baseos\nObsoleting Packages\nnewpkg.x86_64 1.0-1.el9 appstream\n    oldpkg.x86_64 0.9-1.el9 @baseos\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), check.as_bytes(), &limits())?;
    let rows: Vec<(&str, bool, Option<&str>)> = inventory
        .updates
        .iter()
        .map(|update| (update.package.as_str(), update.security, update.severity.as_deref()))
        .collect();
    assert_eq!(rows, [("a", true, None), ("b", false, None), ("c", false, None)]);
    assert!(inventory.skipped.is_empty());
    Ok(())
}


#[test]
fn check_update_alone_has_no_advisory() -> TestResult {
    let inventory = parse_dnf(&device(), EMPTY, CHECK_UPDATE, &limits())?;
    assert_eq!(inventory.updates.len(), CHECK_UPDATE_COUNT);
    assert!(inventory.updates.iter().all(|update| !update.security && update.advisory_id.is_none()));
    Ok(())
}


#[test]
fn security_advisory_beats_bugfix_for_one_package() -> TestResult {
    let updateinfo = "RLBA-1 bugfix pkg-1.0-1.el9.x86_64\nRLSA-2 security pkg-1.0-1.el9.x86_64\nRLSA-3 Low/Sec. pkg-1.0-1.el9.x86_64\nRLBA-4 bugfix pkg-1.0-1.el9.x86_64\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), EMPTY, &limits())?;
    assert_eq!(inventory.updates.len(), 1);
    let update = inventory.updates.first().ok_or("none")?;
    assert!(update.security);
    assert_eq!(update.advisory_id.as_deref(), Some("RLSA-3"));
    assert_eq!(update.severity.as_deref(), Some("low"));
    Ok(())
}


#[test]
fn no_matching_advisory_takes_the_highest_severity() -> TestResult {
    let updateinfo = "RLSA-1 Moderate/Sec. p-1.0-1.el9.x86_64\nRLSA-2 Critical/Sec. p-1.0-2.el9.x86_64\nRLSA-3 Low/Sec. p-1.0-3.el9.x86_64\n";
    let check = "p.x86_64 1.0-9.el9 baseos\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), check.as_bytes(), &limits())?;
    let update = inventory.updates.first().ok_or("none")?;
    assert_eq!(update.advisory_id.as_deref(), Some("RLSA-2"));
    assert_eq!(update.candidate_version, "1.0-9.el9");
    assert_eq!(update.origin.as_deref(), Some("baseos"));
    Ok(())
}


#[test]
fn candidate_match_wins_over_higher_severity() -> TestResult {
    let updateinfo = "RLSA-1 Critical/Sec. p-1.0-1.el9.x86_64\nRLSA-2 Low/Sec. p-1.0-2.el9.x86_64\n";
    let check = "p.x86_64 1.0-2.el9 baseos\n";
    let inventory = parse_dnf(&device(), updateinfo.as_bytes(), check.as_bytes(), &limits())?;
    let update = inventory.updates.first().ok_or("none")?;
    assert_eq!(update.advisory_id.as_deref(), Some("RLSA-2"));
    assert_eq!(update.origin.as_deref(), Some("baseos"));
    Ok(())
}


#[test]
fn progress_lines_are_ignored_and_lookalikes_are_malformed() -> TestResult {
    let progress = "zzbase  11 MB/s | 47 MB  00:04\nzzbase 980 kB/s | 1.2 MB 00:00\n";
    let lookalikes = "zzbase 11 MB | 47 MB 00:04\nzzbase x MB/s | 47 MB 00:04\nzzbase 11 MB/s | y MB 00:04\nzzbase 11 MB/s | 47 MBYTES 00:04\nzzbase 11 MB/s | 47 MB 0:a\nzzbase 11 MB/s | 47 MB 00::04\n";
    let both = format!("{progress}{lookalikes}");
    let inventory = parse_dnf(&device(), both.as_bytes(), progress.as_bytes(), &limits())?;
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::Malformed), LOOKALIKE_COUNT);
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


#[test]
fn finish_prefers_a_security_duplicate_over_a_plain_one() -> TestResult {
    let plain = bare_update(&device(), "p", "x86_64", "1.0-1", None);
    let security = Update {
        security: true,
        ..plain.clone()
    };
    let replaced = finish(Family::Rpm, vec![plain.clone(), security.clone()], SkipCounts::new());
    assert_eq!(replaced.updates, std::slice::from_ref(&security));
    let kept = finish(Family::Rpm, vec![security.clone(), plain], SkipCounts::new());
    assert_eq!(kept.updates, std::slice::from_ref(&security));
    let twice = finish(Family::Rpm, vec![security.clone(), security.clone()], SkipCounts::new());
    assert_eq!(twice.updates, std::slice::from_ref(&security));
    Ok(())
}
