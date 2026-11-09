mod common;


use common::{device, limits, skipped_count, FailingReader, TestResult};
use patch_inventory::apt::parse_apt;
use patch_inventory::error::InventoryError;
use patch_inventory::model::{Limits, SkipReason};


const HOST_OUTPUT: &[u8] = include_bytes!("fixtures/apt-ubuntu-host.txt");


const SECURITY_OUTPUT: &[u8] = include_bytes!("fixtures/apt-security.txt");


const SMALL_LINE_CAP: usize = 40;


const SMALL_LINE_COUNT_CAP: usize = 2;


const TWO: usize = 2;


const SIX_MALFORMED: usize = 6;


#[test]
fn real_ubuntu_output_is_parsed_and_stamped() -> TestResult {
    let inventory = parse_apt(&device(), HOST_OUTPUT, &limits())?;
    let expected = String::from_utf8_lossy(HOST_OUTPUT)
        .lines()
        .filter(|line| line.contains("[upgradable from: "))
        .count();
    assert_eq!(inventory.updates.len(), expected);
    assert!(inventory.skipped.is_empty());
    assert!(inventory.updates.iter().all(|update| !update.security));
    assert!(inventory
        .updates
        .iter()
        .all(|update| update.tenant == "tenant-a" && update.device_id == "device-1"));
    let names: Vec<(&str, &str)> = inventory
        .updates
        .iter()
        .map(|update| (update.package.as_str(), update.architecture.as_str()))
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    let first = inventory.updates.first().ok_or("no update")?;
    assert_eq!(first.package, "apparmor");
    assert_eq!(first.candidate_version, "5.0.2-0ubuntu1~26.04.1");
    assert_eq!(first.installed_version.as_deref(), Some("5.0.0~beta1-0ubuntu7"));
    assert_eq!(first.origin.as_deref(), Some("resolute-updates"));
    Ok(())
}


#[test]
fn security_suites_are_flagged() -> TestResult {
    let inventory = parse_apt(&device(), SECURITY_OUTPUT, &limits())?;
    let flags: Vec<(&str, bool)> = inventory
        .updates
        .iter()
        .map(|update| (update.package.as_str(), update.security))
        .collect();
    assert_eq!(flags, [("curl", true), ("libcurl4t64", true), ("openssl", true), ("tzdata", false)]);
    let curl = inventory.updates.first().ok_or("no update")?;
    assert_eq!(curl.origin.as_deref(), Some("noble-updates,noble-security"));
    assert_eq!(curl.advisory_id, None);
    Ok(())
}


#[test]
fn malformed_lines_are_counted() -> TestResult {
    let input = "garbage\npkg/ 1.0 amd64\n/suite 1.0 amd64\na/b 1.0 amd64 [upgradable from: 0.9\na/b 1.0\nnoslash 1.0 amd64\nWARNING: unstable\n\nListing...\n";
    let inventory = parse_apt(&device(), input.as_bytes(), &limits())?;
    assert!(inventory.updates.is_empty());
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::Malformed), SIX_MALFORMED);
    Ok(())
}


#[test]
fn option_like_architectures_are_malformed() -> TestResult {
    let input = "a/noble 1.0 -o\npkg/noble 1.0 --allow-unauthenticated\n";
    let inventory = parse_apt(&device(), input.as_bytes(), &limits())?;
    assert!(inventory.updates.is_empty());
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::Malformed), TWO);
    Ok(())
}


#[test]
fn installed_version_is_optional() -> TestResult {
    let inventory = parse_apt(&device(), "a/b 1.0 amd64\r\n".as_bytes(), &limits())?;
    let update = inventory.updates.first().ok_or("no update")?;
    assert_eq!(update.installed_version, None);
    Ok(())
}


#[test]
fn control_characters_and_bad_utf8_are_skipped() -> TestResult {
    let mut input = b"a/b 1.0 amd64 \x1b[31m\n".to_vec();
    input.extend_from_slice(b"a/c 1.0\tamd64\n\xff\xfe\n");
    let inventory = parse_apt(&device(), input.as_slice(), &limits())?;
    assert!(inventory.updates.is_empty());
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::ControlCharacters), TWO);
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::Malformed), 1);
    Ok(())
}


#[test]
fn long_line_is_skipped_and_counted() -> TestResult {
    let small = Limits {
        max_line_bytes: SMALL_LINE_CAP,
        ..limits()
    };
    let input = format!("a/b 1.0 amd64\n{}\n", "x".repeat(SMALL_LINE_CAP + 1));
    let inventory = parse_apt(&device(), input.as_bytes(), &small)?;
    assert_eq!(inventory.updates.len(), 1);
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::LineTooLong), 1);
    Ok(())
}


#[test]
fn total_size_over_the_cap_is_refused() -> TestResult {
    let input = "a/b 1.0 amd64\n";
    let exact = Limits {
        max_bytes: input.len(),
        ..limits()
    };
    assert_eq!(parse_apt(&device(), input.as_bytes(), &exact)?.updates.len(), 1);
    let below = Limits {
        max_bytes: input.len() - 1,
        ..limits()
    };
    let refused = parse_apt(&device(), input.as_bytes(), &below);
    assert!(matches!(refused, Err(InventoryError::TooLarge { limit }) if limit == input.len() - 1));
    Ok(())
}


#[test]
fn line_count_over_the_cap_is_refused() -> TestResult {
    let small = Limits {
        max_lines: SMALL_LINE_COUNT_CAP,
        ..limits()
    };
    let refused = parse_apt(&device(), "a/b 1.0 amd64\nc/d 1.0 amd64\ne/f 1.0 amd64\n".as_bytes(), &small);
    assert!(matches!(refused, Err(InventoryError::TooManyLines { limit }) if limit == SMALL_LINE_COUNT_CAP));
    assert_eq!(
        refused.err().map(|error| error.to_string()).as_deref(),
        Some("input has more than 2 lines")
    );
    Ok(())
}


#[test]
fn unparsable_versions_are_counted_and_dropped() -> TestResult {
    let input = "a/b !!bad amd64 [upgradable from: 1.0]\nc/d 2.0 amd64 [upgradable from: !!bad]\ne/f 2.0 amd64 [upgradable from: 1.0]\n";
    let inventory = parse_apt(&device(), input.as_bytes(), &limits())?;
    assert_eq!(inventory.updates.len(), 1);
    assert_eq!(skipped_count(&inventory.skipped, SkipReason::UnparsableVersion), TWO);
    Ok(())
}


#[test]
fn duplicates_collapse_and_security_wins() -> TestResult {
    let forward = parse_apt(
        &device(),
        "a/x-updates 1.1 amd64\na/x-security 1.2 amd64\na/x-updates 1.3 amd64\n".as_bytes(),
        &limits(),
    )?;
    assert_eq!(forward.updates.len(), 1);
    assert!(forward.updates.first().ok_or("none")?.security);
    let backward = parse_apt(
        &device(),
        "a/x-security 1.2 amd64\na/x-updates 1.1 amd64\na/x-updates 1.1 i386\n".as_bytes(),
        &limits(),
    )?;
    assert_eq!(backward.updates.len(), TWO);
    assert!(backward.updates.iter().any(|update| update.architecture == "amd64" && update.security));
    Ok(())
}


#[test]
fn read_failure_is_an_error() -> TestResult {
    let failed = parse_apt(&device(), FailingReader, &limits());
    assert!(matches!(failed, Err(InventoryError::Read(_))));
    assert_eq!(
        failed.err().map(|error| error.to_string()).as_deref(),
        Some("reading the package manager output failed")
    );
    Ok(())
}
