#[path = "support/types.rs"]
mod types;


use discovery::error::DiscoveryError;
use discovery::model::{ScopeFile, DEFAULT_MAX_EDGES, MAX_EDGES_CEILING, MAX_RANGES, MAX_RETENTION_DAYS, MILLIS_PER_DAY};
use discovery::scope::{in_scope, load_scope, validate_scope};
use ipnet::IpNet;
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use tempfile::tempdir;
use types::TestResult;


const OVERSIZED_RETENTION: u32 = 401;


const ONE_OVER_CEILING: usize = 1_000_001;


const THIRTY: u32 = 30;


const FILE_MAX_EDGES: usize = 500;


const FILE_RANGES: usize = 2;


const BROAD_RANGES: [&str; 4] = ["0.0.0.0/0", "::/0", "10.0.0.0/7", "2001::/31"];


fn file_of(ranges: &[&str], retention_days: u32, max_edges: Option<usize>) -> Result<ScopeFile, Box<dyn Error>> {
    let owned_ranges = ranges.iter().map(|text| text.parse::<IpNet>()).collect::<Result<Vec<_>, _>>()?;
    Ok(ScopeFile {
        owned_ranges,
        retention_days,
        max_edges,
    })
}


fn address(text: &str) -> Result<IpAddr, Box<dyn Error>> {
    Ok(text.parse()?)
}


#[test]
fn valid_scope_is_masked_merged_and_sorted() -> TestResult {
    let file = file_of(
        &["10.0.0.128/25", "10.0.0.0/25", "192.168.1.77/24", "fd00::/48", "10.0.0.0/24"],
        THIRTY,
        None,
    )?;
    let scope = validate_scope(&file)?;
    let expected: Vec<IpNet> = ["10.0.0.0/24", "192.168.1.0/24", "fd00::/48"]
        .iter()
        .map(|text| text.parse())
        .collect::<Result<_, _>>()?;
    assert_eq!(scope.ranges, expected);
    assert_eq!(scope.retention_ms, i64::from(THIRTY) * MILLIS_PER_DAY);
    assert_eq!(scope.max_edges, DEFAULT_MAX_EDGES);
    Ok(())
}


#[test]
fn boundaries_are_accepted() -> TestResult {
    let at_limits = file_of(&["10.0.0.0/8", "2001::/32"], MAX_RETENTION_DAYS, Some(MAX_EDGES_CEILING))?;
    assert_eq!(validate_scope(&at_limits)?.max_edges, MAX_EDGES_CEILING);
    let at_minimums = file_of(&["10.0.0.0/32"], 1, Some(1))?;
    assert_eq!(validate_scope(&at_minimums)?.max_edges, 1);
    Ok(())
}


#[test]
fn no_range_is_refused() -> TestResult {
    let refused = validate_scope(&file_of(&[], THIRTY, None)?);
    assert!(matches!(refused, Err(DiscoveryError::NoRanges)));
    Ok(())
}


#[test]
fn too_many_ranges_are_refused_before_merging() -> TestResult {
    let one_range: IpNet = "10.0.0.0/24".parse()?;
    let file = ScopeFile {
        owned_ranges: vec![one_range; MAX_RANGES + 1],
        retention_days: THIRTY,
        max_edges: None,
    };
    let refused = validate_scope(&file);
    assert!(matches!(refused, Err(DiscoveryError::TooManyRanges { count, max }) if count == MAX_RANGES + 1 && max == MAX_RANGES));
    let at_cap = ScopeFile {
        owned_ranges: vec![one_range; MAX_RANGES],
        ..file
    };
    assert_eq!(validate_scope(&at_cap)?.ranges.len(), 1);
    Ok(())
}


#[test]
fn broad_ranges_are_refused() -> TestResult {
    BROAD_RANGES.iter().try_for_each(|broad| {
        let refused = validate_scope(&file_of(&[broad], THIRTY, None)?);
        assert!(matches!(refused, Err(DiscoveryError::RangeTooBroad { .. })), "{broad}: {refused:?}");
        let mixed = validate_scope(&file_of(&["10.0.0.0/24", broad], THIRTY, None)?);
        assert!(matches!(mixed, Err(DiscoveryError::RangeTooBroad { .. })), "{broad}: {mixed:?}");
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn retention_and_edge_cap_are_bounded() -> TestResult {
    assert!(matches!(
        validate_scope(&file_of(&["10.0.0.0/24"], 0, None)?),
        Err(DiscoveryError::Retention(0))
    ));
    assert!(matches!(
        validate_scope(&file_of(&["10.0.0.0/24"], OVERSIZED_RETENTION, None)?),
        Err(DiscoveryError::Retention(OVERSIZED_RETENTION))
    ));
    assert!(matches!(
        validate_scope(&file_of(&["10.0.0.0/24"], THIRTY, Some(0))?),
        Err(DiscoveryError::MaxEdges(0))
    ));
    assert!(matches!(
        validate_scope(&file_of(&["10.0.0.0/24"], THIRTY, Some(ONE_OVER_CEILING))?),
        Err(DiscoveryError::MaxEdges(ONE_OVER_CEILING))
    ));
    Ok(())
}


#[test]
fn load_reads_a_yaml_file_and_refuses_unknown_fields() -> TestResult {
    let directory = tempdir()?;
    let good = directory.path().join("scope.yaml");
    fs::write(&good, "owned_ranges: [10.0.0.0/24, fd00::/64]\nretention_days: 7\nmax_edges: 500\n")?;
    let scope = load_scope(&good)?;
    assert_eq!(scope.max_edges, FILE_MAX_EDGES);
    assert_eq!(scope.ranges.len(), FILE_RANGES);
    let unknown = directory.path().join("unknown.yaml");
    fs::write(&unknown, "owned_ranges: [10.0.0.0/24]\nretention_days: 7\nmax_edge: 5\n")?;
    assert!(matches!(load_scope(&unknown), Err(DiscoveryError::Config(_))));
    let missing = directory.path().join("missing.yaml");
    assert!(matches!(load_scope(&missing), Err(DiscoveryError::Config(_))));
    let broad = directory.path().join("broad.yaml");
    fs::write(&broad, "owned_ranges: [0.0.0.0/0]\nretention_days: 7\n")?;
    assert!(matches!(load_scope(&broad), Err(DiscoveryError::RangeTooBroad { .. })));
    Ok(())
}


#[test]
fn membership_follows_the_ranges() -> TestResult {
    let scope = validate_scope(&file_of(&["10.0.0.0/24", "10.0.2.0/24", "192.168.0.0/16", "fd00::/64"], THIRTY, None)?)?;
    let inside = [
        "10.0.0.0",
        "10.0.0.255",
        "10.0.2.9",
        "192.168.200.1",
        "fd00::1",
        "fd00::ffff:ffff:ffff:ffff",
    ];
    let outside = [
        "9.255.255.255",
        "10.0.1.1",
        "10.0.3.0",
        "192.169.0.0",
        "fd00:0:0:1::",
        "fe80::1",
        "::1",
        "0.0.0.0",
        "255.255.255.255",
    ];
    inside.iter().try_for_each(|text| {
        assert!(in_scope(&scope, address(text)?), "{text}");
        Ok::<(), Box<dyn Error>>(())
    })?;
    outside.iter().try_for_each(|text| {
        assert!(!in_scope(&scope, address(text)?), "{text}");
        Ok::<(), Box<dyn Error>>(())
    })
}
