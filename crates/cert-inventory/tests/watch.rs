#[path = "common/types.rs"]
mod types;


use cert_inventory::error::{WatchError, ZoneReason};
use cert_inventory::watch::{
    load_watch_list, normalise_zone, parse_watch_list, MAX_HOSTNAME_BYTES, MAX_LABEL_BYTES, MAX_WATCH_FILE_BYTES, MAX_ZONES,
};
use core_pg::scope::tenant_of;
use std::error::Error;
use types::TestResult;


const FILE: &str = "watch.yaml";


const DUPLICATE_INDEX: usize = 2;


const MARKER: &str = "SECRET-MARKER-IN-THE-FILE";


const MARKER_REPEAT: usize = 100;


fn document(zones: &[&str]) -> String {
    let lines = zones.iter().map(|zone| format!("  - \"{zone}\"")).collect::<Vec<_>>().join("\n");
    format!("tenant: acme\nzones:\n{lines}\n")
}


fn refusal(zone: &str) -> Result<ZoneReason, Box<dyn Error>> {
    match parse_watch_list(&document(&[zone]), FILE) {
        Err(WatchError::Zone { index: 0, reason }) => Ok(reason),
        other => Err(format!("zone {zone:?} gave {other:?}").into()),
    }
}


#[test]
fn a_valid_list_is_normalised() -> TestResult {
    let list = parse_watch_list(&document(&["Example.COM.", "sub.Example.co.uk", "a-b.example.org"]), FILE)?;
    assert_eq!(tenant_of(&list.scope), "acme");
    assert_eq!(list.zones, vec!["example.com", "sub.example.co.uk", "a-b.example.org"]);
    Ok(())
}


#[test]
fn grammar_edges_are_refused_with_their_index() -> TestResult {
    let long_label = format!("{}.example.org", "a".repeat(MAX_LABEL_BYTES + 1));
    let long_name = format!(
        "{}.{}.{}.{}.org",
        "a".repeat(MAX_LABEL_BYTES),
        "b".repeat(MAX_LABEL_BYTES),
        "c".repeat(MAX_LABEL_BYTES),
        "d".repeat(MAX_LABEL_BYTES)
    );
    let cases = [
        (".example.org", ZoneReason::BadLabel),
        ("example..org", ZoneReason::BadLabel),
        ("example.org..", ZoneReason::BadLabel),
        ("", ZoneReason::BadLabel),
        ("-a.example.org", ZoneReason::BadLabel),
        ("a-.example.org", ZoneReason::BadLabel),
        (long_label.as_str(), ZoneReason::BadLabel),
        ("*.example.org", ZoneReason::BadCharacter),
        ("*", ZoneReason::BadCharacter),
        ("a\u{3164}b.example.org", ZoneReason::BadCharacter),
        ("exa mple.org", ZoneReason::BadCharacter),
        ("[::1]", ZoneReason::BadCharacter),
        ("com", ZoneReason::TooFewLabels),
        ("localhost.", ZoneReason::TooFewLabels),
        ("co.uk", ZoneReason::PublicSuffix),
        ("github.io", ZoneReason::PublicSuffix),
        ("1.2.3.4", ZoneReason::IpLiteral),
        ("example.123", ZoneReason::IpLiteral),
        (long_name.as_str(), ZoneReason::TooLong),
    ];
    cases.iter().try_for_each(|(zone, expected)| -> TestResult {
        assert_eq!(refusal(zone)?, *expected, "{zone:?}");
        Ok(())
    })?;
    assert!(long_name.len() > MAX_HOSTNAME_BYTES);
    Ok(())
}


#[test]
fn the_index_names_the_refused_zone() -> TestResult {
    let outcome = parse_watch_list(&document(&["example.org", "com"]), FILE);
    assert!(matches!(
        outcome,
        Err(WatchError::Zone {
            index: 1,
            reason: ZoneReason::TooFewLabels
        })
    ));
    assert_eq!(normalise_zone("com").err(), Some(ZoneReason::TooFewLabels));
    Ok(())
}


#[test]
fn duplicates_after_lowercasing_are_refused() -> TestResult {
    let outcome = parse_watch_list(&document(&["Example.org", "other.org", "example.ORG."]), FILE);
    assert!(matches!(
        outcome,
        Err(WatchError::Zone {
            index: DUPLICATE_INDEX,
            reason: ZoneReason::Duplicate
        })
    ));
    Ok(())
}


#[test]
fn too_many_zones_are_refused() -> TestResult {
    let zones = (0..=MAX_ZONES).map(|index| format!("z{index}.example.org")).collect::<Vec<_>>();
    let refs = zones.iter().map(String::as_str).collect::<Vec<_>>();
    let outcome = parse_watch_list(&document(&refs), FILE);
    assert!(matches!(outcome, Err(WatchError::TooManyZones { max: MAX_ZONES })));
    Ok(())
}


#[test]
fn the_tenant_follows_the_store_grammar() -> TestResult {
    let outcome = parse_watch_list("tenant: \"-x\"\nzones: []\n", FILE);
    assert!(matches!(outcome, Err(WatchError::Tenant(_))));
    let empty = parse_watch_list("tenant: acme\nzones: []\n", FILE)?;
    assert!(empty.zones.is_empty());
    Ok(())
}


#[test]
fn unknown_fields_and_wrong_types_never_echo_the_file() -> TestResult {
    let long = MARKER.repeat(MARKER_REPEAT);
    let documents = [
        format!("tenant: acme\nzones: []\n{long}: 1\n"),
        format!("tenant: acme\nzones: {long}\n"),
        format!("tenant: [{long}]\nzones: []\n"),
        format!("tenant: acme\nzones: [\n{long}"),
    ];
    documents.iter().try_for_each(|text| -> TestResult {
        let error = parse_watch_list(text, FILE).err().ok_or("accepted")?;
        let shown = std::iter::successors(Some(&error as &(dyn Error + 'static)), |current| (*current).source())
            .map(|current| format!("{current} {current:?}"))
            .collect::<String>();
        assert!(!shown.contains(MARKER), "{shown}");
        Ok(())
    })
}


#[test]
fn the_file_is_read_through_the_cap() -> TestResult {
    let mut small = document(&["example.org"]).into_bytes();
    assert_eq!(load_watch_list(&mut small.as_slice(), FILE)?.zones, vec!["example.org"]);
    small.resize(usize::try_from(MAX_WATCH_FILE_BYTES)? + 1, b' ');
    assert!(matches!(load_watch_list(&mut small.as_slice(), FILE), Err(WatchError::File(_))));
    Ok(())
}
