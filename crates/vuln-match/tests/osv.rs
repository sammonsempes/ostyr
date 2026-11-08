#[path = "common/types.rs"]
mod types;


use types::TestResult;
use vuln_match::error::OsvError;
use vuln_match::limits::{
    MAX_AFFECTED_PER_RECORD, MAX_EVENTS_PER_RANGE, MAX_RANGES_PER_AFFECTED, MAX_RECORDS, MAX_RECORD_BYTES, MAX_VERSIONS_PER_AFFECTED,
};
use vuln_match::model::Event;
use vuln_match::osv::{parse_record, parse_records};


const FULL: &str = r#"{
  "id": "DSA-1",
  "aliases": ["CVE-2024-0001"],
  "summary": "ignored",
  "affected": [{
    "package": {"ecosystem": "Debian:12", "name": "openssl", "purl": "ignored"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-2"}, {"last_affected": "3"}, {"limit": "9"}]}],
    "versions": ["1.0-1"]
  }]
}"#;


#[test]
fn full_record_is_parsed() -> TestResult {
    let record = parse_record(FULL)?;
    assert_eq!(record.id, "DSA-1");
    assert_eq!(record.aliases, vec!["CVE-2024-0001"]);
    let affected = record.affected.first().ok_or("no affected")?;
    assert_eq!(affected.package.name, "openssl");
    assert_eq!(affected.versions, vec!["1.0-1"]);
    let range = affected.ranges.first().ok_or("no range")?;
    assert_eq!(range.kind, "ECOSYSTEM");
    assert_eq!(
        range.events,
        vec![
            Event::Introduced("0".into()),
            Event::Fixed("1.0-2".into()),
            Event::LastAffected("3".into()),
            Event::Limit("9".into())
        ]
    );
    Ok(())
}


#[test]
fn minimal_record_gets_defaults() -> TestResult {
    let record = parse_record(r#"{"id": "X"}"#)?;
    assert!(record.aliases.is_empty() && record.affected.is_empty());
    let range = parse_record(r#"{"id":"X","affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"GIT"}]}]}"#)?;
    assert!(range.affected.iter().all(|affected| affected.versions.is_empty()));
    Ok(())
}


#[test]
fn invalid_json_is_refused() -> TestResult {
    [
        "not json",
        r#"{"aliases": []}"#,
        r#"{"id":"X","affected":[{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"T","events":[{"bogus":"1"}]}]}]}"#,
    ]
    .iter()
    .for_each(|text| assert!(matches!(parse_record(text), Err(OsvError::Json(_))), "{text}"));
    Ok(())
}


#[test]
fn oversized_record_is_refused_before_parsing() -> TestResult {
    let text = format!(r#"{{"id": "{}"}}"#, "A".repeat(MAX_RECORD_BYTES));
    assert!(matches!(parse_record(&text), Err(OsvError::TooLarge { size, max }) if size == text.len() && max == MAX_RECORD_BYTES));
    Ok(())
}


#[test]
fn record_at_the_limit_is_accepted() -> TestResult {
    let padding = MAX_RECORD_BYTES - r#"{"id": ""}"#.len();
    let text = format!(r#"{{"id": "{}"}}"#, "A".repeat(padding));
    assert_eq!(text.len(), MAX_RECORD_BYTES);
    assert_eq!(parse_record(&text)?.id.len(), padding);
    Ok(())
}


fn affected(count: usize, body: &str) -> String {
    let entry = format!(r#"{{"package":{{"ecosystem":"npm","name":"a"}}{body}}}"#);
    format!(r#"{{"id":"X","affected":[{}]}}"#, vec![entry; count].join(","))
}


#[test]
fn counts_are_bounded() -> TestResult {
    let too_many_affected = affected(MAX_AFFECTED_PER_RECORD + 1, "");
    let ranges = vec![r#"{"type":"SEMVER"}"#; MAX_RANGES_PER_AFFECTED + 1].join(",");
    let versions = vec![r#""1.0.0""#; MAX_VERSIONS_PER_AFFECTED + 1].join(",");
    let events = vec![r#"{"introduced":"0"}"#; MAX_EVENTS_PER_RANGE + 1].join(",");
    let cases = [
        ("affected entries", too_many_affected),
        ("ranges per affected entry", affected(1, &format!(r#","ranges":[{ranges}]"#))),
        ("versions per affected entry", affected(1, &format!(r#","versions":[{versions}]"#))),
        (
            "events per range",
            affected(1, &format!(r#","ranges":[{{"type":"SEMVER","events":[{events}]}}]"#)),
        ),
    ];
    cases.iter().for_each(|(expected, text)| {
        assert!(
            matches!(parse_record(text), Err(OsvError::TooMany { what, .. }) if what == *expected),
            "{expected}"
        );
    });
    Ok(())
}


#[test]
fn record_list_is_parsed_in_order_and_bounded() -> TestResult {
    let records = parse_records(&[r#"{"id":"B"}"#, r#"{"id":"A"}"#])?;
    assert_eq!(records.iter().map(|record| record.id.as_str()).collect::<Vec<_>>(), vec!["B", "A"]);
    assert!(parse_records(&[r#"{"id":"A"}"#, "broken"]).is_err());
    let texts = vec![r#"{"id":"A"}"#; MAX_RECORDS + 1];
    assert!(matches!(parse_records(&texts), Err(OsvError::TooMany { what: "records", .. })));
    Ok(())
}
