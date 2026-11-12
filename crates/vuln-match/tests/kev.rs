#[path = "common/types.rs"]
mod types;


use std::io::{Error, Read};
use types::TestResult;
use vuln_match::error::KevError;
use vuln_match::kev::{parse_kev, KevLimits};
use vuln_match::text::{bounded_text, is_cve_id};


const SAMPLE: &[u8] = include_bytes!("fixtures/kev_sample.json");


const SAMPLE_ENTRIES: usize = 50;


const SAMPLE_DECLARED: u64 = 1779;


const LONG_TEXT: usize = 2000;


const SMALL_TEXT: usize = 4;


const NESTING: usize = 100_000;


const TWO: usize = 2;


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::other("injected"))
    }
}


fn catalogue(count: &str, entries: &str) -> String {
    format!("{{\"catalogVersion\":\"v1\",\"dateReleased\":\"d\",\"count\":{count},\"vulnerabilities\":[{entries}]}}")
}


#[test]
fn golden_sample() -> TestResult {
    let parsed = parse_kev(SAMPLE, &KevLimits::default())?;
    assert_eq!(parsed.ids.len(), SAMPLE_ENTRIES);
    assert_eq!(parsed.entries.len(), SAMPLE_ENTRIES);
    assert_eq!((parsed.bad_entries, parsed.duplicates), (0, 0));
    assert_eq!(parsed.declared_count, Some(SAMPLE_DECLARED));
    assert!(!parsed.count_matches);
    assert_eq!(parsed.catalog_version.as_deref(), Some("2026.11.10"));
    assert!(parsed.date_released.is_some());
    let entry = parsed.entries.get("CVE-2026-124194").ok_or("first entry missing")?;
    assert_eq!(entry.date_added.as_deref(), Some("2026-11-10"));
    assert!(entry.due_date.is_some());
    assert!(entry.ransomware_use.is_some());
    assert!(parsed.ids.contains("CVE-2026-124194"));
    Ok(())
}


#[test]
fn byte_cap_is_exact() -> TestResult {
    let body = catalogue("0", "");
    let exact = KevLimits {
        max_bytes: body.len() as u64,
        ..KevLimits::default()
    };
    assert!(parse_kev(body.as_bytes(), &exact).is_ok());
    let below = KevLimits {
        max_bytes: body.len() as u64 - 1,
        ..KevLimits::default()
    };
    assert!(matches!(parse_kev(body.as_bytes(), &below), Err(KevError::TooLarge { .. })));
    Ok(())
}


#[test]
fn entry_cap() -> TestResult {
    let body = catalogue("2", "{\"cveID\":\"CVE-2024-0001\"},{\"cveID\":\"CVE-2024-0002\"}");
    let limits = KevLimits {
        max_entries: 1,
        ..KevLimits::default()
    };
    assert!(matches!(
        parse_kev(body.as_bytes(), &limits),
        Err(KevError::TooMany { count: TWO, max: 1 })
    ));
    let fits = KevLimits {
        max_entries: TWO,
        ..KevLimits::default()
    };
    assert!(parse_kev(body.as_bytes(), &fits)?.count_matches);
    Ok(())
}


#[test]
fn bad_ids_are_counted_never_kept() -> TestResult {
    let long = format!("CVE-2024-{}", "1".repeat(LONG_TEXT));
    let ids = [
        "CVE-24-1",
        "cve-2024-1234",
        "CVE-2024-12\\u0000",
        "CVE-2024-12345678",
        "CVE-2024-123",
        "CVE-20244-1234",
        "CVE-2024-1234-5",
        "XVE-2024-1234",
        "CVE-\\uff12\\uff10\\uff12\\uff14-1234",
        long.as_str(),
    ];
    let entries: Vec<String> = ids.iter().map(|id| format!("{{\"cveID\":\"{id}\"}}")).collect();
    let body = catalogue("0", &format!("{},{{}},{{\"cveID\":\"CVE-2024-1234567\"}}", entries.join(",")));
    let parsed = parse_kev(body.as_bytes(), &KevLimits::default())?;
    assert_eq!(parsed.bad_entries, ids.len() + 1);
    assert_eq!(parsed.ids.len(), 1);
    assert!(parsed.ids.contains("CVE-2024-1234567"));
    Ok(())
}


#[test]
fn duplicates_first_wins() -> TestResult {
    let body = catalogue(
        "2",
        "{\"cveID\":\"CVE-2024-0001\",\"dateAdded\":\"first\"},{\"cveID\":\"CVE-2024-0001\",\"dateAdded\":\"second\"}",
    );
    let parsed = parse_kev(body.as_bytes(), &KevLimits::default())?;
    assert_eq!(parsed.duplicates, 1);
    assert_eq!(parsed.ids.len(), 1);
    assert_eq!(
        parsed.entries.get("CVE-2024-0001").and_then(|entry| entry.date_added.as_deref()),
        Some("first")
    );
    assert!(parsed.count_matches);
    Ok(())
}


#[test]
fn text_is_bounded_and_printable() -> TestResult {
    let long = "x".repeat(LONG_TEXT);
    let body = catalogue(
        "1",
        &format!("{{\"cveID\":\"CVE-2024-0001\",\"dueDate\":\"{long}\",\"dateAdded\":\"a\\nb\\u00e9\"}}"),
    );
    let limits = KevLimits {
        max_text_chars: SMALL_TEXT,
        ..KevLimits::default()
    };
    let parsed = parse_kev(body.as_bytes(), &limits)?;
    let entry = parsed.entries.get("CVE-2024-0001").ok_or("entry missing")?;
    assert_eq!(entry.due_date.as_deref(), Some("xxxx[cut]"));
    assert_eq!(entry.date_added.as_deref(), Some("a?b?"));
    assert_eq!(bounded_text("abcd", SMALL_TEXT), "abcd");
    assert_eq!(bounded_text("a b", SMALL_TEXT * TWO), "a b");
    Ok(())
}


#[test]
fn json_errors_are_typed() -> TestResult {
    assert!(matches!(parse_kev("not json".as_bytes(), &KevLimits::default()), Err(KevError::Json(_))));
    assert!(matches!(
        parse_kev("{\"count\":1}".as_bytes(), &KevLimits::default()),
        Err(KevError::Json(_))
    ));
    assert!(matches!(parse_kev(Failing, &KevLimits::default()), Err(KevError::Io(_))));
    Ok(())
}


#[test]
fn deep_nesting_in_an_ignored_field_does_not_overflow() -> TestResult {
    let deep = format!("{}{}", "[".repeat(NESTING), "]".repeat(NESTING));
    let body = format!("{{\"count\":1,\"x\":{deep},\"vulnerabilities\":[]}}");
    assert!(parse_kev(body.as_bytes(), &KevLimits::default())?.ids.is_empty());
    let in_known = format!("{{\"vulnerabilities\":[{{\"cveID\":{deep}}}]}}");
    let parsed = parse_kev(in_known.as_bytes(), &KevLimits::default())?;
    assert!(parsed.bad_entries == 1 && parsed.ids.is_empty());
    Ok(())
}


#[test]
fn cve_grammar() -> TestResult {
    assert!(is_cve_id("CVE-2024-0001"));
    assert!(is_cve_id("CVE-1999-1234567"));
    assert!(!is_cve_id(""));
    assert!(!is_cve_id("CVE-2024-"));
    assert!(!is_cve_id("CVE-0000-1234"));
    Ok(())
}


const SMALL_CAP: usize = 10;


const OVER_SMALL_CAP: usize = SMALL_CAP + 1;


const EMPTY_ENTRY_BYTES: usize = 3;


#[test]
fn empty_entries_hit_the_entry_cap_before_any_is_parsed() -> TestResult {
    let limits = KevLimits {
        max_entries: SMALL_CAP,
        ..KevLimits::default()
    };
    let body = format!("{{\"vulnerabilities\":[{}]}}", ["{}"; OVER_SMALL_CAP].join(","));
    assert!(matches!(
        parse_kev(body.as_bytes(), &limits),
        Err(KevError::TooMany {
            count: OVER_SMALL_CAP,
            max: SMALL_CAP
        })
    ));
    let default_cap = usize::try_from(KevLimits::default().max_bytes)?;
    let big = format!("{{\"vulnerabilities\":[{}]}}", "{},".repeat(default_cap / EMPTY_ENTRY_BYTES));
    assert!(matches!(parse_kev(big.as_bytes(), &KevLimits::default()), Err(KevError::TooLarge { .. })));
    Ok(())
}
