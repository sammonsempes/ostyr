#[path = "common/types.rs"]
mod types;


use dns_rpz::limits::{MAX_NAME_BYTES, WILDCARD_PREFIX};
use dns_rpz::name::{check_length, is_under, normalise_name, NameError};
use types::TestResult;


const ZONE: &str = "rpz.example.org";


#[test]
fn names_are_lowercased_punycoded_and_lose_their_trailing_dots() -> TestResult {
    assert_eq!(normalise_name("Example.COM.")?, "example.com");
    assert_eq!(normalise_name("b\u{fc}cher.example")?, "xn--bcher-kva.example");
    Ok(())
}


#[test]
fn names_that_cannot_be_in_a_zone_are_refused() -> TestResult {
    assert!(matches!(normalise_name(""), Err(NameError::Invalid(_))));
    assert!(matches!(normalise_name("_dmarc.example"), Err(NameError::Invalid(_))));
    assert!(matches!(normalise_name("a b.example"), Err(NameError::Invalid(_))));
    assert!(matches!(normalise_name("*.example"), Err(NameError::Invalid(_))));
    assert!(matches!(
        normalise_name(&format!("{}.example", "a".repeat(MAX_NAME_BYTES))),
        Err(NameError::Invalid(_))
    ));
    Ok(())
}


#[test]
fn the_owner_name_with_the_zone_and_the_wildcard_must_fit() -> TestResult {
    let room = MAX_NAME_BYTES - 1 - ZONE.len();
    check_length(&"a".repeat(room), ZONE, false)?;
    assert!(matches!(check_length(&"a".repeat(room + 1), ZONE, false), Err(NameError::TooLong(total)) if total == MAX_NAME_BYTES + 1));
    let wildcard_room = room - WILDCARD_PREFIX.len();
    check_length(&"a".repeat(wildcard_room), ZONE, true)?;
    assert!(check_length(&"a".repeat(wildcard_room + 1), ZONE, true).is_err());
    Ok(())
}


#[test]
fn a_name_is_under_itself_and_its_parents_only_at_a_label_boundary() -> TestResult {
    assert!(is_under("example.org", "example.org"));
    assert!(is_under("www.example.org", "example.org"));
    assert!(!is_under("notexample.org", "example.org"));
    assert!(!is_under("example.org", "www.example.org"));
    assert!(!is_under("example.com", "example.org"));
    Ok(())
}
