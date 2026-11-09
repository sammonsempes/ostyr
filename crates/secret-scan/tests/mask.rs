#[path = "common/types.rs"]
mod types;


use secret_scan::mask::{escape_bounded, mask_secret, masked_excerpt, MASK_MARKER};
use types::TestResult;


const KEPT: usize = 4;


const WIDE: usize = 100;


const NARROW: usize = 8;


const THREE: usize = 3;


#[test]
fn long_secret_keeps_only_the_prefix() -> TestResult {
    assert_eq!(mask_secret("abcdefghijkl", KEPT), "abcd********");
    assert_eq!(mask_secret("abcdefghijklmnopqrstuvwxyz", KEPT), "abcd********");
    Ok(())
}


#[test]
fn short_secret_keeps_nothing() -> TestResult {
    assert_eq!(mask_secret("abc", KEPT), MASK_MARKER);
    assert_eq!(mask_secret("abcdefg", KEPT), MASK_MARKER);
    assert_eq!(mask_secret("", KEPT), MASK_MARKER);
    Ok(())
}


#[test]
fn zero_kept_chars_keeps_nothing() -> TestResult {
    assert_eq!(mask_secret("abcdefghijkl", 0), MASK_MARKER);
    Ok(())
}


#[test]
fn kept_prefix_counts_characters_not_bytes() -> TestResult {
    assert_eq!(mask_secret("éééééééé", KEPT), "éééé********");
    Ok(())
}


#[test]
fn excerpt_masks_every_occurrence_and_keeps_context() -> TestResult {
    let excerpt = masked_excerpt("a=PASSWORD1234 b=PASSWORD1234", "PASSWORD1234", KEPT, WIDE);
    assert_eq!(excerpt, "a=PASS******** b=PASS********");
    Ok(())
}


#[test]
fn excerpt_masks_the_whole_match_without_secret() -> TestResult {
    assert_eq!(masked_excerpt("token = abcdefghijkl", "", KEPT, WIDE), "toke********");
    assert_eq!(masked_excerpt("token = abcdefghijkl", "other", KEPT, WIDE), "toke********");
    assert_eq!(masked_excerpt("", "", KEPT, WIDE), MASK_MARKER);
    Ok(())
}


#[test]
fn excerpt_is_escaped_and_bounded() -> TestResult {
    assert_eq!(escape_bounded("a\nb\"c", WIDE), "a\\nb\\\"c");
    assert_eq!(escape_bounded("abcdef", THREE), "abc");
    let excerpt = masked_excerpt("line1\nline2 SECRETSECRET1", "SECRETSECRET1", KEPT, NARROW);
    assert_eq!(excerpt, "line1\\nl");
    Ok(())
}
