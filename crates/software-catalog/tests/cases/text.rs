use crate::common::TestResult;
use software_catalog::text::{is_clean, is_entry_name, is_fingerprint, is_msi_key, is_sha256, is_subject, is_winget_id};


const SIXTY_FOUR: usize = 64;


const TWO_HUNDRED: usize = 200;


const TWO: usize = 2;


const SUBJECT_LIMIT: usize = 256;


#[test]
fn clean_text_refuses_empty_dash_and_invisible_characters() -> TestResult {
    assert!(is_clean("Example Corp"));
    assert!(!is_clean("") && !is_clean("-x") && !is_clean("a\u{202e}b") && !is_clean("a\u{200b}b") && !is_clean("a\nb"));
    Ok(())
}


#[test]
fn entry_names_follow_the_grammar() -> TestResult {
    assert!(is_entry_name("jq") && is_entry_name("7zip") && is_entry_name("a.b_c-d"));
    assert!(!is_entry_name("") && !is_entry_name("-jq") && !is_entry_name("Jq") && !is_entry_name("j q"));
    assert!(is_entry_name(&"a".repeat(SIXTY_FOUR)));
    assert!(!is_entry_name(&"a".repeat(SIXTY_FOUR + 1)));
    Ok(())
}


#[test]
fn winget_ids_need_two_clean_segments() -> TestResult {
    assert!(is_winget_id("Microsoft.PowerToys") && is_winget_id("a-b.c.d9"));
    assert!(!is_winget_id("single") && !is_winget_id("a..b") && !is_winget_id("a.b c") && !is_winget_id("a.b;c"));
    assert!(!is_winget_id("-a.b") && !is_winget_id("a.-b") && !is_winget_id("a.b\u{202e}") && !is_winget_id(".a.b"));
    assert!(!is_winget_id(&format!("a.{}", "b".repeat(SUBJECT_LIMIT))));
    Ok(())
}


#[test]
fn msi_keys_stay_inside_the_store() -> TestResult {
    assert!(is_msi_key("tools/app-1.2.msi") && is_msi_key("a"));
    assert!(!is_msi_key("../a.msi") && !is_msi_key("a/../b.msi") && !is_msi_key("/abs.msi") && !is_msi_key("a//b") && !is_msi_key("a/./b"));
    assert!(!is_msi_key("a/") && !is_msi_key("-a.msi") && !is_msi_key("A.msi") && !is_msi_key("a\u{200b}.msi") && !is_msi_key(""));
    assert!(is_msi_key(&"a".repeat(TWO_HUNDRED + 1)));
    assert!(!is_msi_key(&"a".repeat(TWO_HUNDRED + TWO)));
    Ok(())
}


#[test]
fn digests_and_fingerprints_have_fixed_shapes() -> TestResult {
    assert!(
        is_sha256(crate::common::DIGEST)
            && !is_sha256(&crate::common::DIGEST.to_uppercase())
            && !is_sha256("abc")
            && !is_sha256(&"g".repeat(SIXTY_FOUR))
    );
    assert!(is_fingerprint(crate::common::FINGERPRINT) && !is_fingerprint(&crate::common::FINGERPRINT.to_lowercase()) && !is_fingerprint("ABC"));
    assert!(is_subject("CN=Example") && !is_subject("CN=A\nB") && !is_subject("-CN") && !is_subject(&"a".repeat(SUBJECT_LIMIT + 1)));
    Ok(())
}
