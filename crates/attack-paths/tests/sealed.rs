use attack_paths::error::TagsError;
use attack_paths::tags::{digest_hex, load_tags, sealed_text, split_trailer, verify_sealed, TRAILER_BYTES, TRAILER_PREFIX};
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const DIGEST_CHARS: usize = 64;


const EXPECTED_TRAILER_BYTES: usize = 82;


const MIN_BOUNDARIES: usize = 4;


const MIN_REFUSED_AT_BOUNDARY: usize = 3;


const OLD_BODY: &str = "critical:\n  - Admins\n  - Backup\n";


const NEW_BODY: &str = "critical:\n  - Vault\n  - Admins\n";


fn load_text(dir: &Path, text: &[u8]) -> Result<Result<Vec<String>, TagsError>, Box<dyn std::error::Error>> {
    let file = dir.join("tags.yaml");
    fs::write(&file, text)?;
    Ok(load_tags(&file).map(|tags| tags.critical))
}


#[test]
fn a_sealed_file_is_loaded_and_the_trailer_is_82_bytes() -> TestResult {
    let dir = tempdir()?;
    let sealed = sealed_text(OLD_BODY);
    assert_eq!(sealed.len(), OLD_BODY.len() + TRAILER_BYTES);
    assert_eq!(TRAILER_BYTES, EXPECTED_TRAILER_BYTES);
    assert_eq!(
        load_text(dir.path(), sealed.as_bytes())??,
        vec!["Admins".to_string(), "Backup".to_string()]
    );
    Ok(())
}


#[test]
fn a_trailer_alone_means_no_manual_tags_and_an_empty_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let only = sealed_text("");
    assert_eq!(only.len(), TRAILER_BYTES);
    assert!(load_text(dir.path(), only.as_bytes())??.is_empty());
    assert!(matches!(load_text(dir.path(), b"")?, Err(TagsError::Incomplete)));
    Ok(())
}


#[test]
fn an_unknown_key_under_a_valid_seal_is_refused_by_the_parser() -> TestResult {
    let dir = tempdir()?;
    let text = sealed_text("critical: []\nimportant: [a]\n");
    assert!(matches!(load_text(dir.path(), text.as_bytes())?, Err(TagsError::Config(_))));
    let doubled = sealed_text(&sealed_text(OLD_BODY));
    assert!(matches!(load_text(dir.path(), doubled.as_bytes())?, Err(TagsError::Config(_))));
    assert!(matches!(load_tags(&dir.path().join("absent.yaml")), Err(TagsError::Config(_))));
    Ok(())
}


fn malformed_trailers() -> Vec<(&'static str, Vec<u8>)> {
    let digest = digest_hex(OLD_BODY);
    let upper = digest.to_ascii_uppercase();
    let short: String = digest.chars().take(DIGEST_CHARS - 1).collect();
    let long = format!("{digest}0");
    let multibyte = format!("\u{e9}{}", "a".repeat(TRAILER_BYTES - 1));
    vec![
        ("the old trailer", format!("{OLD_BODY}complete: true\n").into_bytes()),
        ("uppercase hex", format!("{OLD_BODY}{TRAILER_PREFIX}{upper}\n").into_bytes()),
        ("63 hex digits", format!("{OLD_BODY}{TRAILER_PREFIX}{short}\n").into_bytes()),
        ("65 hex digits", format!("{OLD_BODY}{TRAILER_PREFIX}{long}\n").into_bytes()),
        ("no sha256 prefix", format!("{OLD_BODY}complete: {digest}\n").into_bytes()),
        ("a trailing space", format!("{OLD_BODY}{TRAILER_PREFIX}{digest} \n").into_bytes()),
        ("no final newline", format!("{OLD_BODY}{TRAILER_PREFIX}{digest}").into_bytes()),
        ("an empty line after", format!("{}\n", sealed_text(OLD_BODY)).into_bytes()),
        ("a line appended", format!("{}x: 1\n", sealed_text(OLD_BODY)).into_bytes()),
        ("shorter than the trailer", b"critical: []\n".to_vec()),
        ("a character cut in two", multibyte.into_bytes()),
        ("a non-hex digit", format!("{OLD_BODY}{TRAILER_PREFIX}{short}g\n").into_bytes()),
        ("no newline before it", format!("critical: []{TRAILER_PREFIX}{digest}\n").into_bytes()),
    ]
}


#[test]
fn every_malformed_trailer_is_refused_as_incomplete() -> TestResult {
    let dir = tempdir()?;
    malformed_trailers().iter().try_for_each(|(name, bytes)| -> TestResult {
        let loaded = load_text(dir.path(), bytes)?;
        assert!(matches!(loaded, Err(TagsError::Incomplete)), "{name}: {loaded:?}");
        Ok(())
    })
}


#[test]
fn a_body_edited_after_sealing_or_a_foreign_digest_is_refused_as_altered() -> TestResult {
    let dir = tempdir()?;
    let edited = sealed_text(OLD_BODY).replace("Backup", "Backu9");
    let foreign = format!("{NEW_BODY}{TRAILER_PREFIX}{}\n", digest_hex(OLD_BODY));
    let whole = format!("{OLD_BODY}{TRAILER_PREFIX}{}\n", digest_hex(&sealed_text(OLD_BODY)));
    [edited, foreign, whole].iter().try_for_each(|text| -> TestResult {
        let loaded = load_text(dir.path(), text.as_bytes())?;
        assert!(matches!(loaded, Err(TagsError::Altered)), "{loaded:?}");
        Ok(())
    })?;
    assert_eq!(TagsError::Altered.to_string(), "the tag file changed after it was sealed: run seal-tags");
    Ok(())
}


#[test]
fn any_carriage_return_is_refused_first() -> TestResult {
    let dir = tempdir()?;
    let crlf = sealed_text("critical:\r\n  - a\r\n");
    let lone = sealed_text("critical:\r  - a\n");
    let in_trailer = sealed_text(OLD_BODY).replace("sha256:", "sha256:\r");
    [crlf, lone, in_trailer].iter().try_for_each(|text| -> TestResult {
        let loaded = load_text(dir.path(), text.as_bytes())?;
        assert!(matches!(loaded, Err(TagsError::CarriageReturn)), "{loaded:?}");
        Ok(())
    })?;
    assert_eq!(TagsError::CarriageReturn.to_string(), "CR line endings: write the file with LF");
    Ok(())
}


#[test]
fn a_file_spliced_from_two_complete_versions_is_never_loaded_as_clean() -> TestResult {
    let dir = tempdir()?;
    let (old, new) = (sealed_text(OLD_BODY), sealed_text(NEW_BODY));
    let boundaries: Vec<usize> = new.match_indices('\n').map(|(index, _)| index + 1).collect();
    assert!(boundaries.len() >= MIN_BOUNDARIES);
    (1..=new.len()).try_for_each(|prefix| -> TestResult {
        let mut spliced = old.clone().into_bytes();
        let overwritten = prefix.min(spliced.len());
        spliced.splice(..overwritten, new.bytes().take(prefix));
        let loaded = load_text(dir.path(), &spliced)?;
        let is_a_version = spliced == old.as_bytes() || spliced == new.as_bytes();
        assert!(
            is_a_version || loaded.is_err(),
            "prefix {prefix} (line boundary: {}): {loaded:?}",
            boundaries.contains(&prefix)
        );
        Ok(())
    })?;
    let at_boundary = boundaries
        .iter()
        .try_fold(0, |refused, prefix| -> Result<usize, Box<dyn std::error::Error>> {
            let mut spliced = old.clone().into_bytes();
            let overwritten = (*prefix).min(spliced.len());
            spliced.splice(..overwritten, new.bytes().take(*prefix));
            Ok(refused + usize::from(load_text(dir.path(), &spliced)?.is_err()))
        })?;
    assert!(at_boundary >= MIN_REFUSED_AT_BOUNDARY, "{at_boundary}");
    Ok(())
}


#[test]
fn the_split_and_the_verification_agree_on_a_good_file() -> TestResult {
    let sealed = sealed_text(OLD_BODY);
    let (body, digits) = split_trailer(&sealed).ok_or("no trailer")?;
    assert_eq!((body, digits), (OLD_BODY, digest_hex(OLD_BODY).as_str()));
    assert_eq!(verify_sealed(&sealed)?, OLD_BODY);
    assert!(split_trailer("").is_none());
    Ok(())
}
