#![cfg(unix)]

mod common;


use common::types::TestResult;
use std::fs;
use std::process::Command;
use tempfile::tempdir;
use traces_ingest::senders::{
    fingerprint, load_senders, parse_senders, senders_loader, senders_state, FINGERPRINT_CHARS, MAX_SENDERS_FILE_BYTES, MAX_TRACE_SENDERS,
};


const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";


const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";


const DIGEST_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";


const HEX_WIDTH: usize = 64;


const PAIR: usize = 2;


const FILE: &str = "senders.yaml";


fn entry(name: &str, digest: &str) -> String {
    format!("  - name: {name}\n    token_sha256: {digest}\n")
}


fn file_of(entries: &[(&str, &str)]) -> String {
    let body: String = entries.iter().map(|(name, digest)| entry(name, digest)).collect();
    format!("senders:\n{body}")
}


fn refused(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let error = parse_senders(&mut text.as_bytes(), FILE).err().ok_or("accepted")?;
    Ok(error.to_string())
}


#[test]
fn a_valid_file_maps_each_digest_to_its_sender() -> TestResult {
    let table = parse_senders(&mut file_of(&[("collector-a", DIGEST_A), ("collector_b", DIGEST_B)]).as_bytes(), FILE)?;
    assert_eq!(table.get(DIGEST_A).map(String::as_str), Some("collector-a"));
    assert_eq!(table.get(DIGEST_B).map(String::as_str), Some("collector_b"));
    assert_eq!(table.len(), PAIR);
    let empty = parse_senders(&mut "senders: []\n".as_bytes(), FILE);
    assert!(empty.is_err());
    Ok(())
}


#[test]
fn each_defect_refuses_the_whole_file_naming_the_index_and_field_never_the_digest() -> TestResult {
    let upper = DIGEST_A.to_uppercase();
    let short: String = DIGEST_A.chars().take(HEX_WIDTH - 1).collect();
    let non_hex = format!("{short}g");
    let cases = [
        (
            file_of(&[("ok", DIGEST_A), ("bad", &upper)]),
            "senders[1].token_sha256 is outside its grammar",
        ),
        (file_of(&[("bad", &short)]), "senders[0].token_sha256 is outside its grammar"),
        (file_of(&[("bad", &non_hex)]), "senders[0].token_sha256 is outside its grammar"),
        (file_of(&[("-lead", DIGEST_A)]), "senders[0].name is outside its grammar"),
        (file_of(&[("a b", DIGEST_A)]), "senders[0].name is outside its grammar"),
        (
            file_of(&[("same", DIGEST_A), ("same", DIGEST_B)]),
            "senders[1].name repeats senders[0].name",
        ),
        (
            file_of(&[("one", DIGEST_A), ("two", DIGEST_A)]),
            "senders[1].token_sha256 repeats senders[0].token_sha256",
        ),
    ];
    for (text, expected) in cases {
        let message = refused(&text)?;
        assert!(message.contains(expected), "{message}");
        assert!(
            !message.contains(DIGEST_A) && !message.contains(DIGEST_B) && !message.contains(&upper),
            "{message}"
        );
    }
    Ok(())
}


#[test]
fn more_than_the_maximum_number_of_senders_is_refused_whole() -> TestResult {
    let names: Vec<String> = (0..=MAX_TRACE_SENDERS).map(|index| format!("s{index}")).collect();
    let digests: Vec<String> = (0..=MAX_TRACE_SENDERS).map(|index| format!("{index:064x}")).collect();
    let pairs: Vec<(&str, &str)> = names
        .iter()
        .zip(digests.iter())
        .map(|(name, digest)| (name.as_str(), digest.as_str()))
        .collect();
    let message = refused(&file_of(&pairs))?;
    assert!(message.contains("too many senders"), "{message}");
    let kept = pairs.get(..MAX_TRACE_SENDERS).ok_or("too few pairs")?;
    let within = parse_senders(&mut file_of(kept).as_bytes(), FILE)?;
    assert_eq!(within.len(), MAX_TRACE_SENDERS);
    Ok(())
}


#[test]
fn a_tenant_key_or_any_unknown_field_is_refused() -> TestResult {
    let tenant = format!("senders:\n  - name: a\n    token_sha256: {DIGEST_A}\n    tenant: b\n");
    assert!(refused(&tenant).is_ok());
    assert!(refused(&format!("tenant: b\n{}", file_of(&[("a", DIGEST_A)]))).is_ok());
    assert!(refused("senders:\n  - name: a\n").is_ok());
    Ok(())
}


#[test]
fn yaml_features_and_bytes_that_hide_text_are_refused_before_any_typed_pass() -> TestResult {
    let base = file_of(&[("a", DIGEST_A)]);
    let cases = [
        base.replace("name: a", "name: !!str a"),
        base.replace("name: a", "name: &x a"),
        format!("{base}x: *x\n"),
        base.replace("  - name", "  - <<: {}\n    name"),
        base.replace("name: a", "name: \"\\x61\""),
        base.replace("name: a", "name: |\n      a"),
        "senders: [{name: a, token_sha256: x}]\n".to_owned(),
        base.replace("name: a", "name: \u{e9}"),
        base.replace('\n', "\r"),
        base.replace("name: a", "name: a\t"),
        format!("# \u{202e}\n{base}"),
    ];
    for text in cases {
        assert!(refused(&text).is_ok(), "{text}");
    }
    let features = refused(&base.replace("name: a", "name: &x a"))?;
    assert!(features.contains("anchors"), "{features}");
    Ok(())
}


#[test]
fn a_file_over_the_byte_cap_is_refused_and_a_crlf_file_is_read() -> TestResult {
    let padding = " ".repeat(usize::try_from(MAX_SENDERS_FILE_BYTES)?);
    assert!(refused(&format!("{}\n{padding}", file_of(&[("a", DIGEST_A)]))).is_ok());
    let crlf = file_of(&[("a", DIGEST_A)]).replace('\n', "\r\n");
    assert_eq!(parse_senders(&mut crlf.as_bytes(), FILE)?.len(), 1);
    Ok(())
}


#[test]
fn the_loader_reads_the_file_once_and_refuses_a_fifo_and_a_missing_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join(FILE);
    fs::write(&path, file_of(&[("a", DIGEST_A)]))?;
    assert_eq!(load_senders(&path)?.len(), 1);
    assert_eq!(senders_loader(path.clone())()?.len(), 1);
    fs::write(&path, file_of(&[("a", DIGEST_B)]))?;
    assert!(senders_loader(path.clone())()?.contains_key(DIGEST_B));
    let fifo = dir.path().join("fifo.yaml");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(load_senders(&fifo).is_err());
    assert!(load_senders(&dir.path().join("missing.yaml")).is_err());
    Ok(())
}


#[test]
fn the_audited_state_shows_a_rotation_and_never_the_digest() -> TestResult {
    let before = parse_senders(&mut file_of(&[("a", DIGEST_A)]).as_bytes(), FILE)?;
    let rotated = parse_senders(&mut file_of(&[("a", DIGEST_B)]).as_bytes(), FILE)?;
    let state_before = senders_state(&before);
    let state_after = senders_state(&rotated);
    assert_ne!(state_before, state_after);
    assert_eq!(state_before.keys().collect::<Vec<_>>(), vec!["senders.a"]);
    let shown = format!("{state_before:?}{state_after:?}");
    assert!(!shown.contains(DIGEST_A) && !shown.contains(DIGEST_B));
    assert_eq!(fingerprint(DIGEST_A).len(), FINGERPRINT_CHARS);
    assert_ne!(fingerprint(DIGEST_A), fingerprint(DIGEST_ZERO));
    assert!(!DIGEST_A.starts_with(&fingerprint(DIGEST_A)));
    Ok(())
}
