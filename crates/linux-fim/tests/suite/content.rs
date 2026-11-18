use crate::types::TestResult;
use linux_fim::content::{
    symbols, token_content, ACCESS_KEY_CHARS, ALPHANUMERIC, CANARY_CHARS, FILLER, KEY_LINES, KEY_LINE_CHARS, RANDOM_BYTES, SECRET_KEY_CHARS,
};
use linux_fim::model::HoneytokenKind;


const BYTE_RANGE: usize = 256;


const ARMOUR_LINES: usize = 2;


fn bytes_from(offset: usize) -> Vec<u8> {
    (0..RANDOM_BYTES)
        .map(|index| u8::try_from((index + offset) % BYTE_RANGE).unwrap_or(0))
        .collect()
}


#[test]
fn symbols_pick_one_character_per_byte_inside_the_alphabet() -> TestResult {
    let text = symbols(&bytes_from(0), 0, BYTE_RANGE, ALPHANUMERIC);
    assert_eq!(text.chars().count(), BYTE_RANGE);
    assert!(text.chars().all(|character| ALPHANUMERIC.contains(character)));
    Ok(())
}


#[test]
fn an_empty_alphabet_gives_the_filler_never_a_panic() -> TestResult {
    assert_eq!(
        symbols(&bytes_from(0), 0, ACCESS_KEY_CHARS, ""),
        FILLER.to_string().repeat(ACCESS_KEY_CHARS)
    );
    Ok(())
}


#[test]
fn an_aws_decoy_is_a_default_profile_with_an_akia_id() -> TestResult {
    let text = token_content(HoneytokenKind::AwsCredentials, &bytes_from(0));
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("[default]"));
    let id = lines
        .next()
        .and_then(|line| line.strip_prefix("aws_access_key_id = AKIA"))
        .ok_or("no key id")?;
    assert_eq!(id.len(), ACCESS_KEY_CHARS);
    let secret = lines
        .next()
        .and_then(|line| line.strip_prefix("aws_secret_access_key = "))
        .ok_or("no secret")?;
    assert_eq!(secret.len(), SECRET_KEY_CHARS);
    Ok(())
}


#[test]
fn an_ssh_decoy_is_an_armoured_block_of_random_lines() -> TestResult {
    let text = token_content(HoneytokenKind::SshKey, &bytes_from(0));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), KEY_LINES + ARMOUR_LINES);
    assert_eq!(lines.first().copied(), Some("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert_eq!(lines.last().copied(), Some("-----END OPENSSH PRIVATE KEY-----"));
    assert!(lines.iter().skip(1).take(KEY_LINES).all(|line| line.len() == KEY_LINE_CHARS));
    Ok(())
}


#[test]
fn a_password_decoy_has_three_name_password_lines() -> TestResult {
    let text = token_content(HoneytokenKind::PasswordFile, &bytes_from(0));
    let names: Vec<&str> = text.lines().filter_map(|line| line.split_once(": ").map(|(name, _)| name)).collect();
    assert_eq!(names, ["admin", "backup", "root"]);
    Ok(())
}


#[test]
fn a_canary_is_one_random_line() -> TestResult {
    let text = token_content(HoneytokenKind::Canary, &bytes_from(0));
    assert_eq!(text.lines().count(), 1);
    assert_eq!(text.trim_end().len(), CANARY_CHARS);
    Ok(())
}


#[test]
fn other_random_bytes_give_another_decoy() -> TestResult {
    assert_ne!(
        token_content(HoneytokenKind::Canary, &bytes_from(0)),
        token_content(HoneytokenKind::Canary, &bytes_from(1))
    );
    Ok(())
}


#[test]
fn bytes_over_the_largest_multiple_are_rejected_not_folded() -> TestResult {
    let rejected = [u8::MAX; ARMOUR_LINES * ACCESS_KEY_CHARS];
    assert_eq!(
        symbols(&rejected, 0, ACCESS_KEY_CHARS, ALPHANUMERIC),
        FILLER.to_string().repeat(ACCESS_KEY_CHARS)
    );
    let mixed = [u8::MAX, 0, u8::MAX, 1];
    assert_eq!(symbols(&mixed, 0, ARMOUR_LINES, ALPHANUMERIC), "AB");
    Ok(())
}
