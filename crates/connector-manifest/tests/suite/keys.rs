use crate::common::types::TestResult;
use crate::common::{key_file_text, public_hex, signing_key, KEY_ID, NOT_AFTER, PUBLISHER, SEED_BYTE};
use connector_manifest::error::ConnectorError;
use connector_manifest::keys::{load_trusted_keys, parse_signing_key, parse_trusted_keys};
use connector_manifest::model::{MAX_KEYS_BYTES, MAX_TRUSTED_KEYS};
use data_encoding::HEXLOWER;
use std::fs;


const NOT_A_POINT_BYTE: u8 = 2;


const NOT_UTF8: u8 = 0xff;


const PUBLIC_KEY_BYTES: usize = 32;


fn invalid_field(text: &str) -> Result<&'static str, Box<dyn std::error::Error>> {
    match parse_trusted_keys(text, "keys.yaml") {
        Err(ConnectorError::Invalid { field }) => Ok(field),
        other => Err(format!("unexpected: {other:?}").into()),
    }
}


fn seed_hex() -> String {
    HEXLOWER.encode(&[SEED_BYTE; PUBLIC_KEY_BYTES])
}


#[test]
fn a_trusted_key_file_parses() -> TestResult {
    let keys = parse_trusted_keys(&key_file_text(KEY_ID, PUBLISHER, &public_hex(), NOT_AFTER), "keys.yaml")?;
    let key = keys.keys.get(KEY_ID).ok_or("key missing")?;
    assert_eq!((key.publisher.as_str(), key.not_after), (PUBLISHER, NOT_AFTER));
    assert_eq!(key.public_key, signing_key().verifying_key());
    Ok(())
}


#[test]
fn a_bad_trusted_key_file_is_refused() -> TestResult {
    let public = public_hex();
    assert_eq!(invalid_field(&key_file_text("-id", PUBLISHER, &public, NOT_AFTER))?, "keys.id");
    assert_eq!(invalid_field(&key_file_text(KEY_ID, "Bad", &public, NOT_AFTER))?, "keys.publisher");
    assert_eq!(invalid_field(&key_file_text(KEY_ID, PUBLISHER, "zz", NOT_AFTER))?, "keys.public_key");
    assert_eq!(invalid_field(&key_file_text(KEY_ID, PUBLISHER, "00", NOT_AFTER))?, "keys.public_key");
    let not_a_point = HEXLOWER.encode(&[NOT_A_POINT_BYTE; PUBLIC_KEY_BYTES]);
    assert_eq!(
        invalid_field(&key_file_text(KEY_ID, PUBLISHER, &not_a_point, NOT_AFTER))?,
        "keys.public_key"
    );
    let twice = format!(
        "{}{}",
        key_file_text(KEY_ID, PUBLISHER, &public, NOT_AFTER),
        "  - id: acme-2026\n    publisher: acme\n    public_key: "
    );
    let duplicate = format!("{twice}{public}\n    not_after: 1\n");
    assert_eq!(invalid_field(&duplicate)?, "keys.id");
    assert!(matches!(
        parse_trusted_keys(
            &format!("{}extra: 1\n", key_file_text(KEY_ID, PUBLISHER, &public, NOT_AFTER)),
            "keys.yaml"
        ),
        Err(ConnectorError::Config(_))
    ));
    Ok(())
}


#[test]
fn more_trusted_keys_than_the_cap_are_refused() -> TestResult {
    let entry = format!("  - id: k\n    publisher: acme\n    public_key: {}\n    not_after: 1\n", public_hex());
    let text = format!("keys:\n{}", entry.repeat(MAX_TRUSTED_KEYS + 1));
    let message = parse_trusted_keys(&text, "keys.yaml").err().ok_or("accepted")?.to_string();
    assert!(message.contains("too many elements"), "{message}");
    Ok(())
}


#[test]
fn a_trusted_key_file_loads_from_disk_with_a_size_cap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("keys.yaml");
    fs::write(&path, key_file_text(KEY_ID, PUBLISHER, &public_hex(), NOT_AFTER))?;
    assert!(load_trusted_keys(&path)?.keys.contains_key(KEY_ID));
    assert!(matches!(
        load_trusted_keys(&directory.path().join("absent.yaml")),
        Err(ConnectorError::Io { .. })
    ));
    fs::write(&path, " ".repeat(usize::try_from(MAX_KEYS_BYTES)? + 1))?;
    assert!(matches!(load_trusted_keys(&path), Err(ConnectorError::Config(_))));
    Ok(())
}


#[test]
fn a_signing_key_line_parses_and_every_other_form_is_refused() -> TestResult {
    let (key_id, key) = parse_signing_key(format!("{KEY_ID} {}\n", seed_hex()).as_bytes())?;
    assert_eq!((key_id.as_str(), key.verifying_key()), (KEY_ID, signing_key().verifying_key()));
    let refusals: Vec<Vec<u8>> = vec![
        vec![NOT_UTF8],
        KEY_ID.as_bytes().to_vec(),
        format!("-bad {}", seed_hex()).into_bytes(),
        format!("{KEY_ID} zz").into_bytes(),
        format!("{KEY_ID} 00").into_bytes(),
        format!("{KEY_ID} {} extra", seed_hex()).into_bytes(),
    ];
    refusals.iter().try_for_each(|bytes| {
        assert!(matches!(
            parse_signing_key(bytes),
            Err(ConnectorError::Invalid { field: "signing key file" })
        ));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
