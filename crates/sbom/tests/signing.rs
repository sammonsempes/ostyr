#[path = "common/types.rs"]
mod types;


use ed25519_dalek::SigningKey;
use sbom::error::SigningError;
use sbom::model::{DocumentMeta, DocumentSignature, Limits, SignedDocument, TrustedKey};
use sbom::signing::{
    check_owner, check_version, diff_signed, load_signing_key, memory_signer, parse_seed, sign_document, signing_message, verify_document,
};
use sbom::types::{SignerFn, TrustedKeys};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use types::TestResult;


const FIXTURE: &str = include_str!("fixtures/syft-debian.cdx.json");


const SECOND: &str = r#"{"components":[{"type":"library","name":"a","version":"1","purl":"pkg:cargo/a@1"}]}"#;


const KEY_ID: &str = "sbom-1";


const SEED_LENGTH: usize = 32;


const SEED: [u8; SEED_LENGTH] = [7; SEED_LENGTH];


const OTHER_SEED: [u8; SEED_LENGTH] = [9; SEED_LENGTH];


const SECOND_VERSION: u64 = 2;


const THIRD_VERSION: u64 = 3;


const SMALL_LIMIT: usize = 4;


const SHORT_SIGNATURE: usize = 3;


const LATER: u64 = NOW + 2;


const OTHER_OWNER: u32 = 2;


const NOW: u64 = 1_000;


const PRIVATE_MODE: u32 = 0o600;


const OPEN_MODE: u32 = 0o644;


const DIRECTORY_MODE: u32 = 0o700;


const SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";


fn meta(version: u64) -> DocumentMeta {
    DocumentMeta {
        tenant: "tenant-a".to_owned(),
        artefact: "image-x".to_owned(),
        version,
    }
}


fn trusted(not_before: u64, not_after: u64, revoked: bool) -> TrustedKeys {
    let key = SigningKey::from_bytes(&SEED);
    TrustedKeys::from([(
        KEY_ID.to_owned(),
        TrustedKey {
            public_key: key.verifying_key(),
            not_before,
            not_after,
            revoked,
        },
    )])
}


fn signer() -> Box<SignerFn> {
    memory_signer(SigningKey::from_bytes(&SEED))
}


fn signed(text: &str, version: u64) -> Result<SignedDocument, Box<dyn std::error::Error>> {
    let bytes = text.as_bytes().to_vec();
    let signature = sign_document(&bytes, &meta(version), KEY_ID, &*signer(), &Limits::default())?;
    Ok(SignedDocument {
        bytes,
        meta: meta(version),
        signature,
    })
}


fn verify(document: &SignedDocument, keys: &TrustedKeys) -> Result<(), SigningError> {
    verify_document(&document.bytes, &document.meta, &document.signature, keys, NOW, &Limits::default())
}


#[test]
fn round_trip() -> TestResult {
    let document = signed(FIXTURE, 1)?;
    verify(&document, &trusted(0, NOW + 1, false))?;
    Ok(())
}


#[test]
fn flipped_byte_in_document() -> TestResult {
    let mut document = signed(FIXTURE, 1)?;
    let first = document.bytes.first_mut().ok_or("empty")?;
    *first ^= 1;
    assert!(matches!(verify(&document, &trusted(0, NOW + 1, false)), Err(SigningError::BadSignature)));
    Ok(())
}


#[test]
fn each_metadata_field_is_bound() -> TestResult {
    let keys = trusted(0, NOW + 1, false);
    let document = signed(FIXTURE, 1)?;
    let mut tenant = document.clone();
    tenant.meta.tenant = "tenant-b".to_owned();
    let mut artefact = document.clone();
    artefact.meta.artefact = "image-y".to_owned();
    let mut version = document.clone();
    version.meta.version = SECOND_VERSION;
    [tenant, artefact, version]
        .iter()
        .for_each(|forged| assert!(matches!(verify(forged, &keys), Err(SigningError::BadSignature))));
    Ok(())
}


#[test]
fn message_separates_tenant_from_artefact() -> TestResult {
    let first = DocumentMeta {
        tenant: "ab".to_owned(),
        artefact: "c".to_owned(),
        version: 1,
    };
    let second = DocumentMeta {
        tenant: "a".to_owned(),
        artefact: "bc".to_owned(),
        version: 1,
    };
    assert_ne!(signing_message(b"x", &first), signing_message(b"x", &second));
    Ok(())
}


#[test]
fn wrong_unknown_revoked_expired_keys() -> TestResult {
    let document = signed(FIXTURE, 1)?;
    let other = SigningKey::from_bytes(&OTHER_SEED);
    let wrong = TrustedKeys::from([(
        KEY_ID.to_owned(),
        TrustedKey {
            public_key: other.verifying_key(),
            not_before: 0,
            not_after: NOW + 1,
            revoked: false,
        },
    )]);
    assert!(matches!(verify(&document, &wrong), Err(SigningError::BadSignature)));
    assert!(matches!(verify(&document, &TrustedKeys::new()), Err(SigningError::UnknownKey)));
    assert!(matches!(verify(&document, &trusted(0, NOW + 1, true)), Err(SigningError::KeyRevoked)));
    assert!(matches!(
        verify(&document, &trusted(0, NOW - 1, false)),
        Err(SigningError::KeyOutsideValidity)
    ));
    assert!(matches!(
        verify(&document, &trusted(NOW + 1, LATER, false)),
        Err(SigningError::KeyOutsideValidity)
    ));
    Ok(())
}


#[test]
fn short_signature_is_bad() -> TestResult {
    let mut document = signed(FIXTURE, 1)?;
    document.signature = DocumentSignature {
        key_id: KEY_ID.to_owned(),
        bytes: vec![1; SHORT_SIGNATURE],
    };
    assert!(matches!(verify(&document, &trusted(0, NOW + 1, false)), Err(SigningError::BadSignature)));
    Ok(())
}


#[test]
fn oversized_document_is_refused_both_ways() -> TestResult {
    let small = Limits {
        max_bytes: SMALL_LIMIT,
        ..Limits::default()
    };
    let signature = sign_document(b"abcd", &meta(1), KEY_ID, &*signer(), &small)?;
    assert!(matches!(
        sign_document(b"abcde", &meta(1), KEY_ID, &*signer(), &small),
        Err(SigningError::TooLarge { max: SMALL_LIMIT })
    ));
    let keys = trusted(0, NOW + 1, false);
    assert!(matches!(
        verify_document(b"abcde", &meta(1), &signature, &keys, NOW, &small),
        Err(SigningError::TooLarge { .. })
    ));
    verify_document(b"abcd", &meta(1), &signature, &keys, NOW, &small)?;
    Ok(())
}


#[test]
fn failing_signer_keeps_its_cause() -> TestResult {
    let failing: Box<SignerFn> = Box::new(|_| Err("vault down".into()));
    let result = sign_document(b"x", &meta(1), KEY_ID, &*failing, &Limits::default());
    assert!(matches!(result, Err(SigningError::Signer(_))));
    Ok(())
}


#[test]
fn version_order() -> TestResult {
    check_version(1, SECOND_VERSION)?;
    assert!(matches!(
        check_version(SECOND_VERSION, SECOND_VERSION),
        Err(SigningError::VersionNotIncreasing {
            previous: SECOND_VERSION,
            next: SECOND_VERSION
        })
    ));
    assert!(matches!(
        check_version(THIRD_VERSION, SECOND_VERSION),
        Err(SigningError::VersionNotIncreasing { .. })
    ));
    Ok(())
}


#[test]
fn diff_of_two_signed_versions() -> TestResult {
    let keys = trusted(0, NOW + 1, false);
    let old = signed(FIXTURE, 1)?;
    let new = signed(SECOND, SECOND_VERSION)?;
    let result = diff_signed(&old, &new, &keys, NOW, &Limits::default())?;
    assert_eq!(result.added.len(), 1);
    assert!(!result.removed.is_empty());
    assert!(matches!(
        diff_signed(&new, &old, &keys, NOW, &Limits::default()),
        Err(SigningError::VersionNotIncreasing { .. })
    ));
    Ok(())
}


#[test]
fn diff_verifies_both_sides_first() -> TestResult {
    let keys = trusted(0, NOW + 1, false);
    let old = signed(FIXTURE, 1)?;
    let new = signed(SECOND, SECOND_VERSION)?;
    let mut tampered_old = old.clone();
    tampered_old.meta.version = THIRD_VERSION;
    let mut tampered_new = new.clone();
    tampered_new.meta.tenant = "other".to_owned();
    assert!(matches!(
        diff_signed(&tampered_old, &new, &keys, NOW, &Limits::default()),
        Err(SigningError::BadSignature)
    ));
    assert!(matches!(
        diff_signed(&old, &tampered_new, &keys, NOW, &Limits::default()),
        Err(SigningError::BadSignature)
    ));
    Ok(())
}


#[test]
fn diff_refuses_different_artefacts() -> TestResult {
    let keys = trusted(0, NOW + 1, false);
    let old = signed(FIXTURE, 1)?;
    let other = DocumentMeta {
        artefact: "image-y".to_owned(),
        ..meta(SECOND_VERSION)
    };
    let bytes = SECOND.as_bytes().to_vec();
    let signature = sign_document(&bytes, &other, KEY_ID, &*signer(), &Limits::default())?;
    let new = SignedDocument {
        bytes,
        meta: other,
        signature,
    };
    assert!(matches!(
        diff_signed(&old, &new, &keys, NOW, &Limits::default()),
        Err(SigningError::Diff(_))
    ));
    Ok(())
}


#[test]
fn unparsable_signed_bytes_surface_the_parse_error() -> TestResult {
    let keys = trusted(0, NOW + 1, false);
    let broken = signed("not json", 1)?;
    let good = signed(SECOND, SECOND_VERSION)?;
    assert!(matches!(
        diff_signed(&broken, &good, &keys, NOW, &Limits::default()),
        Err(SigningError::Sbom(_))
    ));
    Ok(())
}


fn write_key(directory: &std::path::Path, text: &str, mode: u32) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join("sbom.key");
    let mut file = fs::File::create(&path)?;
    file.write_all(text.as_bytes())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(path)
}


#[test]
fn key_file_loads() -> TestResult {
    let directory = tempdir()?;
    let path = write_key(directory.path(), &format!("{SEED_HEX}\n"), PRIVATE_MODE)?;
    let key = load_signing_key(&path)?;
    assert_eq!(key.to_bytes(), SEED);
    Ok(())
}


#[test]
fn key_file_refusals_carry_no_key_material() -> TestResult {
    let directory = tempdir()?;
    let open = write_key(directory.path(), SEED_HEX, OPEN_MODE)?;
    let refused = load_signing_key(&open).err().ok_or("accepted")?;
    assert!(matches!(refused, SigningError::KeyNotPrivate(_)));
    assert!(!format!("{refused:?} {refused}").contains(SEED_HEX));
    let bad = write_key(directory.path(), &"zz".repeat(SEED_LENGTH), PRIVATE_MODE)?;
    assert!(matches!(load_signing_key(&bad), Err(SigningError::KeyHex(_))));
    let short = write_key(directory.path(), "0707", PRIVATE_MODE)?;
    assert!(matches!(load_signing_key(&short), Err(SigningError::KeyLength)));
    let long = write_key(directory.path(), &SEED_HEX.repeat(SMALL_LIMIT), PRIVATE_MODE)?;
    assert!(matches!(load_signing_key(&long), Err(SigningError::KeyLength)));
    assert!(matches!(load_signing_key(&directory.path().join("missing")), Err(SigningError::KeyIo(_))));
    Ok(())
}


#[test]
fn key_file_read_failure_is_an_io_error() -> TestResult {
    let directory = tempdir()?;
    let private = directory.path().join("private");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(DIRECTORY_MODE))?;
    assert!(matches!(load_signing_key(&private), Err(SigningError::KeyIo(_))));
    Ok(())
}


#[test]
fn owner_mismatch_is_refused() -> TestResult {
    check_owner(1, 1)?;
    assert!(matches!(check_owner(1, OTHER_OWNER), Err(SigningError::KeyWrongOwner)));
    parse_seed(SEED_HEX)?;
    Ok(())
}
