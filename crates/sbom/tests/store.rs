#[path = "common/fake_store.rs"]
mod fake_store;
#[path = "common/types.rs"]
mod types;


use fake_store::{
    answering, failing, fixture, meta, scope, signed, store_with, trusted, FIRST, KEY_ID, NOW, SECOND, SECRET_KEY, SEED, SEED_LENGTH,
    STATUS_NOT_FOUND, STATUS_OK,
};
use sbom::error::{SigningError, StoreError};
use sbom::model::{DocumentSignature, HttpResponse, Limits, StoreMethod};
use sbom::store::{
    check_scope, decode_signature, diff_versions, encode_signature, exchange, fetch_signed, object_keys, presign, put_version, read_version,
    validate_name,
};
use sbom::types::{HttpFn, TrustedKeys};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use types::TestResult;


const REDIRECT: u16 = 301;


const LONG_NAME: usize = 129;


const SMALL_LIMIT: usize = 8;


const SIGNATURE_OBJECT_OVERSIZE: usize = 600;


const FOUR_OBJECTS: usize = 4;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const THIRD: u64 = 3;


const TWO: u64 = 2;


#[test]
fn names_refuse_everything_that_could_leave_the_prefix() -> TestResult {
    let long = "a".repeat(LONG_NAME);
    let refused = ["", "a/b", "a\\b", "..", ".hidden", "a..b", "-x", "a b", "a\nb", "a\0b", long.as_str()];
    assert!(refused
        .iter()
        .all(|name| matches!(validate_name("tenant", name), Err(StoreError::InvalidName("tenant")))));
    assert!(validate_name("tenant", "tenant-a_1.x").is_ok());
    Ok(())
}


#[test]
fn keys_hold_tenant_artefact_and_version() -> TestResult {
    let keys = object_keys(&meta("tenant-a", TWO))?;
    assert_eq!(keys.document, "tenant-a/image-x/2.cdx.json");
    assert_eq!(keys.signature, "tenant-a/image-x/2.cdx.json.sig");
    assert!(object_keys(&meta("../tenant-b", 1)).is_err());
    let mut bad_artefact = meta("tenant-a", 1);
    bad_artefact.artefact = "-rf".to_owned();
    assert!(matches!(object_keys(&bad_artefact), Err(StoreError::InvalidName("artefact"))));
    Ok(())
}


#[test]
fn scope_is_the_tenant_of_the_caller() -> TestResult {
    assert!(check_scope(&scope("tenant-a"), "tenant-a").is_ok());
    assert!(matches!(check_scope(&scope("tenant-a"), "tenant-b"), Err(StoreError::OutsideScope)));
    Ok(())
}


#[test]
fn a_presigned_url_names_the_key_and_never_the_secret() -> TestResult {
    let fixture = fixture()?;
    let get = presign(&fixture.store, StoreMethod::Get, "tenant-a/image-x/1.cdx.json");
    let put = presign(&fixture.store, StoreMethod::Put, "tenant-a/image-x/1.cdx.json");
    assert!(get.starts_with("https://minio.example:9000/sboms/tenant-a/image-x/1.cdx.json?"));
    assert!(put.contains("X-Amz-Signature="));
    assert!(!get.contains(SECRET_KEY) && !put.contains(SECRET_KEY));
    Ok(())
}


#[test]
fn two_tenants_round_trip_and_cannot_read_each_other() -> TestResult {
    let fixture = fixture()?;
    let limits = Limits::default();
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &limits)?;
    put_version(&fixture.store, &scope("tenant-b"), &signed("tenant-b", 1, SECOND)?, &limits)?;
    let read_a = read_version(&fixture.store, &scope("tenant-a"), &meta("tenant-a", 1), &trusted(), NOW, &limits)?;
    let read_b = read_version(&fixture.store, &scope("tenant-b"), &meta("tenant-b", 1), &trusted(), NOW, &limits)?;
    assert_eq!(read_a.bytes, FIRST.as_bytes());
    assert_eq!(read_b.bytes, SECOND.as_bytes());
    let before = fixture.calls.load(Ordering::SeqCst);
    let crossing = read_version(&fixture.store, &scope("tenant-b"), &meta("tenant-a", 1), &trusted(), NOW, &limits);
    assert!(matches!(crossing, Err(StoreError::OutsideScope)));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), before);
    let writing = put_version(&fixture.store, &scope("tenant-b"), &signed("tenant-a", TWO, FIRST)?, &limits);
    assert!(matches!(writing, Err(StoreError::OutsideScope)));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), before);
    assert_eq!(fixture.objects.lock().map_err(|_poisoned| "poisoned")?.len(), FOUR_OBJECTS);
    Ok(())
}


#[test]
fn a_tampered_object_is_refused() -> TestResult {
    let fixture = fixture()?;
    let limits = Limits::default();
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &limits)?;
    fixture
        .objects
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .insert("/sboms/tenant-a/image-x/1.cdx.json".to_owned(), SECOND.as_bytes().to_vec());
    let read = read_version(&fixture.store, &scope("tenant-a"), &meta("tenant-a", 1), &trusted(), NOW, &limits);
    assert!(matches!(read, Err(StoreError::Signing(SigningError::BadSignature))));
    Ok(())
}


#[test]
fn an_object_moved_to_another_version_is_refused() -> TestResult {
    let fixture = fixture()?;
    let limits = Limits::default();
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &limits)?;
    let mut objects = fixture.objects.lock().map_err(|_poisoned| "poisoned")?;
    let document = objects.get("/sboms/tenant-a/image-x/1.cdx.json").cloned().ok_or("missing")?;
    let signature = objects.get("/sboms/tenant-a/image-x/1.cdx.json.sig").cloned().ok_or("missing")?;
    objects.insert("/sboms/tenant-a/image-x/2.cdx.json".to_owned(), document);
    objects.insert("/sboms/tenant-a/image-x/2.cdx.json.sig".to_owned(), signature);
    drop(objects);
    let read = read_version(&fixture.store, &scope("tenant-a"), &meta("tenant-a", TWO), &trusted(), NOW, &limits);
    assert!(matches!(read, Err(StoreError::Signing(SigningError::BadSignature))));
    Ok(())
}


#[test]
fn an_unknown_key_is_refused_on_read() -> TestResult {
    let fixture = fixture()?;
    let limits = Limits::default();
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &limits)?;
    let read = read_version(
        &fixture.store,
        &scope("tenant-a"),
        &meta("tenant-a", 1),
        &TrustedKeys::new(),
        NOW,
        &limits,
    );
    assert!(matches!(read, Err(StoreError::Signing(SigningError::UnknownKey))));
    Ok(())
}


#[test]
fn the_download_is_bounded_before_parsing() -> TestResult {
    let fixture = fixture()?;
    let small = Limits {
        max_bytes: FIRST.len() - 1,
        ..Limits::default()
    };
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &Limits::default())?;
    let read = fetch_signed(&fixture.store, &scope("tenant-a"), &meta("tenant-a", 1), &small);
    assert!(matches!(read, Err(StoreError::TooLarge { .. })));
    let exact = Limits {
        max_bytes: FIRST.len(),
        ..Limits::default()
    };
    assert!(fetch_signed(&fixture.store, &scope("tenant-a"), &meta("tenant-a", 1), &exact).is_ok());
    let written = put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", TWO, FIRST)?, &small);
    assert!(matches!(written, Err(StoreError::Signing(SigningError::TooLarge { .. }))));
    Ok(())
}


#[test]
fn a_server_that_ignores_the_bound_is_still_refused() -> TestResult {
    let store = store_with(answering(STATUS_OK, vec![b'x'; SMALL_LIMIT]))?;
    let limits = Limits {
        max_bytes: SMALL_LIMIT - FOUR_OBJECTS,
        ..Limits::default()
    };
    let read = fetch_signed(&store, &scope("tenant-a"), &meta("tenant-a", 1), &limits);
    assert!(matches!(read, Err(StoreError::TooLarge { .. })));
    Ok(())
}


#[test]
fn an_oversized_signature_object_is_refused() -> TestResult {
    let store = store_with(answering(STATUS_OK, vec![b'x'; SIGNATURE_OBJECT_OVERSIZE]))?;
    let read = fetch_signed(&store, &scope("tenant-a"), &meta("tenant-a", 1), &Limits::default());
    assert!(matches!(read, Err(StoreError::BadSignatureObject)));
    Ok(())
}


#[test]
fn a_missing_object_a_redirect_and_a_dead_server_are_refused() -> TestResult {
    let missing = store_with(answering(STATUS_NOT_FOUND, Vec::new()))?;
    let read = fetch_signed(&missing, &scope("tenant-a"), &meta("tenant-a", 1), &Limits::default());
    assert!(matches!(read, Err(StoreError::Status(STATUS_NOT_FOUND))));
    let redirect = store_with(answering(REDIRECT, Vec::new()))?;
    assert!(matches!(
        exchange(&redirect, StoreMethod::Get, "k", Vec::new(), 1),
        Err(StoreError::Status(REDIRECT))
    ));
    let dead = store_with(failing())?;
    let put = put_version(&dead, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &Limits::default());
    assert!(matches!(put, Err(StoreError::Transport(_))));
    Ok(())
}


#[test]
fn a_document_without_its_signature_is_refused() -> TestResult {
    let fixture = fixture()?;
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &Limits::default())?;
    fixture
        .objects
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .remove("/sboms/tenant-a/image-x/1.cdx.json.sig");
    let read = read_version(
        &fixture.store,
        &scope("tenant-a"),
        &meta("tenant-a", 1),
        &trusted(),
        NOW,
        &Limits::default(),
    );
    assert!(matches!(read, Err(StoreError::Status(STATUS_NOT_FOUND))));
    Ok(())
}


#[test]
fn signature_objects_round_trip_and_malformed_ones_are_refused() -> TestResult {
    let signature = DocumentSignature {
        key_id: KEY_ID.to_owned(),
        bytes: SEED.to_vec(),
    };
    assert_eq!(decode_signature(&encode_signature(&signature)?)?, signature);
    let hex = "07".repeat(SEED_LENGTH);
    let dashed = format!("-bad {hex}").into_bytes();
    let malformed: [&[u8]; FOUR_OBJECTS] = [&NOT_UTF8, b"nospace", b"sbom-1 zz", &dashed];
    assert!(matches!(decode_signature(&NOT_UTF8), Err(StoreError::SignatureText(_))));
    assert!(matches!(decode_signature(b"nospace"), Err(StoreError::BadSignatureObject)));
    assert!(matches!(decode_signature(b"sbom-1 zz"), Err(StoreError::SignatureHex(_))));
    assert!(matches!(decode_signature(&dashed), Err(StoreError::InvalidName("key id"))));
    assert!(malformed.iter().all(|bytes| decode_signature(bytes).is_err()));
    let spaced = DocumentSignature {
        key_id: "has space".to_owned(),
        bytes: Vec::new(),
    };
    assert!(matches!(encode_signature(&spaced), Err(StoreError::InvalidName("key id"))));
    Ok(())
}


#[test]
fn a_failing_second_put_is_reported() -> TestResult {
    let counter = Arc::new(AtomicUsize::new(0));
    let http: Box<HttpFn> = Box::new(move |_request| {
        let status = if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            STATUS_OK
        } else {
            REDIRECT
        };
        Ok(HttpResponse { status, body: Vec::new() })
    });
    let store = store_with(http)?;
    let put = put_version(&store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &Limits::default());
    assert!(matches!(put, Err(StoreError::Status(REDIRECT))));
    Ok(())
}


#[test]
fn a_diff_reads_two_verified_versions() -> TestResult {
    let fixture = fixture()?;
    let limits = Limits::default();
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", 1, FIRST)?, &limits)?;
    put_version(&fixture.store, &scope("tenant-a"), &signed("tenant-a", TWO, SECOND)?, &limits)?;
    let result = diff_versions(
        &fixture.store,
        &scope("tenant-a"),
        &meta("tenant-a", 1),
        &meta("tenant-a", TWO),
        &trusted(),
        NOW,
        &limits,
    )?;
    assert_eq!(result.changed.len(), 1);
    let backwards = diff_versions(
        &fixture.store,
        &scope("tenant-a"),
        &meta("tenant-a", TWO),
        &meta("tenant-a", 1),
        &trusted(),
        NOW,
        &limits,
    );
    assert!(matches!(backwards, Err(StoreError::Signing(SigningError::VersionNotIncreasing { .. }))));
    let missing = diff_versions(
        &fixture.store,
        &scope("tenant-a"),
        &meta("tenant-a", 1),
        &meta("tenant-a", THIRD),
        &trusted(),
        NOW,
        &limits,
    );
    assert!(matches!(missing, Err(StoreError::Status(STATUS_NOT_FOUND))));
    Ok(())
}
