#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use core_config::load::load_file;
use sbom::error::{SigningError, StoreError};
use sbom::model::HttpResponse;
use sbom::store_settings::{open_bucket, open_store, read_credential, validate_store_settings, StoreSettings};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


const PRIVATE_MODE: u32 = 0o600;


const OPEN_MODE: u32 = 0o644;


const OVERSIZE_CREDENTIAL: usize = 257;


const SMALL: u64 = 100;


fn write_private(path: &Path, text: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, text)?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_MODE))?;
    Ok(())
}


fn valid(directory: &Path) -> Result<StoreSettings, Box<dyn std::error::Error>> {
    let access = directory.join("access");
    let secret = directory.join("secret");
    write_private(&access, b"AKIDEXAMPLE\n")?;
    write_private(&secret, b"SECRETEXAMPLE\n")?;
    Ok(StoreSettings {
        endpoint: "https://minio.example:9000".to_owned(),
        bucket: "sboms".to_owned(),
        region: "us-east-1".to_owned(),
        ca_file: Some(directory.join("ca.pem")),
        access_key_file: access,
        secret_key_file: secret,
        connect_millis: SMALL,
        read_millis: SMALL,
        total_millis: SMALL,
    })
}


fn refused(settings: &StoreSettings, field: &str) -> bool {
    matches!(validate_store_settings(settings), Err(StoreError::Settings(name)) if name == field)
}


#[test]
fn valid_settings_pass_and_each_bad_field_is_named() -> TestResult {
    let directory = tempdir()?;
    let good = valid(directory.path())?;
    assert!(validate_store_settings(&good).is_ok());
    let mut plain = good.clone();
    plain.endpoint = "http://minio.example:9000".to_owned();
    assert!(refused(&plain, "endpoint"));
    let mut ftp = good.clone();
    ftp.endpoint = "ftp://minio.example".to_owned();
    assert!(matches!(validate_store_settings(&ftp), Err(StoreError::Bucket(_))));
    let mut garbage = good.clone();
    garbage.endpoint = "no url".to_owned();
    assert!(refused(&garbage, "endpoint"));
    for name in ["ab", "Upper", "-lead", ".lead", "under_score"] {
        let mut bad = good.clone();
        bad.bucket = name.to_owned();
        assert!(refused(&bad, "bucket"));
    }
    let mut numbered = good.clone();
    numbered.bucket = "sboms-2.a".to_owned();
    assert!(validate_store_settings(&numbered).is_ok());
    let mut region = good.clone();
    region.region = String::new();
    assert!(refused(&region, "region"));
    let mut access = good.clone();
    access.access_key_file = "relative".into();
    assert!(refused(&access, "access_key_file"));
    let mut secret = good.clone();
    secret.secret_key_file = "relative".into();
    assert!(refused(&secret, "secret_key_file"));
    let mut ca = good.clone();
    ca.ca_file = Some("relative".into());
    assert!(refused(&ca, "ca_file"));
    let mut connect = good.clone();
    connect.connect_millis = 0;
    assert!(refused(&connect, "connect_millis"));
    let mut read = good.clone();
    read.read_millis = 0;
    assert!(refused(&read, "read_millis"));
    let mut total = good.clone();
    total.total_millis = SMALL - 1;
    assert!(refused(&total, "total_millis"));
    let mut no_ca = good;
    no_ca.ca_file = None;
    assert!(validate_store_settings(&no_ca).is_ok());
    Ok(())
}


#[test]
fn a_bucket_refusal_keeps_its_cause() -> TestResult {
    let error = StoreError::from(rusty_s3::BucketError::MissingHost);
    assert!(std::error::Error::source(&error).is_some());
    Ok(())
}


#[test]
fn unknown_fields_are_refused_by_the_format() -> TestResult {
    let text = r#"{"endpoint":"https://a","bucket":"abc","region":"r","ca_file":null,"access_key_file":"/a","secret_key_file":"/b","connect_millis":1,"read_millis":1,"total_millis":1,"extra":1}"#;
    let directory = tempdir()?;
    let path = directory.path().join("store.yaml");
    fs::write(&path, text)?;
    assert!(load_file::<StoreSettings>(&path).is_err());
    fs::write(&path, text.replace(r#","extra":1"#, ""))?;
    assert_eq!(load_file::<StoreSettings>(&path)?.bucket, "abc");
    assert_eq!(open_bucket(&load_file::<StoreSettings>(&path)?)?.base_url().scheme(), "https");
    Ok(())
}


#[test]
fn credentials_follow_the_key_file_pattern() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("cred");
    write_private(&path, b"  AKID \n")?;
    assert_eq!(read_credential(&path)?.as_str(), "AKID");
    fs::set_permissions(&path, fs::Permissions::from_mode(OPEN_MODE))?;
    assert!(matches!(read_credential(&path), Err(StoreError::Signing(SigningError::KeyNotPrivate(_)))));
    write_private(&path, b" \n")?;
    assert!(matches!(read_credential(&path), Err(StoreError::BadCredential)));
    write_private(&path, b"AK\x07ID")?;
    assert!(matches!(read_credential(&path), Err(StoreError::BadCredential)));
    write_private(&path, &vec![b'a'; OVERSIZE_CREDENTIAL])?;
    assert!(matches!(read_credential(&path), Err(StoreError::Signing(SigningError::KeyTooLarge))));
    assert!(matches!(
        read_credential(directory.path()),
        Err(StoreError::Signing(SigningError::KeyNotRegular))
    ));
    Ok(())
}


#[test]
fn the_store_opens_with_both_credentials_and_refuses_bad_settings() -> TestResult {
    let directory = tempdir()?;
    let settings = valid(directory.path())?;
    let store = open_store(&settings, Box::new(|_request| Ok(HttpResponse { status: 1, body: Vec::new() })))?;
    assert_eq!(store.bucket.name(), "sboms");
    assert_eq!(store.bucket.region(), "us-east-1");
    let mut no_secret = settings.clone();
    no_secret.secret_key_file = directory.path().join("absent");
    assert!(matches!(
        open_store(&no_secret, Box::new(|_request| Err("unused".into()))),
        Err(StoreError::Signing(_))
    ));
    let mut bad = settings;
    bad.region = String::new();
    assert!(matches!(
        open_store(&bad, Box::new(|_request| Err("unused".into()))),
        Err(StoreError::Settings("region"))
    ));
    Ok(())
}
