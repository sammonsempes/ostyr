use core_pg::error::PgError;
use core_pg::tls::{client_config, MAX_CA_BYTES};
use std::error::Error;
use std::fs;
use tempfile::tempdir;


const GARBAGE_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";


const BROKEN_PEM: &str = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";


#[test]
fn a_missing_ca_file_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    assert!(matches!(client_config(&dir.path().join("absent.pem")), Err(PgError::Io { .. })));
    Ok(())
}


#[test]
fn a_file_without_certificate_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("ca.pem");
    fs::write(&path, "no certificate here\n")?;
    assert!(matches!(client_config(&path), Err(PgError::NoCertificate { .. })));
    Ok(())
}


#[test]
fn broken_pem_and_unparsable_certificates_are_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("ca.pem");
    fs::write(&path, BROKEN_PEM)?;
    assert!(matches!(client_config(&path), Err(PgError::Pem { .. })));
    fs::write(&path, GARBAGE_CERTIFICATE)?;
    assert!(matches!(client_config(&path), Err(PgError::Tls(_))));
    Ok(())
}


#[test]
fn an_oversized_ca_file_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("ca.pem");
    fs::write(&path, vec![b'a'; usize::try_from(MAX_CA_BYTES)? + 1])?;
    assert!(matches!(client_config(&path), Err(PgError::TooLarge { .. })));
    Ok(())
}
