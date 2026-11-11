#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use cert_inventory::error::CertError;
use cert_inventory::scan::{absorb, no_hook, read_bounded, reason_of, scan, scan_with, Loaded, ScanSettings, ScanState, MAX_DEPTH_CEILING};
use cert_inventory::walk::{adopt, handle_next, is_swap, level_of, open_root, plan, scan_root, step, Step};
use rcgen::{CertificateParams, KeyPair};
use rustix::fs::FileType;
use rustix::io::Errno;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{create_dir_all, remove_dir_all, remove_file, write, File};
use std::io::{self, Cursor};
use std::ops::ControlFlow;
use std::os::fd::OwnedFd;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::TempDir;
use types::TestResult;


const DEEP_LEVELS: usize = 20;


const MANY_BLOCKS: usize = 65;


const MANY_CERTIFICATES: usize = 33;


const SMALL_LISTING: usize = 2;


const FILES_FOR_CUT: usize = 5;


const BIG_LISTING: usize = 1_000;


const CAP_BYTES: usize = 4;


fn make_certificate() -> Result<(String, String), Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let certificate = CertificateParams::new(vec!["walk.example.test".to_string()])?.self_signed(&key)?;
    Ok((certificate.pem(), key.serialize_pem()))
}


fn settings_for(root: &Path) -> ScanSettings {
    ScanSettings {
        roots: vec![root.to_path_buf()],
        ..ScanSettings::default()
    }
}


fn swap_directories(path: &Path) {
    if let Err(error) = try_swap_directories(path) {
        tracing::warn!(%error, "swap failed");
    }
}


fn try_swap_directories(path: &Path) -> io::Result<()> {
    let name = path.file_name();
    let top = path.parent().and_then(Path::parent).ok_or_else(|| io::Error::other("no top"))?;
    if name == Some(OsStr::new("d")) {
        remove_dir_all(path)?;
        symlink(top.join("secret"), path)
    } else if name == Some(OsStr::new("gone")) {
        remove_dir_all(path)
    } else {
        Ok(())
    }
}


fn swap_file(path: &Path) {
    if let Err(error) = try_swap_file(path) {
        tracing::warn!(%error, "swap failed");
    }
}


fn try_swap_file(path: &Path) -> io::Result<()> {
    let top = path.parent().and_then(Path::parent).ok_or_else(|| io::Error::other("no top"))?;
    if path.file_name() == Some(OsStr::new("swap.pem")) {
        remove_file(path)?;
        symlink(top.join("secret/a.pem"), path)
    } else {
        Ok(())
    }
}


#[test]
fn a_directory_swapped_for_a_symlink_after_listing_is_never_followed() -> TestResult {
    let (pem, _) = make_certificate()?;
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root/d"))?;
    create_dir_all(directory.path().join("root/gone"))?;
    create_dir_all(directory.path().join("secret"))?;
    write(directory.path().join("secret/a.pem"), &pem)?;
    write(directory.path().join("root/d/a.pem"), "x")?;
    let outcome = scan_with(&settings_for(&directory.path().join("root")), swap_directories, BIG_LISTING);
    assert!(outcome.records.is_empty());
    assert_eq!(outcome.skipped.swapped, 1);
    assert_eq!(outcome.skipped.unreadable, 1);
    assert_eq!(outcome.examined, 0);
    Ok(())
}


#[test]
fn a_file_swapped_for_a_symlink_after_listing_is_not_read() -> TestResult {
    let (pem, _) = make_certificate()?;
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    create_dir_all(directory.path().join("secret"))?;
    write(directory.path().join("secret/a.pem"), &pem)?;
    write(directory.path().join("root/swap.pem"), "x")?;
    let outcome = scan_with(&settings_for(&directory.path().join("root")), swap_file, BIG_LISTING);
    assert!(outcome.records.is_empty());
    assert_eq!(outcome.skipped.not_regular, 1);
    Ok(())
}


#[test]
fn open_directories_never_exceed_the_depth() -> TestResult {
    let directory = TempDir::new()?;
    let deep = (0..DEEP_LEVELS).fold(directory.path().to_path_buf(), |path, index| path.join(format!("l{index}")));
    create_dir_all(&deep)?;
    write(deep.join("far.pem"), "x")?;
    write(directory.path().join("l0/near.pem"), "x")?;
    let mut settings = settings_for(directory.path());
    settings.max_depth = MAX_DEPTH_CEILING;
    let outcome = scan(&settings);
    assert_eq!(outcome.max_open_dirs, MAX_DEPTH_CEILING);
    assert_eq!(outcome.examined, 1);
    Ok(())
}


#[test]
fn a_long_listing_is_cut_with_one_error() -> TestResult {
    let directory = TempDir::new()?;
    (0..FILES_FOR_CUT).try_for_each(|index| write(directory.path().join(format!("f{index}.pem")), "x"))?;
    let outcome = scan_with(&settings_for(directory.path()), no_hook, SMALL_LISTING);
    assert_eq!(outcome.errors.len(), 1);
    assert!(outcome.errors.iter().all(|line| line.contains("listing cut")));
    assert!(outcome.examined < FILES_FOR_CUT);
    Ok(())
}


#[test]
fn a_root_that_is_a_symlink_is_refused() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("real"))?;
    symlink(directory.path().join("real"), directory.path().join("link"))?;
    let outcome = scan(&settings_for(&directory.path().join("link")));
    assert_eq!(outcome.errors.len(), 1);
    assert!(open_root(&directory.path().join("link")).is_err());
    Ok(())
}


#[test]
fn a_directory_read_error_abandons_that_directory_with_one_error() -> TestResult {
    let directory = TempDir::new()?;
    let settings = settings_for(directory.path());
    let mut state = ScanState::default();
    let mut stack = vec![open_root(directory.path())?];
    let flow = handle_next(&settings, &mut stack, no_hook, &mut state, Some(Err(Errno::IO)));
    assert_eq!(flow, ControlFlow::Continue(()));
    assert!(stack.is_empty());
    assert_eq!(state.skipped.unreadable, 1);
    assert_eq!(step(&settings, &mut stack, no_hook, &mut state), ControlFlow::Break(()));
    scan_root(&settings, directory.path(), no_hook, BIG_LISTING, &mut state);
    assert_eq!(state.errors.len(), 1);
    Ok(())
}


#[test]
fn an_unreadable_descriptor_is_counted_and_abandoned() -> TestResult {
    let directory = TempDir::new()?;
    let mut state = ScanState::default();
    assert!(adopt(Err(io::Error::other("no reader")), &mut state, directory.path()).is_none());
    assert_eq!(state.skipped.unreadable, 1);
    assert!(adopt(Ok(open_root(directory.path())?), &mut state, directory.path()).is_some());
    assert_eq!(state.skipped.unreadable, 1);
    Ok(())
}


#[test]
fn a_file_handle_is_not_a_directory_level() -> TestResult {
    let directory = TempDir::new()?;
    write(directory.path().join("f"), "x")?;
    let handle = OwnedFd::from(File::open(directory.path().join("f"))?);
    assert!(level_of(handle, directory.path().to_path_buf()).is_err());
    Ok(())
}


#[test]
fn plan_decides_per_entry_type_and_name() -> TestResult {
    let settings = ScanSettings::default();
    assert_eq!(plan(&settings, OsStr::new("."), FileType::Directory), Step::Ignore);
    assert_eq!(plan(&settings, OsStr::new(".."), FileType::Directory), Step::Ignore);
    assert_eq!(plan(&settings, OsStr::new("sub"), FileType::Directory), Step::Descend);
    assert_eq!(plan(&settings, OsStr::new("a.PEM"), FileType::Symlink), Step::Examine);
    assert_eq!(plan(&settings, OsStr::new("a.PEM"), FileType::Unknown), Step::Examine);
    assert_eq!(plan(&settings, OsStr::new("a.txt"), FileType::RegularFile), Step::Ignore);
    assert_eq!(plan(&settings, OsStr::new("noext"), FileType::RegularFile), Step::Ignore);
    assert!(is_swap(Errno::LOOP));
    assert!(is_swap(Errno::NOTDIR));
    assert!(!is_swap(Errno::NOENT));
    Ok(())
}


#[test]
fn read_bounded_does_not_overflow_at_the_largest_cap() -> TestResult {
    assert_eq!(
        read_bounded(Cursor::new(vec![1u8; CAP_BYTES]), u64::MAX)?,
        Loaded::Bytes(vec![1u8; CAP_BYTES])
    );
    Ok(())
}


#[test]
fn parse_failures_are_counted_per_reason() -> TestResult {
    let (pem, key) = make_certificate()?;
    let directory = TempDir::new()?;
    write(
        directory.path().join("pem.pem"),
        "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
    )?;
    write(directory.path().join("der.der"), "not a certificate")?;
    write(directory.path().join("blocks.pem"), key.repeat(MANY_BLOCKS))?;
    write(directory.path().join("certs.pem"), pem.repeat(MANY_CERTIFICATES))?;
    let outcome = scan(&settings_for(directory.path()));
    assert_eq!(outcome.malformed.get("pem"), Some(&1));
    assert_eq!(outcome.malformed.get("certificate"), Some(&1));
    assert_eq!(outcome.malformed.get("too_many_blocks"), Some(&1));
    assert_eq!(outcome.malformed.get("too_many_certificates"), Some(&1));
    Ok(())
}


#[test]
fn every_parse_error_has_a_fixed_reason() -> TestResult {
    let mut state = ScanState::default();
    absorb(&mut state, Path::new("p"), b"");
    assert_eq!(state.malformed.get("certificate"), Some(&1));
    assert_eq!(reason_of(&CertError::InputTooLarge { size: 1, max: 0 }), "input_too_large");
    assert_eq!(reason_of(&CertError::Pem(x509_parser::error::PEMError::MissingHeader)), "pem");
    assert_eq!(
        reason_of(&CertError::Extension(x509_parser::error::X509Error::InvalidVersion)),
        "extension"
    );
    Ok(())
}
