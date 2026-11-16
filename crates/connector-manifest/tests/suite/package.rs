use crate::common::types::TestResult;
use crate::common::VALID_MANIFEST;
use connector_manifest::error::ConnectorError;
use connector_manifest::model::{Limits, Package, MANIFEST_NAME, MAX_FILE_NAME_BYTES, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, SIGNATURE_NAME};
use connector_manifest::package::{digest_bytes, hash_capped, read_capped, read_package, read_package_with};
use connector_manifest::scan::{check_regular_with, list_names, list_names_with, shown_name};
use data_encoding::HEXLOWER;
use rustix::fs::{mknodat, FileType, Mode, CWD};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;
use tempfile::TempDir;


const CODE: &[u8] = b"print(1)";


const SMALL_FILE_LIMIT: u64 = 8;


const SMALL_MAX_FILES: usize = 2;


const SPARE_BYTES: u64 = 4;


const SHOWN_CUT: usize = 64;


const NOT_UTF8_NAME: &[u8] = b"bad\xff.py";


fn put(directory: &Path, name: &str, bytes: &[u8]) -> TestResult {
    fs::write(directory.join(name), bytes)?;
    Ok(())
}


fn package_dir() -> Result<TempDir, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    put(directory.path(), MANIFEST_NAME, VALID_MANIFEST.as_bytes())?;
    put(directory.path(), "main.py", CODE)?;
    Ok(directory)
}


fn limits(max_files: usize, max_file_bytes: u64, spare: u64) -> Limits {
    Limits {
        max_files,
        max_file_bytes,
        max_package_bytes: VALID_MANIFEST.len() as u64 + spare,
    }
}


fn refusal(directory: &Path, limits: &Limits) -> Result<ConnectorError, Box<dyn std::error::Error>> {
    match read_package_with(directory, limits) {
        Ok(_) => Err("package accepted".into()),
        Err(error) => Ok(error),
    }
}


fn special(directory: &Path, name: &str, kind: FileType) -> TestResult {
    mknodat(CWD, directory.join(name), kind, Mode::RUSR | Mode::WUSR, 0)?;
    Ok(())
}


#[test]
fn a_package_is_read_with_its_digests_and_manifest_bytes() -> TestResult {
    let directory = package_dir()?;
    let package = read_package(directory.path())?;
    let names: Vec<&str> = package.files.keys().map(String::as_str).collect();
    assert_eq!(names, vec![MANIFEST_NAME, "main.py"]);
    assert_eq!(package.manifest, VALID_MANIFEST.as_bytes());
    assert_eq!(package.signature, None);
    let code = package.files.get("main.py").ok_or("no main.py")?;
    assert_eq!(code.sha256, HEXLOWER.encode(&Sha256::digest(CODE)));
    assert_eq!(code.size, CODE.len() as u64);
    assert_eq!(package.total_bytes, (VALID_MANIFEST.len() + CODE.len()) as u64);
    Ok(())
}


#[test]
fn the_signature_file_is_kept_apart_and_not_listed() -> TestResult {
    let directory = package_dir()?;
    put(directory.path(), SIGNATURE_NAME, b"signature text")?;
    let package = read_package(directory.path())?;
    assert_eq!(package.signature.as_deref(), Some(b"signature text".as_slice()));
    assert!(!package.files.contains_key(SIGNATURE_NAME));
    Ok(())
}


#[test]
fn a_symlink_a_fifo_a_socket_and_a_subdirectory_are_refused() -> TestResult {
    let all = limits(SMALL_MAX_FILES * SHOWN_CUT, MAX_MANIFEST_BYTES as u64, SHOWN_CUT as u64);
    let link = package_dir()?;
    symlink("main.py", link.path().join("link"))?;
    assert!(matches!(refusal(link.path(), &all)?, ConnectorError::Symlink { path } if path == "link"));
    let fifo = package_dir()?;
    special(fifo.path(), "pipe", FileType::Fifo)?;
    assert!(matches!(refusal(fifo.path(), &all)?, ConnectorError::NotRegular { path } if path == "pipe"));
    let socket = package_dir()?;
    special(socket.path(), "sock", FileType::Socket)?;
    assert!(matches!(refusal(socket.path(), &all)?, ConnectorError::NotRegular { path } if path == "sock"));
    let nested = package_dir()?;
    fs::create_dir(nested.path().join("sub"))?;
    assert!(matches!(refusal(nested.path(), &all)?, ConnectorError::NotRegular { path } if path == "sub"));
    Ok(())
}


#[test]
fn a_hard_linked_file_is_refused() -> TestResult {
    let directory = package_dir()?;
    fs::hard_link(directory.path().join("main.py"), directory.path().join("copy.py"))?;
    assert!(matches!(
        refusal(directory.path(), &limits(SHOWN_CUT, SMALL_FILE_LIMIT, SHOWN_CUT as u64))?,
        ConnectorError::HardLinked { path } if path == "main.py" || path == "copy.py"
    ));
    Ok(())
}


#[test]
fn a_file_over_the_per_file_limit_is_refused_and_one_at_the_limit_is_read() -> TestResult {
    let directory = package_dir()?;
    put(directory.path(), "big.bin", &[0; SMALL_FILE_LIMIT as usize])?;
    read_package_with(directory.path(), &limits(SHOWN_CUT, SMALL_FILE_LIMIT, SHOWN_CUT as u64))?;
    put(directory.path(), "big.bin", &[0; SMALL_FILE_LIMIT as usize + 1])?;
    assert!(matches!(
        refusal(directory.path(), &limits(SHOWN_CUT, SMALL_FILE_LIMIT, SHOWN_CUT as u64))?,
        ConnectorError::FileTooLarge { path, max } if path == "big.bin" && max == SMALL_FILE_LIMIT
    ));
    Ok(())
}


#[test]
fn more_files_than_the_limit_are_refused_before_any_is_read() -> TestResult {
    let directory = tempfile::tempdir()?;
    put(directory.path(), MANIFEST_NAME, VALID_MANIFEST.as_bytes())?;
    put(directory.path(), "a", b"a")?;
    put(directory.path(), SIGNATURE_NAME, b"s")?;
    read_package_with(directory.path(), &limits(SMALL_MAX_FILES, SMALL_FILE_LIMIT, SHOWN_CUT as u64))?;
    fs::remove_file(directory.path().join(SIGNATURE_NAME))?;
    put(directory.path(), "b", b"b")?;
    assert!(matches!(
        refusal(directory.path(), &limits(SMALL_MAX_FILES, SMALL_FILE_LIMIT, SHOWN_CUT as u64))?,
        ConnectorError::TooManyFiles { max } if max == SMALL_MAX_FILES
    ));
    (0..SHOWN_CUT).try_for_each(|i| put(directory.path(), &format!("f{i}"), b"x"))?;
    assert!(matches!(
        refusal(directory.path(), &limits(SMALL_MAX_FILES, SMALL_FILE_LIMIT, SHOWN_CUT as u64))?,
        ConnectorError::TooManyFiles { max } if max == SMALL_MAX_FILES
    ));
    Ok(())
}


#[test]
fn a_total_over_the_package_limit_is_refused() -> TestResult {
    let directory = package_dir()?;
    let fits = limits(SHOWN_CUT, SMALL_FILE_LIMIT, CODE.len() as u64);
    read_package_with(directory.path(), &fits)?;
    put(directory.path(), "more.bin", &[0; SPARE_BYTES as usize])?;
    assert!(matches!(refusal(directory.path(), &fits)?, ConnectorError::PackageTooLarge { max } if max == fits.max_package_bytes));
    Ok(())
}


#[test]
fn a_file_name_outside_the_ascii_allowlist_is_refused() -> TestResult {
    let all = limits(SHOWN_CUT, SMALL_FILE_LIMIT, SHOWN_CUT as u64);
    let long = "a".repeat(MAX_FILE_NAME_BYTES + 1);
    [
        OsStr::new("bad name"),
        OsStr::new(".hidden"),
        OsStr::new("caf\u{e9}.py"),
        OsStr::new(&long),
        OsStr::from_bytes(NOT_UTF8_NAME),
    ]
    .iter()
    .try_for_each(|name| {
        let directory = package_dir()?;
        fs::write(directory.path().join(name), b"x")?;
        assert!(matches!(refusal(directory.path(), &all)?, ConnectorError::BadFileName { .. }));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn a_shown_name_is_escaped_and_cut() -> TestResult {
    assert_eq!(shown_name(NOT_UTF8_NAME), "bad\\u{fffd}.py");
    assert_eq!(shown_name("a".repeat(MAX_FILE_NAME_BYTES).as_bytes()).len(), SHOWN_CUT);
    Ok(())
}


#[test]
fn a_package_without_its_manifest_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    put(directory.path(), "main.py", CODE)?;
    assert!(matches!(read_package(directory.path()), Err(ConnectorError::MissingManifest)));
    Ok(())
}


#[test]
fn the_manifest_and_the_signature_have_their_own_caps() -> TestResult {
    let manifest = package_dir()?;
    put(manifest.path(), MANIFEST_NAME, &vec![b' '; MAX_MANIFEST_BYTES])?;
    assert_eq!(read_package(manifest.path())?.manifest.len(), MAX_MANIFEST_BYTES);
    put(manifest.path(), MANIFEST_NAME, &vec![b' '; MAX_MANIFEST_BYTES + 1])?;
    assert!(matches!(read_package(manifest.path()), Err(ConnectorError::FileTooLarge { path, .. }) if path == MANIFEST_NAME));
    let signature = package_dir()?;
    put(signature.path(), SIGNATURE_NAME, &vec![b' '; MAX_SIGNATURE_BYTES as usize + 1])?;
    assert!(matches!(read_package(signature.path()), Err(ConnectorError::FileTooLarge { path, .. }) if path == SIGNATURE_NAME));
    Ok(())
}


#[test]
fn a_directory_that_is_missing_a_file_or_a_symlink_is_refused() -> TestResult {
    let directory = package_dir()?;
    let link = directory.path().join("dirlink");
    symlink(directory.path(), &link)?;
    assert!(matches!(read_package(&link), Err(ConnectorError::Io { .. })));
    assert!(matches!(read_package(&directory.path().join("absent")), Err(ConnectorError::Io { .. })));
    assert!(matches!(read_package(&directory.path().join("main.py")), Err(ConnectorError::Io { .. })));
    Ok(())
}


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
}


#[test]
fn the_capped_readers_report_the_digest_the_size_and_a_failing_source() -> TestResult {
    let digest = digest_bytes(CODE);
    let mut first: &[u8] = CODE;
    let mut second: &[u8] = CODE;
    let mut third: &[u8] = CODE;
    assert_eq!(hash_capped(&mut first, CODE.len() as u64, "x").ok(), Some(digest));
    assert!(matches!(
        hash_capped(&mut second, 1, "x"),
        Err(ConnectorError::FileTooLarge { max: 1, .. })
    ));
    assert!(matches!(hash_capped(&mut Failing, 1, "x"), Err(ConnectorError::Io { .. })));
    assert!(matches!(read_capped(&mut Failing, 1, "x"), Err(ConnectorError::Io { .. })));
    assert_eq!(read_capped(&mut third, CODE.len() as u64, "x").ok().as_deref(), Some(CODE));
    assert_eq!(Package::default().total_bytes, 0);
    Ok(())
}


fn failing_lister(_directory: &OwnedFd, _limit: usize) -> Result<Vec<Vec<u8>>, Errno> {
    Err(Errno::IO)
}


fn failing_inspect(_handle: &File) -> io::Result<Metadata> {
    Err(io::Error::other("fstat failed"))
}


#[test]
fn a_failing_directory_listing_or_stat_is_reported_with_the_path() -> TestResult {
    let directory = package_dir()?;
    let handle = OwnedFd::from(File::open(directory.path())?);
    assert!(matches!(list_names_with(failing_lister, &handle, "dir", SHOWN_CUT), Err(ConnectorError::Io { path, .. }) if path == "dir"));
    let file = File::open(directory.path().join("main.py"))?;
    assert!(matches!(check_regular_with(failing_inspect, &file, "main.py"), Err(ConnectorError::Io { path, .. }) if path == "main.py"));
    assert!(list_names(&handle, "dir", SHOWN_CUT)?.contains(&"main.py".to_owned()));
    Ok(())
}
