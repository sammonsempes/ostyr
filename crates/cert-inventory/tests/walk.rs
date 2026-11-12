#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use cert_inventory::error::CertError;
use cert_inventory::scan::{absorb, no_hook, read_bounded, reason_of, scan, scan_with, Loaded, ScanSettings, ScanState, MAX_DEPTH_CEILING};
use cert_inventory::walk::{adopt, handle_next, is_swap, level_of, open_root, plan, resolve_type, scan_root, step, Level, Listed, Step};
use rcgen::{CertificateParams, KeyPair};
use rustix::fs::FileType;
use rustix::io::Errno;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{create_dir_all, remove_dir_all, remove_file, rename, write, File};
use std::io::{self, Cursor};
use std::ops::ControlFlow;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
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


const EXAMINED_WITH_LINK: usize = 2;


const OTHER_TYPES: usize = 5;


const TWO_NAMES: usize = 2;


const NESTED_LEVELS: usize = 3;


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


fn swap_ancestor_at_directory(path: &Path) {
    swap_ancestor_when(path, "e");
}


fn swap_ancestor_at_file(path: &Path) {
    swap_ancestor_when(path, "f.pem");
}


fn swap_ancestor_when(path: &Path, trigger: &str) {
    if let Err(error) = try_swap_ancestor(path, trigger) {
        tracing::warn!(%error, "swap failed");
    }
}


fn try_swap_ancestor(path: &Path, trigger: &str) -> io::Result<()> {
    let top = path
        .ancestors()
        .find(|ancestor| ancestor.join("root").is_dir())
        .ok_or_else(|| io::Error::other("no top"))?;
    let ancestor = top.join("root/d");
    if path.file_name() == Some(OsStr::new(trigger)) && !ancestor.is_symlink() {
        rename(&ancestor, top.join("moved"))?;
        symlink(top.join("secret"), &ancestor)
    } else {
        Ok(())
    }
}


fn ancestor_layout(top: &Path, secret_pem: &str) -> io::Result<()> {
    create_dir_all(top.join("root/d/e"))?;
    create_dir_all(top.join("secret/e"))?;
    write(top.join("root/d/e/a.pem"), "x")?;
    write(top.join("root/d/e/f.pem"), "x")?;
    write(top.join("secret/e/a.pem"), secret_pem)?;
    write(top.join("secret/e/f.pem"), secret_pem)
}


#[test]
fn an_ancestor_swapped_for_a_symlink_before_a_sub_directory_open_is_never_followed() -> TestResult {
    let (pem, _) = make_certificate()?;
    let directory = TempDir::new()?;
    ancestor_layout(directory.path(), &pem)?;
    let outcome = scan_with(&settings_for(&directory.path().join("root")), swap_ancestor_at_directory, BIG_LISTING);
    assert!(directory.path().join("root/d").is_symlink());
    assert!(outcome.records.is_empty());
    assert_eq!(outcome.skipped.swapped, 0);
    Ok(())
}


#[test]
fn an_ancestor_swapped_for_a_symlink_before_a_file_open_is_never_followed() -> TestResult {
    let (pem, _) = make_certificate()?;
    let directory = TempDir::new()?;
    ancestor_layout(directory.path(), &pem)?;
    let outcome = scan_with(&settings_for(&directory.path().join("root")), swap_ancestor_at_file, BIG_LISTING);
    assert!(directory.path().join("root/d").is_symlink());
    assert!(outcome.records.is_empty());
    assert!(outcome.malformed.values().sum::<usize>() > 0);
    Ok(())
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
    assert_eq!(plan(&settings, OsStr::new("a.PEM"), FileType::Symlink), Step::NotRegular);
    assert_eq!(plan(&settings, OsStr::new("a.PEM"), FileType::RegularFile), Step::Examine);
    assert_eq!(plan(&settings, OsStr::new("a.txt"), FileType::CharacterDevice), Step::Ignore);
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


fn unknown(name: &str) -> Listed {
    Listed {
        name: OsString::from(name),
        file_type: FileType::Unknown,
    }
}


fn swap_unknown_directory(path: &Path) {
    if path.file_name() == Some(OsStr::new("u")) && !path.is_symlink() {
        if let Err(error) = try_swap_unknown(path) {
            tracing::warn!(%error, "swap failed");
        }
    }
}


fn try_swap_unknown(path: &Path) -> io::Result<()> {
    let top = path.parent().and_then(Path::parent).ok_or_else(|| io::Error::other("no top"))?;
    remove_dir_all(path)?;
    symlink(top.join("secret"), path)
}


fn run_unknown_walk(directory: &Path, before_open: fn(&Path), names: &[&str]) -> Result<ScanState, Box<dyn Error>> {
    let settings = settings_for(&directory.join("root"));
    let mut state = ScanState::default();
    let mut stack = vec![open_root(&directory.join("root"))?];
    names.iter().for_each(|name| {
        let first = handle_next(&settings, &mut stack, before_open, &mut state, Some(Ok(unknown(name))));
        let drained = (0..BIG_LISTING).try_for_each(|_| match stack.len() > 1 {
            true => step(&settings, &mut stack, before_open, &mut state),
            false => ControlFlow::Break(()),
        });
        assert!(first.is_continue() && drained.is_break());
    });
    Ok(state)
}


#[test]
fn an_unknown_directory_and_file_are_resolved_and_scanned() -> TestResult {
    let (pem, _) = make_certificate()?;
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root/sub/deeper"))?;
    write(directory.path().join("root/sub/deeper/a.pem"), &pem)?;
    write(directory.path().join("root/top.pem"), &pem)?;
    symlink(directory.path().join("root/top.pem"), directory.path().join("root/link.pem"))?;
    let state = run_unknown_walk(directory.path(), no_hook, &["sub", "top.pem", "link.pem"])?;
    assert_eq!(state.examined, EXAMINED_WITH_LINK);
    assert_eq!(state.skipped.not_regular, 1);
    assert_eq!(state.max_open_dirs, NESTED_LEVELS);
    Ok(())
}


#[test]
fn an_unknown_directory_swapped_after_the_stat_is_never_followed() -> TestResult {
    let (pem, _) = make_certificate()?;
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root/u"))?;
    create_dir_all(directory.path().join("secret"))?;
    write(directory.path().join("root/u/a.pem"), "x")?;
    write(directory.path().join("secret/a.pem"), &pem)?;
    let state = run_unknown_walk(directory.path(), swap_unknown_directory, &["u"])?;
    assert!(directory.path().join("root/u").is_symlink());
    assert_eq!(state.skipped.swapped, 1);
    assert_eq!(state.examined, 0);
    Ok(())
}


#[test]
fn resolve_type_keeps_known_types_and_failed_stats() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root/sub"))?;
    let level = open_root(&directory.path().join("root"))?;
    assert_eq!(resolve_type(&level.handle, OsStr::new("sub"), FileType::Unknown), Ok(FileType::Directory));
    assert_eq!(
        resolve_type(&level.handle, OsStr::new("sub"), FileType::RegularFile),
        Ok(FileType::RegularFile)
    );
    assert_eq!(resolve_type(&level.handle, OsStr::new("missing"), FileType::Unknown), Err(Errno::NOENT));
    Ok(())
}


fn run_listed(directory: &Path, listed: Vec<Listed>) -> Result<ScanState, Box<dyn Error>> {
    let settings = settings_for(&directory.join("root"));
    let mut state = ScanState::default();
    let mut stack = vec![open_root(&directory.join("root"))?];
    listed.into_iter().for_each(|entry| {
        assert!(handle_next(&settings, &mut stack, no_hook, &mut state, Some(Ok(entry))).is_continue());
    });
    Ok(state)
}


#[test]
fn wanted_names_of_other_types_are_counted_and_never_opened() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    let listed = [
        FileType::CharacterDevice,
        FileType::BlockDevice,
        FileType::Fifo,
        FileType::Socket,
        FileType::Symlink,
    ]
    .into_iter()
    .map(|file_type| Listed {
        name: OsString::from(format!("{file_type:?}.pem")),
        file_type,
    })
    .collect();
    let state = run_listed(directory.path(), listed)?;
    assert_eq!(state.skipped.not_regular, OTHER_TYPES);
    assert_eq!(state.examined, 0);
    assert_eq!(state.skipped.unreadable, 0);
    assert!(state.errors.is_empty());
    Ok(())
}


#[test]
fn a_real_fifo_named_pem_is_not_opened() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    let status = std::process::Command::new("mkfifo").arg(directory.path().join("root/x.pem")).status()?;
    assert!(status.success());
    let outcome = scan(&settings_for(&directory.path().join("root")));
    assert_eq!(outcome.skipped.not_regular, 1);
    assert_eq!(outcome.examined, 0);
    Ok(())
}


#[test]
fn an_unknown_entry_that_vanished_is_counted_without_an_error() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    let state = run_listed(directory.path(), vec![unknown("gone.pem"), unknown("gone.txt")])?;
    assert_eq!(state.skipped.vanished, TWO_NAMES);
    assert_eq!(state.skipped.unreadable, 0);
    assert!(state.errors.is_empty());
    Ok(())
}


#[test]
fn an_unknown_entry_whose_stat_fails_otherwise_is_unreadable() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    write(directory.path().join("root/plain"), "x")?;
    let settings = settings_for(&directory.path().join("root"));
    let mut state = ScanState::default();
    let directory_level = open_root(&directory.path().join("root"))?;
    let file_handle = OwnedFd::from(File::open(directory.path().join("root/plain"))?);
    let mut stack = vec![Level {
        handle: file_handle,
        dir: directory_level.dir,
        path: directory.path().join("root"),
    }];
    assert!(handle_next(&settings, &mut stack, mark_hook, &mut state, Some(Ok(unknown("a.pem")))).is_continue());
    assert_eq!(state.skipped.unreadable, 1);
    assert_eq!(state.skipped.vanished, 0);
    assert_eq!(state.examined, 0);
    assert_eq!(state.errors.len(), 1);
    assert!(!directory.path().join("root/a.pem.hooked").exists());
    Ok(())
}


fn mark_hook(path: &Path) {
    if let Err(error) = write(path.with_extension("pem.hooked"), "x") {
        tracing::warn!(%error, "mark failed");
    }
}


fn remove_listed_file(path: &Path) {
    if let Err(error) = remove_file(path) {
        tracing::warn!(%error, "remove failed");
    }
}


#[test]
fn a_file_deleted_between_listing_and_open_is_vanished_without_an_error() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    write(directory.path().join("root/gone.pem"), "x")?;
    let outcome = scan_with(&settings_for(&directory.path().join("root")), remove_listed_file, BIG_LISTING);
    assert_eq!(outcome.skipped.vanished, 1);
    assert_eq!(outcome.skipped.unreadable, 0);
    assert_eq!(outcome.examined, 1);
    assert!(outcome.errors.is_empty());
    Ok(())
}


fn bind_short(path: &Path) -> io::Result<()> {
    let parent = File::open(path.parent().ok_or_else(|| io::Error::other("no parent"))?)?;
    let name = path.file_name().ok_or_else(|| io::Error::other("no name"))?;
    UnixListener::bind(Path::new("/proc/self/fd").join(parent.as_raw_fd().to_string()).join(name)).map(drop)
}


fn swap_for_socket(path: &Path) {
    if let Err(error) = try_swap_for_socket(path) {
        tracing::warn!(%error, "swap failed");
    }
}


fn try_swap_for_socket(path: &Path) -> io::Result<()> {
    remove_file(path)?;
    match path.file_name() == Some(OsStr::new("dir.pem")) {
        true => create_dir_all(path),
        false => bind_short(path),
    }
}


#[test]
fn a_file_swapped_for_a_socket_or_directory_after_listing_is_judged_on_the_handle() -> TestResult {
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("root"))?;
    write(directory.path().join("root/swap.pem"), "x")?;
    write(directory.path().join("root/dir.pem"), "x")?;
    let outcome = scan_with(&settings_for(&directory.path().join("root")), swap_for_socket, BIG_LISTING);
    assert_eq!(outcome.skipped.unreadable, 1);
    assert_eq!(outcome.skipped.not_regular, 1);
    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.examined, TWO_NAMES);
    Ok(())
}
