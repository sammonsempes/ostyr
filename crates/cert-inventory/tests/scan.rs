#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use cert_inventory::error::ScanError;
use cert_inventory::scan::{
    check_settings, cut_path, read_bounded, scan, Loaded, ScanSettings, CUT_MARKER, MAX_DEPTH_CEILING, MAX_ERRORS, MAX_EXTENSIONS,
    MAX_EXTENSION_BYTES, MAX_FILES_CEILING, MAX_FILE_BYTES_CEILING, MAX_PATHS_PER_CERT, MAX_PATH_CHARS, MAX_ROOTS,
};
use cert_inventory::walk::{load_at, open_root};
use rcgen::{CertificateParams, KeyPair};
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{create_dir_all, write, File};
use std::io::{self, Cursor, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use types::TestResult;


const EXTRA_COPIES: usize = 3;


const CANDIDATES: usize = 10;


const LIMITED_FILES: usize = 3;


const MISSING_ROOTS: usize = 20;


const SMALL_CAP: u64 = 4;


const PAIR: usize = 2;


const SPECIAL_FILES: usize = 5;


const CAP_BYTES: usize = 4;


const OVER_CAP_BYTES: usize = 5;


struct Generated {
    pem: String,
    der: Vec<u8>,
    key_pem: String,
}


fn make_certificate() -> Result<Generated, Box<dyn Error>> {
    let key = KeyPair::generate()?;
    let certificate = CertificateParams::new(vec!["scan.example.test".to_string()])?.self_signed(&key)?;
    Ok(Generated {
        pem: certificate.pem(),
        der: certificate.der().to_vec(),
        key_pem: key.serialize_pem(),
    })
}


fn settings_for(root: &Path) -> ScanSettings {
    ScanSettings {
        roots: vec![root.to_path_buf()],
        ..ScanSettings::default()
    }
}


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("failing reader"))
    }
}


#[test]
fn pem_and_der_copies_give_one_record_with_two_paths() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    create_dir_all(directory.path().join("a"))?;
    create_dir_all(directory.path().join("b"))?;
    write(directory.path().join("a/one.PEM"), &generated.pem)?;
    write(directory.path().join("b/two.der"), &generated.der)?;
    write(directory.path().join("b/ignored.txt"), &generated.pem)?;
    let outcome = scan(&settings_for(directory.path()));
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.examined, PAIR);
    let found = outcome.records.first().ok_or("no record")?;
    assert_eq!(found.paths.len(), PAIR);
    assert_eq!(found.paths_omitted, 0);
    assert_eq!(found.record.dns_names, ["scan.example.test"]);
    Ok(())
}


#[test]
fn overlapping_roots_and_bundle_duplicates_list_one_path() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    write(directory.path().join("bundle.pem"), format!("{}{}", generated.pem, generated.pem))?;
    let mut settings = settings_for(directory.path());
    settings.roots.push(directory.path().to_path_buf());
    let outcome = scan(&settings);
    assert_eq!(outcome.records.len(), 1);
    assert_eq!(outcome.records.first().ok_or("no record")?.paths.len(), 1);
    Ok(())
}


#[test]
fn paths_are_capped_with_an_omitted_count() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    (0..MAX_PATHS_PER_CERT + EXTRA_COPIES).try_for_each(|index| write(directory.path().join(format!("c{index}.pem")), &generated.pem))?;
    let outcome = scan(&settings_for(directory.path()));
    let found = outcome.records.first().ok_or("no record")?;
    assert_eq!(found.paths.len(), MAX_PATHS_PER_CERT);
    assert_eq!(found.paths_omitted, EXTRA_COPIES);
    Ok(())
}


#[test]
fn symlinks_fifos_sockets_and_directories_are_not_read() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    let root = directory.path().join("root");
    create_dir_all(root.join("y.crt"))?;
    create_dir_all(directory.path().join("elsewhere"))?;
    write(directory.path().join("real.pem"), &generated.pem)?;
    symlink(directory.path().join("real.pem"), root.join("link.pem"))?;
    symlink(root.join("loop.pem"), root.join("loop.pem"))?;
    symlink(directory.path().join("elsewhere"), root.join("dirlink.pem"))?;
    let status = Command::new("mkfifo").arg(root.join("x.pem")).status()?;
    assert!(status.success());
    let root_handle = File::open(&root)?;
    let listener = UnixListener::bind(format!("/proc/self/fd/{}/s.pem", root_handle.as_raw_fd()))?;
    let outcome = scan(&settings_for(&root));
    assert!(outcome.records.is_empty());
    assert_eq!(outcome.examined, 0);
    assert_eq!(outcome.skipped.not_regular, SPECIAL_FILES);
    assert_eq!(outcome.skipped.unreadable, 0);
    assert!(outcome.errors.is_empty());
    drop(listener);
    Ok(())
}


#[test]
fn load_at_refuses_a_symlink_and_reports_a_missing_file() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    write(directory.path().join("real.pem"), &generated.pem)?;
    symlink(directory.path().join("real.pem"), directory.path().join("swapped.pem"))?;
    let level = open_root(directory.path())?;
    assert_eq!(
        load_at(&level.handle, OsStr::new("swapped.pem"), MAX_FILE_BYTES_CEILING)?,
        Loaded::NotRegular
    );
    assert!(load_at(&level.handle, OsStr::new("missing.pem"), MAX_FILE_BYTES_CEILING).is_err());
    assert!(matches!(
        load_at(&level.handle, OsStr::new("real.pem"), MAX_FILE_BYTES_CEILING)?,
        Loaded::Bytes(_)
    ));
    Ok(())
}


#[test]
fn a_sparse_file_above_the_cap_is_too_large() -> TestResult {
    let directory = TempDir::new()?;
    File::create(directory.path().join("big.crt"))?.set_len(MAX_FILE_BYTES_CEILING + 1)?;
    let mut settings = settings_for(directory.path());
    settings.max_file_bytes = MAX_FILE_BYTES_CEILING;
    let outcome = scan(&settings);
    assert_eq!(outcome.skipped.too_large, 1);
    assert!(outcome.malformed.is_empty());
    Ok(())
}


#[test]
fn a_reader_past_the_cap_is_too_large_and_a_failing_reader_errors() -> TestResult {
    assert_eq!(
        read_bounded(Cursor::new(vec![u8::default(); OVER_CAP_BYTES]), SMALL_CAP)?,
        Loaded::TooLarge
    );
    assert_eq!(
        read_bounded(Cursor::new(vec![u8::default(); CAP_BYTES]), SMALL_CAP)?,
        Loaded::Bytes(vec![u8::default(); CAP_BYTES])
    );
    assert_eq!(read_bounded(io::repeat(1), SMALL_CAP)?, Loaded::TooLarge);
    assert!(read_bounded(Failing, SMALL_CAP).is_err());
    Ok(())
}


#[test]
fn file_count_and_depth_are_bounded() -> TestResult {
    let directory = TempDir::new()?;
    (0..CANDIDATES).try_for_each(|index| write(directory.path().join(format!("f{index}.pem")), "x"))?;
    let mut settings = settings_for(directory.path());
    settings.max_files = LIMITED_FILES;
    let outcome = scan(&settings);
    assert_eq!(outcome.examined, LIMITED_FILES);
    assert_eq!(outcome.skipped.over_count, CANDIDATES - LIMITED_FILES);
    assert_eq!(outcome.malformed.get("certificate"), Some(&LIMITED_FILES));
    create_dir_all(directory.path().join("sub"))?;
    write(directory.path().join("sub/nested.pem"), "x")?;
    let mut shallow = settings_for(directory.path());
    shallow.max_depth = 1;
    assert_eq!(scan(&shallow).examined, CANDIDATES);
    assert_eq!(scan(&settings_for(directory.path())).examined, CANDIDATES + 1);
    Ok(())
}


#[test]
fn a_key_only_pem_gives_no_record_and_no_key_text() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    write(directory.path().join("key.pem"), &generated.key_pem)?;
    let outcome = scan(&settings_for(directory.path()));
    assert!(outcome.records.is_empty());
    assert_eq!(outcome.private_keys_refused, 1);
    let body = generated.key_pem.lines().nth(1).ok_or("no key body")?;
    assert!(!format!("{outcome:?}").contains(body));
    Ok(())
}


#[test]
fn unreadable_roots_are_counted_and_other_roots_still_scan() -> TestResult {
    let generated = make_certificate()?;
    let directory = TempDir::new()?;
    write(directory.path().join("a.pem"), &generated.pem)?;
    let mut settings = settings_for(&directory.path().join("missing"));
    settings.roots.push(directory.path().to_path_buf());
    let outcome = scan(&settings);
    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.records.len(), 1);
    Ok(())
}


#[test]
fn errors_are_capped_with_an_omitted_count() -> TestResult {
    let directory = TempDir::new()?;
    let roots = (0..MISSING_ROOTS)
        .map(|index| directory.path().join(format!("missing{index}")))
        .collect::<Vec<PathBuf>>();
    let outcome = scan(&ScanSettings {
        roots,
        ..ScanSettings::default()
    });
    assert_eq!(outcome.errors.len(), MAX_ERRORS);
    assert_eq!(outcome.errors_omitted, MISSING_ROOTS - MAX_ERRORS);
    Ok(())
}


#[test]
fn path_text_is_escaped_and_cut_visibly() -> TestResult {
    assert_eq!(cut_path(Path::new("a\nb")), "a\\nb");
    let long = "d".repeat(MAX_PATH_CHARS + 1);
    let cut = cut_path(Path::new(&long));
    assert!(cut.ends_with(CUT_MARKER));
    assert_eq!(cut.chars().count(), MAX_PATH_CHARS + CUT_MARKER.chars().count());
    assert_eq!(cut_path(Path::new(&long[..MAX_PATH_CHARS])).len(), MAX_PATH_CHARS);
    Ok(())
}


#[test]
fn settings_bounds_are_refused_at_zero_and_above_the_ceiling() -> TestResult {
    let valid = settings_for(Path::new("/"));
    assert!(check_settings(&valid).is_ok());
    let zero_depth = ScanSettings {
        max_depth: 0,
        ..valid.clone()
    };
    assert!(matches!(check_settings(&zero_depth), Err(ScanError::Zero { name: "max_depth" })));
    let high_depth = ScanSettings {
        max_depth: MAX_DEPTH_CEILING + 1,
        ..valid.clone()
    };
    assert!(matches!(
        check_settings(&high_depth),
        Err(ScanError::AboveCeiling { name: "max_depth", .. })
    ));
    let zero_files = ScanSettings {
        max_files: 0,
        ..valid.clone()
    };
    assert!(matches!(check_settings(&zero_files), Err(ScanError::Zero { name: "max_files" })));
    let high_files = ScanSettings {
        max_files: MAX_FILES_CEILING + 1,
        ..valid.clone()
    };
    assert!(matches!(
        check_settings(&high_files),
        Err(ScanError::AboveCeiling { name: "max_files", .. })
    ));
    let zero_bytes = ScanSettings {
        max_file_bytes: 0,
        ..valid.clone()
    };
    assert!(matches!(check_settings(&zero_bytes), Err(ScanError::Zero { name: "max_file_bytes" })));
    let high_bytes = ScanSettings {
        max_file_bytes: MAX_FILE_BYTES_CEILING + 1,
        ..valid.clone()
    };
    assert!(matches!(
        check_settings(&high_bytes),
        Err(ScanError::AboveCeiling { name: "max_file_bytes", .. })
    ));
    let no_roots = ScanSettings {
        roots: Vec::new(),
        ..valid.clone()
    };
    assert!(matches!(check_settings(&no_roots), Err(ScanError::Zero { name: "roots" })));
    let many_roots = ScanSettings {
        roots: vec![PathBuf::from("/"); MAX_ROOTS + 1],
        ..valid.clone()
    };
    assert!(matches!(check_settings(&many_roots), Err(ScanError::AboveCeiling { name: "roots", .. })));
    let no_extensions = ScanSettings {
        extensions: Vec::new(),
        ..valid.clone()
    };
    assert!(matches!(check_settings(&no_extensions), Err(ScanError::Zero { name: "extensions" })));
    let many_extensions = ScanSettings {
        extensions: vec!["pem".to_string(); MAX_EXTENSIONS + 1],
        ..valid.clone()
    };
    assert!(matches!(
        check_settings(&many_extensions),
        Err(ScanError::AboveCeiling { name: "extensions", .. })
    ));
    Ok(())
}


#[test]
fn bad_extensions_are_refused() -> TestResult {
    let valid = settings_for(Path::new("/"));
    let long = "e".repeat(MAX_EXTENSION_BYTES + 1);
    [String::new(), ".pem".to_string(), "a/b".to_string(), "a\\b".to_string(), long]
        .into_iter()
        .try_for_each(|extension| {
            let settings = ScanSettings {
                extensions: vec![extension],
                ..valid.clone()
            };
            let error = check_settings(&settings).err().ok_or("accepted")?;
            assert!(error.to_string().contains("extension"));
            Ok::<(), Box<dyn Error>>(())
        })
}


#[test]
fn invalid_settings_scan_nothing_and_report_one_error() -> TestResult {
    let directory = TempDir::new()?;
    write(directory.path().join("a.pem"), "x")?;
    let mut settings = settings_for(directory.path());
    settings.max_files = 0;
    let outcome = scan(&settings);
    assert_eq!(outcome.examined, 0);
    assert_eq!(outcome.errors.len(), 1);
    Ok(())
}
