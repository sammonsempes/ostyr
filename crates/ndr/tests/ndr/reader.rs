use crate::support::{store, TestResult, FOUR, SHA_A, SHA_B, SHA_C, SHA_D, TINY_LIMIT};
use ndr::model::Loaded;
use ndr::reader::{load_handle, load_stored, read_capped, split_name};
use std::fs::{self, File};
use std::io::{self, Read};


struct FailingRead;


impl Read for FailingRead {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected read failure"))
    }
}


#[test]
fn read_capped_returns_content_within_the_cap() -> TestResult {
    assert_eq!(read_capped(&b"abcd"[..], FOUR)?, Some(b"abcd".to_vec()));
    assert_eq!(read_capped(&b"abc"[..], FOUR)?, Some(b"abc".to_vec()));
    Ok(())
}


#[test]
fn read_capped_refuses_a_longer_source_instead_of_truncating() -> TestResult {
    assert_eq!(read_capped(&b"abcde"[..], FOUR)?, None);
    Ok(())
}


#[test]
fn read_capped_keeps_the_read_error() -> TestResult {
    assert!(read_capped(FailingRead, FOUR).is_err());
    Ok(())
}


#[test]
fn split_name_accepts_only_lowercase_hex_of_the_right_length() -> TestResult {
    assert_eq!(split_name(SHA_A).map(|(prefix, _)| prefix), Some("aa"));
    assert_eq!(split_name(SHA_A).map(|(_, name)| name), Some(SHA_A));
    assert!(split_name("../../etc/shadow").is_none());
    assert!(split_name(&SHA_A.to_uppercase()).is_none());
    assert!(split_name("aa").is_none());
    assert!(split_name(&SHA_A.replace('0', "g")).is_none());
    Ok(())
}


#[test]
fn a_stored_file_is_read() -> TestResult {
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, b"content")?;
    assert_eq!(load_stored(root.path(), SHA_A, TINY_LIMIT)?, Loaded::Content(b"content".to_vec()));
    Ok(())
}


#[test]
fn a_file_over_the_cap_is_too_large_and_one_at_the_cap_is_read() -> TestResult {
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, b"123456789")?;
    store(root.path(), SHA_B, b"12345678")?;
    assert_eq!(load_stored(root.path(), SHA_A, TINY_LIMIT)?, Loaded::TooLarge);
    assert_eq!(load_stored(root.path(), SHA_B, TINY_LIMIT)?, Loaded::Content(b"12345678".to_vec()));
    Ok(())
}


#[test]
fn a_missing_file_or_directory_is_missing() -> TestResult {
    let root = tempfile::tempdir()?;
    assert_eq!(load_stored(root.path(), SHA_A, TINY_LIMIT)?, Loaded::Missing);
    fs::create_dir(root.path().join("aa"))?;
    assert_eq!(load_stored(root.path(), SHA_A, TINY_LIMIT)?, Loaded::Missing);
    Ok(())
}


#[test]
fn a_hash_that_is_not_a_sha256_is_refused_without_touching_the_disk() -> TestResult {
    let root = tempfile::tempdir()?;
    assert_eq!(load_stored(root.path(), "../../etc/shadow", TINY_LIMIT)?, Loaded::Refused);
    Ok(())
}


#[test]
fn a_directory_in_place_of_the_file_is_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("aa").join(SHA_A))?;
    assert_eq!(load_stored(root.path(), SHA_A, TINY_LIMIT)?, Loaded::Refused);
    assert_eq!(load_handle(File::open(root.path())?, TINY_LIMIT)?, Loaded::Refused);
    Ok(())
}


#[test]
fn a_regular_file_in_place_of_the_sub_directory_is_refused() -> TestResult {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("aa"), b"x")?;
    assert_eq!(load_stored(root.path(), SHA_A, TINY_LIMIT)?, Loaded::Refused);
    Ok(())
}


#[test]
fn a_missing_root_is_an_error() -> TestResult {
    let root = tempfile::tempdir()?;
    assert!(load_stored(&root.path().join("absent"), SHA_A, TINY_LIMIT).is_err());
    Ok(())
}


#[cfg(unix)]
mod unix_only {
    use super::*;
    use ndr::reader::step;
    use rustix::fs::OFlags;
    use std::os::unix::fs::symlink;


    #[test]
    fn a_symlink_as_the_file_is_refused_and_its_target_is_not_read() -> TestResult {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("secret"), b"secret")?;
        fs::create_dir(root.path().join("cc"))?;
        symlink(outside.path().join("secret"), root.path().join("cc").join(SHA_C))?;
        assert_eq!(load_stored(root.path(), SHA_C, TINY_LIMIT)?, Loaded::Refused);
        Ok(())
    }


    #[test]
    fn a_symlink_as_the_sub_directory_is_refused() -> TestResult {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        store(outside.path(), SHA_D, b"secret")?;
        symlink(outside.path().join("dd"), root.path().join("dd"))?;
        assert_eq!(load_stored(root.path(), SHA_D, TINY_LIMIT)?, Loaded::Refused);
        Ok(())
    }


    #[test]
    fn an_unopenable_name_is_an_error() -> TestResult {
        let directory = tempfile::tempdir()?;
        let handle = File::open(directory.path())?;
        assert!(step(&handle, "a\0b", OFlags::RDONLY).is_err());
        Ok(())
    }
}
