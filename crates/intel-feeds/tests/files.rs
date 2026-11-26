#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use core_config::secret_file::SecretFileError;
use core_pg::error::PgError;
use intel_feeds::error::pg_category;
use intel_feeds::files::{pg_error, read_trusted};
use std::fs;
use std::io;
use tempfile::tempdir;
use types::TestResult;


const LIMIT: u64 = 16;


#[test]
fn a_ca_file_is_read_through_the_trusted_open_and_capped() -> TestResult {
    let dir = tempdir()?;
    let ca = dir.path().join("ca.pem");
    fs::write(&ca, "pem")?;
    assert_eq!(read_trusted(&ca, LIMIT)?.as_slice(), b"pem");
    fs::write(&ca, "x".repeat(usize::try_from(LIMIT)? + 1))?;
    assert!(matches!(read_trusted(&ca, LIMIT), Err(PgError::TooLarge { .. })));
    let link = dir.path().join("link.pem");
    std::os::unix::fs::symlink(&ca, &link)?;
    assert!(matches!(read_trusted(&link, LIMIT), Err(PgError::SecretSymlink { .. })));
    let fifo = dir.path().join("fifo.pem");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(read_trusted(&fifo, LIMIT), Err(PgError::NotRegular { .. })));
    assert!(matches!(read_trusted(&dir.path().join("absent"), LIMIT), Err(PgError::Io { .. })));
    Ok(())
}


#[test]
fn each_refusal_keeps_its_category() -> TestResult {
    let file = || "f".to_owned();
    let io_error = SecretFileError::Io {
        file: file(),
        source: io::Error::other("x"),
    };
    assert!(matches!(pg_error(io_error), PgError::Io { .. }));
    assert!(matches!(pg_error(SecretFileError::Mode { file: file() }), PgError::SecretMode { .. }));
    assert!(matches!(pg_error(SecretFileError::Owner { file: file() }), PgError::SecretOwner { .. }));
    let names = [
        pg_category(&PgError::Io {
            file: file(),
            source: io::Error::other("x"),
        }),
        pg_category(&PgError::NotRegular { file: file() }),
        pg_category(&PgError::SecretSymlink { file: file() }),
        pg_category(&PgError::SecretMode { file: file() }),
        pg_category(&PgError::SecretOwner { file: file() }),
        pg_category(&PgError::TooLarge { file: file(), limit: 1 }),
        pg_category(&PgError::EmptyPassword { file: file() }),
        pg_category(&PgError::DeadlineOverflow),
    ];
    assert_eq!(
        names,
        [
            "unreadable",
            "not a regular file",
            "not a regular file",
            "permissions",
            "permissions",
            "too large",
            "empty",
            "invalid"
        ]
    );
    Ok(())
}
