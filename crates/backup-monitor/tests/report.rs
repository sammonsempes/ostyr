#![cfg(unix)]
use backup_monitor::borg::{BorgError, MODE_MASK};
use backup_monitor::report::{read_report, read_up_to, report_directory, report_directory_with, write_all_to, write_report, ReportError};
use core_pg::scope::{tenant_scope, TenantScope};
use std::error::Error;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::TempDir;


const PRIVATE: u32 = 0o700;


const SECRET: u32 = 0o600;


const OPEN: u32 = 0o755;


const WIDE_OPEN: u32 = 0o777;


const WORLD_READABLE: u32 = 0o644;


const CAP: u64 = 1000;


const SMALL_CAP: u64 = 2;


struct Setup {
    dir: TempDir,
    state: PathBuf,
    tenant: TenantScope,
}


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken"))
    }
}


impl Write for Broken {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn setup() -> Result<Setup, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("state");
    std::fs::create_dir(&state)?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(PRIVATE))?;
    Ok(Setup {
        dir,
        state,
        tenant: tenant_scope("acme")?,
    })
}


fn mode(path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(std::fs::metadata(path)?.permissions().mode() & MODE_MASK)
}


fn handle(setup: &Setup) -> Result<OwnedFd, Box<dyn Error>> {
    Ok(report_directory(&setup.state, &setup.tenant, euid())?)
}


fn level(setup: &Setup) -> PathBuf {
    setup.state.join("reports").join("acme")
}


fn refusing(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("no mkdir"))
}


fn directory_refused(setup: &Setup) -> bool {
    matches!(
        report_directory(&setup.state, &setup.tenant, euid()),
        Err(ReportError::Directory(BorgError::BaseDir))
    )
}


#[test]
fn the_levels_are_made_private_and_reused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    handle(&setup)?;
    assert_eq!(mode(&setup.state.join("reports"))?, PRIVATE);
    assert_eq!(mode(&level(&setup))?, PRIVATE);
    handle(&setup)?;
    Ok(())
}


#[test]
fn a_refused_state_directory_gets_no_reports_level() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    std::fs::set_permissions(&setup.state, std::fs::Permissions::from_mode(WIDE_OPEN))?;
    assert!(directory_refused(&setup));
    assert!(!setup.state.join("reports").exists());
    assert!(report_directory(&setup.dir.path().join("absent"), &setup.tenant, euid()).is_err());
    Ok(())
}


#[test]
fn a_loose_existing_level_is_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    handle(&setup)?;
    std::fs::set_permissions(level(&setup), std::fs::Permissions::from_mode(OPEN))?;
    assert!(directory_refused(&setup));
    std::fs::set_permissions(level(&setup), std::fs::Permissions::from_mode(PRIVATE))?;
    std::fs::set_permissions(setup.state.join("reports"), std::fs::Permissions::from_mode(OPEN))?;
    assert!(directory_refused(&setup));
    Ok(())
}


#[test]
fn a_directory_that_cannot_be_made_is_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    assert!(report_directory_with(&setup.state, &setup.tenant, euid(), refusing).is_err());
    Ok(())
}


#[test]
fn a_report_is_written_private_and_read_back() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    write_report(&directory, "a.borg.snapshots", b"one")?;
    write_report(&directory, "a.borg.snapshots", b"two")?;
    assert_eq!(std::fs::read(level(&setup).join("a.borg.snapshots"))?, b"two");
    assert_eq!(mode(&level(&setup).join("a.borg.snapshots"))?, SECRET);
    assert_eq!(read_report(&directory, "a.borg.snapshots", euid(), CAP)?, Some(b"two".to_vec()));
    assert_eq!(read_report(&directory, "a.borg.snapshots", euid(), SMALL_CAP)?, Some(b"tw".to_vec()));
    assert_eq!(read_report(&directory, "absent", euid(), CAP)?, None);
    Ok(())
}


#[test]
fn a_planted_loose_report_is_replaced_by_a_private_one() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    let path = level(&setup).join("a.restic.id");
    std::fs::write(&path, "planted")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(WORLD_READABLE))?;
    write_report(&directory, "a.restic.id", b"fresh")?;
    assert_eq!(std::fs::read(&path)?, b"fresh");
    assert_eq!(mode(&path)?, SECRET);
    Ok(())
}


#[test]
fn a_symlinked_report_is_never_followed() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    let victim = setup.dir.path().join("victim");
    std::fs::write(&victim, "keep")?;
    let path = level(&setup).join("a.borg.snapshots");
    symlink(&victim, &path)?;
    write_report(&directory, "a.borg.snapshots", b"fresh")?;
    assert_eq!(std::fs::read(&victim)?, b"keep");
    assert!(!std::fs::symlink_metadata(&path)?.file_type().is_symlink());
    assert_eq!(std::fs::read(&path)?, b"fresh");
    std::fs::remove_file(&path)?;
    symlink(&victim, &path)?;
    assert!(matches!(
        read_report(&directory, "a.borg.snapshots", euid(), CAP),
        Err(ReportError::Io(_))
    ));
    symlink(&victim, level(&setup).join(".b.tmp"))?;
    write_report(&directory, "b", b"fresh")?;
    assert_eq!(std::fs::read(&victim)?, b"keep");
    Ok(())
}


#[test]
fn names_outside_the_plain_form_are_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    ["", "../x", "a/b", ".hidden"].iter().for_each(|name| {
        assert!(matches!(write_report(&directory, name, b"x"), Err(ReportError::Refused)), "{name:?}");
        assert!(
            matches!(read_report(&directory, name, euid(), CAP), Err(ReportError::Refused)),
            "{name:?}"
        );
    });
    Ok(())
}


#[test]
fn a_report_that_is_not_a_regular_file_of_the_caller_is_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    std::fs::create_dir(level(&setup).join("sub"))?;
    assert!(matches!(read_report(&directory, "sub", euid(), CAP), Err(ReportError::Refused)));
    std::fs::write(level(&setup).join("file"), "x")?;
    assert!(matches!(
        read_report(&directory, "file", euid().wrapping_add(1), CAP),
        Err(ReportError::Refused)
    ));
    Ok(())
}


#[test]
fn a_blocked_destination_or_temporary_is_an_io_error() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    std::fs::create_dir(level(&setup).join("dest"))?;
    assert!(matches!(write_report(&directory, "dest", b"x"), Err(ReportError::Io(_))));
    std::fs::create_dir(level(&setup).join(".other.tmp"))?;
    assert!(matches!(write_report(&directory, "other", b"x"), Err(ReportError::Io(_))));
    Ok(())
}


#[test]
fn a_fifo_report_never_blocks() -> Result<(), Box<dyn Error>> {
    let setup = setup()?;
    let directory = handle(&setup)?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        level(&setup).join("pipe"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )?;
    assert!(matches!(read_report(&directory, "pipe", euid(), CAP), Err(ReportError::Refused)));
    Ok(())
}


#[test]
fn a_failing_reader_or_writer_is_an_io_error() -> Result<(), Box<dyn Error>> {
    assert!(matches!(read_up_to(&mut Broken, CAP), Err(ReportError::Io(_))));
    assert!(matches!(write_all_to(&mut Broken, b"x"), Err(ReportError::Io(_))));
    Ok(())
}
