use crate::support::{capture, logged, names_in, own_uid, PERMISSIONS, THIRD};
use crate::types::Plant;
use command_issue::error::IssueError;
use command_issue::limits::{MAX_QUEUE_SCAN_ENTRIES, MAX_STAGING_SCAN_ENTRIES, STAGING_NAME};
use command_issue::queue::{
    clean_staging, discard, envelope_name, is_regular, list_names, list_queue, open_agent_directory, open_command_dirs, open_directory, open_staging,
    parse_name, prune, rename_staged, retract, stage, stage_with, FileIdentity,
};
use rustix::fs::{fstat, mknodat, openat, FileType, Mode, OFlags, CWD};
use std::error::Error;
use std::fs::{self, File};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{chown, symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;


const OTHER_UID: u32 = 65_534;


const FIRST: u64 = 1;


const SECOND: u64 = 2;


const NOW: u64 = 10_000;


const SKEW: u64 = 30;


const PRIVATE: u32 = 0o700;


const READABLE: u32 = 0o755;


const OPEN: u32 = 0o777;


const FILE_MODE: u32 = 0o640;


const FILE_TYPE_BITS: u32 = 0o170_000;


const FIFO_MODE: u32 = 0o600;


const AGENT: &str = "agent1";


const TENANT: &str = "acme";


pub fn handle_of(path: &Path) -> Result<OwnedFd, Box<dyn Error>> {
    Ok(openat(
        CWD,
        path,
        OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC),
        Mode::empty(),
    )?)
}


pub fn entries_of(directory: &Path) -> Result<Vec<std::ffi::OsString>, Box<dyn Error>> {
    Ok(fs::read_dir(directory)?
        .map(|entry| entry.map(|found| found.file_name()))
        .collect::<Result<Vec<_>, io::Error>>()?)
}


pub fn plant(directory: &Path, sequence: u64, expires_at: u64) -> Result<String, Box<dyn Error>> {
    let name = envelope_name(sequence, expires_at);
    fs::write(directory.join(&name), b"envelope")?;
    Ok(name)
}


pub fn fail_unlink(_directory: &OwnedFd, _name: &str) -> io::Result<()> {
    Err(io::Error::other("unlink failed"))
}


pub fn fail_fill(_file: &mut File, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::other("fill failed"))
}


#[test]
fn names_round_trip_and_only_the_exact_form_parses() -> Result<(), Box<dyn Error>> {
    assert_eq!(envelope_name(FIRST, NOW), "00000000000000000001-00000000000000010000.env");
    assert_eq!(parse_name(&envelope_name(FIRST, NOW)), Some((FIRST, NOW)));
    let bad = [
        "",
        "x.env",
        "00000000000000000001-00000000000000010000",
        "00000000000000000001-00000000000000010000.ENV",
        "0000000000000000001-00000000000000010000.env",
        "00000000000000000001-0000000000000010000.env",
        "+0000000000000000001-00000000000000010000.env",
        "00000000000000000001_00000000000000010000.env",
        "99999999999999999999-00000000000000010000.env",
        "00000000000000000001-99999999999999999999.env",
        "00000000000000000001-00000000000000010000.env.env",
        "0000000000000000000a-00000000000000010000.env",
    ];
    bad.iter().for_each(|name| assert_eq!(parse_name(name), None, "{name}"));
    assert!(!is_regular(FILE_TYPE_BITS));
    Ok(())
}


#[test]
fn start_creates_the_private_staging_directory_and_reopens_it() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let first = open_command_dirs(&root, own_uid())?;
    assert_eq!(fs::metadata(root.join(STAGING_NAME))?.permissions().mode() & PERMISSIONS, PRIVATE);
    assert_eq!(first.service_uid, own_uid());
    fs::set_permissions(root.join(STAGING_NAME), fs::Permissions::from_mode(OPEN))?;
    open_command_dirs(&root, own_uid())?;
    assert_eq!(fs::metadata(root.join(STAGING_NAME))?.permissions().mode() & PERMISSIONS, PRIVATE);
    Ok(())
}


#[test]
fn a_root_that_is_not_trusted_refuses_the_start() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let missing = open_command_dirs(&dir.path().join("missing"), own_uid()).err().ok_or("opened")?;
    assert!(matches!(missing, IssueError::Trusted(_)), "{missing}");
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let foreign = open_command_dirs(&root, OTHER_UID).err().ok_or("opened")?;
    assert!(matches!(foreign, IssueError::Trusted(_)), "{foreign}");
    Ok(())
}


#[test]
fn staging_leftovers_are_removed_at_start() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir_all(root.join(STAGING_NAME))?;
    fs::write(root.join(STAGING_NAME).join("crashed-one"), b"a")?;
    fs::write(root.join(STAGING_NAME).join("crashed-two"), b"b")?;
    let handle = handle_of(&root.join(STAGING_NAME))?;
    assert_eq!(clean_staging(&handle)?, usize::try_from(SECOND)?);
    open_command_dirs(&root, own_uid())?;
    assert!(names_in(&root.join(STAGING_NAME))?.is_empty());
    Ok(())
}


#[test]
fn a_staging_entry_that_is_not_a_file_or_too_many_entries_refuse_the_start() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    let staging = root.join(STAGING_NAME);
    fs::create_dir_all(staging.join("a-directory"))?;
    let refused = open_command_dirs(&root, own_uid()).err().ok_or("opened")?;
    assert!(
        matches!(refused, IssueError::DirectoryRefused(text) if text.contains("not a file")),
        "{refused}"
    );
    fs::remove_dir(staging.join("a-directory"))?;
    (0..MAX_STAGING_SCAN_ENTRIES).try_for_each(|index| fs::write(staging.join(format!("f{index}")), b"x"))?;
    let full = open_command_dirs(&root, own_uid()).err().ok_or("opened")?;
    assert!(matches!(full, IssueError::DirectoryRefused(text) if text.contains("too many")), "{full}");
    assert_eq!(names_in(&staging)?.len(), MAX_STAGING_SCAN_ENTRIES);
    Ok(())
}


#[test]
fn staging_must_belong_to_the_service_and_not_be_a_link() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let handle = handle_of(&root)?;
    let refused = open_staging(&handle, OTHER_UID).err().ok_or("opened")?;
    assert!(matches!(refused, IssueError::DirectoryRefused(_)), "{refused}");
    fs::remove_dir(root.join(STAGING_NAME))?;
    symlink(dir.path(), root.join(STAGING_NAME))?;
    let linked = open_command_dirs(&root, own_uid()).err().ok_or("opened")?;
    assert!(matches!(linked, IssueError::Fs(_)), "{linked}");
    Ok(())
}


#[test]
fn a_removed_root_cannot_make_directories() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let handle = handle_of(&root)?;
    fs::remove_dir(&root)?;
    let refused = open_staging(&handle, own_uid()).err().ok_or("opened")?;
    assert!(matches!(refused, IssueError::Fs(_)), "{refused}");
    assert!(open_directory(&handle, "x", PRIVATE).is_err());
    Ok(())
}


#[test]
fn the_agent_directory_is_made_and_judged_on_its_handle() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let dirs = open_command_dirs(&root, own_uid())?;
    let first = open_agent_directory(&dirs, TENANT, AGENT)?;
    let again = open_agent_directory(&dirs, TENANT, AGENT)?;
    assert_eq!(fstat(&first)?.st_ino, fstat(&again)?.st_ino);
    let path = root.join(format!("{TENANT}@{AGENT}"));
    assert!(fs::metadata(&path)?.is_dir());
    fs::set_permissions(&path, fs::Permissions::from_mode(OPEN))?;
    let writable = open_agent_directory(&dirs, TENANT, AGENT).err().ok_or("opened")?;
    assert!(
        matches!(writable, IssueError::DirectoryRefused(text) if text.contains("writable")),
        "{writable}"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(READABLE))?;
    chown(&path, Some(OTHER_UID), None)?;
    let foreign = open_agent_directory(&dirs, TENANT, AGENT).err().ok_or("opened")?;
    assert!(
        matches!(foreign, IssueError::DirectoryRefused(text) if text.contains("another user")),
        "{foreign}"
    );
    symlink(dir.path(), root.join("acme@linked"))?;
    let linked = open_agent_directory(&dirs, TENANT, "linked").err().ok_or("opened")?;
    assert!(matches!(linked, IssueError::Fs(_)), "{linked}");
    Ok(())
}


#[test]
fn a_queue_lists_well_formed_files_and_prunes_only_expired_ones() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let live = plant(dir.path(), FIRST, NOW)?;
    plant(dir.path(), SECOND, NOW - SKEW - 1)?;
    let edge = plant(dir.path(), SECOND + 1, NOW - SKEW)?;
    let handle = handle_of(dir.path())?;
    let entries = list_queue(&handle, TENANT, AGENT)?;
    assert_eq!(entries.len(), usize::try_from(THIRD)?);
    let kept = prune(&handle, entries, NOW)?;
    let mut kept_names = kept.iter().map(|entry| entry.name.clone()).collect::<Vec<String>>();
    kept_names.sort();
    assert_eq!(kept_names, vec![live.clone(), edge.clone()]);
    assert_eq!(names_in(dir.path())?, vec![live, edge]);
    Ok(())
}


#[test]
fn a_foreign_entry_makes_the_queue_invalid_and_nothing_is_deleted() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let dir = tempdir()?;
    let handle = handle_of(dir.path())?;
    let target = plant(dir.path(), FIRST, NOW)?;
    let planted: Vec<(&str, Plant)> = vec![
        (
            "symlink",
            Box::new(|path| Ok(symlink("elsewhere", path.join(envelope_name(SECOND, NOW)))?)),
        ),
        (
            "fifo",
            Box::new(|path| {
                let directory = handle_of(path)?;
                Ok(mknodat(
                    &directory,
                    envelope_name(SECOND, NOW),
                    FileType::Fifo,
                    Mode::from_raw_mode(FIFO_MODE),
                    0,
                )?)
            }),
        ),
        ("directory", Box::new(|path| Ok(fs::create_dir(path.join(envelope_name(SECOND, NOW)))?))),
        ("badname", Box::new(|path| Ok(fs::write(path.join("notes.txt"), b"x")?))),
        (
            "overflow",
            Box::new(|path| Ok(fs::write(path.join("99999999999999999999-00000000000000010000.env"), b"x")?)),
        ),
        (
            "binary",
            Box::new(|path| Ok(fs::write(path.join(std::ffi::OsStr::from_bytes(b"bad\xff\xfe-name")), b"x")?)),
        ),
    ];
    planted.iter().try_for_each(|(label, plant_one)| {
        let before = entries_of(dir.path())?;
        plant_one(dir.path())?;
        let refused = list_queue(&handle, TENANT, AGENT).err().ok_or("accepted")?;
        assert!(matches!(refused, IssueError::QueueInvalid), "{label}: {refused}");
        let after = entries_of(dir.path())?;
        assert_eq!(after.len(), before.len() + 1, "{label}");
        assert!(names_in(dir.path())?.contains(&target));
        let entry = after.into_iter().find(|name| !before.contains(name)).ok_or("no entry")?;
        let path = dir.path().join(&entry);
        fs::remove_file(&path).or_else(|_file| fs::remove_dir(&path))?;
        Ok::<(), Box<dyn Error>>(())
    })?;
    let text = logged(&buffer);
    assert!(
        text.contains("agent queue holds a foreign entry") && text.contains(AGENT) && text.contains("notes.txt"),
        "{text}"
    );
    Ok(())
}


#[test]
fn a_full_scan_is_refused_loudly() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let dir = tempdir()?;
    (0..MAX_QUEUE_SCAN_ENTRIES).try_for_each(|index| plant(dir.path(), u64::try_from(index)? + FIRST, NOW).map(|_name| ()))?;
    let handle = handle_of(dir.path())?;
    let refused = list_queue(&handle, TENANT, AGENT).err().ok_or("accepted")?;
    assert!(matches!(refused, IssueError::QueueInvalid), "{refused}");
    assert!(logged(&buffer).contains("agent queue scan cap reached"));
    assert_eq!(names_in(dir.path())?.len(), MAX_QUEUE_SCAN_ENTRIES);
    assert_eq!(list_names(&handle, MAX_QUEUE_SCAN_ENTRIES)?.len(), MAX_QUEUE_SCAN_ENTRIES);
    Ok(())
}


#[test]
fn a_staged_file_is_private_complete_and_named_randomly() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let dirs = open_command_dirs(&root, own_uid())?;
    let first = stage(&dirs, b"first")?;
    let second = stage(&dirs, b"second")?;
    assert_ne!(first.name, second.name);
    let path = root.join(STAGING_NAME).join(&first.name);
    assert_eq!(fs::read(&path)?, b"first");
    let metadata = fs::metadata(&path)?;
    assert_eq!(metadata.permissions().mode() & PERMISSIONS, FILE_MODE);
    assert_eq!((metadata.dev(), metadata.ino()), (first.identity.device, first.identity.inode));
    Ok(())
}


#[test]
fn a_failed_fill_removes_the_staged_file() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let dirs = open_command_dirs(&root, own_uid())?;
    discard(&dirs, "missing-name");
    let refused = stage_with(&dirs, b"x", fail_fill).err().ok_or("staged")?;
    assert!(matches!(refused, IssueError::Io(_)), "{refused}");
    assert!(names_in(&root.join(STAGING_NAME))?.is_empty());
    assert!(logged(&buffer).contains("cannot remove a staged envelope"));
    Ok(())
}


#[test]
fn the_rename_never_replaces_an_existing_name() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let root = dir.path().join("commands");
    fs::create_dir(&root)?;
    let dirs = open_command_dirs(&root, own_uid())?;
    let directory = open_agent_directory(&dirs, TENANT, AGENT)?;
    let path = root.join(format!("{TENANT}@{AGENT}"));
    let name = plant(&path, FIRST, NOW)?;
    let staged = stage(&dirs, b"new")?;
    let refused = rename_staged(&dirs, &directory, &staged, &name).err().ok_or("replaced")?;
    assert_eq!(refused, rustix::io::Errno::EXIST);
    assert_eq!(fs::read(path.join(&name))?, b"envelope");
    let free = envelope_name(SECOND, NOW);
    rename_staged(&dirs, &directory, &staged, &free)?;
    assert_eq!(fs::read(path.join(&free))?, b"new");
    Ok(())
}


#[test]
fn a_retract_removes_only_the_inode_that_was_staged() -> Result<(), Box<dyn Error>> {
    let (dispatch, buffer) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let dir = tempdir()?;
    let handle = handle_of(dir.path())?;
    let name = plant(dir.path(), FIRST, NOW)?;
    let metadata = fs::metadata(dir.path().join(&name))?;
    let identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    retract(&handle, &name, identity, fail_unlink);
    assert!(logged(&buffer).contains("cannot retract a published envelope"));
    assert!(dir.path().join(&name).exists());
    retract(
        &handle,
        &name,
        FileIdentity {
            inode: identity.inode + 1,
            ..identity
        },
        command_issue::queue::unlink_name,
    );
    assert!(logged(&buffer).contains("replaced by another file"));
    retract(
        &handle,
        &name,
        FileIdentity {
            device: identity.device + 1,
            ..identity
        },
        command_issue::queue::unlink_name,
    );
    assert!(dir.path().join(&name).exists());
    assert!(dir.path().join(&name).exists());
    retract(&handle, &name, identity, command_issue::queue::unlink_name);
    assert!(!dir.path().join(&name).exists());
    retract(&handle, &name, identity, command_issue::queue::unlink_name);
    assert!(logged(&buffer).contains("already gone"));
    Ok(())
}
