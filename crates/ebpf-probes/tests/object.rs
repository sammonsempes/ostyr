#![cfg(target_os = "linux")]

use ebpf_probes::object::{
    check_directory, check_file, meta_of, open_last, plain_names, read_bounded, read_object, read_object_with, real_open, real_stat, same_file,
    walk_object, Meta, ObjectError, DIRECTORY_FLAGS, EXEC_OBJECT_PATH, GROUP_OTHER_WRITE, MAX_OBJECT_BYTES,
};
use ebpf_probes::types::Opened;
use rustix::fs::{fstat, mknodat, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};


const SYSTEM_FILE: &str = "/etc/passwd";


const REGULAR_MODE: u32 = 0o100_644;


const DIRECTORY_MODE: u32 = 0o040_755;


const FIFO_MODE: u32 = 0o010_644;


const SYMLINK_MODE: u32 = 0o120_777;


const GROUP_WRITE: u32 = 0o020;


const OTHER_WRITE: u32 = 0o002;


const STICKY_OTHER_WRITE: u32 = 0o1002;


const FIFO_PERMISSIONS: u32 = 0o644;


const FOREIGN_UID: u32 = 1000;


const FILE_INODE: u64 = 77;


const FILE_DEVICE: u64 = 5;


const SMALL_SIZE: u64 = 10;


const SPARSE_BYTES: u64 = 1 << 41;


const TEST_DEPTH: usize = 9;


const SECOND_COMPONENT: usize = 2;


const THIRD_COMPONENT: usize = 3;


const FILL_BYTE: u8 = 7;


const READ_LIMIT: u64 = 4;


const OPEN_COUNTER: &str = concat!(env!("CARGO_TARGET_TMPDIR"), "/object-open-counter-written-by-one-test-only");


fn file_meta() -> Meta {
    Meta {
        mode: REGULAR_MODE,
        uid: 0,
        size: SMALL_SIZE,
        dev: FILE_DEVICE,
        ino: FILE_INODE,
    }
}


fn directory_meta() -> Meta {
    Meta {
        mode: DIRECTORY_MODE,
        uid: 0,
        size: 0,
        dev: FILE_DEVICE,
        ino: 1,
    }
}


fn scratch(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("object-{name}-{}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    fs::create_dir_all(&path)?;
    Ok(path)
}


fn count_file_open() -> Result<(), Errno> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(OPEN_COUNTER)
        .and_then(|mut counter| counter.write_all(b"x"))
        .map_err(|_| Errno::IO)
}


fn fake_open(_parent: BorrowedFd<'_>, _name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    if flags.contains(OFlags::DIRECTORY) {
        let handle = rustix::fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?;
        Ok((handle, directory_meta()))
    } else {
        let handle = rustix::fs::open(SYSTEM_FILE, OFlags::RDONLY, Mode::empty())?;
        Ok((handle, file_meta()))
    }
}


fn counting_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    if !flags.contains(OFlags::DIRECTORY) {
        count_file_open()?;
    }
    fake_open(parent, name, flags)
}


fn fake_stat(_parent: BorrowedFd<'_>, _name: &OsStr) -> Result<Meta, Errno> {
    Ok(file_meta())
}


fn denied_open(_parent: BorrowedFd<'_>, _name: &OsStr, _flags: OFlags) -> Result<Opened, Errno> {
    Err(Errno::ACCESS)
}


fn loop_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    if flags.contains(OFlags::DIRECTORY) {
        fake_open(parent, name, flags)
    } else {
        Err(Errno::LOOP)
    }
}


fn foreign_ancestor_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    fake_open(parent, name, flags).map(|(handle, meta)| (handle, Meta { uid: FOREIGN_UID, ..meta }))
}


fn foreign_second_ancestor_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    if name == OsStr::new("b") {
        foreign_ancestor_open(parent, name, flags)
    } else {
        fake_open(parent, name, flags)
    }
}


fn writable_ancestor_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    fake_open(parent, name, flags).map(|(handle, meta)| {
        (
            handle,
            Meta {
                mode: meta.mode | GROUP_WRITE,
                ..meta
            },
        )
    })
}


fn not_directory_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    fake_open(parent, name, flags).map(|(handle, meta)| (handle, Meta { mode: REGULAR_MODE, ..meta }))
}


fn other_inode_open(parent: BorrowedFd<'_>, name: &OsStr, flags: OFlags) -> Result<Opened, Errno> {
    fake_open(parent, name, flags).map(|(handle, meta)| (handle, Meta { ino: meta.ino + 1, ..meta }))
}


fn failing_root_open(_parent: BorrowedFd<'_>, _name: &OsStr, _flags: OFlags) -> Result<Opened, Errno> {
    Err(Errno::NOENT)
}


fn missing_stat(_parent: BorrowedFd<'_>, _name: &OsStr) -> Result<Meta, Errno> {
    Err(Errno::NOENT)
}


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(ErrorKind::PermissionDenied))
    }
}


#[test]
fn a_regular_root_file_with_closed_modes_passes() -> Result<(), Box<dyn Error>> {
    assert_eq!(check_file(&file_meta()), Ok(()));
    assert_eq!(
        check_file(&Meta {
            size: MAX_OBJECT_BYTES,
            ..file_meta()
        }),
        Ok(())
    );
    Ok(())
}


#[test]
fn every_file_check_refuses_by_name() -> Result<(), Box<dyn Error>> {
    let refuse = |meta: Meta| check_file(&meta);
    assert_eq!(
        refuse(Meta {
            mode: DIRECTORY_MODE,
            ..file_meta()
        }),
        Err(ObjectError::NotRegular)
    );
    assert_eq!(
        refuse(Meta {
            mode: FIFO_MODE,
            ..file_meta()
        }),
        Err(ObjectError::NotRegular)
    );
    assert_eq!(
        refuse(Meta {
            mode: SYMLINK_MODE,
            ..file_meta()
        }),
        Err(ObjectError::NotRegular)
    );
    assert_eq!(
        refuse(Meta {
            uid: FOREIGN_UID,
            ..file_meta()
        }),
        Err(ObjectError::Owner)
    );
    assert_eq!(
        refuse(Meta {
            mode: REGULAR_MODE | GROUP_WRITE,
            ..file_meta()
        }),
        Err(ObjectError::Writable)
    );
    assert_eq!(
        refuse(Meta {
            mode: REGULAR_MODE | OTHER_WRITE,
            ..file_meta()
        }),
        Err(ObjectError::Writable)
    );
    assert_eq!(
        refuse(Meta {
            size: MAX_OBJECT_BYTES + 1,
            ..file_meta()
        }),
        Err(ObjectError::TooLarge)
    );
    assert_eq!(GROUP_OTHER_WRITE, GROUP_WRITE | OTHER_WRITE);
    Ok(())
}


#[test]
fn every_directory_check_refuses_by_name_with_its_depth() -> Result<(), Box<dyn Error>> {
    let refuse = |meta: Meta| check_directory(&meta, TEST_DEPTH);
    assert_eq!(refuse(directory_meta()), Ok(()));
    assert_eq!(
        refuse(Meta {
            mode: REGULAR_MODE,
            ..directory_meta()
        }),
        Err(ObjectError::NotDirectory { depth: TEST_DEPTH })
    );
    assert_eq!(
        refuse(Meta {
            uid: FOREIGN_UID,
            ..directory_meta()
        }),
        Err(ObjectError::AncestorOwner { depth: TEST_DEPTH })
    );
    assert_eq!(
        refuse(Meta {
            mode: DIRECTORY_MODE | GROUP_WRITE,
            ..directory_meta()
        }),
        Err(ObjectError::AncestorWritable { depth: TEST_DEPTH })
    );
    assert_eq!(
        refuse(Meta {
            mode: DIRECTORY_MODE | STICKY_OTHER_WRITE,
            ..directory_meta()
        }),
        Err(ObjectError::AncestorWritable { depth: TEST_DEPTH })
    );
    Ok(())
}


#[test]
fn identity_is_device_and_inode() -> Result<(), Box<dyn Error>> {
    assert!(same_file(&file_meta(), &file_meta()));
    assert!(!same_file(
        &file_meta(),
        &Meta {
            ino: FILE_INODE + 1,
            ..file_meta()
        }
    ));
    assert!(!same_file(
        &file_meta(),
        &Meta {
            dev: FILE_DEVICE + 1,
            ..file_meta()
        }
    ));
    Ok(())
}


#[test]
fn only_a_plain_absolute_path_is_split() -> Result<(), Box<dyn Error>> {
    assert_eq!(plain_names(Path::new("/a/b"))?, (OsString::from("b"), vec![OsString::from("a")]));
    assert_eq!(plain_names(Path::new("a/b")), Err(ObjectError::PathNotAbsolute));
    ["/", "//a", "/a//b", "/a/./b", "/a/../b", "/a/", "/a/."].iter().try_for_each(|text| {
        let refused = plain_names(Path::new(text));
        if refused == Err(ObjectError::PathNotPlain) {
            Ok(())
        } else {
            Err(format!("{text} gave {refused:?}"))
        }
    })?;
    Ok(())
}


#[test]
fn every_error_has_a_fixed_text() -> Result<(), Box<dyn Error>> {
    let errors = [
        ObjectError::PathNotAbsolute,
        ObjectError::PathNotPlain,
        ObjectError::Symlink { depth: TEST_DEPTH },
        ObjectError::NotDirectory { depth: TEST_DEPTH },
        ObjectError::AncestorOwner { depth: TEST_DEPTH },
        ObjectError::AncestorWritable { depth: TEST_DEPTH },
        ObjectError::Open {
            depth: TEST_DEPTH,
            errno: Errno::ACCESS.raw_os_error(),
        },
        ObjectError::NotRegular,
        ObjectError::Owner,
        ObjectError::Writable,
        ObjectError::TooLarge,
        ObjectError::Swapped,
        ObjectError::ReadTooLarge,
        ObjectError::Read { kind: ErrorKind::NotFound },
    ];
    let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
    assert!(texts.iter().all(|text| text.starts_with("object ")));
    assert!(texts.iter().all(|text| !text.contains('/')));
    assert!(errors.iter().all(|error| std::error::Error::source(error).is_none()));
    Ok(())
}


#[test]
fn the_real_walk_reads_a_root_owned_system_file() -> Result<(), Box<dyn Error>> {
    let bytes = read_object(Path::new(SYSTEM_FILE))?;
    assert_eq!(bytes, fs::read(SYSTEM_FILE)?);
    let stat = fstat(File::open(SYSTEM_FILE)?)?;
    let meta = meta_of(&stat);
    assert_eq!(meta.uid, 0);
    assert_eq!(meta.size, u64::try_from(bytes.len())?);
    assert_eq!(FileType::from_raw_mode(meta.mode), FileType::RegularFile);
    Ok(())
}


#[test]
fn the_const_path_is_plain_and_a_missing_file_is_named() -> Result<(), Box<dyn Error>> {
    assert!(plain_names(Path::new(EXEC_OBJECT_PATH)).is_ok());
    let refused = read_object(Path::new("/etc/ostyr-absent-object"));
    assert_eq!(
        refused,
        Err(ObjectError::Open {
            depth: SECOND_COMPONENT,
            errno: Errno::NOENT.raw_os_error()
        })
    );
    Ok(())
}


#[test]
fn a_component_that_is_a_file_is_refused_with_its_depth() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        read_object(Path::new("/etc/passwd/x")),
        Err(ObjectError::NotDirectory { depth: SECOND_COMPONENT })
    );
    Ok(())
}


#[test]
fn a_path_that_is_not_plain_never_opens_anything() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_object(Path::new("etc/passwd")), Err(ObjectError::PathNotAbsolute));
    assert_eq!(read_object(Path::new("//etc/passwd")), Err(ObjectError::PathNotPlain));
    assert_eq!(read_object(Path::new("/etc/../etc/passwd")), Err(ObjectError::PathNotPlain));
    Ok(())
}


#[test]
fn the_object_is_opened_exactly_once() -> Result<(), Box<dyn Error>> {
    if Path::new(OPEN_COUNTER).exists() {
        fs::remove_file(OPEN_COUNTER)?;
    }
    let bytes = read_object_with(Path::new("/a/b/exec.o"), counting_open, fake_stat)?;
    assert_eq!(bytes, fs::read(SYSTEM_FILE)?);
    assert_eq!(fs::metadata(OPEN_COUNTER)?.len(), 1);
    fs::remove_file(OPEN_COUNTER)?;
    Ok(())
}


#[test]
fn a_foreign_or_writable_or_non_directory_ancestor_is_refused_at_its_depth() -> Result<(), Box<dyn Error>> {
    let path = Path::new("/a/b/exec.o");
    assert_eq!(
        read_object_with(path, foreign_ancestor_open, fake_stat),
        Err(ObjectError::AncestorOwner { depth: 0 })
    );
    assert_eq!(
        read_object_with(Path::new("/a/b/c/exec.o"), foreign_second_ancestor_open, fake_stat),
        Err(ObjectError::AncestorOwner { depth: SECOND_COMPONENT })
    );
    assert_eq!(
        read_object_with(path, writable_ancestor_open, fake_stat),
        Err(ObjectError::AncestorWritable { depth: 0 })
    );
    assert_eq!(
        read_object_with(path, not_directory_open, fake_stat),
        Err(ObjectError::NotDirectory { depth: 0 })
    );
    Ok(())
}


#[test]
fn an_open_failure_names_its_depth_and_errno() -> Result<(), Box<dyn Error>> {
    let path = Path::new("/a/b/exec.o");
    assert_eq!(
        read_object_with(path, denied_open, fake_stat),
        Err(ObjectError::Open {
            depth: 0,
            errno: Errno::ACCESS.raw_os_error()
        })
    );
    assert_eq!(
        read_object_with(path, failing_root_open, fake_stat),
        Err(ObjectError::Open {
            depth: 0,
            errno: Errno::NOENT.raw_os_error()
        })
    );
    assert_eq!(
        read_object_with(path, loop_open, fake_stat),
        Err(ObjectError::Symlink { depth: THIRD_COMPONENT })
    );
    assert_eq!(
        read_object_with(path, fake_open, missing_stat),
        Err(ObjectError::Open {
            depth: THIRD_COMPONENT,
            errno: Errno::NOENT.raw_os_error()
        })
    );
    Ok(())
}


#[test]
fn a_file_swapped_between_the_stat_and_the_open_is_refused() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        read_object_with(Path::new("/a/exec.o"), other_inode_open, fake_stat),
        Err(ObjectError::Swapped)
    );
    Ok(())
}


#[test]
fn the_walk_judges_every_ancestor_from_the_real_root() -> Result<(), Box<dyn Error>> {
    let handle = walk_object(Path::new(SYSTEM_FILE), real_open, real_stat)?;
    assert_eq!(meta_of(&fstat(handle.as_fd())?).uid, 0);
    Ok(())
}


#[test]
fn a_symlink_at_the_last_name_is_refused_before_any_open() -> Result<(), Box<dyn Error>> {
    let directory = scratch("symlink")?;
    symlink(SYSTEM_FILE, directory.join("exec.o"))?;
    let handle = File::open(&directory)?;
    let refused = open_last(handle.as_fd(), OsStr::new("exec.o"), TEST_DEPTH, real_open, real_stat);
    fs::remove_dir_all(&directory)?;
    assert_eq!(refused.err(), Some(ObjectError::NotRegular));
    Ok(())
}


#[test]
fn a_symlink_swapped_in_after_the_stat_is_a_named_loop() -> Result<(), Box<dyn Error>> {
    let directory = scratch("loop")?;
    symlink(SYSTEM_FILE, directory.join("exec.o"))?;
    let handle = File::open(&directory)?;
    let refused = open_last(handle.as_fd(), OsStr::new("exec.o"), TEST_DEPTH, real_open, fake_stat);
    fs::remove_dir_all(&directory)?;
    assert_eq!(refused.err(), Some(ObjectError::Symlink { depth: TEST_DEPTH }));
    Ok(())
}


#[test]
fn a_symlinked_directory_component_cannot_be_opened() -> Result<(), Box<dyn Error>> {
    let directory = scratch("dirlink")?;
    symlink("/etc", directory.join("link"))?;
    let handle = File::open(&directory)?;
    let refused = real_open(handle.as_fd(), OsStr::new("link"), DIRECTORY_FLAGS);
    fs::remove_dir_all(&directory)?;
    assert!(matches!(refused, Err(Errno::NOTDIR | Errno::LOOP)));
    Ok(())
}


#[test]
fn a_fifo_is_refused_by_type_without_hanging() -> Result<(), Box<dyn Error>> {
    let directory = scratch("fifo")?;
    let handle = File::open(&directory)?;
    mknodat(handle.as_fd(), "exec.o", FileType::Fifo, Mode::from_raw_mode(FIFO_PERMISSIONS), 0)?;
    let direct = open_last(handle.as_fd(), OsStr::new("exec.o"), 1, real_open, real_stat);
    let raced = open_last(handle.as_fd(), OsStr::new("exec.o"), 1, real_open, fake_stat);
    fs::remove_dir_all(&directory)?;
    assert_eq!(direct.err(), Some(ObjectError::NotRegular));
    assert_eq!(raced.err(), Some(ObjectError::NotRegular));
    Ok(())
}


#[test]
fn a_file_over_the_limit_is_refused_on_its_handle() -> Result<(), Box<dyn Error>> {
    let directory = scratch("sparse")?;
    File::create(directory.join("exec.o"))?.set_len(SPARSE_BYTES)?;
    let handle = File::open(&directory)?;
    let refused = open_last(handle.as_fd(), OsStr::new("exec.o"), 1, real_open, real_stat);
    fs::remove_dir_all(&directory)?;
    assert!(matches!(refused.err(), Some(ObjectError::TooLarge | ObjectError::Owner)));
    Ok(())
}


#[test]
fn a_sparse_read_stops_one_byte_past_the_limit() -> Result<(), Box<dyn Error>> {
    let directory = scratch("sparse-read")?;
    let path = directory.join("big");
    File::create(&path)?.set_len(SPARSE_BYTES)?;
    let refused = read_bounded(&mut File::open(&path)?, MAX_OBJECT_BYTES);
    fs::remove_dir_all(&directory)?;
    assert_eq!(refused, Err(ObjectError::ReadTooLarge));
    Ok(())
}


#[test]
fn the_bounded_read_keeps_exactly_the_limit_and_names_a_read_error() -> Result<(), Box<dyn Error>> {
    let exactly = vec![FILL_BYTE; usize::try_from(READ_LIMIT)?];
    assert_eq!(read_bounded(&mut io::repeat(FILL_BYTE).take(READ_LIMIT), READ_LIMIT), Ok(exactly));
    assert_eq!(
        read_bounded(&mut io::repeat(FILL_BYTE).take(READ_LIMIT + 1), READ_LIMIT),
        Err(ObjectError::ReadTooLarge)
    );
    assert_eq!(
        read_bounded(&mut FailingReader, READ_LIMIT),
        Err(ObjectError::Read {
            kind: ErrorKind::PermissionDenied
        })
    );
    Ok(())
}


#[test]
fn the_root_directory_handle_is_a_directory() -> Result<(), Box<dyn Error>> {
    let handle = File::open("/")?;
    assert_eq!(check_directory(&meta_of(&fstat(handle.as_fd())?), 0), Ok(()));
    Ok(())
}
