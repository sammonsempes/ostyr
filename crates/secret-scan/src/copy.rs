//! Copies a directory tree into a private root-owned directory through held directory handles (Unix only).

use crate::model::CopyCounts;
use crate::scan::{ensure, ScanError, IGNORE_NAME};
use rustix::fs::{fstat, mkdirat, openat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Permissions};
use std::io::{self, Read, Write};
use std::ops::ControlFlow;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;


pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 20;


pub const DEFAULT_MAX_ENTRIES: usize = 200_000;


pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;


pub const DEFAULT_MAX_DEPTH: usize = 64;


pub const DEFAULT_MAX_OPEN_DIRS: usize = DEFAULT_MAX_DEPTH + 2;


pub const CEILING_ENTRIES: usize = 5_000_000;


pub const CEILING_BYTES: u64 = 16 << 30;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const STICKY_BIT: u32 = 0o1000;


pub const PRIVATE_DIR_MODE: u32 = 0o700;


pub const REMOVE_STEPS_PER_ENTRY: usize = 8;


pub const REMOVE_STEPS_SLACK: usize = 16;


pub const WALK_STEPS_PER_ENTRY: usize = 4;


pub const WALK_STEPS_SLACK: usize = 4;


pub const TREE_DIR: &str = "tree";


pub const DATA_DIR: &str = "data";


pub const RUN_DIR: &str = "run";


pub const GIT_DIR_NAME: &str = ".git";


pub const GIT_CONFIG_NAME: &str = "config";


pub const RESERVED_PREFIX: &str = "secret-scan-reserved-";


pub const STAGED_NAME: &str = "secret-scan-reserved-git-config";


pub const RENAMED_PREFIX: &str = "secret-scan-reserved-name-";


pub const IGNORE_FILE_NAME: &str = ".gitleaksignore";


pub const TOML_FILE_NAME: &str = ".gitleaks.toml";


pub const DIR_PREFIX: &str = "secret-scan-";


pub const MAX_TAIL_BYTES: usize = 64;


pub const SWEEP_MAX_ENTRIES: usize = CEILING_ENTRIES;


const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY.union(OFlags::DIRECTORY).union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);


const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);


const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);


const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);


/// Bounds of one copy: a bound that is reached refuses the scan with `CopyLimit`, never a partial copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyLimits {
    pub max_file_bytes: u64,
    pub max_entries: usize,
    pub max_bytes: u64,
    pub max_depth: usize,
    pub max_open_dirs: usize,
}


impl Default for CopyLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_open_dirs: DEFAULT_MAX_OPEN_DIRS,
        }
    }
}


/// What one copy did: counts of what was copied, skipped or counted, and the raw original names given a reserved copy name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CopySummary {
    pub entries: usize,
    pub bytes: u64,
    pub truncated_files: usize,
    pub skipped_special: usize,
    pub skipped_swapped: usize,
    pub skipped_vanished: usize,
    pub config_files: usize,
    pub foreign_owner_files: usize,
    pub other_device: usize,
    pub denied_entries: usize,
    pub leased_files: usize,
    pub renamed: Vec<OsString>,
}


/// One open directory of the walk: the source handle, the copy's handle and the reader of the source.
pub struct Level {
    pub uid: u32,
    pub src: OwnedFd,
    pub dst: OwnedFd,
    pub dir: Dir,
    pub rel: PathBuf,
}


/// Fixed inputs of one copy.
pub struct Ctx<'a> {
    pub root: &'a Path,
    pub root_dev: u64,
    pub limits: &'a CopyLimits,
    pub before_open: fn(&Path),
    pub open_file: fn(&OwnedFd, &OsStr) -> Result<OwnedFd, Errno>,
    pub expired: &'a dyn Fn() -> bool,
}


/// The private directory `<work>/secret-scan-XXXX` held by handles, holding `data/` (scanned) and `run/` (report, ignore file); removed on drop.
pub struct PrivateDir {
    pub work: OwnedFd,
    pub name: OsString,
    pub root: OwnedFd,
    pub run: OwnedFd,
    pub path: PathBuf,
}


impl Drop for PrivateDir {
    fn drop(&mut self) {
        let outcome = remove_private(self);
        if let Err(error) = outcome {
            warn!(error = %error, "private scan directory not fully removed");
        }
    }
}


/// The production hook between a listing and the open of an entry: nothing.
pub fn no_hook(_path: &Path) {}


/// Ceilings only: a larger value is refused before any directory is created.
pub fn check_limits(limits: &CopyLimits) -> Result<(), ScanError> {
    ensure(
        limits.max_entries <= CEILING_ENTRIES,
        ScanError::BadSettings("max_copy_entries above the ceiling"),
    )?;
    ensure(
        limits.max_bytes <= CEILING_BYTES,
        ScanError::BadSettings("max_copy_bytes above the ceiling"),
    )
}


fn io_error(errno: Errno) -> ScanError {
    ScanError::Io(io::Error::from(errno))
}


/// Counts a tolerated failure of one entry and passes any other errno on as `Io`.
pub fn tolerate(errno: Errno, counter: &mut usize, tolerated: bool) -> Result<(), ScanError> {
    *counter += usize::from(tolerated);
    ensure(tolerated, io_error(errno))
}


/// `EACCES` and `EWOULDBLOCK` skip and count one entry; any other errno is tolerated only when `tolerated`, counted by `fallback`.
pub fn tolerate_entry(errno: Errno, state: &mut CopySummary, fallback: fn(&mut CopySummary) -> &mut usize, tolerated: bool) -> Result<(), ScanError> {
    match errno {
        Errno::ACCESS => {
            state.denied_entries += 1;
            Ok(())
        }
        Errno::WOULDBLOCK => {
            state.leased_files += 1;
            Ok(())
        }
        _ => tolerate(errno, fallback(state), tolerated),
    }
}


fn swapped(state: &mut CopySummary) -> &mut usize {
    &mut state.skipped_swapped
}


fn vanished(state: &mut CopySummary) -> &mut usize {
    &mut state.skipped_vanished
}


fn special(state: &mut CopySummary) -> &mut usize {
    &mut state.skipped_special
}


/// Opens a source file below its parent handle without following a link and without blocking.
pub fn open_file(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, Errno> {
    openat(parent, name, FILE_FLAGS, Mode::empty())
}


fn make_dir(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, ScanError> {
    mkdirat(parent, name, Mode::RWXU).map_err(io_error)?;
    openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)
}


fn check_ancestor(handle: &OwnedFd, expected_uid: u32) -> Result<(), ScanError> {
    let stat = fstat(handle).map_err(io_error)?;
    ensure(
        stat.st_uid == 0 || stat.st_uid == expected_uid,
        ScanError::BadSettings("work directory ancestor is not owned by root or the caller"),
    )?;
    ensure(
        stat.st_mode & GROUP_OTHER_WRITE == 0 || stat.st_mode & STICKY_BIT != 0,
        ScanError::BadSettings("work directory ancestor is writable by group or others"),
    )
}


/// The work directory is absolute and holds only names (no `..`, no `.`), checked before anything is opened.
pub fn check_work_dir(work_dir: &Path) -> Result<(), ScanError> {
    ensure(work_dir.is_absolute(), ScanError::BadSettings("work directory is not absolute"))?;
    ensure(
        work_dir
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        ScanError::BadSettings("work directory has a component other than a name"),
    )
}


fn names_of(path: &Path) -> impl Iterator<Item = &OsStr> {
    path.components().filter_map(|part| match part {
        Component::Normal(name) => Some(name),
        _ => None,
    })
}


/// Opens the work root from `/` one component at a time without following a link; every ancestor is checked, never trusted by path.
pub fn open_work_root(work_dir: &Path, expected_uid: u32) -> Result<OwnedFd, ScanError> {
    check_work_dir(work_dir)?;
    let start = openat(rustix::fs::CWD, "/", DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    let work = names_of(work_dir).try_fold(start, |parent, name| {
        check_ancestor(&parent, expected_uid)?;
        openat(&parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)
    })?;
    let stat = fstat(&work).map_err(io_error)?;
    ensure(
        stat.st_uid == expected_uid,
        ScanError::BadSettings("work directory is not owned by the caller"),
    )?;
    ensure(
        stat.st_mode & GROUP_OTHER_WRITE == 0,
        ScanError::BadSettings("work directory is writable by group or others"),
    )?;
    Ok(work)
}


/// Creates the private directory under the work root, whose ancestors are root's or the caller's and not group or other writable.
pub fn create_private(work_dir: &Path, expected_uid: u32) -> Result<PrivateDir, ScanError> {
    create_private_with(work_dir, expected_uid, make_dir)
}


/// `create_private` with the step that makes `data` and `run` injected; the directory is owned by a guard from its creation, so a failing step leaves nothing.
pub fn create_private_with(
    work_dir: &Path,
    expected_uid: u32,
    make: fn(&OwnedFd, &OsStr) -> Result<OwnedFd, ScanError>,
) -> Result<PrivateDir, ScanError> {
    let work = open_work_root(work_dir, expected_uid)?;
    let created = tempfile::Builder::new()
        .prefix(DIR_PREFIX)
        .permissions(Permissions::from_mode(PRIVATE_DIR_MODE))
        .tempdir_in(work_dir)?;
    let name = created.path().file_name().map_or_else(OsString::new, OsStr::to_os_string);
    let root = openat(&work, &name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    let run = root.try_clone()?;
    let path = created.keep();
    let mut private = PrivateDir { work, name, root, run, path };
    make(&private.root, OsStr::new(DATA_DIR)).map(drop)?;
    private.run = make(&private.root, OsStr::new(RUN_DIR))?;
    Ok(private)
}


/// Creates the empty ignore file gitleaks is pointed at, through the handle of the run directory.
pub fn write_ignore(private: &PrivateDir) -> Result<(), ScanError> {
    openat(&private.run, IGNORE_NAME, CREATE_FLAGS, PRIVATE_FILE_MODE)
        .map(drop)
        .map_err(io_error)
}


/// The directory gitleaks scans.
pub fn data_path(private: &PrivateDir) -> PathBuf {
    private.path.join(DATA_DIR)
}


/// The directory of gitleaks's report, ignore file and home.
pub fn run_path(private: &PrivateDir) -> PathBuf {
    private.path.join(RUN_DIR)
}


/// Opens the scan root from `/` one component at a time without following a link; a link or a non-directory anywhere is refused.
pub fn open_root(path: &Path) -> Result<OwnedFd, ScanError> {
    let start = openat(rustix::fs::CWD, "/", DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    names_of(path).try_fold(start, |parent, name| match openat(&parent, name, DIRECTORY_FLAGS, Mode::empty()) {
        Err(Errno::LOOP | Errno::NOTDIR) => Err(ScanError::BadPath("symlink in path")),
        other => other.map_err(io_error),
    })
}


/// A directory that is now a symlink or no longer a directory was swapped after it was listed.
pub fn is_swap(errno: Errno) -> bool {
    errno == Errno::LOOP || errno == Errno::NOTDIR
}


/// Resolves an `Unknown` reported type with one `fstatat` that does not follow symlinks.
pub fn resolve_type(parent: &OwnedFd, name: &OsStr, reported: FileType) -> Result<FileType, Errno> {
    match reported {
        FileType::Unknown => statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map(|stat| FileType::from_raw_mode(stat.st_mode)),
        _ => Ok(reported),
    }
}


fn level_of(src: OwnedFd, dst: OwnedFd, rel: PathBuf) -> Result<Level, ScanError> {
    let dir = Dir::read_from(&src).map_err(io_error)?;
    let uid = fstat(&src).map_err(io_error)?.st_uid;
    Ok(Level { uid, src, dst, dir, rel })
}


fn check_room(ctx: &Ctx, level: &Level, open: usize) -> Result<(), ScanError> {
    ensure(level.rel.components().count() < ctx.limits.max_depth, ScanError::CopyLimit("depth"))?;
    ensure(open < ctx.limits.max_open_dirs, ScanError::CopyLimit("open directories"))
}


/// True when the handle is on the scan root's device; FUSE, bind mounts and other filesystems are never entered.
pub fn same_device(ctx: &Ctx, handle: &OwnedFd) -> Result<bool, ScanError> {
    fstat(handle).map(|stat| stat.st_dev == ctx.root_dev).map_err(io_error)
}


/// The plain tail (at most `MAX_TAIL_BYTES` of `[A-Za-z0-9._-]`, no leading digit) of the valid UTF-8 text after the last invalid byte of `name`.
pub fn name_tail(name: &OsStr) -> String {
    let after_last_invalid = name
        .as_bytes()
        .utf8_chunks()
        .last()
        .filter(|chunk| chunk.invalid().is_empty())
        .map_or("", |chunk| chunk.valid());
    let plain: Vec<char> = after_last_invalid
        .chars()
        .rev()
        .take_while(|part| part.is_ascii_alphanumeric() || matches!(part, '.' | '_' | '-'))
        .take(MAX_TAIL_BYTES)
        .collect();
    plain.iter().rev().skip_while(|part| part.is_ascii_digit()).collect()
}


/// The name a copy is stored under: the name itself, or a reserved name keeping the plain tail of a name that is not UTF-8 (the original is kept in `renamed`).
pub fn destination(ctx: &Ctx, state: &mut CopySummary, name: &OsStr) -> Result<OsString, ScanError> {
    match name.to_str() {
        Some(_) => Ok(name.to_os_string()),
        None => {
            let stored = OsString::from(format!("{RENAMED_PREFIX}{}{}", state.renamed.len(), name_tail(name)));
            state.bytes = state.bytes.saturating_add(name.len() as u64);
            ensure(state.bytes <= ctx.limits.max_bytes, ScanError::CopyLimit("bytes"))?;
            state.renamed.push(name.to_os_string());
            Ok(stored)
        }
    }
}


fn open_tree_dir(ctx: &Ctx, level: &Level, open: usize, state: &mut CopySummary, name: &OsStr) -> Result<Option<Level>, ScanError> {
    check_room(ctx, level, open)?;
    match openat(&level.src, name, DIRECTORY_FLAGS, Mode::empty()) {
        Err(errno) => tolerate_entry(errno, state, swapped, is_swap(errno)).map(|()| None),
        Ok(src) if !same_device(ctx, &src)? => {
            state.other_device += 1;
            Ok(None)
        }
        Ok(src) => {
            let stored = destination(ctx, state, name)?;
            let dst = make_dir(&level.dst, &stored)?;
            level_of(src, dst, level.rel.join(name)).map(Some)
        }
    }
}


/// Copies only the `config` file of the `.git` directory of `level`, as `STAGED_NAME` beside it, through the handle of that directory.
pub fn copy_git_config(ctx: &Ctx, level: &Level, state: &mut CopySummary) -> Result<Option<Level>, ScanError> {
    match openat(&level.src, GIT_DIR_NAME, DIRECTORY_FLAGS, Mode::empty()) {
        Err(errno) => tolerate_entry(errno, state, swapped, is_swap(errno)).map(|()| None),
        Ok(git) if !same_device(ctx, &git)? => {
            state.other_device += 1;
            Ok(None)
        }
        Ok(git) => {
            let git_uid = fstat(&git).map_err(io_error)?.st_uid;
            copy_regular(
                ctx,
                &git,
                &level.dst,
                (OsStr::new(GIT_CONFIG_NAME), OsStr::new(STAGED_NAME)),
                git_uid,
                state,
            )
            .map(|()| None)
        }
    }
}


fn copy_handle(ctx: &Ctx, dst: &OwnedFd, file: File, destination: &OsStr, dir_uid: u32, state: &mut CopySummary) -> Result<(), ScanError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        state.skipped_special += 1;
        Ok(())
    } else if metadata.dev() != ctx.root_dev {
        state.other_device += 1;
        Ok(())
    } else if metadata.uid() != dir_uid {
        state.foreign_owner_files += 1;
        Ok(())
    } else {
        let created = openat(dst, destination, CREATE_FLAGS, PRIVATE_FILE_MODE).map_err(io_error)?;
        let mut output = File::from(created);
        let copied = io::copy(&mut file.take(ctx.limits.max_file_bytes), &mut output)?;
        state.bytes = state.bytes.saturating_add(copied);
        state.truncated_files += usize::from(metadata.len() > ctx.limits.max_file_bytes);
        ensure(state.bytes <= ctx.limits.max_bytes, ScanError::CopyLimit("bytes"))
    }
}


/// Copies `names.0` of the source handle to `names.1` (at most `max_file_bytes`), only when the file's owner is `dir_uid`, its directory's owner.
pub fn copy_regular(
    ctx: &Ctx,
    src: &OwnedFd,
    dst: &OwnedFd,
    names: (&OsStr, &OsStr),
    dir_uid: u32,
    state: &mut CopySummary,
) -> Result<(), ScanError> {
    let (name, destination) = names;
    match (ctx.open_file)(src, name) {
        Ok(handle) => copy_handle(ctx, dst, File::from(handle), destination, dir_uid, state),
        Err(errno) => {
            let missing = errno == Errno::NOENT;
            let fallback = if missing { vanished } else { special };
            tolerate_entry(errno, state, fallback, missing || matches!(errno, Errno::LOOP | Errno::NXIO))
        }
    }
}


fn copy_named(ctx: &Ctx, level: &Level, state: &mut CopySummary, name: &OsStr) -> Result<(), ScanError> {
    let stored = destination(ctx, state, name)?;
    copy_regular(ctx, &level.src, &level.dst, (name, &stored), level.uid, state)
}


fn act(ctx: &Ctx, level: &Level, open: usize, state: &mut CopySummary, name: &OsStr, file_type: FileType) -> Result<Option<Level>, ScanError> {
    match file_type {
        _ if name == IGNORE_FILE_NAME => Err(ScanError::IgnoreFileInTree),
        _ if name == TOML_FILE_NAME => {
            state.config_files += 1;
            Ok(None)
        }
        FileType::Directory if name == GIT_DIR_NAME => copy_git_config(ctx, level, state),
        FileType::Directory => open_tree_dir(ctx, level, open, state, name),
        FileType::RegularFile => copy_named(ctx, level, state, name).map(|()| None),
        _ => {
            state.skipped_special += 1;
            Ok(None)
        }
    }
}


/// Counts one listed entry against the bounds and the deadline, then acts on it.
pub fn visit_entry(
    ctx: &Ctx,
    level: &Level,
    open: usize,
    state: &mut CopySummary,
    name: &OsStr,
    reported: FileType,
) -> Result<Option<Level>, ScanError> {
    state.entries += 1;
    ensure(state.entries <= ctx.limits.max_entries, ScanError::CopyLimit("entries"))?;
    ensure(!(ctx.expired)(), ScanError::TimedOut)?;
    match resolve_type(&level.src, name, reported) {
        Err(errno) => tolerate_entry(errno, state, vanished, errno == Errno::NOENT).map(|()| None),
        Ok(file_type) => {
            (ctx.before_open)(&ctx.root.join(&level.rel).join(name));
            ensure(!name.as_bytes().starts_with(RESERVED_PREFIX.as_bytes()), ScanError::NameClash)?;
            act(ctx, level, open, state, name, file_type)
        }
    }
}


fn visit(ctx: &Ctx, stack: &[Level], state: &mut CopySummary, entry: rustix::fs::DirEntry) -> Result<Option<Level>, ScanError> {
    let name = OsStr::from_bytes(entry.file_name().to_bytes());
    let dots = name == OsStr::new(".") || name == OsStr::new("..");
    let opened = stack
        .last()
        .filter(|_| !dots)
        .map(|level| visit_entry(ctx, level, stack.len(), state, name, entry.file_type()))
        .transpose()?;
    Ok(opened.flatten())
}


/// Reads the next entry of the innermost directory; an empty stack ends the walk.
pub fn step(ctx: &Ctx, stack: &mut Vec<Level>, state: &mut CopySummary) -> Result<ControlFlow<()>, ScanError> {
    let next = stack.last_mut().map(|level| level.dir.next().transpose().map_err(io_error)).transpose()?;
    match next {
        None => Ok(ControlFlow::Break(())),
        Some(None) => {
            stack.pop();
            Ok(ControlFlow::Continue(()))
        }
        Some(Some(entry)) => {
            let opened = visit(ctx, stack, state, entry)?;
            stack.extend(opened);
            Ok(ControlFlow::Continue(()))
        }
    }
}


/// Creates `name` below `dir` holding `contents`, through the directory handle, never overwriting.
pub fn write_file(dir: &OwnedFd, name: &str, contents: &[u8]) -> Result<(), ScanError> {
    let created = openat(dir, name, CREATE_FLAGS, PRIVATE_FILE_MODE).map_err(io_error)?;
    File::from(created).write_all(contents)?;
    Ok(())
}


/// Copies `root` into `<private>/data/tree`; the `config` of each `.git` directory becomes `STAGED_NAME` beside it.
pub fn copy_tree(
    root: &Path,
    private: &PrivateDir,
    limits: &CopyLimits,
    before_open: fn(&Path),
    expired: &dyn Fn() -> bool,
) -> Result<CopySummary, ScanError> {
    let source = open_root(root)?;
    let source_stat = fstat(&source).map_err(io_error)?;
    let data = openat(&private.root, DATA_DIR, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    let tree = make_dir(&data, OsStr::new(TREE_DIR))?;
    let ctx = Ctx {
        root,
        root_dev: source_stat.st_dev,
        limits,
        before_open,
        open_file,
        expired,
    };
    let mut summary = CopySummary::default();
    let mut stack = vec![level_of(source, tree, PathBuf::new())?];
    let steps = limits.max_entries.saturating_mul(WALK_STEPS_PER_ENTRY).saturating_add(WALK_STEPS_SLACK);
    let finished = (0..steps).find_map(|_| match step(&ctx, &mut stack, &mut summary) {
        Ok(ControlFlow::Continue(())) => None,
        Ok(ControlFlow::Break(())) => Some(Ok(())),
        Err(error) => Some(Err(error)),
    });
    finished.unwrap_or(Err(ScanError::CopyLimit("steps")))?;
    Ok(summary)
}


/// The counts of a copy as reported to the caller.
pub fn counts_of(summary: &CopySummary) -> CopyCounts {
    CopyCounts {
        entries: summary.entries,
        bytes: summary.bytes,
        truncated_files: summary.truncated_files,
        skipped_special: summary.skipped_special,
        skipped_swapped: summary.skipped_swapped,
        skipped_vanished: summary.skipped_vanished,
        config_files: summary.config_files,
        foreign_owner_files: summary.foreign_owner_files,
        other_device: summary.other_device,
        denied_entries: summary.denied_entries,
        leased_files: summary.leased_files,
        renamed_names: summary.renamed.len(),
    }
}


/// A path with every byte that is not UTF-8 written `\x{ff}` and every backslash doubled, so the text maps back to the bytes.
pub fn display_path(path: &Path) -> String {
    path.as_os_str()
        .as_bytes()
        .utf8_chunks()
        .map(|chunk| {
            let escaped: String = chunk.invalid().iter().map(|byte| format!("\\x{{{byte:02x}}}")).collect();
            format!("{}{escaped}", chunk.valid().replace('\\', "\\\\"))
        })
        .collect()
}


fn restored_part(built: PathBuf, name: &OsStr, renamed: &[OsString]) -> Option<PathBuf> {
    match name.as_bytes().strip_prefix(RENAMED_PREFIX.as_bytes()) {
        Some(rest) => {
            let digit_count = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let digits = rest.get(..digit_count)?;
            let index = std::str::from_utf8(digits).ok()?.parse::<usize>().ok()?;
            Some(built.join(renamed.get(index)?))
        }
        None if name == STAGED_NAME => Some(built.join(GIT_DIR_NAME).join(GIT_CONFIG_NAME)),
        None => Some(built.join(name)),
    }
}


/// Maps a path gitleaks reported below `root` (the copy is mounted at the original path) back to the original bytes, shown with `display_path`; any other path is returned unchanged.
pub fn original_path(file: &str, root: &Path, renamed: &[OsString]) -> String {
    Path::new(file)
        .strip_prefix(root)
        .ok()
        .and_then(|inner| {
            inner
                .components()
                .try_fold(root.to_path_buf(), |built, part| restored_part(built, part.as_os_str(), renamed))
        })
        .map_or_else(|| file.to_string(), |original| display_path(&original))
}


/// One open directory of the removal walk; an empty `name` marks the private directory itself.
pub struct Doomed {
    pub handle: OwnedFd,
    pub dir: Dir,
    pub name: OsString,
}


/// Wraps an open directory handle for the removal walk.
pub fn doomed_of(handle: OwnedFd, name: OsString) -> Result<Doomed, Errno> {
    Dir::read_from(&handle).map(|dir| Doomed { handle, dir, name })
}


/// Unlinks a non-directory entry through its parent handle, or opens a directory entry for descent.
pub fn doom_entry(top: &Doomed, name: &OsStr, reported: FileType) -> Result<Option<Doomed>, Errno> {
    match resolve_type(&top.handle, name, reported)? {
        FileType::Directory => openat(&top.handle, name, DIRECTORY_FLAGS, Mode::empty())
            .and_then(|handle| doomed_of(handle, name.to_os_string()))
            .map(Some),
        _ => unlinkat(&top.handle, name, AtFlags::empty()).map(|()| None),
    }
}


/// One step of the removal walk; `doom` handles one listed entry.
pub fn remove_step(stack: &mut Vec<Doomed>, doom: fn(&Doomed, &OsStr, FileType) -> Result<Option<Doomed>, Errno>) -> Result<ControlFlow<()>, Errno> {
    let next = stack.last_mut().map(|top| top.dir.next().transpose()).transpose()?;
    match next {
        None => Ok(ControlFlow::Break(())),
        Some(None) => {
            let finished = stack.pop();
            let parent = stack.last();
            finished
                .zip(parent)
                .map_or(Ok(()), |(done, above)| unlinkat(&above.handle, &done.name, AtFlags::REMOVEDIR))
                .map(|()| ControlFlow::Continue(()))
        }
        Some(Some(entry)) => {
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            let dots = name == OsStr::new(".") || name == OsStr::new("..");
            let opened = stack.last().filter(|_| !dots).map(|top| doom(top, name, entry.file_type())).transpose()?;
            stack.extend(opened.flatten());
            Ok(ControlFlow::Continue(()))
        }
    }
}


/// Removes everything below the private directory and the directory itself, each entry through the handle of its parent, never by path.
pub fn remove_private(private: &PrivateDir) -> Result<(), ScanError> {
    let top = openat(&private.root, ".", DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    remove_tree(&private.work, &private.name, top)
}


/// Empties the directory held by `top` and removes it, named `name` below `work`, through handles only.
pub fn remove_tree(work: &OwnedFd, name: &OsStr, top: OwnedFd) -> Result<(), ScanError> {
    let mut stack = vec![doomed_of(top, OsString::new()).map_err(io_error)?];
    let steps = CEILING_ENTRIES.saturating_mul(REMOVE_STEPS_PER_ENTRY).saturating_add(REMOVE_STEPS_SLACK);
    (0..steps)
        .map(|_| remove_step(&mut stack, doom_entry))
        .take_while(|flow| !matches!(flow, Ok(ControlFlow::Break(()))))
        .try_for_each(|flow| flow.map(drop))
        .map_err(io_error)?;
    unlinkat(work, name, AtFlags::REMOVEDIR).map_err(io_error)
}


fn is_stale(work: &OwnedFd, name: &OsStr, caller_uid: u32, older_than: Duration) -> Result<bool, ScanError> {
    let stat = statat(work, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
    let age = now.as_secs().saturating_sub(stat.st_mtime.max(0).unsigned_abs());
    Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Directory && stat.st_uid == caller_uid && age >= older_than.as_secs())
}


fn sweep_one(work: &OwnedFd, name: &OsStr) -> Result<(), ScanError> {
    let top = openat(work, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    remove_tree(work, name, top)
}


/// Removes the `secret-scan-*` directories of the work directory that belong to the caller and are older than `older_than`, through the work root handle.
pub fn sweep_stale(work_dir: &Path, caller_uid: u32, older_than: Duration) -> Result<usize, ScanError> {
    let work = open_work_root(work_dir, caller_uid)?;
    let listing = Dir::read_from(&work).map_err(io_error)?;
    listing.take(SWEEP_MAX_ENTRIES).try_fold(0, |removed: usize, listed| {
        let entry = listed.map_err(io_error)?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        let candidate = name.as_bytes().starts_with(DIR_PREFIX.as_bytes());
        let doomed = candidate && is_stale(&work, name, caller_uid, older_than)?;
        if doomed {
            sweep_one(&work, name)?;
        }
        Ok(removed + usize::from(doomed))
    })
}
