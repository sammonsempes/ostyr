//! Copies a directory tree into a private root-owned directory through held directory handles (Unix only).

use crate::scan::{ensure, ScanError};
use rustix::fs::{fstat, mkdirat, openat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Permissions};
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tracing::warn;


pub const DEFAULT_MAX_FILE_BYTES: u64 = 1 << 20;


pub const DEFAULT_MAX_ENTRIES: usize = 200_000;


pub const DEFAULT_MAX_BYTES: u64 = 1 << 30;


pub const DEFAULT_MAX_DEPTH: usize = 64;


pub const DEFAULT_MAX_OPEN_DIRS: usize = DEFAULT_MAX_DEPTH + 2;


pub const CEILING_ENTRIES: usize = 5_000_000;


pub const CEILING_BYTES: u64 = 16 << 30;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const PRIVATE_DIR_MODE: u32 = 0o700;


pub const REMOVE_STEPS_PER_ENTRY: usize = 8;


pub const REMOVE_STEPS_SLACK: usize = 16;


pub const WALK_STEPS_PER_ENTRY: usize = 4;


pub const WALK_STEPS_SLACK: usize = 4;


pub const TREE_DIR: &str = "tree";


pub const GIT_ROOT_DIR: &str = "git";


pub const DATA_DIR: &str = "data";


pub const RUN_DIR: &str = "run";


pub const GIT_DIR_NAME: &str = ".git";


pub const GIT_CONFIG_NAME: &str = "config";


pub const STAGED_NAME: &str = "git-config";


pub const IGNORE_FILE_NAME: &str = ".gitleaksignore";


pub const TOML_FILE_NAME: &str = ".gitleaks.toml";


pub const DIR_PREFIX: &str = "secret-scan-";


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


/// What one copy did: counts of what was copied, skipped or counted, and the original path of each `.git/config` directory copied.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CopySummary {
    pub entries: usize,
    pub bytes: u64,
    pub truncated_files: usize,
    pub skipped_special: usize,
    pub skipped_swapped: usize,
    pub skipped_vanished: usize,
    pub skipped_names: usize,
    pub config_files: usize,
    pub git_originals: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tree,
    Git,
}


/// One open directory of the walk: the source handle, the copy's handle and the reader of the source.
pub struct Level {
    pub src: OwnedFd,
    pub dst: OwnedFd,
    pub dir: Dir,
    pub rel: PathBuf,
    pub kind: Kind,
}


/// Fixed inputs of one copy.
pub struct Ctx<'a> {
    pub root: &'a Path,
    pub git_root: OwnedFd,
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


/// Opens a source file below its parent handle without following a link and without blocking.
pub fn open_file(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, Errno> {
    openat(parent, name, FILE_FLAGS, Mode::empty())
}


fn make_dir(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, ScanError> {
    mkdirat(parent, name, Mode::RWXU).map_err(io_error)?;
    openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)
}


/// Creates the private directory under the work root, which is opened without following a link, owned by `expected_uid` and not group or other writable.
pub fn create_private(work_dir: &Path, expected_uid: u32) -> Result<PrivateDir, ScanError> {
    let work = openat(rustix::fs::CWD, work_dir, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    let stat = fstat(&work).map_err(io_error)?;
    ensure(
        stat.st_uid == expected_uid,
        ScanError::BadSettings("work directory is not owned by the caller"),
    )?;
    ensure(
        stat.st_mode & GROUP_OTHER_WRITE == 0,
        ScanError::BadSettings("work directory is writable by group or others"),
    )?;
    let path = tempfile::Builder::new()
        .prefix(DIR_PREFIX)
        .permissions(Permissions::from_mode(PRIVATE_DIR_MODE))
        .tempdir_in(work_dir)?
        .keep();
    let name = path.file_name().map_or_else(OsString::new, OsStr::to_os_string);
    let root = openat(&work, &name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    let private = PrivateDir { work, name, root, path };
    make_dir(&private.root, OsStr::new(DATA_DIR))?;
    make_dir(&private.root, OsStr::new(RUN_DIR))?;
    Ok(private)
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
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .try_fold(start, |parent, name| match openat(&parent, name, DIRECTORY_FLAGS, Mode::empty()) {
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


fn level_of(src: OwnedFd, dst: OwnedFd, rel: PathBuf, kind: Kind) -> Result<Level, ScanError> {
    let dir = Dir::read_from(&src).map_err(io_error)?;
    Ok(Level { src, dst, dir, rel, kind })
}


fn check_room(ctx: &Ctx, level: &Level, open: usize) -> Result<(), ScanError> {
    ensure(level.rel.components().count() < ctx.limits.max_depth, ScanError::CopyLimit("depth"))?;
    ensure(open < ctx.limits.max_open_dirs, ScanError::CopyLimit("open directories"))
}


fn open_tree_dir(ctx: &Ctx, level: &Level, open: usize, state: &mut CopySummary, name: &OsStr) -> Result<Option<Level>, ScanError> {
    check_room(ctx, level, open)?;
    match openat(&level.src, name, DIRECTORY_FLAGS, Mode::empty()) {
        Err(errno) => tolerate(errno, &mut state.skipped_swapped, is_swap(errno)).map(|()| None),
        Ok(src) => {
            let dst = make_dir(&level.dst, name)?;
            level_of(src, dst, level.rel.join(name), Kind::Tree).map(Some)
        }
    }
}


fn open_git_dir(ctx: &Ctx, level: &Level, open: usize, state: &mut CopySummary) -> Result<Option<Level>, ScanError> {
    check_room(ctx, level, open)?;
    let original = ctx
        .root
        .join(&level.rel)
        .join(GIT_DIR_NAME)
        .join(GIT_CONFIG_NAME)
        .to_str()
        .map(str::to_string);
    match (original, openat(&level.src, GIT_DIR_NAME, DIRECTORY_FLAGS, Mode::empty())) {
        (None, _) => {
            state.skipped_names += 1;
            Ok(None)
        }
        (Some(_), Err(errno)) => tolerate(errno, &mut state.skipped_swapped, is_swap(errno)).map(|()| None),
        (Some(text), Ok(src)) => {
            let index = state.git_originals.len();
            state.git_originals.push(text);
            let dst = make_dir(&ctx.git_root, OsStr::new(&index.to_string()))?;
            level_of(src, dst, level.rel.join(GIT_DIR_NAME), Kind::Git).map(Some)
        }
    }
}


fn copy_handle(ctx: &Ctx, level: &Level, file: File, destination: &OsStr, state: &mut CopySummary) -> Result<(), ScanError> {
    let metadata = file.metadata()?;
    if metadata.is_file() {
        let created = openat(&level.dst, destination, CREATE_FLAGS, PRIVATE_FILE_MODE).map_err(io_error)?;
        let mut output = File::from(created);
        let copied = io::copy(&mut file.take(ctx.limits.max_file_bytes), &mut output)?;
        state.bytes = state.bytes.saturating_add(copied);
        state.truncated_files += usize::from(metadata.len() > ctx.limits.max_file_bytes);
        ensure(state.bytes <= ctx.limits.max_bytes, ScanError::CopyLimit("bytes"))
    } else {
        state.skipped_special += 1;
        Ok(())
    }
}


/// Opens `name` below the source handle once without following a link, judges that handle, and copies at most `max_file_bytes` of it to `destination`.
pub fn copy_regular(ctx: &Ctx, level: &Level, name: &OsStr, destination: &OsStr, state: &mut CopySummary) -> Result<(), ScanError> {
    match (ctx.open_file)(&level.src, name) {
        Ok(handle) => copy_handle(ctx, level, File::from(handle), destination, state),
        Err(errno) => {
            let missing = errno == Errno::NOENT;
            let counter = if missing {
                &mut state.skipped_vanished
            } else {
                &mut state.skipped_special
            };
            tolerate(errno, counter, missing || matches!(errno, Errno::LOOP | Errno::NXIO))
        }
    }
}


fn act(ctx: &Ctx, level: &Level, open: usize, state: &mut CopySummary, name: &OsStr, file_type: FileType) -> Result<Option<Level>, ScanError> {
    match (level.kind, file_type) {
        (Kind::Tree, _) if name == IGNORE_FILE_NAME => Err(ScanError::IgnoreFileInTree),
        (Kind::Tree, _) if name == TOML_FILE_NAME => {
            state.config_files += 1;
            Ok(None)
        }
        (Kind::Tree, FileType::Directory) if name == GIT_DIR_NAME => open_git_dir(ctx, level, open, state),
        (Kind::Tree, FileType::Directory) => open_tree_dir(ctx, level, open, state, name),
        (Kind::Tree, FileType::RegularFile) => copy_regular(ctx, level, name, name, state).map(|()| None),
        (Kind::Git, FileType::RegularFile) if name == GIT_CONFIG_NAME => {
            copy_regular(ctx, level, name, OsStr::new(STAGED_NAME), state).map(|()| None)
        }
        (Kind::Git, _) => Ok(None),
        (Kind::Tree, _) => {
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
        Err(errno) => tolerate(errno, &mut state.skipped_vanished, errno == Errno::NOENT).map(|()| None),
        Ok(file_type) => {
            (ctx.before_open)(&ctx.root.join(&level.rel).join(name));
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


/// Copies `root` into `<private>/data/tree` and the `config` of each `.git` directory into `<private>/data/git/<n>/git-config`.
pub fn copy_tree(
    root: &Path,
    private: &PrivateDir,
    limits: &CopyLimits,
    before_open: fn(&Path),
    expired: &dyn Fn() -> bool,
) -> Result<CopySummary, ScanError> {
    let source = open_root(root)?;
    let data = openat(&private.root, DATA_DIR, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?;
    let tree = make_dir(&data, OsStr::new(TREE_DIR))?;
    let git_root = make_dir(&data, OsStr::new(GIT_ROOT_DIR))?;
    let ctx = Ctx {
        root,
        git_root,
        limits,
        before_open,
        open_file,
        expired,
    };
    let mut stack = vec![level_of(source, tree, PathBuf::new(), Kind::Tree)?];
    let mut summary = CopySummary::default();
    let steps = limits.max_entries.saturating_mul(WALK_STEPS_PER_ENTRY).saturating_add(WALK_STEPS_SLACK);
    let finished = (0..steps).find_map(|_| match step(&ctx, &mut stack, &mut summary) {
        Ok(ControlFlow::Continue(())) => None,
        Ok(ControlFlow::Break(())) => Some(Ok(())),
        Err(error) => Some(Err(error)),
    });
    finished.unwrap_or(Err(ScanError::CopyLimit("steps")))?;
    Ok(summary)
}


/// Maps a path gitleaks reported inside `data` back to the original path; any other path is returned unchanged.
pub fn original_path(file: &str, data: &Path, root: &Path, originals: &[String]) -> String {
    Path::new(file)
        .strip_prefix(data)
        .ok()
        .and_then(|rest| mapped(rest, root, originals))
        .unwrap_or_else(|| file.to_string())
}


fn mapped(rest: &Path, root: &Path, originals: &[String]) -> Option<String> {
    let mut parts = rest.components();
    let top = parts.next()?.as_os_str();
    if top == TREE_DIR {
        root.join(parts.as_path()).to_str().map(str::to_string)
    } else if top == GIT_ROOT_DIR {
        let index = parts.next()?.as_os_str().to_str()?.parse::<usize>().ok()?;
        originals.get(index).cloned()
    } else {
        None
    }
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
    let mut stack = vec![doomed_of(top, OsString::new()).map_err(io_error)?];
    let steps = CEILING_ENTRIES.saturating_mul(REMOVE_STEPS_PER_ENTRY).saturating_add(REMOVE_STEPS_SLACK);
    (0..steps)
        .map(|_| remove_step(&mut stack, doom_entry))
        .take_while(|flow| !matches!(flow, Ok(ControlFlow::Break(()))))
        .try_for_each(|flow| flow.map(drop))
        .map_err(io_error)?;
    unlinkat(&private.work, &private.name, AtFlags::REMOVEDIR).map_err(io_error)
}
