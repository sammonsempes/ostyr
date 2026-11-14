#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use rustix::fs::{openat, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use secret_scan::copy::{
    check_limits, copy_regular, copy_tree, create_private, data_path, doomed_of, is_swap, no_hook, open_file, open_root, original_path,
    remove_private, remove_step, resolve_type, run_path, tolerate, visit_entry, CopyLimits, CopySummary, Ctx, Doomed, Kind, Level, PrivateDir,
    CEILING_BYTES, CEILING_ENTRIES, DATA_DIR,
};
use secret_scan::scan::ScanError;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use types::TestResult;


const SECRET: &str = "TOPSECRET";


const FOUR_BYTES: &[u8] = b"abcd";


const EIGHT_BYTES: u64 = 8;


const SEVEN_BYTES: u64 = 7;


const TWENTY_BYTES: usize = 20;


const SIXTEEN_BYTES: u64 = 16;


const THREE: usize = 3;


const TWO: usize = 2;


const FOUR: usize = 4;


const FIVE: usize = 5;


const PRIVATE_FILE_MODE: u32 = 0o600;


const PRIVATE_DIR_MODE: u32 = 0o700;


const MODE_MASK: u32 = 0o777;


const GROUP_WRITABLE: u32 = 0o775;


const NON_UTF8_BYTE: u8 = 0xff;


struct Env {
    root: TempDir,
    work: PathBuf,
    tree: PathBuf,
}


fn setup() -> Result<Env, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let work = root.path().join("work");
    let tree = root.path().join("tree");
    fs::create_dir(&work)?;
    fs::create_dir(&tree)?;
    fs::create_dir(root.path().join("secret"))?;
    fs::write(root.path().join("secret/key.txt"), SECRET)?;
    Ok(Env { root, work, tree })
}


fn owner() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn never() -> bool {
    false
}


fn always() -> bool {
    true
}


fn limits_with(change: fn(&mut CopyLimits)) -> CopyLimits {
    let mut limits = CopyLimits::default();
    change(&mut limits);
    limits
}


fn run_copy(env: &Env, limits: &CopyLimits, hook: fn(&Path)) -> Result<(PrivateDir, CopySummary), ScanError> {
    let private = create_private(&env.work, owner())?;
    let summary = copy_tree(&env.tree, &private, limits, hook, &never)?;
    Ok((private, summary))
}


fn work_is_empty(env: &Env) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(fs::read_dir(&env.work)?.next().is_none())
}


fn in_copy(private: &PrivateDir, relative: &str) -> PathBuf {
    data_path(private).join("tree").join(relative)
}


fn leaked(private: &PrivateDir) -> Result<bool, Box<dyn std::error::Error>> {
    let found = Command::new("grep").arg("-rl").arg(SECRET).arg(&private.path).output()?;
    Ok(!found.stdout.is_empty())
}


fn swap_victim(path: &Path) {
    if path.file_name() == Some(OsStr::new("victim")) {
        let secret = path.parent().and_then(Path::parent).map(|up| up.join("secret"));
        let outcome = fs::rename(path, path.with_file_name("victim.moved")).and_then(|()| secret.map_or(Ok(()), |target| symlink(target, path)));
        assert!(outcome.is_ok());
    }
}


fn swap_leak(path: &Path) {
    if path.file_name() == Some(OsStr::new("leak.txt")) {
        let secret = path.parent().and_then(Path::parent).map(|up| up.join("secret/key.txt"));
        let outcome = fs::remove_file(path).and_then(|()| secret.map_or(Ok(()), |target| symlink(target, path)));
        assert!(outcome.is_ok());
    }
}


fn remove_victim(path: &Path) {
    if path.file_name() == Some(OsStr::new("victim")) {
        assert!(fs::remove_dir_all(path).is_ok());
    }
}


fn remove_dot_git(path: &Path) {
    if path.file_name() == Some(OsStr::new(".git")) {
        assert!(fs::remove_dir_all(path).is_ok());
    }
}


fn remove_leak(path: &Path) {
    if path.file_name() == Some(OsStr::new("leak.txt")) {
        assert!(fs::remove_file(path).is_ok());
    }
}


#[test]
fn files_are_copied_with_private_modes() -> TestResult {
    let env = setup()?;
    fs::create_dir(env.tree.join("sub"))?;
    fs::write(env.tree.join("a.txt"), FOUR_BYTES)?;
    fs::write(env.tree.join("sub/b.txt"), FOUR_BYTES)?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(fs::read(in_copy(&private, "a.txt"))?, FOUR_BYTES);
    assert_eq!(fs::read(in_copy(&private, "sub/b.txt"))?, FOUR_BYTES);
    assert_eq!(
        fs::metadata(in_copy(&private, "a.txt"))?.permissions().mode() & MODE_MASK,
        PRIVATE_FILE_MODE
    );
    assert_eq!(fs::metadata(in_copy(&private, "sub"))?.permissions().mode() & MODE_MASK, PRIVATE_DIR_MODE);
    assert_eq!(fs::metadata(&private.path)?.permissions().mode() & MODE_MASK, PRIVATE_DIR_MODE);
    assert_eq!(summary.entries, THREE);
    assert!(run_path(&private).is_dir());
    Ok(())
}


#[test]
fn a_directory_swapped_for_a_symlink_copies_nothing_from_outside() -> TestResult {
    let env = setup()?;
    fs::create_dir(env.tree.join("victim"))?;
    fs::write(env.tree.join("victim/inner.txt"), b"own bytes")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), swap_victim)?;
    assert_eq!(summary.skipped_swapped, 1);
    assert!(!in_copy(&private, "victim").exists());
    assert!(!leaked(&private)?);
    Ok(())
}


#[test]
fn a_file_swapped_for_a_symlink_copies_nothing_from_outside() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("leak.txt"), b"own bytes")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), swap_leak)?;
    assert_eq!(summary.skipped_special, 1);
    assert!(!in_copy(&private, "leak.txt").exists());
    assert!(!leaked(&private)?);
    Ok(())
}


#[test]
fn a_directory_that_disappears_is_an_io_error_and_a_file_is_counted() -> TestResult {
    let env = setup()?;
    fs::create_dir(env.tree.join("victim"))?;
    assert!(matches!(run_copy(&env, &CopyLimits::default(), remove_victim), Err(ScanError::Io(_))));
    assert!(work_is_empty(&env)?);
    fs::create_dir_all(env.tree.join("sub/.git"))?;
    assert!(matches!(run_copy(&env, &CopyLimits::default(), remove_dot_git), Err(ScanError::Io(_))));
    fs::remove_dir_all(env.tree.join("sub"))?;
    fs::write(env.tree.join("leak.txt"), b"x")?;
    let (_private, summary) = run_copy(&env, &CopyLimits::default(), remove_leak)?;
    assert_eq!(summary.skipped_vanished, 1);
    Ok(())
}


#[test]
fn a_symlink_in_the_scan_path_is_refused() -> TestResult {
    let env = setup()?;
    let via = env.root.path().join("via");
    symlink(env.root.path().join("secret"), &via)?;
    fs::create_dir(env.tree.join("sub"))?;
    let linked_tree = env.root.path().join("linked");
    symlink(&env.tree, &linked_tree)?;
    let private = create_private(&env.work, owner())?;
    let refused = [via, linked_tree.join("sub"), linked_tree, env.root.path().join("secret/key.txt")];
    refused
        .iter()
        .try_for_each(|path| match copy_tree(path, &private, &CopyLimits::default(), no_hook, &never) {
            Err(ScanError::BadPath("symlink in path")) => Ok(()),
            other => Err(format!("not refused: {path:?}: {other:?}")),
        })?;
    assert!(matches!(open_root(&env.root.path().join("missing")), Err(ScanError::Io(_))));
    assert!(open_root(&env.tree).is_ok());
    Ok(())
}


#[test]
fn every_bound_refuses_at_its_limit_plus_one() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.tree.join("a/b/c"))?;
    fs::write(env.tree.join("one"), FOUR_BYTES)?;
    fs::write(env.tree.join("a/two"), FOUR_BYTES)?;
    let big = || CopyLimits::default();
    let entries = |max: usize| CopyLimits { max_entries: max, ..big() };
    let bytes = |max: u64| CopyLimits { max_bytes: max, ..big() };
    let depth = |max: usize| CopyLimits { max_depth: max, ..big() };
    let open = |max: usize| CopyLimits { max_open_dirs: max, ..big() };
    let (_all, summary) = run_copy(&env, &big(), no_hook)?;
    assert_eq!(summary.entries, FIVE);
    assert!(run_copy(&env, &entries(summary.entries), no_hook).is_ok());
    assert!(matches!(
        run_copy(&env, &entries(summary.entries - 1), no_hook),
        Err(ScanError::CopyLimit("entries"))
    ));
    assert!(run_copy(&env, &bytes(EIGHT_BYTES), no_hook).is_ok());
    assert!(matches!(run_copy(&env, &bytes(SEVEN_BYTES), no_hook), Err(ScanError::CopyLimit("bytes"))));
    assert!(run_copy(&env, &depth(THREE), no_hook).is_ok());
    assert!(matches!(run_copy(&env, &depth(TWO), no_hook), Err(ScanError::CopyLimit("depth"))));
    assert!(run_copy(&env, &open(FOUR), no_hook).is_ok());
    assert!(matches!(
        run_copy(&env, &open(THREE), no_hook),
        Err(ScanError::CopyLimit("open directories"))
    ));
    assert_eq!(fs::read_dir(&env.work)?.count(), 1);
    Ok(())
}


#[test]
fn limits_above_their_ceilings_are_refused() -> TestResult {
    assert!(check_limits(&CopyLimits::default()).is_ok());
    let entries = CopyLimits {
        max_entries: CEILING_ENTRIES + 1,
        ..CopyLimits::default()
    };
    let bytes = CopyLimits {
        max_bytes: CEILING_BYTES + 1,
        ..CopyLimits::default()
    };
    assert!(matches!(check_limits(&entries), Err(ScanError::BadSettings(_))));
    assert!(matches!(check_limits(&bytes), Err(ScanError::BadSettings(_))));
    Ok(())
}


#[test]
fn a_large_file_has_its_first_bytes_copied_and_is_counted() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("big"), vec![b'a'; TWENTY_BYTES])?;
    let limits = limits_with(|limits| limits.max_file_bytes = SIXTEEN_BYTES);
    let (private, summary) = run_copy(&env, &limits, no_hook)?;
    assert_eq!(fs::metadata(in_copy(&private, "big"))?.len(), SIXTEEN_BYTES);
    assert_eq!(summary.truncated_files, 1);
    assert_eq!(summary.bytes, SIXTEEN_BYTES);
    Ok(())
}


#[test]
fn fifos_sockets_and_devices_are_skipped_without_blocking() -> TestResult {
    let env = setup()?;
    assert!(Command::new("mkfifo").arg(env.tree.join("fifo")).status()?.success());
    let tree_handle = fs::File::open(&env.tree)?;
    let _listener = UnixListener::bind(format!("/proc/self/fd/{}/socket", tree_handle.as_raw_fd()))?;
    symlink("/etc/passwd", env.tree.join("link"))?;
    let device = Command::new("mknod")
        .arg(env.tree.join("device"))
        .arg("c")
        .arg("1")
        .arg("3")
        .status()?
        .success();
    fs::write(env.tree.join("plain"), b"x")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.skipped_special, THREE + usize::from(device));
    assert!(in_copy(&private, "plain").is_file());
    ["fifo", "socket", "link", "device"]
        .iter()
        .for_each(|name| assert!(!in_copy(&private, name).exists()));
    Ok(())
}


#[test]
fn only_the_config_of_a_dot_git_directory_is_copied_and_mapped() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.tree.join(".git/objects"))?;
    fs::create_dir_all(env.tree.join("deep/.git"))?;
    fs::create_dir_all(env.tree.join("linked/.git"))?;
    fs::write(env.tree.join(".git/config"), "root-marker")?;
    fs::write(env.tree.join(".git/HEAD"), "ref")?;
    fs::write(env.tree.join(".git/objects/config"), "not a config")?;
    fs::write(env.tree.join("deep/.git/config"), "deep-marker")?;
    symlink("/etc/passwd", env.tree.join("linked/.git/config"))?;
    fs::create_dir(env.tree.join("file-git"))?;
    fs::write(env.tree.join("file-git/.git"), "gitdir: elsewhere")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.git_originals.len(), THREE);
    let copies = summary
        .git_originals
        .iter()
        .enumerate()
        .try_fold(Vec::new(), |mut found, (index, original)| {
            let copy = data_path(&private).join(format!("git/{index}/git-config"));
            found.push((original.clone(), fs::read_to_string(copy).ok()));
            Ok::<_, std::io::Error>(found)
        })?;
    let root_config = format!("{}/.git/config", env.tree.display());
    let deep_config = format!("{}/deep/.git/config", env.tree.display());
    assert!(copies.contains(&(root_config, Some("root-marker".to_string()))));
    assert!(copies.contains(&(deep_config, Some("deep-marker".to_string()))));
    assert!(!in_copy(&private, ".git").exists());
    assert!(!in_copy(&private, "deep/.git").exists());
    assert_eq!(fs::read_to_string(in_copy(&private, "file-git/.git"))?, "gitdir: elsewhere");
    assert!(!data_path(&private).join("git/0/HEAD").exists());
    Ok(())
}


#[test]
fn an_ignore_file_is_refused_at_any_depth_and_a_toml_is_not_copied() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.tree.join("a/b"))?;
    fs::write(env.tree.join(".gitleaks.toml"), "useDefault = false")?;
    fs::write(env.tree.join("a/.gitleaks.toml"), "useDefault = false")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.config_files, TWO);
    assert!(!in_copy(&private, ".gitleaks.toml").exists());
    assert!(!in_copy(&private, "a/.gitleaks.toml").exists());
    drop(private);
    fs::write(env.tree.join("a/b/.gitleaksignore"), "x:y:1")?;
    assert!(matches!(
        run_copy(&env, &CopyLimits::default(), no_hook),
        Err(ScanError::IgnoreFileInTree)
    ));
    fs::remove_file(env.tree.join("a/b/.gitleaksignore"))?;
    symlink("/etc/passwd", env.tree.join(".gitleaksignore"))?;
    assert!(matches!(
        run_copy(&env, &CopyLimits::default(), no_hook),
        Err(ScanError::IgnoreFileInTree)
    ));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn names_that_are_not_utf8_keep_their_bytes_and_skip_a_git_config() -> TestResult {
    let env = setup()?;
    let name = OsString::from_vec(vec![b'n', NON_UTF8_BYTE]);
    fs::create_dir_all(env.tree.join(&name).join(".git"))?;
    fs::write(env.tree.join(&name).join(".git/config"), "x")?;
    fs::write(env.tree.join(&name).join("file"), "kept")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.skipped_names, 1);
    assert!(summary.git_originals.is_empty());
    assert_eq!(fs::read_to_string(data_path(&private).join("tree").join(&name).join("file"))?, "kept");
    Ok(())
}


#[test]
fn an_expired_deadline_stops_the_copy() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("a"), "x")?;
    let private = create_private(&env.work, owner())?;
    assert!(matches!(
        copy_tree(&env.tree, &private, &CopyLimits::default(), no_hook, &always),
        Err(ScanError::TimedOut)
    ));
    Ok(())
}


#[test]
fn the_private_directory_is_removed_through_its_handle() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.tree.join("a/b/c"))?;
    fs::write(env.tree.join("a/b/c/f"), "x")?;
    let (private, _summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    symlink(env.root.path().join("secret"), run_path(&private).join("link"))?;
    fs::create_dir_all(run_path(&private).join("sub/deeper"))?;
    fs::write(run_path(&private).join("sub/deeper/report"), "r")?;
    assert!(remove_private(&private).is_ok());
    assert!(work_is_empty(&env)?);
    assert!(env.root.path().join("secret/key.txt").is_file());
    drop(private);
    Ok(())
}


#[test]
fn a_private_directory_already_gone_is_only_logged_on_drop() -> TestResult {
    let env = setup()?;
    let private = create_private(&env.work, owner())?;
    fs::remove_dir_all(&private.path)?;
    assert!(remove_private(&private).is_err());
    drop(private);
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_work_directory_is_checked_on_its_handle() -> TestResult {
    let env = setup()?;
    assert!(matches!(
        create_private(&env.work, owner() + 1),
        Err(ScanError::BadSettings("work directory is not owned by the caller"))
    ));
    fs::set_permissions(&env.work, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(
        create_private(&env.work, owner()),
        Err(ScanError::BadSettings("work directory is writable by group or others"))
    ));
    fs::set_permissions(&env.work, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    assert!(matches!(create_private(&env.root.path().join("missing"), owner()), Err(ScanError::Io(_))));
    let link = env.root.path().join("work-link");
    symlink(&env.work, &link)?;
    assert!(matches!(create_private(&link, owner()), Err(ScanError::Io(_))));
    assert!(work_is_empty(&env)?);
    Ok(())
}


fn failing_open(_parent: &OwnedFd, _name: &OsStr) -> Result<OwnedFd, Errno> {
    Err(Errno::ACCESS)
}


fn level_in(env: &Env, private: &PrivateDir) -> Result<(Level, OwnedFd), Box<dyn std::error::Error>> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let src = openat(rustix::fs::CWD, &env.tree, flags, Mode::empty())?;
    let data = openat(&private.root, DATA_DIR, flags, Mode::empty())?;
    let dst = openat(&data, ".", flags, Mode::empty())?;
    let git_root = openat(&data, ".", flags, Mode::empty())?;
    let dir = Dir::read_from(&src)?;
    Ok((
        Level {
            src,
            dst,
            dir,
            rel: PathBuf::new(),
            kind: Kind::Tree,
        },
        git_root,
    ))
}


#[test]
fn a_file_open_failure_is_io_and_an_existing_destination_is_refused() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("f"), "x")?;
    fs::create_dir(env.tree.join("d"))?;
    let private = create_private(&env.work, owner())?;
    let (level, git_root) = level_in(&env, &private)?;
    let limits = CopyLimits::default();
    let ctx = Ctx {
        root: &env.tree,
        git_root,
        limits: &limits,
        before_open: no_hook,
        open_file: failing_open,
        expired: &never,
    };
    let mut summary = CopySummary::default();
    assert!(matches!(
        copy_regular(&ctx, &level, OsStr::new("f"), OsStr::new("f"), &mut summary),
        Err(ScanError::Io(_))
    ));
    let real = Ctx { open_file, ..ctx };
    copy_regular(&real, &level, OsStr::new("f"), OsStr::new("f"), &mut summary)?;
    assert!(matches!(
        copy_regular(&real, &level, OsStr::new("f"), OsStr::new("f"), &mut summary),
        Err(ScanError::Io(_))
    ));
    copy_regular(&real, &level, OsStr::new("d"), OsStr::new("d"), &mut summary)?;
    assert_eq!(summary.skipped_special, 1);
    copy_regular(&real, &level, OsStr::new("absent"), OsStr::new("absent"), &mut summary)?;
    assert_eq!(summary.skipped_vanished, 1);
    assert!(visit_entry(&real, &level, 1, &mut summary, OsStr::new("absent"), FileType::Unknown)?.is_none());
    assert_eq!(summary.skipped_vanished, TWO);
    Ok(())
}


#[test]
fn small_helpers_classify_errors_and_types() -> TestResult {
    let env = setup()?;
    assert!(is_swap(Errno::LOOP));
    assert!(is_swap(Errno::NOTDIR));
    assert!(!is_swap(Errno::NOENT));
    let mut counter = 0;
    assert!(tolerate(Errno::NOENT, &mut counter, true).is_ok());
    assert!(tolerate(Errno::NOENT, &mut counter, false).is_err());
    assert_eq!(counter, 1);
    fs::create_dir(env.tree.join("d"))?;
    fs::write(env.tree.join("f"), "x")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY;
    let parent = openat(rustix::fs::CWD, &env.tree, flags, Mode::empty())?;
    assert_eq!(resolve_type(&parent, OsStr::new("d"), FileType::Unknown)?, FileType::Directory);
    assert_eq!(resolve_type(&parent, OsStr::new("f"), FileType::Unknown)?, FileType::RegularFile);
    assert_eq!(resolve_type(&parent, OsStr::new("anything"), FileType::Symlink)?, FileType::Symlink);
    assert_eq!(resolve_type(&parent, OsStr::new("missing"), FileType::Unknown), Err(Errno::NOENT));
    Ok(())
}


#[test]
fn reported_paths_map_back_to_the_original_tree() -> TestResult {
    let data = Path::new("/w/secret-scan-x/data");
    let root = Path::new("/srv/tree");
    let originals = ["/srv/tree/.git/config".to_string(), "/srv/tree/deep/.git/config".to_string()];
    let map = |file: &str| original_path(file, data, root, &originals);
    assert_eq!(map("/w/secret-scan-x/data/tree/a/b.txt"), "/srv/tree/a/b.txt");
    assert_eq!(map("/w/secret-scan-x/data/git/1/git-config"), "/srv/tree/deep/.git/config");
    assert_eq!(map("/w/secret-scan-x/data/git/0/git-config"), "/srv/tree/.git/config");
    [
        "/w/secret-scan-x/data/git/2/git-config",
        "/w/secret-scan-x/data/git/x/git-config",
        "/w/secret-scan-x/data/git",
    ]
    .iter()
    .for_each(|file| assert_eq!(map(file), *file));
    ["/w/secret-scan-x/data/other/a", "/w/secret-scan-x/data", "/elsewhere/a", "relative"]
        .iter()
        .for_each(|file| assert_eq!(map(file), *file));
    Ok(())
}


fn failing_doom(_top: &Doomed, _name: &OsStr, _reported: FileType) -> Result<Option<Doomed>, Errno> {
    Err(Errno::ACCESS)
}


#[test]
fn a_removal_failure_on_one_entry_ends_the_walk_with_its_errno() -> TestResult {
    let env = setup()?;
    fs::write(env.work.join("entry"), "x")?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY;
    let handle = openat(rustix::fs::CWD, &env.work, flags, Mode::empty())?;
    let mut stack = vec![doomed_of(handle, OsString::new())?];
    let failure = (0..FIVE).map(|_| remove_step(&mut stack, failing_doom)).find_map(Result::err);
    assert_eq!(failure, Some(Errno::ACCESS));
    assert!(env.work.join("entry").exists());
    Ok(())
}


fn swap_ancestor(path: &Path) {
    let parent = path.parent();
    if path.file_name() == Some(OsStr::new("sub")) && parent.and_then(Path::file_name) == Some(OsStr::new("victim")) {
        let secret = parent.and_then(Path::parent).and_then(Path::parent).map(|up| up.join("secret"));
        let outcome = parent.map_or(Ok(()), |victim| {
            fs::rename(victim, victim.with_file_name("victim.moved")).and_then(|()| secret.map_or(Ok(()), |target| symlink(target, victim)))
        });
        assert!(outcome.is_ok());
    }
}


#[test]
fn an_ancestor_swapped_after_it_was_opened_is_still_read_through_its_handle() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.tree.join("victim/sub"))?;
    fs::write(env.tree.join("victim/sub/f.txt"), "own bytes")?;
    fs::create_dir_all(env.root.path().join("secret/sub"))?;
    fs::write(env.root.path().join("secret/sub/f.txt"), SECRET)?;
    let (private, _summary) = run_copy(&env, &CopyLimits::default(), swap_ancestor)?;
    assert_eq!(fs::read_to_string(in_copy(&private, "victim/sub/f.txt"))?, "own bytes");
    assert!(!leaked(&private)?);
    Ok(())
}
