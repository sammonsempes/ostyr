#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use rustix::fs::{openat, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;
use secret_scan::copy::{
    check_limits, check_work_dir, copy_git_config, copy_regular, copy_tree, counts_of, create_private, create_private_with, data_path, destination,
    display_path, doomed_of, is_swap, name_tail, no_hook, open_file, open_root, open_work_root, original_path, remove_private, remove_step,
    resolve_type, run_path, sweep_stale, tolerate, tolerate_entry, visit_entry, write_ignore, CopyLimits, CopySummary, Ctx, Doomed, Level,
    PrivateDir, CEILING_BYTES, CEILING_ENTRIES, DATA_DIR, RENAMED_PREFIX, STAGED_NAME,
};
use secret_scan::scan::ScanError;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{chown, symlink, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
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
fn only_the_config_of_a_dot_git_directory_is_copied_beside_it() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.tree.join(".git/objects"))?;
    fs::create_dir_all(env.tree.join("deep/.git"))?;
    fs::create_dir_all(env.tree.join("linked/.git"))?;
    fs::create_dir_all(env.tree.join("nogit/.git"))?;
    fs::write(env.tree.join(".git/config"), "root-marker")?;
    fs::write(env.tree.join(".git/HEAD"), "ref")?;
    fs::write(env.tree.join(".git/objects/config"), "not a config")?;
    fs::write(env.tree.join("deep/.git/config"), "deep-marker")?;
    symlink("/etc/passwd", env.tree.join("linked/.git/config"))?;
    fs::create_dir(env.tree.join("file-git"))?;
    fs::write(env.tree.join("file-git/.git"), "gitdir: elsewhere")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(fs::read_to_string(in_copy(&private, STAGED_NAME))?, "root-marker");
    assert_eq!(fs::read_to_string(in_copy(&private, &format!("deep/{STAGED_NAME}")))?, "deep-marker");
    assert!(!in_copy(&private, &format!("linked/{STAGED_NAME}")).exists());
    assert!(!in_copy(&private, &format!("nogit/{STAGED_NAME}")).exists());
    assert_eq!(summary.skipped_special, 1);
    assert_eq!(summary.skipped_vanished, 1);
    assert!(summary.renamed.is_empty());
    assert!(!in_copy(&private, ".git").exists());
    assert!(!in_copy(&private, "deep/.git").exists());
    assert!(!in_copy(&private, "HEAD").exists());
    assert_eq!(fs::read_to_string(in_copy(&private, "file-git/.git"))?, "gitdir: elsewhere");
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
fn names_that_are_not_utf8_are_copied_under_reserved_names_and_keep_their_bytes() -> TestResult {
    let env = setup()?;
    let name = OsString::from_vec(vec![b'o', b'k', NON_UTF8_BYTE]);
    fs::create_dir_all(env.tree.join(&name).join(".git"))?;
    fs::write(env.tree.join(&name).join(".git/config"), "pat")?;
    fs::write(env.tree.join(&name).join("file"), "kept")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.renamed, vec![name.clone()]);
    let stored = format!("{RENAMED_PREFIX}0");
    assert_eq!(fs::read_to_string(in_copy(&private, &format!("{stored}/{STAGED_NAME}")))?, "pat");
    assert_eq!(fs::read_to_string(in_copy(&private, &format!("{stored}/file")))?, "kept");
    assert_eq!(summary.bytes, TEN_BYTES);
    Ok(())
}


#[test]
fn the_bytes_of_every_kept_name_count_against_the_copy_bound() -> TestResult {
    let env = setup()?;
    fs::create_dir(env.tree.join(OsString::from_vec(vec![b'a', b'b', NON_UTF8_BYTE])))?;
    let limit = |max: u64| CopyLimits {
        max_bytes: max,
        ..CopyLimits::default()
    };
    assert!(run_copy(&env, &limit(THREE_BYTES), no_hook).is_ok());
    assert!(matches!(run_copy(&env, &limit(TWO_BYTES), no_hook), Err(ScanError::CopyLimit("bytes"))));
    fs::create_dir_all((0..FIVE * FIVE).try_fold(env.tree.join("empty"), |path, index| {
        fs::create_dir_all(path.join(format!("{index}/.git")))?;
        Ok::<_, std::io::Error>(path.join(format!("{index}")))
    })?)?;
    let (_private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.renamed.len(), 1);
    Ok(())
}


#[test]
fn a_reserved_name_in_the_tree_is_refused() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join(format!("{RENAMED_PREFIX}0")), "x")?;
    assert!(matches!(run_copy(&env, &CopyLimits::default(), no_hook), Err(ScanError::NameClash)));
    fs::remove_file(env.tree.join(format!("{RENAMED_PREFIX}0")))?;
    fs::create_dir(env.tree.join(STAGED_NAME))?;
    assert!(matches!(run_copy(&env, &CopyLimits::default(), no_hook), Err(ScanError::NameClash)));
    assert!(work_is_empty(&env)?);
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
    Err(Errno::IO)
}


fn denied_open(_parent: &OwnedFd, _name: &OsStr) -> Result<OwnedFd, Errno> {
    Err(Errno::ACCESS)
}


fn leased_open(_parent: &OwnedFd, _name: &OsStr) -> Result<OwnedFd, Errno> {
    Err(Errno::WOULDBLOCK)
}


fn skipped(state: &mut CopySummary) -> &mut usize {
    &mut state.skipped_special
}


fn fail_data(_parent: &OwnedFd, _name: &OsStr) -> Result<OwnedFd, ScanError> {
    Err(ScanError::BadSettings("injected data failure"))
}


fn fail_run(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, ScanError> {
    if name == OsStr::new("run") {
        Err(ScanError::BadSettings("injected run failure"))
    } else {
        rustix::fs::mkdirat(parent, name, Mode::RWXU).map_err(std::io::Error::from)?;
        Ok(openat(parent, name, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).map_err(std::io::Error::from)?)
    }
}


#[test]
fn a_denied_or_leased_entry_is_counted_and_skipped_and_the_scan_goes_on() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("f"), "x")?;
    let private = create_private(&env.work, owner())?;
    let level = level_in(&env, &private)?;
    let limits = CopyLimits::default();
    let base = ctx_of(&env, &limits, same_dev(&env)?);
    let mut summary = CopySummary::default();
    let names = (OsStr::new("f"), OsStr::new("f"));
    let denied = Ctx {
        open_file: denied_open,
        ..ctx_of(&env, &limits, same_dev(&env)?)
    };
    copy_regular(&denied, &level.src, &level.dst, names, level.uid, &mut summary)?;
    let leased = Ctx {
        open_file: leased_open,
        ..ctx_of(&env, &limits, same_dev(&env)?)
    };
    copy_regular(&leased, &level.src, &level.dst, names, level.uid, &mut summary)?;
    assert_eq!((summary.denied_entries, summary.leased_files, summary.skipped_special), (1, 1, 0));
    copy_regular(&base, &level.src, &level.dst, names, level.uid, &mut summary)?;
    assert_eq!(fs::read_to_string(data_path(&private).join("f"))?, "x");
    let counts = counts_of(&summary);
    assert_eq!((counts.denied_entries, counts.leased_files), (1, 1));
    let mut state = CopySummary::default();
    tolerate_entry(Errno::ACCESS, &mut state, skipped, false)?;
    tolerate_entry(Errno::WOULDBLOCK, &mut state, skipped, false)?;
    tolerate_entry(Errno::LOOP, &mut state, skipped, true)?;
    assert!(tolerate_entry(Errno::IO, &mut state, skipped, false).is_err());
    assert_eq!((state.denied_entries, state.leased_files, state.skipped_special), (1, 1, 1));
    Ok(())
}


#[test]
fn a_failing_step_of_the_private_directory_leaves_nothing_behind() -> TestResult {
    let env = setup()?;
    assert!(matches!(
        create_private_with(&env.work, owner(), fail_data),
        Err(ScanError::BadSettings("injected data failure"))
    ));
    assert!(work_is_empty(&env)?);
    assert!(matches!(
        create_private_with(&env.work, owner(), fail_run),
        Err(ScanError::BadSettings("injected run failure"))
    ));
    assert!(work_is_empty(&env)?);
    Ok(())
}


#[test]
fn the_work_directory_is_checked_before_anything_is_opened() -> TestResult {
    let env = setup()?;
    let hostile = env.work.join("absent/../elsewhere");
    assert!(matches!(
        check_work_dir(&hostile),
        Err(ScanError::BadSettings("work directory has a component other than a name"))
    ));
    assert!(matches!(
        sweep_stale(&hostile, owner(), Duration::ZERO),
        Err(ScanError::BadSettings("work directory has a component other than a name"))
    ));
    assert!(matches!(
        check_work_dir(Path::new("relative")),
        Err(ScanError::BadSettings("work directory is not absolute"))
    ));
    assert!(check_work_dir(&env.work).is_ok());
    Ok(())
}


fn level_in(env: &Env, private: &PrivateDir) -> Result<Level, Box<dyn std::error::Error>> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let src = openat(rustix::fs::CWD, &env.tree, flags, Mode::empty())?;
    let data = openat(&private.root, DATA_DIR, flags, Mode::empty())?;
    let dst = openat(&data, ".", flags, Mode::empty())?;
    let dir = Dir::read_from(&src)?;
    Ok(Level {
        uid: owner(),
        src,
        dst,
        dir,
        rel: PathBuf::new(),
    })
}


fn ctx_of<'a>(env: &'a Env, limits: &'a CopyLimits, root_dev: u64) -> Ctx<'a> {
    Ctx {
        root: &env.tree,
        root_dev,
        limits,
        before_open: no_hook,
        open_file,
        expired: &never,
    }
}


fn same_dev(env: &Env) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(fs::metadata(&env.tree)?.dev())
}


#[test]
fn a_file_open_failure_is_io_and_an_existing_destination_is_refused() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("f"), "x")?;
    fs::create_dir(env.tree.join("d"))?;
    let private = create_private(&env.work, owner())?;
    let level = level_in(&env, &private)?;
    let limits = CopyLimits::default();
    let ctx = Ctx {
        open_file: failing_open,
        ..ctx_of(&env, &limits, same_dev(&env)?)
    };
    let mut summary = CopySummary::default();
    let names = (OsStr::new("f"), OsStr::new("f"));
    assert!(matches!(
        copy_regular(&ctx, &level.src, &level.dst, names, level.uid, &mut summary),
        Err(ScanError::Io(_))
    ));
    let real = Ctx { open_file, ..ctx };
    copy_regular(&real, &level.src, &level.dst, names, level.uid, &mut summary)?;
    assert!(matches!(
        copy_regular(&real, &level.src, &level.dst, names, level.uid, &mut summary),
        Err(ScanError::Io(_))
    ));
    copy_regular(&real, &level.src, &level.dst, (OsStr::new("d"), OsStr::new("d")), level.uid, &mut summary)?;
    assert_eq!(summary.skipped_special, 1);
    copy_regular(
        &real,
        &level.src,
        &level.dst,
        (OsStr::new("absent"), OsStr::new("absent")),
        level.uid,
        &mut summary,
    )?;
    assert_eq!(summary.skipped_vanished, 1);
    assert!(visit_entry(&real, &level, 1, &mut summary, OsStr::new("absent"), FileType::Unknown)?.is_none());
    assert_eq!(summary.skipped_vanished, TWO);
    Ok(())
}


#[test]
fn a_file_whose_owner_is_not_the_owner_of_its_directory_is_skipped_and_counted() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("mine"), "own")?;
    fs::write(env.tree.join("alone"), "single")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.foreign_owner_files, 0);
    assert!(in_copy(&private, "mine").is_file());
    let level = level_in(&env, &private)?;
    let limits = CopyLimits::default();
    let ctx = ctx_of(&env, &limits, same_dev(&env)?);
    let mut counted = CopySummary::default();
    let names = (OsStr::new("alone"), OsStr::new("single-copy"));
    copy_regular(&ctx, &level.src, &level.dst, names, level.uid + 1, &mut counted)?;
    assert_eq!(counted.foreign_owner_files, 1);
    assert!(!data_path(&private).join("single-copy").exists());
    copy_regular(&ctx, &level.src, &level.dst, names, level.uid, &mut counted)?;
    assert_eq!(counted.foreign_owner_files, 1);
    assert_eq!(fs::read_to_string(data_path(&private).join("single-copy"))?, "single");
    Ok(())
}


#[test]
fn a_file_of_another_user_is_skipped_whatever_its_link_count_in_the_real_walk() -> TestResult {
    let env = setup()?;
    fs::create_dir(env.tree.join("sub"))?;
    fs::write(env.tree.join("sub/removed-original"), "root only")?;
    fs::hard_link(env.tree.join("sub/removed-original"), env.tree.join("sub/planted"))?;
    fs::remove_file(env.tree.join("sub/removed-original"))?;
    fs::write(env.tree.join("sub/own"), "mine")?;
    fs::create_dir_all(env.tree.join("repo/.git"))?;
    fs::write(env.tree.join("repo/.git/config"), "pat")?;
    let stranger = owner() + OTHER_OWNER_OFFSET;
    let moved =
        chown(env.tree.join("sub/planted"), Some(stranger), None).is_ok() && chown(env.tree.join("repo/.git/config"), Some(stranger), None).is_ok();
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(summary.foreign_owner_files, if moved { TWO } else { 0 });
    assert_eq!(in_copy(&private, "sub/planted").exists(), !moved);
    assert_eq!(in_copy(&private, &format!("repo/{STAGED_NAME}")).exists(), !moved);
    assert!(in_copy(&private, "sub/own").is_file());
    assert!(moved || owner() != 0);
    Ok(())
}


#[test]
fn another_device_is_skipped_and_counted_never_read() -> TestResult {
    let env = setup()?;
    fs::write(env.tree.join("f"), "x")?;
    fs::create_dir_all(env.tree.join("d/inner"))?;
    fs::create_dir(env.tree.join("g"))?;
    fs::create_dir(env.tree.join("g/.git"))?;
    fs::write(env.tree.join("g/.git/config"), "x")?;
    let private = create_private(&env.work, owner())?;
    let level = level_in(&env, &private)?;
    let limits = CopyLimits::default();
    let ctx = ctx_of(&env, &limits, same_dev(&env)? + 1);
    let mut summary = CopySummary::default();
    copy_regular(&ctx, &level.src, &level.dst, (OsStr::new("f"), OsStr::new("f")), level.uid, &mut summary)?;
    assert_eq!(summary.other_device, 1);
    assert!(visit_entry(&ctx, &level, 1, &mut summary, OsStr::new("d"), FileType::Directory)?.is_none());
    assert_eq!(summary.other_device, TWO);
    assert!(!data_path(&private).join("d").exists());
    let inner = Level {
        uid: owner(),
        src: openat(&level.src, "g", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?,
        dst: openat(&level.dst, ".", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?,
        dir: Dir::read_from(&level.src)?,
        rel: PathBuf::new(),
    };
    assert!(copy_git_config(&ctx, &inner, &mut summary)?.is_none());
    assert_eq!(summary.other_device, THREE);
    assert_eq!(summary.entries, 1);
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
    let root = Path::new("/srv/tree");
    let renamed = [OsString::from_vec(vec![b'o', NON_UTF8_BYTE]), OsString::from("plain")];
    let map = |file: &str| original_path(file, root, &renamed);
    assert_eq!(map("/srv/tree/a/b.txt"), "/srv/tree/a/b.txt");
    assert_eq!(map(&format!("/srv/tree/d/{STAGED_NAME}")), "/srv/tree/d/.git/config");
    assert_eq!(
        map(&format!("/srv/tree/{RENAMED_PREFIX}0/{STAGED_NAME}")),
        "/srv/tree/o\\x{ff}/.git/config"
    );
    assert_eq!(map(&format!("/srv/tree/{RENAMED_PREFIX}1/f")), "/srv/tree/plain/f");
    assert_eq!(map(&format!("/srv/tree/{RENAMED_PREFIX}0.p12")), "/srv/tree/o\\x{ff}");
    assert_eq!(map(&format!("/srv/tree/{RENAMED_PREFIX}1nuget.config")), "/srv/tree/plain");
    [
        format!("/srv/tree/{RENAMED_PREFIX}2/f"),
        format!("/srv/tree/{RENAMED_PREFIX}x/f"),
        format!("/srv/tree/{RENAMED_PREFIX}-1/f"),
    ]
    .iter()
    .for_each(|file| assert_eq!(map(file), *file));
    ["/srv/treeish/a", "/srv", "/elsewhere/a", "relative"]
        .iter()
        .for_each(|file| assert_eq!(map(file), *file));
    Ok(())
}


#[test]
fn display_escapes_invalid_bytes_and_backslashes_never_with_the_replacement_char() -> TestResult {
    let raw = PathBuf::from(OsString::from_vec(vec![b'/', b'a', NON_UTF8_BYTE, b'\\', b'b']));
    assert_eq!(display_path(&raw), "/a\\x{ff}\\\\b");
    assert!(!display_path(&raw).contains('\u{fffd}'));
    assert_eq!(display_path(Path::new("/plain/path")), "/plain/path");
    Ok(())
}


#[test]
fn destination_keeps_valid_names_and_numbers_the_others() -> TestResult {
    let env = setup()?;
    let limits = CopyLimits::default();
    let ctx = ctx_of(&env, &limits, same_dev(&env)?);
    let mut summary = CopySummary::default();
    assert_eq!(destination(&ctx, &mut summary, OsStr::new("fine"))?, OsString::from("fine"));
    let odd = OsString::from_vec(vec![NON_UTF8_BYTE]);
    assert_eq!(destination(&ctx, &mut summary, &odd)?, OsString::from(format!("{RENAMED_PREFIX}0")));
    assert_eq!(destination(&ctx, &mut summary, &odd)?, OsString::from(format!("{RENAMED_PREFIX}1")));
    assert_eq!(summary.renamed.len(), TWO);
    let with_tail = OsString::from_vec(b"x\xff.p12".to_vec());
    assert_eq!(
        destination(&ctx, &mut summary, &with_tail)?,
        OsString::from(format!("{RENAMED_PREFIX}2.p12"))
    );
    Ok(())
}


#[test]
fn a_renamed_name_keeps_the_plain_tail_after_its_last_invalid_byte() -> TestResult {
    let long_tail = format!("{}.p12", "a".repeat(SIXTEEN_BYTES as usize * FOUR));
    let cases: Vec<(Vec<u8>, String)> = vec![
        (b"x\xff.p12".to_vec(), ".p12".to_string()),
        (b"y\xffnuget.config".to_vec(), "nuget.config".to_string()),
        (b"a\xff123.tf".to_vec(), ".tf".to_string()),
        (b"a\xff12345".to_vec(), String::new()),
        (b"ab\xff".to_vec(), String::new()),
        (b"a\xffb\xffc.yml".to_vec(), "c.yml".to_string()),
        (b"a\xff\xc3\xa9.php".to_vec(), ".php".to_string()),
        (b"a\xff/odd name.hcl".to_vec(), "name.hcl".to_string()),
    ];
    cases.iter().for_each(|(raw, tail)| {
        let name = OsString::from_vec(raw.clone());
        assert_eq!(name_tail(&name), *tail, "{raw:?}");
    });
    let capped = OsString::from_vec([b"a\xff".to_vec(), long_tail.into_bytes()].concat());
    assert_eq!(name_tail(&capped).len(), SIXTEEN_BYTES as usize * FOUR);
    assert!(name_tail(&capped).ends_with("a.p12"));
    Ok(())
}


#[test]
fn a_tail_name_is_copied_and_mapped_back_to_its_raw_bytes() -> TestResult {
    let env = setup()?;
    let name = OsString::from_vec(b"x\xff.p12".to_vec());
    fs::write(env.tree.join(&name), "bundle")?;
    let (private, summary) = run_copy(&env, &CopyLimits::default(), no_hook)?;
    assert_eq!(fs::read_to_string(in_copy(&private, &format!("{RENAMED_PREFIX}0.p12")))?, "bundle");
    let reported = env.tree.join(format!("{RENAMED_PREFIX}0.p12")).display().to_string();
    let shown = original_path(&reported, &env.tree, &summary.renamed);
    assert_eq!(shown, format!("{}/x\\x{{ff}}.p12", env.tree.display()));
    Ok(())
}


#[test]
fn stale_private_directories_of_the_caller_are_swept_through_the_work_handle() -> TestResult {
    let env = setup()?;
    fs::create_dir_all(env.work.join("secret-scan-old/data/deeper"))?;
    fs::write(env.work.join("secret-scan-old/data/deeper/f"), "x")?;
    fs::create_dir(env.work.join("secret-scan-foreign"))?;
    fs::create_dir(env.work.join("unrelated"))?;
    fs::write(env.work.join("secret-scan-file"), "x")?;
    symlink(env.root.path().join("secret"), env.work.join("secret-scan-link"))?;
    assert_eq!(sweep_stale(&env.work, owner(), Duration::from_secs(SWEEP_FRESH_SECONDS))?, 0);
    assert!(env.work.join("secret-scan-old").is_dir());
    let stranger = owner() + OTHER_OWNER_OFFSET;
    let moved = chown(env.work.join("secret-scan-foreign"), Some(stranger), None).is_ok();
    assert_eq!(sweep_stale(&env.work, owner(), Duration::ZERO)?, 1);
    assert!(!env.work.join("secret-scan-old").exists());
    assert_eq!(env.work.join("secret-scan-foreign").exists(), moved);
    assert!(env.work.join("unrelated").is_dir());
    assert!(env.work.join("secret-scan-file").is_file());
    assert!(env.work.join("secret-scan-link").is_symlink());
    assert!(env.root.path().join("secret/key.txt").is_file());
    assert!(matches!(
        sweep_stale(&env.root.path().join("missing"), owner(), Duration::ZERO),
        Err(ScanError::Io(_))
    ));
    assert!(moved || owner() != 0);
    Ok(())
}


#[test]
fn counts_of_carries_every_count() -> TestResult {
    let summary = CopySummary {
        entries: 1,
        bytes: TWO as u64,
        truncated_files: THREE,
        skipped_special: FOUR,
        skipped_swapped: FIVE,
        skipped_vanished: FIVE + 1,
        config_files: FIVE + TWO,
        foreign_owner_files: FIVE + THREE,
        other_device: FIVE + FOUR,
        denied_entries: FIVE + FIVE,
        leased_files: FIVE + FIVE + 1,
        renamed: vec![OsString::new(); FIVE * TWO],
    };
    let counts = counts_of(&summary);
    assert_eq!(
        [
            counts.entries,
            counts.bytes as usize,
            counts.truncated_files,
            counts.skipped_special,
            counts.skipped_swapped,
            counts.skipped_vanished,
            counts.config_files,
            counts.foreign_owner_files,
            counts.other_device,
            counts.denied_entries,
            counts.leased_files,
            counts.renamed_names,
        ],
        [
            1,
            TWO,
            THREE,
            FOUR,
            FIVE,
            FIVE + 1,
            FIVE + TWO,
            FIVE + THREE,
            FIVE + FOUR,
            FIVE * TWO,
            FIVE * TWO + 1,
            FIVE * TWO
        ]
    );
    Ok(())
}


struct Restore {
    path: PathBuf,
    uid: u32,
}


impl Drop for Restore {
    fn drop(&mut self) {
        assert!(chown(&self.path, Some(self.uid), None).is_ok());
    }
}


#[test]
fn every_ancestor_of_the_work_directory_is_checked() -> TestResult {
    let env = setup()?;
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(ALL_WRITABLE))?;
    assert!(matches!(
        create_private(&env.work, owner()),
        Err(ScanError::BadSettings("work directory ancestor is writable by group or others"))
    ));
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(STICKY_WRITABLE))?;
    assert!(create_private(&env.work, owner()).is_ok());
    fs::set_permissions(env.root.path(), fs::Permissions::from_mode(NORMAL_DIR))?;
    assert!(matches!(
        create_private(Path::new("relative/work"), owner()),
        Err(ScanError::BadSettings("work directory is not absolute"))
    ));
    assert!(matches!(
        open_work_root(&env.work.join("../work"), owner()),
        Err(ScanError::BadSettings("work directory has a component other than a name"))
    ));
    let restore = Restore {
        path: env.root.path().to_path_buf(),
        uid: fs::metadata(env.root.path())?.uid(),
    };
    let stranger = owner() + OTHER_OWNER_OFFSET;
    let moved = chown(env.root.path(), Some(stranger), None).is_ok();
    assert!(matches!(
        create_private(&env.work, owner() + 1),
        Err(ScanError::BadSettings("work directory ancestor is not owned by root or the caller"))
    ));
    assert!(moved || owner() != 0);
    drop(restore);
    Ok(())
}


#[test]
fn the_ignore_file_is_created_empty_through_the_run_handle_once() -> TestResult {
    let env = setup()?;
    let private = create_private(&env.work, owner())?;
    write_ignore(&private)?;
    let ignore = run_path(&private).join("ignore");
    assert_eq!(fs::metadata(&ignore)?.len(), 0);
    assert_eq!(fs::metadata(&ignore)?.permissions().mode() & MODE_MASK, PRIVATE_FILE_MODE);
    assert!(matches!(write_ignore(&private), Err(ScanError::Io(_))));
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


const TEN_BYTES: u64 = 10;


const THREE_BYTES: u64 = 3;


const TWO_BYTES: u64 = 2;


const ALL_WRITABLE: u32 = 0o777;


const STICKY_WRITABLE: u32 = 0o1777;


const NORMAL_DIR: u32 = 0o755;


const OTHER_OWNER_OFFSET: u32 = 3;


const SWEEP_FRESH_SECONDS: u64 = 3600;
