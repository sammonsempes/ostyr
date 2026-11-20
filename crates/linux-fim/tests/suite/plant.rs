use crate::types::TestResult;
use linux_fim::cli::{parse_planted, planted_from};
use linux_fim::content::{token_content, RANDOM_BYTES};
use linux_fim::error::{CliError, PlantError, PlantRefusal};
use linux_fim::limits::default_limits;
use linux_fim::model::{Honeytoken, HoneytokenKind, Limits, PlantReport, PlantedIdentity, Role};
use linux_fim::plant::{
    check_unloaded, directory_verdict, file_verdict, first_cause, first_failure, first_refusal, fresh_token, group_outcome, list_first,
    list_first_with, list_from, loaded_count, log_reap_failure, made_verdict, no_step, os_claim, os_list_policies, os_ops, os_random, own_outcome,
    pick_binary, plant_command, plant_role, planted_text, read_listing, read_until, reap, spawn_listing, stat_device, wait_readable, wait_until,
    FileFacts, PlantOps, FILE_MODE, PERMISSION_MASK, PROGRAM_CHANGED, TETRA_OWNER_UID,
};
use linux_fim::policy::kernel_device;
use rustix::fs::inotify::{add_watch, init, CreateFlags, WatchFlags};
use rustix::fs::{mkdirat, mknodat, renameat, FileType, Mode, RawMode, CWD};
use rustix::io::{ioctl_fionread, read, Errno};
use rustix::process::{geteuid, kill_process_group, Pid, Signal};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, PipeReader, PipeWriter, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{chown, symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tempfile::{tempdir_in, TempDir};


const BYTE_RANGE: usize = 256;


const TEST_DEADLINE: Duration = Duration::from_secs(30);


const HANG_GUARD: Duration = Duration::from_secs(60);


const SMALL_READS: usize = 300;


const DRAIN_CHUNK: usize = 4096;


const MAX_DRAIN_READS: usize = 4096;


const MAX_SPINS: usize = 1_000_000;


const WORLD_WRITABLE: u32 = 0o777;


const GROUP_WRITABLE: u32 = 0o770;


const WORLD_WRITABLE_STICKY: u32 = 0o1777;


const SEARCH_ONLY: u32 = 0o700;


const WORLD_READABLE: u32 = 0o755;


const OTHER_READABLE: u32 = 0o644;


const GROUP_WRITE_ONLY: u32 = 0o720;


const REGULAR_0600: u32 = 0o100_600;


const REGULAR_0660: u32 = 0o100_660;


const OWNER: u32 = 1000;


const NOBODY: u32 = 65_534;


const EVENT_BUFFER: usize = 256;


const TOKENS: usize = 3;


const CANARY_INDEX: usize = 2;


const SPACE_MODE: RawMode = 0o600;


const DEVICE: u32 = 265_289_729;


const KERNEL_DEVICES: [u32; 3] = [0, 44, DEVICE];


const STAGED_NAME: &str = ".planted.tsv.0001020304050607.tmp";


const PLANTED_BESIDE_ONE_REFUSAL: usize = 4;


const PLANTED_BESIDE_ONE_REFUSAL_OF_TWO: usize = 3;


static SHARED_EXECUTABLES: LazyLock<Result<PathBuf, String>> = LazyLock::new(write_executables);


fn write_executables() -> Result<PathBuf, String> {
    let dir = tempfile::Builder::new()
        .prefix("executables-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .map_err(|error| error.to_string())?
        .keep();
    fs::copy("/usr/bin/echo", dir.join("echo")).map_err(|error| error.to_string())?;
    let broken = dir.join("broken");
    fs::write(&broken, "#!/nonexistent/interpreter\n").map_err(|error| error.to_string())?;
    fs::set_permissions(&broken, fs::Permissions::from_mode(WORLD_READABLE)).map_err(|error| error.to_string())?;
    Ok(dir)
}


fn executable(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    Ok(SHARED_EXECUTABLES.as_ref().map_err(|error| error.clone())?.join(name))
}


fn tree() -> Result<TempDir, Box<dyn Error>> {
    executable("echo")?;
    Ok(tempdir_in(env!("CARGO_TARGET_TMPDIR"))?)
}


fn fixed_random(buffer: &mut [u8]) -> io::Result<()> {
    buffer
        .iter_mut()
        .enumerate()
        .for_each(|(index, byte)| *byte = u8::try_from(index % BYTE_RANGE).unwrap_or(0));
    Ok(())
}


fn failing_random(_buffer: &mut [u8]) -> io::Result<()> {
    Err(io::Error::other("no entropy"))
}


fn failing_claim(_handle: &OwnedFd, _uid: u32, _mode: RawMode) -> Result<(), Errno> {
    Err(Errno::PERM)
}


const TWO_LOADED: usize = 2;


fn nothing_loaded() -> io::Result<String> {
    Ok("ID NAME STATE\n".to_string())
}


fn some_loaded() -> io::Result<String> {
    Ok("ID NAME STATE\n1 ostyr-fimt-server enabled\n2 ostyr-fim-server enabled\n3 other enabled\n".to_string())
}


fn failing_list() -> io::Result<String> {
    Err(io::Error::other("no tetra"))
}


fn ops(root: &Path) -> PlantOps {
    PlantOps {
        root: root.to_path_buf(),
        list_policies: nothing_loaded,
        ..os_ops()
    }
}


fn swap_ancestor(parent: &OwnedFd, name: &str) {
    if name == "swapme" {
        let moved = renameat(parent, "swapme", parent, "swapme-moved");
        let made = mkdirat(parent, "swapme", Mode::from_raw_mode(SEARCH_ONLY));
        assert!(moved.is_ok() && made.is_ok());
    }
}


fn fail_file_claim(_handle: &OwnedFd, _uid: u32, mode: RawMode) -> Result<(), Errno> {
    (mode != FILE_MODE).then_some(()).ok_or(Errno::PERM)
}


fn swap_made(parent: &OwnedFd, name: &str) {
    if name == "madeswap" {
        let moved = renameat(parent, "madeswap", parent, "madeswap-moved");
        let made = mkdirat(parent, "madeswap", Mode::from_raw_mode(SEARCH_ONLY));
        let filled = fs::write(format!("/proc/self/fd/{}/madeswap/inside", std::os::fd::AsRawFd::as_raw_fd(parent)), b"x");
        assert!(moved.is_ok() && made.is_ok() && filled.is_ok());
    }
}


fn swap_created(parent: &OwnedFd, name: &str) {
    if name == ".swapped" {
        let moved = renameat(parent, ".swapped", parent, ".swapped-moved");
        let made = fs::write(format!("/proc/self/fd/{}/.swapped", std::os::fd::AsRawFd::as_raw_fd(parent)), b"other");
        assert!(moved.is_ok() && made.is_ok());
    }
}


fn token(path: &str, kind: HoneytokenKind) -> Honeytoken {
    Honeytoken {
        path: path.to_string(),
        kind,
        owner_uid: geteuid().as_raw(),
    }
}


fn role(tokens: Vec<Honeytoken>) -> Role {
    Role {
        name: "server".to_string(),
        watched: Vec::new(),
        honeytokens: tokens,
    }
}


fn three_tokens() -> Role {
    role(vec![
        token("/root/.aws/credentials", HoneytokenKind::AwsCredentials),
        token("/root/passwords.txt", HoneytokenKind::PasswordFile),
        token("/var/backups/.canary", HoneytokenKind::Canary),
    ])
}


fn paths(report: &PlantReport) -> Vec<&str> {
    report.planted.iter().map(|identity| identity.path.as_str()).collect()
}


fn refused_indexes(report: &PlantReport) -> Vec<usize> {
    report.refused.iter().map(|(index, _)| *index).collect()
}


fn reason(report: &PlantReport, index: usize) -> Result<String, Box<dyn Error>> {
    report
        .refused
        .iter()
        .find(|(candidate, _)| *candidate == index)
        .map(|(_, refusal)| refusal.to_string())
        .ok_or_else(|| "no such refusal".into())
}


fn plant(root: &Path, role: &Role) -> Result<PlantReport, Box<dyn Error>> {
    Ok(plant_role(role, &default_limits(), &ops(root))?)
}


fn real(root: &Path, logical: &str) -> PathBuf {
    root.join(logical.trim_start_matches('/'))
}


fn kept_identity(identity: &PlantedIdentity) -> (String, u32, u64) {
    (identity.path.clone(), identity.device, identity.inode)
}


#[test]
fn a_fresh_plant_records_every_token_and_directory_from_what_was_written() -> TestResult {
    let dir = tree()?;
    let report = plant(dir.path(), &three_tokens())?;
    assert!(report.refused.is_empty());
    assert_eq!(
        paths(&report),
        [
            "/root",
            "/root/.aws",
            "/root/.aws/credentials",
            "/root/passwords.txt",
            "/var",
            "/var/backups",
            "/var/backups/.canary"
        ]
    );
    report.planted.iter().try_for_each(|identity| -> TestResult {
        let metadata = fs::metadata(real(dir.path(), &identity.path))?;
        assert_eq!((identity.device, identity.inode), (kernel_device(metadata.dev()), metadata.ino()));
        Ok(())
    })?;
    let file = fs::metadata(real(dir.path(), "/root/.aws/credentials"))?;
    assert_eq!((file.mode() & PERMISSION_MASK, file.uid()), (FILE_MODE, geteuid().as_raw()));
    assert_eq!(fs::metadata(real(dir.path(), "/root/.aws"))?.mode() & PERMISSION_MASK, SEARCH_ONLY);
    assert!(fs::read_to_string(real(dir.path(), "/root/.aws/credentials"))?.starts_with("[default]\n"));
    Ok(())
}


#[test]
fn the_content_is_the_template_of_the_random_bytes() -> TestResult {
    let dir = tree()?;
    let fixed = PlantOps {
        fill_random: fixed_random,
        ..ops(dir.path())
    };
    plant_role(&three_tokens(), &default_limits(), &fixed)?;
    let mut bytes = [u8::MIN; RANDOM_BYTES];
    fixed_random(&mut bytes)?;
    assert_eq!(
        fs::read_to_string(real(dir.path(), "/var/backups/.canary"))?,
        token_content(HoneytokenKind::Canary, &bytes)
    );
    Ok(())
}


#[test]
fn a_rerun_keeps_the_files_and_records_the_same_identities() -> TestResult {
    let dir = tree()?;
    let first = plant(dir.path(), &three_tokens())?;
    let before = fs::read_to_string(real(dir.path(), "/root/passwords.txt"))?;
    let second = plant(dir.path(), &three_tokens())?;
    assert!(second.refused.is_empty());
    assert_eq!(
        first.planted.iter().map(kept_identity).collect::<Vec<_>>(),
        second.planted.iter().map(kept_identity).collect::<Vec<_>>()
    );
    assert_eq!(fs::read_to_string(real(dir.path(), "/root/passwords.txt"))?, before);
    assert_eq!(planted_text(&first.planted), planted_text(&second.planted));
    Ok(())
}


#[test]
fn the_tsv_round_trips_through_parse_planted_with_the_stat_device() -> TestResult {
    let dir = tree()?;
    let report = plant(dir.path(), &three_tokens())?;
    let output = dir.path().join("planted.tsv");
    linux_fim::plant::write_planted(&ops(dir.path()), &output, &report.planted)?;
    let text = fs::read_to_string(&output)?;
    assert_eq!(parse_planted(&text)?, report.planted);
    let canary = fs::metadata(real(dir.path(), "/var/backups/.canary"))?;
    assert!(text.contains(&format!("/var/backups/.canary\t{}\t{}\n", canary.dev(), canary.ino())));
    assert_eq!(fs::metadata(&output)?.mode() & PERMISSION_MASK, FILE_MODE);
    assert_eq!(
        fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() == STAGED_NAME)
            .count(),
        0
    );
    Ok(())
}


#[test]
fn the_kernel_device_survives_the_round_trip_through_stat_device() -> TestResult {
    KERNEL_DEVICES
        .iter()
        .for_each(|device| assert_eq!(kernel_device(stat_device(*device)), *device));
    assert_eq!(planted_from("/x", stat_device(DEVICE), 1).device, DEVICE);
    Ok(())
}


#[test]
fn a_symlink_at_a_token_path_refuses_that_token_alone() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    let elsewhere = dir.path().join("elsewhere");
    symlink(&elsewhere, real(dir.path(), "/var/backups/.canary"))?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [CANARY_INDEX]);
    assert_eq!(
        reason(&report, CANARY_INDEX)?,
        "the file at the token path is refused: not a regular file"
    );
    assert!(!elsewhere.exists());
    assert_eq!(paths(&report).len(), PLANTED_BESIDE_ONE_REFUSAL);
    assert!(real(dir.path(), "/root/passwords.txt").exists());
    Ok(())
}


#[test]
fn a_symlink_as_an_ancestor_refuses_the_tokens_below_it_alone() -> TestResult {
    let dir = tree()?;
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere)?;
    symlink(&elsewhere, real(dir.path(), "/root"))?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [0, 1]);
    assert!(report.refused.iter().all(|(_, refusal)| matches!(refusal, PlantRefusal::Io(_))));
    assert_eq!(fs::read_dir(&elsewhere)?.count(), 0);
    assert!(real(dir.path(), "/var/backups/.canary").exists());
    Ok(())
}


#[test]
fn a_fifo_at_a_token_path_is_refused_without_being_opened() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    mknodat(
        CWD,
        real(dir.path(), "/var/backups/.canary"),
        FileType::Fifo,
        Mode::from_raw_mode(SPACE_MODE),
        0,
    )?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [CANARY_INDEX]);
    assert_eq!(
        reason(&report, CANARY_INDEX)?,
        "the file at the token path is refused: not a regular file"
    );
    Ok(())
}


#[test]
fn a_directory_at_a_token_path_is_refused() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups/.canary"))?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [CANARY_INDEX]);
    Ok(())
}


#[test]
fn a_hard_link_at_a_token_path_is_refused_whatever_its_mode_and_owner() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    let secret = dir.path().join("shadow");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SPACE_MODE)
        .open(&secret)?
        .write_all(b"root:x\n")?;
    fs::hard_link(&secret, real(dir.path(), "/var/backups/.canary"))?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [CANARY_INDEX]);
    assert_eq!(
        reason(&report, CANARY_INDEX)?,
        "the file at the token path is refused: more than one link"
    );
    assert_eq!(fs::read_to_string(&secret)?, "root:x\n");
    Ok(())
}


#[test]
fn an_existing_file_with_another_mode_or_no_content_is_refused() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    let canary = real(dir.path(), "/var/backups/.canary");
    fs::write(&canary, "x")?;
    fs::set_permissions(&canary, fs::Permissions::from_mode(OTHER_READABLE))?;
    assert_eq!(
        reason(&plant(dir.path(), &three_tokens())?, CANARY_INDEX)?,
        "the file at the token path is refused: mode is not 0600"
    );
    fs::set_permissions(&canary, fs::Permissions::from_mode(SPACE_MODE))?;
    fs::write(&canary, "")?;
    assert_eq!(
        reason(&plant(dir.path(), &three_tokens())?, CANARY_INDEX)?,
        "the file at the token path is refused: empty"
    );
    Ok(())
}


#[test]
fn a_group_writable_or_sticky_world_writable_ancestor_is_refused() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/root"))?;
    fs::set_permissions(real(dir.path(), "/root"), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    fs::create_dir_all(real(dir.path(), "/var"))?;
    fs::set_permissions(real(dir.path(), "/var"), fs::Permissions::from_mode(WORLD_WRITABLE_STICKY))?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [0, 1, CANARY_INDEX]);
    assert_eq!(reason(&report, 1)?, "a directory above the token is refused: writable by group or others");
    assert_eq!(
        reason(&report, CANARY_INDEX)?,
        "a directory above the token is refused: writable by group or others"
    );
    Ok(())
}


#[test]
fn a_group_writable_directory_holding_the_token_is_refused() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    fs::set_permissions(real(dir.path(), "/var/backups"), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    let report = plant(dir.path(), &role(vec![token("/var/backups/.canary", HoneytokenKind::Canary)]))?;
    assert_eq!(refused_indexes(&report), [0]);
    assert!(!real(dir.path(), "/var/backups/.canary").exists());
    Ok(())
}


#[test]
fn the_walk_stays_in_the_directory_it_holds_when_a_name_is_swapped() -> TestResult {
    let dir = tree()?;
    let swapping = PlantOps {
        after_open: swap_ancestor,
        ..ops(dir.path())
    };
    let report = plant_role(
        &role(vec![token("/swapme/inner/token", HoneytokenKind::Canary)]),
        &default_limits(),
        &swapping,
    )?;
    assert!(report.refused.is_empty());
    assert!(real(dir.path(), "/swapme-moved/inner/token").exists());
    assert_eq!(fs::read_dir(real(dir.path(), "/swapme"))?.count(), 0);
    let held = report.planted.first().ok_or("no identity")?;
    assert_eq!(held.inode, fs::metadata(real(dir.path(), "/swapme-moved"))?.ino());
    assert_ne!(held.inode, fs::metadata(real(dir.path(), "/swapme"))?.ino());
    Ok(())
}


#[test]
fn a_token_in_the_root_directory_has_no_ancestor_identity() -> TestResult {
    let dir = tree()?;
    let report = plant(dir.path(), &role(vec![token("/lonely", HoneytokenKind::Canary)]))?;
    assert_eq!(paths(&report), ["/lonely"]);
    Ok(())
}


#[test]
fn a_path_without_a_name_is_refused() -> TestResult {
    let dir = tree()?;
    let report = plant(dir.path(), &role(vec![token("/", HoneytokenKind::Canary)]))?;
    assert!(matches!(report.refused.first(), Some((0, PlantRefusal::Path))));
    Ok(())
}


#[test]
fn a_missing_root_refuses_every_token() -> TestResult {
    let dir = tree()?;
    let report = plant(&dir.path().join("none"), &three_tokens())?;
    assert_eq!(refused_indexes(&report), [0, 1, CANARY_INDEX]);
    Ok(())
}


#[test]
fn a_failing_random_source_or_claim_refuses_the_token_and_names_no_content() -> TestResult {
    let dir = tree()?;
    let no_entropy = PlantOps {
        fill_random: failing_random,
        ..ops(dir.path())
    };
    let report = plant_role(&three_tokens(), &default_limits(), &no_entropy)?;
    assert_eq!(refused_indexes(&report), [0, 1, CANARY_INDEX]);
    let refusing = PlantOps {
        claim: failing_claim,
        fill_random: fixed_random,
        ..ops(dir.path())
    };
    let claimed = plant_role(&three_tokens(), &default_limits(), &refusing)?;
    assert_eq!(refused_indexes(&claimed), [0, 1, CANARY_INDEX]);
    let mut bytes = [u8::MIN; RANDOM_BYTES];
    fixed_random(&mut bytes)?;
    let secret = token_content(HoneytokenKind::AwsCredentials, &bytes);
    let secret_line = secret.lines().last().ok_or("no line")?;
    claimed.refused.iter().try_for_each(|(_, refusal)| -> TestResult {
        let chain: Vec<String> = std::iter::successors(Some(refusal as &dyn Error), |cause| Error::source(*cause))
            .map(|cause| format!("{cause} {cause:?}"))
            .collect();
        assert!(chain.iter().all(|text| !text.contains(secret_line)));
        Ok(())
    })?;
    Ok(())
}


#[test]
fn a_claim_that_fails_on_a_file_leaves_the_directories_made() -> TestResult {
    let dir = tree()?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    let refusing = PlantOps {
        claim: failing_claim,
        ..ops(dir.path())
    };
    let report = plant_role(
        &role(vec![token("/var/backups/.canary", HoneytokenKind::Canary)]),
        &default_limits(),
        &refusing,
    )?;
    assert_eq!(refused_indexes(&report), [0]);
    Ok(())
}


#[test]
fn more_tokens_than_the_limit_are_refused_before_anything_is_written() -> TestResult {
    let dir = tree()?;
    let limits = Limits {
        max_honeytokens: 1,
        ..default_limits()
    };
    let result = plant_role(&three_tokens(), &limits, &ops(dir.path()));
    assert!(matches!(result, Err(PlantError::TooMany { count: TOKENS, max: 1 })));
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    Ok(())
}


#[test]
fn a_shared_directory_is_recorded_once() -> TestResult {
    let dir = tree()?;
    let report = plant(dir.path(), &three_tokens())?;
    assert_eq!(report.planted.iter().filter(|identity| identity.path == "/root").count(), 1);
    Ok(())
}


#[test]
fn the_verdicts_name_the_first_failed_check() -> TestResult {
    let owner = OWNER;
    assert_eq!(first_failure(&[(true, "a"), (false, "b"), (false, "c")]), Some("b"));
    assert_eq!(first_failure(&[(true, "a")]), None);
    assert!(directory_verdict(0, WORLD_READABLE, owner).is_ok());
    assert!(directory_verdict(owner, SEARCH_ONLY, owner).is_ok());
    assert!(matches!(
        directory_verdict(owner + 1, SEARCH_ONLY, owner),
        Err(PlantRefusal::Directory(_))
    ));
    assert!(matches!(
        directory_verdict(owner, GROUP_WRITE_ONLY, owner),
        Err(PlantRefusal::Directory(_))
    ));
    assert!(matches!(
        directory_verdict(owner, WORLD_WRITABLE_STICKY, owner),
        Err(PlantRefusal::Directory(_))
    ));
    let good = FileFacts {
        regular: true,
        single_link: true,
        uid: owner,
        mode: REGULAR_0600,
        has_content: true,
    };
    assert!(file_verdict(&good, owner).is_ok());
    let bad = [
        FileFacts { regular: false, ..good },
        FileFacts { single_link: false, ..good },
        FileFacts { uid: owner + 1, ..good },
        FileFacts { mode: REGULAR_0660, ..good },
        FileFacts { has_content: false, ..good },
    ];
    bad.iter()
        .for_each(|facts| assert!(matches!(file_verdict(facts, owner), Err(PlantRefusal::File(_)))));
    Ok(())
}


#[test]
fn the_os_operations_read_entropy_and_claim_a_held_handle() -> TestResult {
    let mut bytes = [u8::MIN; RANDOM_BYTES];
    os_random(&mut bytes)?;
    assert_ne!(bytes, [u8::MIN; RANDOM_BYTES]);
    assert_eq!(os_ops().root, Path::new("/"));
    let dir = tree()?;
    let handle: OwnedFd = fs::File::open(dir.path())?.into();
    assert!(os_claim(&handle, geteuid().as_raw(), SEARCH_ONLY).is_ok());
    no_step(&handle, "name");
    Ok(())
}


#[test]
fn an_output_path_without_a_name_or_in_a_shared_directory_is_refused() -> TestResult {
    let dir = tree()?;
    let none: &[PlantedIdentity] = &[];
    assert!(matches!(
        linux_fim::plant::write_planted(&ops(dir.path()), Path::new("/"), none),
        Err(PlantError::OutputPath)
    ));
    let shared = dir.path().join("shared");
    fs::create_dir(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(
        linux_fim::plant::write_planted(&ops(dir.path()), &shared.join("planted.tsv"), none),
        Err(PlantError::Directory(_))
    ));
    assert!(!shared.join("planted.tsv").exists());
    Ok(())
}


#[test]
fn a_staging_name_already_taken_or_no_entropy_fails_the_output_write() -> TestResult {
    let dir = tree()?;
    let none: &[PlantedIdentity] = &[];
    let fixed = PlantOps {
        fill_random: fixed_random,
        ..ops(dir.path())
    };
    fs::write(dir.path().join(STAGED_NAME), "taken")?;
    let taken = linux_fim::plant::write_planted(&fixed, &dir.path().join("planted.tsv"), none);
    assert!(matches!(taken, Err(PlantError::Io(_))));
    let no_entropy = PlantOps {
        fill_random: failing_random,
        ..ops(dir.path())
    };
    assert!(matches!(
        linux_fim::plant::write_planted(&no_entropy, &dir.path().join("planted.tsv"), none),
        Err(PlantError::Io(_))
    ));
    assert_eq!(fs::read_to_string(dir.path().join(STAGED_NAME))?, "taken");
    Ok(())
}


struct BudgetWriter {
    budget: usize,
    written: Vec<u8>,
}


fn writer(budget: usize) -> BudgetWriter {
    BudgetWriter { budget, written: Vec::new() }
}


impl Write for BudgetWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let taken = buffer.len().min(self.budget);
        self.budget -= taken;
        self.written.extend(buffer.iter().take(taken));
        (taken > 0).then_some(taken).ok_or_else(|| io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn table_file(dir: &Path) -> Result<PathBuf, io::Error> {
    let table = dir.join("roles.yaml");
    fs::write(
        &table,
        "version: 1\nroles:\n  - name: server\n    honeytokens:\n      - { path: /root/.aws/credentials, kind: aws_credentials }\n      - { path: /var/backups/.canary, kind: canary }\n  - name: none\n    watched:\n      - { path: /etc/passwd, kind: file }\n",
    )?;
    Ok(table)
}


#[test]
fn the_command_plants_prints_the_counts_and_writes_the_tsv() -> TestResult {
    let dir = tree()?;
    let tables = tree()?;
    let table = table_file(tables.path())?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    symlink(dir.path().join("elsewhere"), real(dir.path(), "/var/backups/.canary"))?;
    let output = tables.path().join("planted.tsv");
    let mut out = writer(usize::MAX);
    let refused = plant_command(&table, "server", &output, &default_limits(), &ops(dir.path()), &mut out)?;
    assert_eq!(refused, 1);
    assert_eq!(
        String::from_utf8(out.written)?,
        "planted 1 refused 1\nrefused 1: the file at the token path is refused: not a regular file\n"
    );
    assert_eq!(parse_planted(&fs::read_to_string(&output)?)?.len(), PLANTED_BESIDE_ONE_REFUSAL_OF_TWO);
    Ok(())
}


#[test]
fn the_command_reports_a_missing_role_a_bad_output_and_a_closed_output() -> TestResult {
    let dir = tree()?;
    let tables = tree()?;
    let table = table_file(tables.path())?;
    let output = tables.path().join("planted.tsv");
    let missing = plant_command(&table, "nobody", &output, &default_limits(), &ops(dir.path()), &mut writer(usize::MAX));
    assert!(matches!(missing, Err(CliError::NoRole(_))));
    let bad_output = plant_command(
        &table,
        "server",
        Path::new("/"),
        &default_limits(),
        &ops(dir.path()),
        &mut writer(usize::MAX),
    );
    assert!(matches!(bad_output, Err(CliError::Plant(PlantError::OutputPath))));
    let closed = plant_command(&table, "server", &output, &default_limits(), &ops(dir.path()), &mut writer(0));
    assert!(matches!(closed, Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn a_closed_output_while_listing_refusals_is_an_error() -> TestResult {
    let dir = tree()?;
    let tables = tree()?;
    let table = table_file(tables.path())?;
    fs::create_dir_all(real(dir.path(), "/var/backups"))?;
    symlink(dir.path().join("elsewhere"), real(dir.path(), "/var/backups/.canary"))?;
    let output = tables.path().join("planted.tsv");
    let line = "planted 1 refused 1\n";
    let closed = plant_command(&table, "server", &output, &default_limits(), &ops(dir.path()), &mut writer(line.len()));
    assert!(matches!(closed, Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn a_rerun_never_opens_an_existing_token() -> TestResult {
    let dir = tree()?;
    plant(dir.path(), &three_tokens())?;
    let watcher = init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC)?;
    ["/root/passwords.txt", "/root/.aws/credentials", "/var/backups/.canary"]
        .iter()
        .try_for_each(|logical| add_watch(&watcher, real(dir.path(), logical), WatchFlags::OPEN | WatchFlags::ACCESS).map(|_| ()))?;
    let report = plant(dir.path(), &three_tokens())?;
    assert!(report.refused.is_empty());
    let mut buffer = [u8::MIN; EVENT_BUFFER];
    assert_eq!(read(&watcher, &mut buffer), Err(Errno::AGAIN));
    Ok(())
}


#[test]
fn a_directory_swapped_in_after_the_mkdir_is_refused_and_not_claimed() -> TestResult {
    let dir = tree()?;
    let swapping = PlantOps {
        after_make: swap_made,
        ..ops(dir.path())
    };
    let report = plant_role(
        &role(vec![token("/madeswap/token", HoneytokenKind::Canary)]),
        &default_limits(),
        &swapping,
    )?;
    assert_eq!(refused_indexes(&report), [0]);
    assert_eq!(reason(&report, 0)?, "a directory above the token is refused: made directory is not empty");
    assert!(!real(dir.path(), "/madeswap/token").exists());
    Ok(())
}


#[test]
fn the_made_verdict_names_the_owner_then_the_content() -> TestResult {
    assert!(made_verdict(OWNER, OWNER, true).is_ok());
    assert!(matches!(made_verdict(OWNER + 1, OWNER, true), Err(PlantRefusal::Directory(_))));
    assert!(matches!(made_verdict(OWNER, OWNER, false), Err(PlantRefusal::Directory(_))));
    Ok(())
}


#[test]
fn a_failed_write_after_the_create_removes_the_partial_token() -> TestResult {
    let dir = tree()?;
    let refusing = PlantOps {
        claim: fail_file_claim,
        ..ops(dir.path())
    };
    let report = plant_role(
        &role(vec![token("/var/backups/.canary", HoneytokenKind::Canary)]),
        &default_limits(),
        &refusing,
    )?;
    assert_eq!(refused_indexes(&report), [0]);
    assert!(!real(dir.path(), "/var/backups/.canary").exists());
    let rerun = plant(dir.path(), &role(vec![token("/var/backups/.canary", HoneytokenKind::Canary)]))?;
    assert!(rerun.refused.is_empty());
    Ok(())
}


#[test]
fn a_partial_token_replaced_by_another_file_is_left_alone() -> TestResult {
    let dir = tree()?;
    let refusing = PlantOps {
        claim: fail_file_claim,
        after_create: swap_created,
        ..ops(dir.path())
    };
    let report = plant_role(&role(vec![token("/var/.swapped", HoneytokenKind::Canary)]), &default_limits(), &refusing)?;
    assert_eq!(refused_indexes(&report), [0]);
    assert_eq!(fs::read_to_string(real(dir.path(), "/var/.swapped"))?, "other");
    Ok(())
}


#[test]
fn planting_is_refused_while_a_policy_is_loaded_and_writes_nothing() -> TestResult {
    let dir = tree()?;
    let loaded = PlantOps {
        list_policies: some_loaded,
        ..ops(dir.path())
    };
    let refused = plant_role(&three_tokens(), &default_limits(), &loaded);
    assert!(matches!(refused, Err(PlantError::PoliciesLoaded { count: TWO_LOADED })));
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);
    let unknown = PlantOps {
        list_policies: failing_list,
        ..ops(dir.path())
    };
    assert!(matches!(check_unloaded(&unknown), Err(PlantError::PolicyList(_))));
    assert!(check_unloaded(&ops(dir.path())).is_ok());
    Ok(())
}


#[test]
fn the_listing_counts_only_ostyr_fim_names() -> TestResult {
    assert_eq!(loaded_count("1 ostyr-fimt-a enabled\n2 ostyr-other x\n3 ostyr-fimp-b y"), TWO_LOADED);
    assert_eq!(loaded_count(""), 0);
    Ok(())
}


#[test]
fn the_real_listing_runs_the_binary_and_fails_closed() -> TestResult {
    executable("echo")?;
    assert_eq!(list_from("/bin/echo", TEST_DEADLINE)?, "tracingpolicy list\n");
    assert!(list_from("/bin/false", TEST_DEADLINE).is_err());
    assert!(list_from("/nonexistent/tetra", TEST_DEADLINE).is_err());
    assert!(list_from("/", TEST_DEADLINE).is_err());
    Ok(())
}


#[test]
fn a_listing_that_never_returns_is_cut_at_the_deadline_and_fails_closed() -> TestResult {
    executable("echo")?;
    let hang = format!("{}/tests/fixtures/tetra-hang.sh", env!("CARGO_MANIFEST_DIR"));
    let failure = list_from(&hang, Duration::ZERO).err().ok_or("a hanging listing succeeded")?;
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    Ok(())
}


#[test]
fn an_endless_listing_is_refused_as_too_long() -> TestResult {
    executable("echo")?;
    let failure = list_from("/usr/bin/yes", TEST_DEADLINE).err().ok_or("an endless listing succeeded")?;
    assert!(failure.to_string().contains("too long"));
    Ok(())
}


#[test]
fn a_failed_output_rename_leaves_no_staged_file() -> TestResult {
    let dir = tree()?;
    fs::create_dir(dir.path().join("planted.tsv"))?;
    let fixed = PlantOps {
        fill_random: fixed_random,
        ..ops(dir.path())
    };
    let failed = linux_fim::plant::write_planted(&fixed, &dir.path().join("planted.tsv"), &[]);
    assert!(failed.is_err());
    let names: Vec<String> = fs::read_dir(dir.path())?
        .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()?;
    assert_eq!(names, vec!["planted.tsv".to_string()]);
    Ok(())
}


#[test]
fn the_os_listing_reads_the_host_without_failing_on_a_missing_tetra() -> TestResult {
    executable("echo")?;
    let listing = os_list_policies();
    assert!(listing.map_or(true, |text| loaded_count(&text) < usize::MAX));
    Ok(())
}


fn left_running_listing(group_leader: &mpsc::Sender<u32>) -> TestResult {
    let dir = tree()?;
    let lock = dir.path().join("lock");
    let mut child = spawn_listing("/usr/bin/flock", &[lock.to_str().ok_or("path")?, "/usr/bin/yes"])?;
    group_leader.send(child.id())?;
    let mut held = File::from(OwnedFd::from(child.stdout.take().ok_or("no output pipe")?));
    wait_readable(&held, Instant::now() + TEST_DEADLINE)?;
    let (stand_in, closed) = io::pipe()?;
    drop(closed);
    child.stdout = Some(ChildStdout::from(OwnedFd::from(stand_in)));
    let failure = read_listing(child, Duration::ZERO).err().ok_or("a running listing succeeded")?;
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    assert!(drain_to_end(&mut held)?);
    Ok(())
}


fn watch_for_a_hang(leader: &mpsc::Receiver<u32>, finished: &mpsc::Receiver<()>, fired: &AtomicBool) {
    let pid = leader
        .recv_timeout(HANG_GUARD)
        .ok()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    finished.recv_timeout(HANG_GUARD).err().iter().for_each(|_| {
        fired.store(true, Ordering::SeqCst);
        pid.iter().for_each(|group| {
            kill_process_group(*group, Signal::KILL).map_or_else(|errno| assert_eq!(errno, Errno::SRCH), drop);
        });
    });
}


#[test]
fn a_listing_left_running_is_cut_at_the_deadline_and_its_group_is_killed() -> TestResult {
    let (leader_sender, leader) = mpsc::channel();
    let (finished_sender, finished) = mpsc::channel();
    let fired = std::sync::Arc::new(AtomicBool::new(false));
    let watched = std::sync::Arc::clone(&fired);
    let watchdog = std::thread::spawn(move || watch_for_a_hang(&leader, &finished, &watched));
    let outcome = left_running_listing(&leader_sender);
    finished_sender.send(())?;
    watchdog.join().map_err(|_| "the watchdog panicked")?;
    assert!(!fired.load(Ordering::SeqCst), "the exit wait hung and the watchdog killed the group");
    outcome
}


fn rename_leaf_away(parent: &OwnedFd, name: &str) {
    assert!(renameat(parent, name, parent, "moved-away").is_ok());
}


#[test]
fn a_failed_cleanup_keeps_the_refusal_that_started_it() -> TestResult {
    let dir = tree()?;
    let parent = OwnedFd::from(File::open(dir.path())?);
    let handle = OwnedFd::from(OpenOptions::new().write(true).create_new(true).open(dir.path().join("leaf"))?);
    let hooked = PlantOps {
        claim: fail_file_claim,
        after_create: rename_leaf_away,
        ..ops(dir.path())
    };
    let failure = fresh_token(&hooked, geteuid().as_raw(), &parent, "leaf", handle, "content")
        .err()
        .ok_or("a refused claim passed")?;
    assert!(matches!(failure, PlantRefusal::Io(ref error) if error.kind() == io::ErrorKind::PermissionDenied));
    assert!(
        matches!(first_refusal(PlantRefusal::Io(io::Error::other("first")), Err(Errno::IO)), Err(PlantRefusal::Io(ref error)) if error.to_string() == "first")
    );
    assert!(first_refusal(PlantRefusal::Io(io::Error::other("first")), Ok(())).is_err());
    Ok(())
}


#[test]
fn a_group_already_gone_or_a_child_already_reaped_is_not_a_failure() -> TestResult {
    executable("echo")?;
    assert!(group_outcome(Ok(())).is_none());
    assert!(group_outcome(Err(Errno::SRCH)).is_none());
    assert!(group_outcome(Err(Errno::PERM)).is_some());
    assert!(own_outcome(Ok(())).is_none());
    assert!(own_outcome(Err(io::Error::from(io::ErrorKind::InvalidInput))).is_none());
    assert!(own_outcome(Err(io::Error::from(io::ErrorKind::PermissionDenied))).is_some());
    let mut quick = Command::new("/bin/true").spawn()?;
    quick.wait()?;
    assert!(own_outcome(quick.kill()).is_none());
    reap(&mut quick);
    Ok(())
}


#[test]
fn a_skipped_candidate_gives_way_to_the_next_one_and_an_all_bad_list_fails_closed() -> TestResult {
    let dir = tree()?;
    let owner = geteuid().as_raw();
    let bad = dir.path().join("bad");
    fs::create_dir(&bad)?;
    let bad_tetra = good_tetra(&bad)?;
    fs::set_permissions(&bad_tetra, fs::Permissions::from_mode(WORLD_WRITABLE))?;
    let good_path = executable("echo")?;
    let bad_text = bad_tetra.to_str().ok_or("path")?;
    let good_text = good_path.to_str().ok_or("path")?;
    assert_eq!(picked(&[bad_text, good_text], owner)?.as_deref(), Some(good_text));
    assert_eq!(picked(&["/nonexistent/tetra", bad_text, good_text], owner)?.as_deref(), Some(good_text));
    assert!(pick_binary(&[bad_text, "/nonexistent/tetra"], owner).is_err());
    assert!(pick_binary(&["/nonexistent/tetra", bad_text], owner).is_err());
    assert_eq!(
        list_first(&[bad_text, good_text], owner, TEST_DEADLINE)?,
        "tracingpolicy list
"
    );
    assert!(list_first(&[bad_text], owner, TEST_DEADLINE).is_err());
    Ok(())
}


fn drain_to_end(held: &mut File) -> io::Result<bool> {
    let mut chunk = [u8::MIN; DRAIN_CHUNK];
    let mut ended = false;
    let mut reads = 0;
    while !ended && reads < MAX_DRAIN_READS {
        wait_readable(held, Instant::now() + TEST_DEADLINE)?;
        ended = held.read(&mut chunk)? == 0;
        reads += 1;
    }
    Ok(ended)
}


#[test]
fn waiting_for_an_exit_stops_at_the_deadline_and_sees_an_exit() -> TestResult {
    executable("echo")?;
    let mut running = Command::new("/bin/sleep").arg("3600").spawn()?;
    let timed_out = wait_until(&mut running, Instant::now()).err().ok_or("a running child exited")?;
    assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);
    reap(&mut running);
    assert!(running.try_wait()?.is_some());
    reap(&mut running);
    let mut quick = Command::new("/bin/true").spawn()?;
    assert!(wait_until(&mut quick, Instant::now() + TEST_DEADLINE)?.success());
    Ok(())
}


fn feed_one_byte_at_a_time(mut writer: PipeWriter, probe: PipeReader) -> io::Result<()> {
    (0..SMALL_READS).try_for_each(|_| {
        writer.write_all(b"x")?;
        (0..MAX_SPINS)
            .find(|_| {
                std::thread::yield_now();
                ioctl_fionread(&probe).map_or(true, |pending| pending == 0)
            })
            .map(drop)
            .ok_or(io::Error::other("a byte was never read"))
    })
}


#[test]
fn a_listing_in_many_small_reads_is_accepted() -> TestResult {
    let (reader, writer) = io::pipe()?;
    let probe = reader.try_clone()?;
    let feeder = std::thread::spawn(move || feed_one_byte_at_a_time(writer, probe));
    let bytes = read_until(&mut File::from(OwnedFd::from(reader)), Instant::now() + TEST_DEADLINE)?;
    feeder.join().map_err(|_| "the feeder panicked")??;
    assert_eq!(bytes.len(), SMALL_READS);
    Ok(())
}


fn good_tetra(dir: &Path) -> Result<PathBuf, io::Error> {
    let tetra = dir.join("tetra");
    fs::write(&tetra, "")?;
    fs::set_permissions(&tetra, fs::Permissions::from_mode(WORLD_READABLE))?;
    Ok(tetra)
}


fn picked(candidates: &[&str], owner: u32) -> io::Result<Option<String>> {
    pick_binary(candidates, owner).map(|found| found.map(|(path, _handle)| path.to_string()))
}


fn refused(path: &Path, owner: u32) -> Result<io::Error, Box<dyn Error>> {
    let text = path.to_str().ok_or("path")?;
    let error = pick_binary(&[text], owner).err().ok_or("a bad tetra was picked")?;
    assert_ne!(error.kind(), io::ErrorKind::NotFound);
    Ok(error)
}


#[test]
fn the_tetra_binary_is_the_first_existing_trusted_candidate() -> TestResult {
    let dir = tree()?;
    let present = good_tetra(dir.path())?;
    let present_text = present.to_str().ok_or("path")?;
    let owner = geteuid().as_raw();
    assert_eq!(picked(&["/nonexistent/tetra", present_text], owner)?.as_deref(), Some(present_text));
    assert_eq!(picked(&["/nonexistent/tetra"], owner)?, None);
    assert!(pick_binary(&["/etc/passwd/tetra"], owner).is_err());
    assert!(pick_binary(&["tetra"], owner).is_err());
    assert_eq!(list_first(&["/nonexistent/tetra"], owner, TEST_DEADLINE)?, "");
    let echo = executable("echo")?;
    assert_eq!(list_first(&[echo.to_str().ok_or("path")?], owner, TEST_DEADLINE)?, "tracingpolicy list\n");
    log_reap_failure(&io::Error::other("reap"));
    Ok(())
}


#[test]
fn a_root_owned_tetra_that_anyone_can_write_is_refused() -> TestResult {
    let dir = tree()?;
    let tetra = good_tetra(dir.path())?;
    fs::set_permissions(&tetra, fs::Permissions::from_mode(WORLD_WRITABLE))?;
    assert!(refused(&tetra, geteuid().as_raw())?.to_string().contains("writable"));
    fs::set_permissions(&tetra, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    refused(&tetra, geteuid().as_raw())?;
    Ok(())
}


#[test]
fn a_tetra_in_a_shared_directory_or_below_one_is_refused() -> TestResult {
    let dir = tree()?;
    let shared = dir.path().join("shared");
    fs::create_dir(&shared)?;
    let tetra = good_tetra(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(WORLD_WRITABLE))?;
    refused(&tetra, geteuid().as_raw())?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(WORLD_READABLE))?;
    let inner = shared.join("inner");
    fs::create_dir(&inner)?;
    let below = good_tetra(&inner)?;
    assert_eq!(picked(&[below.to_str().ok_or("path")?], geteuid().as_raw())?.as_deref(), below.to_str());
    fs::set_permissions(&shared, fs::Permissions::from_mode(GROUP_WRITABLE))?;
    refused(&below, geteuid().as_raw())?;
    Ok(())
}


#[test]
fn a_symlink_to_a_good_tetra_is_refused() -> TestResult {
    let dir = tree()?;
    let tetra = good_tetra(dir.path())?;
    let link = dir.path().join("link");
    symlink(&tetra, &link)?;
    refused(&link, geteuid().as_raw())?;
    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("absent"), &dangling)?;
    refused(&dangling, geteuid().as_raw())?;
    Ok(())
}


#[test]
fn a_tetra_that_is_not_a_plain_root_owned_file_fails_the_verdict() -> TestResult {
    let dir = tree()?;
    refused(dir.path(), geteuid().as_raw())?;
    Ok(())
}


#[test]
fn a_checked_tetra_that_cannot_start_is_an_error_not_an_empty_listing() -> TestResult {
    let tetra = executable("broken")?;
    let text = tetra.to_str().ok_or("path")?;
    assert_eq!(picked(&[text], geteuid().as_raw())?.as_deref(), Some(text));
    let failure = list_first(&[text], geteuid().as_raw(), TEST_DEADLINE)
        .err()
        .ok_or("a missing interpreter read as no policy")?;
    assert_eq!(failure.kind(), io::ErrorKind::NotFound);
    Ok(())
}


#[test]
fn a_failed_cleanup_keeps_the_first_cause() -> TestResult {
    assert!(matches!(first_cause(PlantError::OutputPath, Err(Errno::IO)), Err(PlantError::OutputPath)));
    assert!(matches!(first_cause(PlantError::OutputPath, Ok(())), Err(PlantError::OutputPath)));
    Ok(())
}


#[test]
fn a_listing_failure_keeps_its_cause_as_the_source() -> TestResult {
    let failure = PlantError::PolicyList(io::Error::other("tetra failed"));
    assert_eq!(failure.source().ok_or("no source")?.to_string(), "tetra failed");
    Ok(())
}


fn swap_in_the_decoy(binary: &str) {
    let moved = format!("{binary}.moved");
    let decoy = format!("{binary}.decoy");
    fs::rename(binary, moved)
        .and_then(|()| fs::rename(decoy, binary))
        .unwrap_or_else(|error| {
            tracing::error!(%error, "swap failed");
        });
}


fn remove_the_binary(binary: &str) {
    fs::remove_file(binary).unwrap_or_else(|error| {
        tracing::error!(%error, "remove failed");
    });
}


#[test]
fn a_rename_between_the_pick_and_the_spawn_refuses_the_listing() -> TestResult {
    let dir = tree()?;
    let tetra = good_tetra(dir.path())?;
    fs::copy(&tetra, dir.path().join("tetra.decoy"))?;
    let text = tetra.to_str().ok_or("path")?;
    let failure = list_first_with(&[text], geteuid().as_raw(), TEST_DEADLINE, swap_in_the_decoy)
        .err()
        .ok_or("a swapped tetra was listed")?;
    assert_eq!(failure.to_string(), PROGRAM_CHANGED);
    assert!(dir.path().join("tetra.moved").exists());
    Ok(())
}


#[test]
fn a_binary_that_vanishes_before_the_spawn_is_a_refusal_not_no_policy() -> TestResult {
    let dir = tree()?;
    let tetra = good_tetra(dir.path())?;
    let text = tetra.to_str().ok_or("path")?;
    let failure = list_first_with(&[text], geteuid().as_raw(), TEST_DEADLINE, remove_the_binary)
        .err()
        .ok_or("a vanished tetra read as no policy")?;
    assert_eq!(failure.to_string(), PROGRAM_CHANGED);
    Ok(())
}


#[test]
fn a_tetra_owned_by_the_nobody_user_is_skipped_under_the_production_owner() -> TestResult {
    let dir = tree()?;
    let foreign = dir.path().join("foreign");
    fs::create_dir(&foreign)?;
    let tetra = good_tetra(&foreign)?;
    let text = tetra.to_str().ok_or("path")?;
    let echo = executable("echo")?;
    let echo_text = echo.to_str().ok_or("path")?;
    geteuid().is_root().then_some(()).map_or(Ok(()), |()| {
        chown(&tetra, Some(NOBODY), None)?;
        assert!(pick_binary(&[text], TETRA_OWNER_UID).is_err());
        assert_eq!(list_first(&[text, echo_text], TETRA_OWNER_UID, TEST_DEADLINE)?, "tracingpolicy list\n");
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn a_tetra_without_the_owner_execute_bit_is_refused() -> TestResult {
    let dir = tree()?;
    let tetra = good_tetra(dir.path())?;
    fs::set_permissions(&tetra, fs::Permissions::from_mode(OTHER_READABLE))?;
    assert!(refused(&tetra, geteuid().as_raw())?.to_string().contains("execute"));
    Ok(())
}
