#![cfg(unix)]
use backup_monitor::declarations::load_declarations;
use backup_monitor::error::BackupError;
use backup_monitor::model::{Limits, ResticSource, RestoreTest, SkipReason};
use backup_monitor::restic::ResticError;
use backup_monitor::restore::{
    choose, covers, digest_hex, dump_arguments, id_gaps, judge, list_arguments, list_cap, listing_gap, outcome_label, parse_id_list, restore_plan,
    restore_test, skip_label, valid_canary_path, valid_test, RestoreOutcome, RestoreTarget, CANARY_FILE_NAME, ID_LINE_BYTES, MAX_CANARY_BYTES,
};
use backup_monitor::secrets::{open_secrets_dir, SecretsDir};
use grandchild::{gone_within_guard, Grandchild};
use net_topology::model::RunFailure;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{set_permissions, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use time::macros::datetime;
use time::OffsetDateTime;


#[path = "common/grandchild.rs"]
mod grandchild;


const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-restic-dump.sh");


const CONFIG_ID: &str = "8ff9e8256a6089f1357840c0fc88b498c541e8948af3317219d4117ce4243ab5";


const CANARY_PATH: &str = "/data/.ostyr-restore-canary";


const CANARY_CONTENT: &str = "canary-v1\n";


const PATIENT: Duration = Duration::from_secs(120);


const IMPATIENT: Duration = Duration::from_secs(2);


const SMALL_CAP: u64 = 1024;


const BIG_CAP: u64 = 8192;


const SCRIPT_MODE: &str = "755";


const PRIVATE_DIRECTORY_MODE: u32 = 0o700;


const SECRET_MODE: u32 = 0o600;


const GROUP_READABLE_MODE: u32 = 0o640;


const FAILED_CODE: i32 = 2;


const TWO_LINES: usize = 2;


const THREE_LINES: usize = 3;


const FOUR_LINES: usize = 4;


const FIVE_LINES: usize = 5;


const TWO_UNLISTED: u64 = 2;


const THREE_UNLISTED: u64 = 3;


const INVALID_UTF8: [u8; 3] = [0xff, 0xfe, b'\n'];


const RUNS_WITH_DUMP: usize = 4;


const RUNS_WITHOUT_DUMP: usize = 3;


const SHA_HEX_LEN: usize = 64;


const NOW: OffsetDateTime = datetime!(2026-11-22 12:00:00 UTC);


const MIDDAY_BEFORE: OffsetDateTime = datetime!(2026-11-21 12:00:00 UTC);


const NEWEST_GOOD_TIME: OffsetDateTime = datetime!(2026-11-21 10:00:00 UTC);


const REFUSED_INDEXES: [usize; 4] = [1, 2, 3, 4];


const LONG_PATH_BYTES: usize = 2000;


const TOO_MANY_PATHS: usize = 257;


const DECLARATIONS: &str =
    "tenant: acme\nrepositories:\n  - repository: main\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/repo\n      \
                            password_file: restic-pw\n    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      sha256: ";


fn clock() -> OffsetDateTime {
    NOW
}


fn id_of(digit: char) -> String {
    digit.to_string().repeat(SHA_HEX_LEN)
}


fn snapshot(digit: char, time: &str, host: &str, paths: &str) -> String {
    let id = id_of(digit);
    format!("{{\"time\":\"{time}\",\"paths\":[{paths}],\"hostname\":\"{host}\",\"id\":\"{id}\",\"short_id\":\"x\"}}")
}


fn id_lines(snapshots: &[String]) -> String {
    snapshots
        .iter()
        .filter_map(|text| {
            text.split_once("\"id\":\"")
                .map(|(_, rest)| rest.chars().take(SHA_HEX_LEN).collect::<String>())
        })
        .map(|id| format!("{id}\n"))
        .collect()
}


fn set_list(setup: &Setup, lines: &str) -> std::io::Result<()> {
    std::fs::write(setup.dir.path().join("list.txt"), lines)
}


struct Setup {
    dir: TempDir,
    program: PathBuf,
    source: ResticSource,
    test: RestoreTest,
    secrets: SecretsDir,
}


fn setup(mode: &str, snapshots: &[String]) -> Result<Setup, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let program = dir.path().join("restic");
    let installed = Command::new("install").arg("-m").arg(SCRIPT_MODE).arg(SCRIPT).arg(&program).status()?;
    assert!(installed.success());
    std::fs::write(dir.path().join("mode"), mode)?;
    std::fs::write(dir.path().join("canary"), CANARY_CONTENT)?;
    std::fs::write(dir.path().join("config.json"), format!("{{\"version\":2,\"id\":\"{CONFIG_ID}\"}}"))?;
    std::fs::write(dir.path().join("snapshots.json"), format!("[{}]", snapshots.join(",")))?;
    std::fs::write(dir.path().join("list.txt"), id_lines(snapshots))?;
    let password = dir.path().join("password");
    std::fs::write(&password, "hunter2\n")?;
    set_permissions(&password, Permissions::from_mode(SECRET_MODE))?;
    let source = ResticSource {
        location: "/srv/repo".to_owned(),
        password_file: "password".to_owned(),
    };
    let test = RestoreTest {
        host: "web1".to_owned(),
        path: CANARY_PATH.to_owned(),
        sha256: digest_hex(CANARY_CONTENT.as_bytes()),
        max_bytes: SMALL_CAP,
    };
    set_permissions(dir.path(), Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
    let secrets = open_secrets_dir(dir.path(), rustix::process::geteuid().as_raw())?;
    Ok(Setup {
        dir,
        program,
        source,
        test,
        secrets,
    })
}


fn good_snapshots() -> Vec<String> {
    vec![
        snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/data\""),
        snapshot('2', "2026-11-21T10:00:00Z", "web1", "\"/data\""),
        snapshot('3', "2026-11-22T10:00:00Z", "web2", "\"/data\""),
    ]
}


fn run(setup: &Setup) -> Result<backup_monitor::restore::RestoreResult, ResticError> {
    let declarations = load_declarations("tenant: acme\n", "d.yaml").map_err(ResticError::Listing)?;
    restore_test(
        &setup.program,
        &setup.secrets,
        &RestoreTarget {
            tenant: &declarations.tenant,
            source: &setup.source,
            test: &setup.test,
        },
        &Limits::default(),
        PATIENT,
        clock,
        rustix::process::geteuid().as_raw(),
    )
}


fn args(setup: &Setup) -> std::io::Result<String> {
    std::fs::read_to_string(setup.dir.path().join("args"))
}


fn runs(setup: &Setup) -> usize {
    args(setup).map_or(0, |text| text.lines().count())
}


fn text_chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |link: &&(dyn Error + 'static)| (**link).source())
        .map(|link| format!("{link} {link:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}


#[test]
fn a_matching_canary_is_restored_from_the_newest_snapshot_of_the_host_by_id() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    let result = run(&setup)?;
    assert_eq!(result.outcome, RestoreOutcome::Restored);
    assert_eq!(result.config_id, CONFIG_ID);
    assert_eq!(result.snapshot_id, Some(id_of('2')));
    assert_eq!(result.snapshot_time, Some(NEWEST_GOOD_TIME));
    assert_eq!(result.tested_at, clock());
    let password = setup.dir.path().join("password").display().to_string();
    let expected = format!(
        "-r /srv/repo --password-file {password} --no-cache --no-lock dump {} {CANARY_PATH}\n",
        id_of('2')
    );
    let recorded = args(&setup)?;
    assert!(recorded.ends_with(&expected), "{recorded}");
    assert!(!recorded.contains("latest"));
    assert_eq!(runs(&setup), RUNS_WITH_DUMP);
    assert!(!format!("{result:?}").contains(&setup.test.sha256));
    Ok(())
}


#[test]
fn a_wrong_digest_is_a_mismatch_without_the_digest_in_the_result() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok", &good_snapshots())?;
    setup.test.sha256 = digest_hex(b"other");
    let result = run(&setup)?;
    assert_eq!(result.outcome, RestoreOutcome::DigestMismatch);
    let shown = format!("{result:?}");
    assert!(!shown.contains(&digest_hex(CANARY_CONTENT.as_bytes())) && !shown.contains(&setup.test.sha256));
    Ok(())
}


#[test]
fn an_oversized_dump_is_too_large() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("big", &good_snapshots())?;
    setup.test.max_bytes = SMALL_CAP;
    assert_eq!(run(&setup)?.outcome, RestoreOutcome::TooLarge);
    setup.test.max_bytes = BIG_CAP;
    assert_eq!(run(&setup)?.outcome, RestoreOutcome::DigestMismatch);
    Ok(())
}


#[test]
fn a_dump_with_the_right_bytes_and_a_failing_exit_is_failed_and_keeps_no_text() -> Result<(), Box<dyn Error>> {
    let setup = setup("failed", &good_snapshots())?;
    let result = run(&setup)?;
    assert_eq!(result.outcome, RestoreOutcome::Failed { code: Some(1) });
    let shown = format!("{result:?}");
    assert!(!shown.contains("hunter2") && !shown.contains("/secret/path") && !shown.contains('\u{1b}'));
    Ok(())
}


#[test]
fn a_stalled_dump_times_out_and_the_group_is_killed() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("hold", &good_snapshots())?;
    let grandchild = Grandchild {
        pid_file: setup.dir.path().join("grandchild"),
    };
    setup.test.max_bytes = SMALL_CAP;
    let declarations = load_declarations("tenant: acme\n", "d.yaml")?;
    let result = restore_test(
        &setup.program,
        &setup.secrets,
        &RestoreTarget {
            tenant: &declarations.tenant,
            source: &setup.source,
            test: &setup.test,
        },
        &Limits::default(),
        PATIENT,
        clock,
        rustix::process::geteuid().as_raw(),
    )?;
    assert_eq!(result.outcome, RestoreOutcome::TooLarge);
    assert!(gone_within_guard(&grandchild)?);
    let sleeping = self::setup("sleep", &good_snapshots())?;
    assert_eq!(
        restore_test(
            &sleeping.program,
            &sleeping.secrets,
            &RestoreTarget {
                tenant: &declarations.tenant,
                source: &sleeping.source,
                test: &sleeping.test,
            },
            &Limits::default(),
            IMPATIENT,
            clock,
            rustix::process::geteuid().as_raw()
        )?
        .outcome,
        RestoreOutcome::Timeout
    );
    Ok(())
}


#[test]
fn a_swapped_password_file_discards_the_outcome() -> Result<(), Box<dyn Error>> {
    let setup = setup("swap", &good_snapshots())?;
    assert!(matches!(run(&setup), Err(ResticError::PasswordFileChanged)));
    Ok(())
}


#[test]
fn a_newer_snapshot_without_the_canary_path_is_not_covered_and_nothing_is_dumped() -> Result<(), Box<dyn Error>> {
    let snapshots = vec![
        snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/data\""),
        snapshot('2', "2026-11-21T10:00:00Z", "web1", "\"/et\", \"/data2\", \"/var\""),
    ];
    let setup = setup("ok", &snapshots)?;
    let result = run(&setup)?;
    assert_eq!(result.outcome, RestoreOutcome::NotCovered);
    assert_eq!(result.snapshot_id, Some(id_of('2')));
    assert_eq!(runs(&setup), RUNS_WITHOUT_DUMP);
    Ok(())
}


#[test]
fn no_snapshot_of_the_host_is_no_snapshot() -> Result<(), Box<dyn Error>> {
    let snapshots = vec![snapshot('3', "2026-11-22T10:00:00Z", "web2", "\"/data\"")];
    let setup = setup("ok", &snapshots)?;
    let result = run(&setup)?;
    assert_eq!(result.outcome, RestoreOutcome::NoSnapshot);
    assert_eq!((result.snapshot_id, result.snapshot_time), (None, None));
    assert_eq!(runs(&setup), RUNS_WITHOUT_DUMP);
    Ok(())
}


#[test]
fn choose_takes_the_newest_of_the_host_with_the_higher_id_on_a_tie() -> Result<(), Box<dyn Error>> {
    let snapshots = [
        snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/data\""),
        snapshot('5', "2026-11-21T10:00:00Z", "web1", "\"/data\""),
        snapshot('7', "2026-11-21T10:00:00Z", "web1", "\"/data\""),
        snapshot('6', "2026-11-21T10:00:00Z", "web1", "\"/data\""),
        snapshot('8', "2026-11-22T10:00:00Z", "web9", "\"/data\""),
        snapshot('9', "2026-11-22T12:04:00Z", "web1", "\"/data\""),
        snapshot('a', "2026-11-22T12:06:00Z", "web1", "\"/data\""),
    ];
    let listing = backup_monitor::parse::parse_restic(format!("[{}]", snapshots.join(",")).as_bytes(), CONFIG_ID, &Limits::default())?;
    let picked = choose(&listing.snapshots, "web1", clock());
    assert_eq!(picked.map(|found| found.id.clone()), Some(id_of('9')));
    let earlier = choose(&listing.snapshots, "web1", MIDDAY_BEFORE);
    assert_eq!(earlier.map(|found| found.id.clone()), Some(id_of('7')));
    assert!(choose(&listing.snapshots, "web3", clock()).is_none());
    let at_the_end_of_time = time::PrimitiveDateTime::MAX.assume_utc();
    let overflowing = choose(&listing.snapshots, "web1", at_the_end_of_time);
    assert_eq!(overflowing.map(|found| found.id.clone()), Some(id_of('a')));
    Ok(())
}


#[test]
fn covers_is_component_wise() -> Result<(), Box<dyn Error>> {
    let listing = backup_monitor::parse::parse_restic(
        format!("[{}]", snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/et\", \"/data/\"")).as_bytes(),
        CONFIG_ID,
        &Limits::default(),
    )?;
    let first = listing.snapshots.first().ok_or("none")?;
    assert!(covers(first, CANARY_PATH));
    assert!(!covers(first, "/etc/.ostyr-restore-canary"));
    assert!(!covers(first, "/data2/.ostyr-restore-canary"));
    assert!(covers(first, "/data/"));
    let file_itself = backup_monitor::parse::parse_restic(
        format!("[{}]", snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/data/.ostyr-restore-canary\"")).as_bytes(),
        CONFIG_ID,
        &Limits::default(),
    )?;
    assert!(covers(file_itself.snapshots.first().ok_or("none")?, CANARY_PATH));
    let root = backup_monitor::parse::parse_restic(
        format!("[{}]", snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/\"")).as_bytes(),
        CONFIG_ID,
        &Limits::default(),
    )?;
    assert!(covers(root.snapshots.first().ok_or("none")?, CANARY_PATH));
    Ok(())
}


#[test]
fn canary_paths_follow_the_grammar() -> Result<(), Box<dyn Error>> {
    assert!(valid_canary_path(CANARY_PATH));
    assert!(valid_canary_path("/.ostyr-restore-canary"));
    assert_eq!(CANARY_FILE_NAME, ".ostyr-restore-canary");
    let long = format!("/{}/{CANARY_FILE_NAME}", "a".repeat(LONG_PATH_BYTES));
    let refused = [
        "/etc/shadow",
        "/",
        "",
        "relative/.ostyr-restore-canary",
        "/data/../.ostyr-restore-canary",
        "/data/./.ostyr-restore-canary",
        "/data//.ostyr-restore-canary",
        "/data/.ostyr-restore-canary/",
        "/data/x.ostyr-restore-canary",
        "/dat\u{e9}/.ostyr-restore-canary",
        "/data/.ostyr-restore-canary/..",
        "/da ta/.ostyr-restore-canary",
        &long,
    ];
    refused.iter().for_each(|path| assert!(!valid_canary_path(path), "{path}"));
    Ok(())
}


#[test]
fn a_test_is_valid_only_with_every_field_valid() -> Result<(), Box<dyn Error>> {
    let good = setup("ok", &[])?.test;
    assert!(valid_test(&good));
    assert!(!valid_test(&RestoreTest {
        host: "-x".to_owned(),
        ..good.clone()
    }));
    assert!(!valid_test(&RestoreTest {
        path: "/etc/shadow".to_owned(),
        ..good.clone()
    }));
    assert!(!valid_test(&RestoreTest {
        sha256: "ABC".to_owned(),
        ..good.clone()
    }));
    assert!(!valid_test(&RestoreTest {
        sha256: "A".repeat(SHA_HEX_LEN),
        ..good.clone()
    }));
    assert!(!valid_test(&RestoreTest {
        max_bytes: u64::MIN,
        ..good.clone()
    }));
    assert!(!valid_test(&RestoreTest {
        max_bytes: MAX_CANARY_BYTES + 1,
        ..good.clone()
    }));
    assert!(valid_test(&RestoreTest {
        max_bytes: MAX_CANARY_BYTES,
        ..good.clone()
    }));
    assert!(valid_test(&RestoreTest { max_bytes: 1, ..good }));
    Ok(())
}


#[test]
fn a_bad_entry_refuses_only_its_own_test_by_index() -> Result<(), Box<dyn Error>> {
    let digest = digest_hex(b"x");
    let text = format!(
        "{DECLARATIONS}{digest}\n      max_bytes: 10\n  \
         - repository: badpath\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/repo\n      password_file: restic-pw\n    restore_test:\n      \
         host: web1\n      path: /etc/shadow\n      sha256: {digest}\n      max_bytes: 10\n  \
         - repository: norestic\n    expected_min_snapshots: 1\n    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      \
         sha256: {digest}\n      max_bytes: 10\n  \
         - repository: both\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/repo\n      password_file: restic-pw\n    borg:\n      \
         location: ssh://u@h/p\n      passphrase_file: x\n    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      \
         sha256: {digest}\n      max_bytes: 10\n  \
         - repository: badsource\n    expected_min_snapshots: 1\n    restic:\n      location: -r\n      password_file: restic-pw\n    restore_test:\n      \
         host: web1\n      path: /data/.ostyr-restore-canary\n      sha256: {digest}\n      max_bytes: 10\n  \
         - repository: plain\n    expected_min_snapshots: 1\n"
    );
    let declarations = load_declarations(&text, "d.yaml")?;
    let planned = restore_plan(&declarations);
    assert_eq!(planned.refused, REFUSED_INDEXES.to_vec());
    assert_eq!(planned.runnable.len(), 1);
    assert_eq!(planned.runnable.first().map(|(name, _, _)| *name), Some("main"));
    Ok(())
}


#[test]
fn a_refused_test_spawns_nothing_and_a_bad_password_file_too() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok", &good_snapshots())?;
    setup.test.path = "/etc/shadow".to_owned();
    assert!(matches!(run(&setup), Err(ResticError::Refused)));
    setup.test.path = CANARY_PATH.to_owned();
    setup.source.location = "-r".to_owned();
    assert!(matches!(run(&setup), Err(ResticError::Refused)));
    setup.source.location = "/srv/repo".to_owned();
    set_permissions(setup.dir.path().join("password"), Permissions::from_mode(GROUP_READABLE_MODE))?;
    assert!(matches!(run(&setup), Err(ResticError::PasswordFile)));
    assert_eq!(runs(&setup), 0);
    Ok(())
}


#[test]
fn a_hostile_listing_is_an_error_without_its_text() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok", &[])?;
    std::fs::write(setup.dir.path().join("snapshots.json"), "{\"MARKER\":1}")?;
    let error = run(&setup).err().ok_or("accepted")?;
    assert!(matches!(error, ResticError::Listing(BackupError::Malformed { .. })));
    assert!(!text_chain(&error).contains("MARKER"));
    std::fs::write(setup.dir.path().join("config.json"), "{}")?;
    assert!(matches!(run(&setup), Err(ResticError::BadConfig)));
    setup.program = PathBuf::from("/nonexistent/restic");
    assert!(matches!(run(&setup), Err(ResticError::Spawn)));
    Ok(())
}


#[test]
fn run_failures_of_the_dump_are_outcomes_or_fixed_errors() -> Result<(), Box<dyn Error>> {
    let test = setup("ok", &[])?.test;
    assert_eq!(judge(Ok(CANARY_CONTENT.as_bytes().to_vec()), &test)?, RestoreOutcome::Restored);
    assert_eq!(judge(Ok(Vec::new()), &test)?, RestoreOutcome::DigestMismatch);
    assert_eq!(judge(Err(RunFailure::TooLarge), &test)?, RestoreOutcome::TooLarge);
    assert_eq!(judge(Err(RunFailure::TimedOut), &test)?, RestoreOutcome::Timeout);
    assert_eq!(
        judge(
            Err(RunFailure::Failed {
                code: Some(FAILED_CODE),
                read: 0
            }),
            &test
        )?,
        RestoreOutcome::Failed { code: Some(FAILED_CODE) }
    );
    assert!(matches!(judge(Err(RunFailure::Spawn), &test), Err(ResticError::Spawn)));
    Ok(())
}


#[test]
fn the_dump_vector_carries_the_sftp_transport_and_no_json_flag() -> Result<(), Box<dyn Error>> {
    let source = ResticSource {
        location: "sftp:u@h:/r".to_owned(),
        password_file: "pw".to_owned(),
    };
    let transport = vec!["-o".to_owned(), "x".to_owned()];
    let vector = dump_arguments(&source, "/pw", &transport, "ID", CANARY_PATH);
    assert_eq!(
        vector,
        vec![
            "-o",
            "x",
            "-r",
            "sftp:u@h:/r",
            "--password-file",
            "/pw",
            "--no-cache",
            "--no-lock",
            "dump",
            "ID",
            CANARY_PATH
        ]
    );
    Ok(())
}


#[test]
fn a_skipped_snapshot_newer_than_the_chosen_one_is_a_gap_and_nothing_is_dumped() -> Result<(), Box<dyn Error>> {
    let bad_tag = format!(
        "{{\"time\":\"2026-11-21T11:00:00Z\",\"paths\":[\"/data\"],\"hostname\":\"web1\",\"tags\":[\"nightly run\"],\"id\":\"{}\",\"short_id\":\"x\"}}",
        id_of('4')
    );
    let mut snapshots = good_snapshots();
    snapshots.push(bad_tag);
    let setup = setup("ok", &snapshots)?;
    let result = run(&setup)?;
    let expected = RestoreOutcome::ListingGap {
        skipped: [(SkipReason::BadTags, 1)].into_iter().collect(),
        future: 0,
        unloadable: 0,
        unlisted: 0,
    };
    assert_eq!(result.outcome, expected);
    assert_eq!((result.snapshot_id, result.snapshot_time), (None, None));
    assert_eq!(runs(&setup), RUNS_WITHOUT_DUMP);
    Ok(())
}


#[test]
fn a_skipped_snapshot_of_another_host_is_also_a_gap() -> Result<(), Box<dyn Error>> {
    let other = format!(
        "{{\"time\":\"2026-11-21T11:00:00Z\",\"paths\":[\"/data\"],\"hostname\":\"web\u{e9}\",\"id\":\"{}\",\"short_id\":\"x\"}}",
        id_of('4')
    );
    let mut snapshots = good_snapshots();
    snapshots.push(other);
    let setup = setup("ok", &snapshots)?;
    assert!(matches!(
        run(&setup)?.outcome,
        RestoreOutcome::ListingGap {
            future: 0,
            unloadable: 0,
            ..
        }
    ));
    Ok(())
}


#[test]
fn too_many_paths_and_a_future_snapshot_of_the_host_are_gaps() -> Result<(), Box<dyn Error>> {
    let many = vec!["\"/a\""; TOO_MANY_PATHS].join(",");
    let mut snapshots = good_snapshots();
    snapshots.push(snapshot('4', "2026-11-21T11:00:00Z", "web1", &many));
    let first = setup("ok", &snapshots)?;
    let gap = run(&first)?.outcome;
    assert_eq!(
        gap,
        RestoreOutcome::ListingGap {
            skipped: [(SkipReason::BadPaths, 1)].into_iter().collect(),
            future: 0,
            unloadable: 0,
            unlisted: 0
        }
    );
    let mut future = good_snapshots();
    future.push(snapshot('5', "9999-01-01T00:00:00Z", "web1", "\"/data\""));
    let second = setup("ok", &future)?;
    assert_eq!(
        run(&second)?.outcome,
        RestoreOutcome::ListingGap {
            skipped: Default::default(),
            future: 1,
            unloadable: 0,
            unlisted: 0
        }
    );
    assert_eq!(runs(&second), RUNS_WITHOUT_DUMP);
    Ok(())
}


#[test]
fn a_future_snapshot_of_another_host_is_not_a_gap() -> Result<(), Box<dyn Error>> {
    let listing = backup_monitor::parse::parse_restic(
        format!("[{}]", snapshot('5', "9999-01-01T00:00:00Z", "web2", "\"/data\"")).as_bytes(),
        CONFIG_ID,
        &Limits::default(),
    )?;
    let listed: BTreeSet<String> = [id_of('5')].into_iter().collect();
    assert!(listing_gap(&listing, "web1", clock(), &listed).is_none());
    assert!(listing_gap(&listing, "web2", clock(), &listed).is_some());
    Ok(())
}


#[test]
fn outcome_labels_are_lowercase_names() -> Result<(), Box<dyn Error>> {
    let all = [
        (RestoreOutcome::Restored, "restored"),
        (RestoreOutcome::DigestMismatch, "digest_mismatch"),
        (RestoreOutcome::TooLarge, "too_large"),
        (RestoreOutcome::NotCovered, "not_covered"),
        (RestoreOutcome::NoSnapshot, "no_snapshot"),
        (RestoreOutcome::Failed { code: None }, "failed"),
        (RestoreOutcome::Timeout, "timeout"),
        (
            RestoreOutcome::ListingGap {
                skipped: Default::default(),
                future: 0,
                unloadable: 0,
                unlisted: 0,
            },
            "listing_gap",
        ),
    ];
    all.iter().for_each(|(outcome, label)| assert_eq!(outcome_label(outcome), *label));
    Ok(())
}


fn limits_of(max_snapshots: usize) -> Limits {
    Limits {
        max_snapshots,
        ..Limits::default()
    }
}


#[test]
fn a_snapshot_file_restic_ignores_is_an_unloadable_gap_and_nothing_is_dumped() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    set_list(&setup, &format!("{}\n{}\n{}\n{}\n", id_of('1'), id_of('2'), id_of('3'), id_of('7')))?;
    let result = run(&setup)?;
    assert_eq!(
        result.outcome,
        RestoreOutcome::ListingGap {
            skipped: Default::default(),
            future: 0,
            unloadable: 1,
            unlisted: 0
        }
    );
    assert_eq!((result.snapshot_id, result.snapshot_time), (None, None));
    assert_eq!(runs(&setup), RUNS_WITHOUT_DUMP);
    Ok(())
}


#[test]
fn a_snapshot_the_list_does_not_hold_is_an_unlisted_gap() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    set_list(&setup, &format!("{}\n{}\n", id_of('1'), id_of('3')))?;
    assert_eq!(
        run(&setup)?.outcome,
        RestoreOutcome::ListingGap {
            skipped: Default::default(),
            future: 0,
            unloadable: 0,
            unlisted: 1
        }
    );
    set_list(&setup, "")?;
    assert!(matches!(
        run(&setup)?.outcome,
        RestoreOutcome::ListingGap {
            unlisted: THREE_UNLISTED,
            ..
        }
    ));
    Ok(())
}


#[test]
fn the_list_call_uses_the_prefix_and_the_shared_flags_without_json() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    run(&setup)?;
    let password = setup.dir.path().join("password").display().to_string();
    let expected = format!("-r /srv/repo --password-file {password} --no-cache --no-lock list snapshots\n");
    assert!(args(&setup)?.contains(&expected));
    let source = ResticSource {
        location: "sftp:u@h:/r".to_owned(),
        password_file: "pw".to_owned(),
    };
    let transport = vec!["-o".to_owned(), "x".to_owned()];
    assert_eq!(
        list_arguments(&source, "/pw", &transport),
        vec![
            "-o",
            "x",
            "-r",
            "sftp:u@h:/r",
            "--password-file",
            "/pw",
            "--no-cache",
            "--no-lock",
            "list",
            "snapshots"
        ]
    );
    Ok(())
}


#[test]
fn a_bad_id_list_is_a_fixed_error() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    let marker = "MARKER-\u{1b}[31m";
    [
        format!("{}\nnot-an-id {marker}\n", id_of('1')),
        format!("{}\r\n", id_of('1')),
        format!("{}\n\n", id_of('1')),
        format!("{}\n", id_of('A')),
    ]
    .iter()
    .try_for_each(|lines| -> Result<(), Box<dyn Error>> {
        set_list(&setup, lines)?;
        let error = run(&setup).err().ok_or("accepted")?;
        assert!(matches!(error, ResticError::BadList));
        assert!(!text_chain(&error).contains("MARKER"));
        Ok(())
    })?;
    std::fs::write(setup.dir.path().join("list.txt"), INVALID_UTF8)?;
    assert!(matches!(run(&setup), Err(ResticError::BadList)));
    Ok(())
}


#[test]
fn too_many_list_lines_and_a_huge_output_are_fixed_errors() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    let declarations = load_declarations("tenant: acme\n", "d.yaml")?;
    let run_with = |limits: &Limits| {
        restore_test(
            &setup.program,
            &setup.secrets,
            &RestoreTarget {
                tenant: &declarations.tenant,
                source: &setup.source,
                test: &setup.test,
            },
            limits,
            PATIENT,
            clock,
            rustix::process::geteuid().as_raw(),
        )
    };
    assert!(matches!(
        run_with(&limits_of(TWO_LINES)),
        Err(ResticError::Listing(BackupError::TooManySnapshots { .. }))
    ));
    let three = limits_of(THREE_LINES);
    assert!(run_with(&three)?.outcome == RestoreOutcome::Restored);
    set_list(&setup, &format!("{}\n", id_of('1')).repeat(FIVE_LINES))?;
    assert!(matches!(run_with(&three), Err(ResticError::Oversized)));
    set_list(&setup, &format!("{}\n", id_of('1')).repeat(FOUR_LINES))?;
    assert!(matches!(run_with(&three), Err(ResticError::BadList)));
    set_list(&setup, &format!("{}\n", id_of('1')).repeat(THREE_LINES))?;
    assert!(matches!(
        run_with(&three)?.outcome,
        RestoreOutcome::ListingGap {
            unloadable: 0,
            unlisted: TWO_UNLISTED,
            ..
        }
    ));
    let listed = format!("{}\n", id_of('1')).repeat(THREE_LINES);
    assert!(parse_id_list(listed.as_bytes(), &limits_of(TWO_LINES)).is_err());
    assert_eq!(parse_id_list(listed.as_bytes(), &three)?.len(), 1);
    assert_eq!(list_cap(&three), ID_LINE_BYTES * (THREE_LINES as u64 + 1));
    assert_eq!(list_cap(&limits_of(usize::MAX)), u64::MAX);
    Ok(())
}


#[test]
fn a_failing_or_hanging_list_is_a_fixed_error_within_the_shared_deadline() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok", &good_snapshots())?;
    let declarations = load_declarations("tenant: acme\n", "d.yaml")?;
    std::fs::write(setup.dir.path().join("list_mode"), "fail")?;
    assert!(matches!(run(&setup), Err(ResticError::Failed { code: Some(1) })));
    std::fs::write(setup.dir.path().join("list_mode"), "hang")?;
    let hung = restore_test(
        &setup.program,
        &setup.secrets,
        &RestoreTarget {
            tenant: &declarations.tenant,
            source: &setup.source,
            test: &setup.test,
        },
        &Limits::default(),
        IMPATIENT,
        clock,
        rustix::process::geteuid().as_raw(),
    );
    assert!(matches!(hung, Err(ResticError::Timeout)));
    assert_eq!(runs(&setup), RUNS_WITHOUT_DUMP * TWO_LINES);
    Ok(())
}


#[test]
fn id_gaps_count_each_side_and_forgive_skipped_snapshots() -> Result<(), Box<dyn Error>> {
    let listing = backup_monitor::parse::parse_restic(
        format!(
            "[{},{}]",
            snapshot('1', "2026-11-20T10:00:00Z", "web1", "\"/data\""),
            snapshot('2', "2026-11-20T11:00:00Z", "web 1", "\"/data\"")
        )
        .as_bytes(),
        CONFIG_ID,
        &Limits::default(),
    )?;
    let listed: BTreeSet<String> = ['1', '2', '3'].iter().map(|digit| id_of(*digit)).collect();
    assert_eq!(id_gaps(&listing, &listed), (1, 0));
    let fewer: BTreeSet<String> = [id_of('2')].into_iter().collect();
    assert_eq!(id_gaps(&listing, &fewer), (0, 1));
    Ok(())
}


#[test]
fn skip_labels_are_fixed_lowercase_names() -> Result<(), Box<dyn Error>> {
    let all = [
        (SkipReason::BadId, "bad_id"),
        (SkipReason::BadTime, "bad_time"),
        (SkipReason::BadHost, "bad_host"),
        (SkipReason::BadName, "bad_name"),
        (SkipReason::BadPaths, "bad_paths"),
        (SkipReason::BadTags, "bad_tags"),
        (SkipReason::BadField, "bad_field"),
        (SkipReason::Duplicate, "duplicate"),
    ];
    all.iter().for_each(|(reason, label)| assert_eq!(skip_label(reason), *label));
    Ok(())
}
