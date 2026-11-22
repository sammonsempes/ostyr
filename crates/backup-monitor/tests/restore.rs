#![cfg(unix)]
use backup_monitor::declarations::load_declarations;
use backup_monitor::error::BackupError;
use backup_monitor::model::{Limits, ResticSource, RestoreTest, SkipReason};
use backup_monitor::restic::ResticError;
use backup_monitor::restore::{
    choose, covers, digest_hex, dump_arguments, judge, listing_gap, outcome_label, restore_plan, restore_test, valid_canary_path, valid_test,
    RestoreOutcome, CANARY_FILE_NAME, MAX_CANARY_BYTES,
};
use net_topology::model::RunFailure;
use std::error::Error;
use std::fs::{set_permissions, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use time::macros::datetime;
use time::OffsetDateTime;


const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-restic-dump.sh");


const CONFIG_ID: &str = "8ff9e8256a6089f1357840c0fc88b498c541e8948af3317219d4117ce4243ab5";


const CANARY_PATH: &str = "/data/.ostyr-restore-canary";


const CANARY_CONTENT: &str = "canary-v1\n";


const PATIENT: Duration = Duration::from_secs(120);


const IMPATIENT: Duration = Duration::from_secs(2);


const SMALL_CAP: u64 = 1024;


const BIG_CAP: u64 = 8192;


const SCRIPT_MODE: &str = "755";


const SECRET_MODE: u32 = 0o600;


const GROUP_READABLE_MODE: u32 = 0o640;


const GONE_ATTEMPTS: usize = 100;


const GONE_POLL: Duration = Duration::from_millis(50);


const FAILED_CODE: i32 = 2;


const RUNS_WITH_DUMP: usize = 3;


const RUNS_WITHOUT_DUMP: usize = 2;


const SHA_HEX_LEN: usize = 64;


const NOW: OffsetDateTime = datetime!(2026-11-22 12:00:00 UTC);


const MIDDAY_BEFORE: OffsetDateTime = datetime!(2026-11-21 12:00:00 UTC);


const NEWEST_GOOD_TIME: OffsetDateTime = datetime!(2026-11-21 10:00:00 UTC);


const REFUSED_INDEXES: [usize; 4] = [1, 2, 3, 4];


const LONG_PATH_BYTES: usize = 2000;


const TOO_MANY_PATHS: usize = 257;


const DECLARATIONS: &str = "tenant: acme\nrepositories:\n  - repository: main\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/repo\n      \
                            password_file: /etc/restic-pw\n    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      sha256: ";


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


struct Setup {
    dir: TempDir,
    program: PathBuf,
    source: ResticSource,
    test: RestoreTest,
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
    let password = dir.path().join("password");
    std::fs::write(&password, "hunter2\n")?;
    set_permissions(&password, Permissions::from_mode(SECRET_MODE))?;
    let source = ResticSource {
        location: "/srv/repo".to_owned(),
        password_file: password.display().to_string(),
    };
    let test = RestoreTest {
        host: "web1".to_owned(),
        path: CANARY_PATH.to_owned(),
        sha256: digest_hex(CANARY_CONTENT.as_bytes()),
        max_bytes: SMALL_CAP,
    };
    Ok(Setup { dir, program, source, test })
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
        &declarations.tenant,
        &setup.source,
        &setup.test,
        &Limits::default(),
        PATIENT,
        clock,
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
    let password = &setup.source.password_file;
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
    let setup = setup("hold", &good_snapshots())?;
    let declarations = load_declarations("tenant: acme\n", "d.yaml")?;
    let result = restore_test(
        &setup.program,
        &declarations.tenant,
        &setup.source,
        &setup.test,
        &Limits::default(),
        IMPATIENT,
        clock,
    )?;
    assert_eq!(result.outcome, RestoreOutcome::Timeout);
    let pid = std::fs::read_to_string(setup.dir.path().join("grandchild"))?.trim().to_owned();
    let gone = (0..GONE_ATTEMPTS).any(|_| {
        std::thread::sleep(GONE_POLL);
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    });
    assert!(gone);
    let sleeping = self::setup("sleep", &good_snapshots())?;
    assert_eq!(
        restore_test(
            &sleeping.program,
            &declarations.tenant,
            &sleeping.source,
            &sleeping.test,
            &Limits::default(),
            IMPATIENT,
            clock
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
         - repository: badpath\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/repo\n      password_file: /etc/restic-pw\n    restore_test:\n      \
         host: web1\n      path: /etc/shadow\n      sha256: {digest}\n      max_bytes: 10\n  \
         - repository: norestic\n    expected_min_snapshots: 1\n    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      \
         sha256: {digest}\n      max_bytes: 10\n  \
         - repository: both\n    expected_min_snapshots: 1\n    restic:\n      location: /srv/repo\n      password_file: /etc/restic-pw\n    borg:\n      \
         location: ssh://u@h/p\n      passphrase_file: /etc/x\n    restore_test:\n      host: web1\n      path: /data/.ostyr-restore-canary\n      \
         sha256: {digest}\n      max_bytes: 10\n  \
         - repository: badsource\n    expected_min_snapshots: 1\n    restic:\n      location: -r\n      password_file: /etc/restic-pw\n    restore_test:\n      \
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
    set_permissions(&setup.source.password_file, Permissions::from_mode(GROUP_READABLE_MODE))?;
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
        password_file: "/pw".to_owned(),
    };
    let transport = vec!["-o".to_owned(), "x".to_owned()];
    let vector = dump_arguments(&source, &transport, "ID", CANARY_PATH);
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
    assert!(matches!(run(&setup)?.outcome, RestoreOutcome::ListingGap { future: 0, .. }));
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
            future: 0
        }
    );
    let mut future = good_snapshots();
    future.push(snapshot('5', "9999-01-01T00:00:00Z", "web1", "\"/data\""));
    let second = setup("ok", &future)?;
    assert_eq!(
        run(&second)?.outcome,
        RestoreOutcome::ListingGap {
            skipped: Default::default(),
            future: 1
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
    assert!(listing_gap(&listing, "web1", clock()).is_none());
    assert!(listing_gap(&listing, "web2", clock()).is_some());
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
            },
            "listing_gap",
        ),
    ];
    all.iter().for_each(|(outcome, label)| assert_eq!(outcome_label(outcome), *label));
    Ok(())
}
