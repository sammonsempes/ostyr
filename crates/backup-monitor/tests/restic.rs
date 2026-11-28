#![cfg(unix)]
use backup_monitor::declarations::load_declarations;
use backup_monitor::error::BackupError;
use backup_monitor::model::{FindingKind, Limits, ResticSource};
use backup_monitor::restic::{
    config_id, findings, parse_run, plan, run_raw, snapshot_listing, unchanged, valid_authority, valid_location, valid_path, valid_source, RawRun,
    ResticError, MAX_LOCATION_BYTES,
};
use backup_monitor::secrets::{open_secrets_dir, SecretsDir, MAX_SECRET_NAME_BYTES};
use grandchild::{gone_within_guard, Grandchild};
use net_topology::model::RunFailure;
use std::error::Error;
use std::fs::{create_dir, set_permissions, File, Permissions};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;


#[path = "common/grandchild.rs"]
mod grandchild;


const CONFIG_ID: &str = "8ff9e8256a6089f1357840c0fc88b498c541e8948af3317219d4117ce4243ab5";


const OTHER_ID: &str = "66ebcb4aeb0ca5efc7d8211023adf4e91c6d815eed0da5d39a1385a9f725805a";


const CURRENT: &str = include_str!("fixtures/restic-current.json");


const PREVIOUS: &str = include_str!("fixtures/restic-previous.json");


const PRUNED: &str = include_str!("fixtures/restic-pruned.json");


const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-restic.sh");


const FAILED_CODE: i32 = 2;


const SCRIPT_MODE: &str = "755";


const PRIVATE_DIRECTORY_MODE: u32 = 0o700;


const SECRET_MODE: u32 = 0o600;


const GROUP_READABLE_MODE: u32 = 0o640;


const PATIENT: Duration = Duration::from_secs(120);


const IMPATIENT: Duration = Duration::from_millis(500);


const FLOOR: usize = 100;


const LONG_MARKER_BYTES: usize = 5000;


const TINY_CAP: u64 = 10;


const DECLARATIONS: &str =
    "tenant: acme\nrepositories:\n  - repository: main\n    expected_min_snapshots: 100\n    restic:\n      location: /srv/repo\n      \
                            password_file: restic-pw\n  - repository: bad\n    expected_min_snapshots: 1\n    restic:\n      location: -r\n      \
                            password_file: restic-pw\n  - repository: plain\n    expected_min_snapshots: 1\n";


struct Setup {
    dir: TempDir,
    program: PathBuf,
    source: ResticSource,
    secrets: SecretsDir,
}


fn setup(mode: &str) -> Result<Setup, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let program = dir.path().join("restic");
    let installed = Command::new("install").arg("-m").arg(SCRIPT_MODE).arg(SCRIPT).arg(&program).status()?;
    assert!(installed.success());
    std::fs::write(dir.path().join("mode"), mode)?;
    std::fs::write(dir.path().join("config.json"), format!("{{\"version\":2,\"id\":\"{CONFIG_ID}\"}}"))?;
    std::fs::write(dir.path().join("snapshots.json"), CURRENT)?;
    let password = dir.path().join("password");
    std::fs::write(&password, "hunter2\n")?;
    set_permissions(&password, Permissions::from_mode(SECRET_MODE))?;
    let source = ResticSource {
        location: "/srv/repo".to_owned(),
        password_file: "password".to_owned(),
    };
    set_permissions(dir.path(), Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
    let secrets = open_secrets_dir(dir.path(), rustix::process::geteuid().as_raw())?;
    Ok(Setup {
        dir,
        program,
        source,
        secrets,
    })
}


fn runs(setup: &Setup) -> usize {
    std::fs::read_to_string(setup.dir.path().join("args")).map_or(0, |text| text.lines().count())
}


fn text_chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |link: &&(dyn Error + 'static)| (**link).source())
        .map(|link| format!("{link} {link:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}


#[test]
fn locations_follow_the_grammar() -> Result<(), Box<dyn Error>> {
    assert!(valid_location("/srv/restic-repo_1.2+3"));
    assert!(valid_location("sftp:backup@host.example:/srv/restic"));
    assert!(valid_location("rest:https://host.example:8000/repo"));
    assert!(valid_location("rest:https://host.example/"));
    assert!(valid_authority("host"));
    let long = format!("/{}", "a".repeat(MAX_LOCATION_BYTES));
    let refused = [
        "-r",
        "--password-command=x",
        "repo",
        "sftp:backup@host",
        "sftp:backup@host:rel",
        "sftp:@host:/x",
        "sftp:-o@host:/x",
        "sftp:u@-host:/x",
        "sftp:u@host:/a/../b",
        "rest:http://host/x",
        "rest:https://host",
        "rest:https://user:pw@host/x",
        "rest:https://host:123456/x",
        "rest:https://host:/x",
        "rest:https://host:8a/x",
        "rest:https://-host/x",
        "rest:https://-host:80/x",
        "s3:bucket",
        "/srv/a b",
        "/srv/%2e%2e/x",
        "/srv/..",
        "/srv/\u{202e}x",
        "/srv/-x\n",
        &long,
    ];
    refused.iter().for_each(|text| assert!(!valid_location(text), "{text}"));
    Ok(())
}


#[test]
fn password_paths_follow_the_grammar() -> Result<(), Box<dyn Error>> {
    assert!(valid_path("/etc/restic.pw"));
    assert!(!valid_path("relative"));
    assert!(!valid_path("/etc/pw --x"));
    let long = "a".repeat(MAX_SECRET_NAME_BYTES + 1);
    let source = ResticSource {
        location: "/srv".to_owned(),
        password_file: long,
    };
    assert!(!valid_source(&source));
    Ok(())
}


#[test]
fn a_refused_entry_refuses_only_its_repository() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "d.yaml")?;
    let planned = plan(&declarations);
    assert_eq!(planned.refused, vec![1]);
    assert_eq!(planned.runnable.len(), 1);
    assert_eq!(planned.runnable.first().map(|(name, _)| *name), Some("main"));
    Ok(())
}


#[test]
fn the_argument_vector_is_fixed_and_the_listing_is_keyed_on_the_config_id() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let listing = snapshot_listing(
        &setup.program,
        &setup.secrets,
        &setup.source,
        &Limits::default(),
        PATIENT,
        rustix::process::geteuid().as_raw(),
    )?;
    assert_eq!(listing.repository, CONFIG_ID);
    assert!(!listing.snapshots.is_empty());
    let args = std::fs::read_to_string(setup.dir.path().join("args"))?;
    let password = setup.dir.path().join("password").display().to_string();
    let expected = format!("-r /srv/repo --password-file {password} --no-cache --no-lock --json cat config\n");
    let second = format!("-r /srv/repo --password-file {password} --no-cache --no-lock --json snapshots\n");
    assert_eq!(args, format!("{expected}{second}"));
    Ok(())
}


#[test]
fn an_sftp_location_names_the_ssh_program_explicitly() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    setup.source.location = "sftp:backup@host.example:/srv/restic".to_owned();
    snapshot_listing(
        &setup.program,
        &setup.secrets,
        &setup.source,
        &Limits::default(),
        PATIENT,
        rustix::process::geteuid().as_raw(),
    )?;
    let args = std::fs::read_to_string(setup.dir.path().join("args"))?;
    let first = args.lines().next().ok_or("no run")?;
    assert!(first.starts_with("-o sftp.command=/usr/bin/ssh -o BatchMode=yes backup@host.example -s sftp -r sftp:backup@host.example:/srv/restic "));
    Ok(())
}


#[test]
fn a_refused_declaration_spawns_nothing() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    setup.source.location = "-r".to_owned();
    assert!(matches!(
        run_raw(
            &setup.program,
            &setup.secrets,
            &setup.source,
            &Limits::default(),
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::Refused)
    ));
    assert_eq!(runs(&setup), 0);
    Ok(())
}


#[test]
fn a_group_readable_password_file_is_refused_before_any_spawn() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    set_permissions(setup.dir.path().join("password"), Permissions::from_mode(GROUP_READABLE_MODE))?;
    assert!(matches!(
        run_raw(
            &setup.program,
            &setup.secrets,
            &setup.source,
            &Limits::default(),
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::PasswordFile)
    ));
    assert_eq!(runs(&setup), 0);
    Ok(())
}


#[test]
fn a_missing_or_linked_password_file_is_refused_before_any_spawn() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let link = setup.dir.path().join("link");
    symlink(setup.dir.path().join("password"), &link)?;
    let linked = ResticSource {
        location: setup.source.location.clone(),
        password_file: "link".to_owned(),
    };
    let missing = ResticSource {
        location: setup.source.location.clone(),
        password_file: "absent".to_owned(),
    };
    let directory = setup.dir.path().join("directory");
    create_dir(&directory)?;
    let not_regular = ResticSource {
        location: setup.source.location.clone(),
        password_file: "directory".to_owned(),
    };
    [linked, missing, not_regular].iter().for_each(|source| {
        assert!(matches!(
            run_raw(
                &setup.program,
                &setup.secrets,
                source,
                &Limits::default(),
                PATIENT,
                rustix::process::geteuid().as_raw()
            ),
            Err(ResticError::PasswordFile)
        ))
    });
    assert_eq!(runs(&setup), 0);
    Ok(())
}


#[test]
fn a_password_file_swapped_for_a_symlink_during_the_run_fails_the_run() -> Result<(), Box<dyn Error>> {
    let setup = setup("swap")?;
    assert!(matches!(
        run_raw(
            &setup.program,
            &setup.secrets,
            &setup.source,
            &Limits::default(),
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::PasswordFileChanged)
    ));
    Ok(())
}


#[test]
fn a_password_file_removed_during_the_run_fails_the_run() -> Result<(), Box<dyn Error>> {
    let setup = setup("remove")?;
    assert!(matches!(
        run_raw(
            &setup.program,
            &setup.secrets,
            &setup.source,
            &Limits::default(),
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::Io)
    ));
    Ok(())
}


#[test]
fn unchanged_accepts_the_same_file() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let path = setup.dir.path().join("password").display().to_string();
    let handle = File::open(&path)?;
    unchanged(&handle, &path)?;
    Ok(())
}


#[test]
fn a_run_past_the_deadline_is_a_timeout() -> Result<(), Box<dyn Error>> {
    let setup = setup("sleep")?;
    assert!(matches!(
        run_raw(
            &setup.program,
            &setup.secrets,
            &setup.source,
            &Limits::default(),
            IMPATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::Timeout)
    ));
    Ok(())
}


#[test]
fn a_grandchild_holding_stdout_is_killed_with_the_group() -> Result<(), Box<dyn Error>> {
    let setup = setup("hold")?;
    let grandchild = Grandchild {
        pid_file: setup.dir.path().join("grandchild"),
    };
    assert!(matches!(
        run_raw(
            &setup.program,
            &setup.secrets,
            &setup.source,
            &Limits {
                max_bytes: TINY_CAP,
                ..Limits::default()
            },
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::Oversized)
    ));
    assert!(gone_within_guard(&grandchild)?);
    Ok(())
}


#[test]
fn output_over_the_cap_is_oversized() -> Result<(), Box<dyn Error>> {
    let config_over = setup("big")?;
    let first = run_raw(
        &config_over.program,
        &config_over.secrets,
        &config_over.source,
        &Limits::default(),
        PATIENT,
        rustix::process::geteuid().as_raw(),
    );
    assert!(matches!(first, Err(ResticError::Oversized)), "{first:?}");
    let snapshots_over = setup("ok")?;
    let limits = Limits {
        max_bytes: TINY_CAP,
        ..Limits::default()
    };
    assert!(matches!(
        run_raw(
            &snapshots_over.program,
            &snapshots_over.secrets,
            &snapshots_over.source,
            &limits,
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::Oversized)
    ));
    Ok(())
}


#[test]
fn a_failing_restic_keeps_no_stderr_text() -> Result<(), Box<dyn Error>> {
    let setup = setup("fail")?;
    let error = run_raw(
        &setup.program,
        &setup.secrets,
        &setup.source,
        &Limits::default(),
        PATIENT,
        rustix::process::geteuid().as_raw(),
    )
    .err()
    .ok_or("no error")?;
    assert!(matches!(error, ResticError::Failed { code: Some(1) }));
    let text = text_chain(&error);
    assert!(!text.contains("hunter2") && !text.contains("stderr") && !text.contains("/srv/repo"));
    Ok(())
}


#[test]
fn a_missing_program_is_a_spawn_error() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let missing = Path::new("/nonexistent/restic");
    assert!(matches!(
        run_raw(
            missing,
            &setup.secrets,
            &setup.source,
            &Limits::default(),
            PATIENT,
            rustix::process::geteuid().as_raw()
        ),
        Err(ResticError::Spawn)
    ));
    Ok(())
}


#[test]
fn run_failures_map_to_fixed_errors() -> Result<(), Box<dyn Error>> {
    assert!(matches!(ResticError::from(RunFailure::TimedOut), ResticError::Timeout));
    assert!(matches!(ResticError::from(RunFailure::TooLarge), ResticError::Oversized));
    assert!(matches!(
        ResticError::from(RunFailure::Failed {
            code: Some(FAILED_CODE),
            read: 0
        }),
        ResticError::Failed { code: Some(FAILED_CODE) }
    ));
    assert!(matches!(ResticError::from(RunFailure::Spawn), ResticError::Spawn));
    assert!(matches!(ResticError::from(RunFailure::Io), ResticError::Io));
    assert!(matches!(ResticError::from(RunFailure::Refused), ResticError::Refused));
    assert!(matches!(ResticError::from(RunFailure::Unwaitable), ResticError::Unwaitable));
    Ok(())
}


#[test]
fn a_bad_config_is_refused_without_its_text() -> Result<(), Box<dyn Error>> {
    let marker = "MARKER".repeat(LONG_MARKER_BYTES);
    let wrong_type = format!("{{\"id\":{{\"x\":\"{marker}\"}}}}");
    let wrong_value = format!("{{\"id\":\"{marker}\"}}");
    let bodies = [wrong_type.as_str(), wrong_value.as_str(), "{}", "not json", "{\"id\":\"ABCDEF\"}"];
    for body in bodies {
        let error = config_id(body.as_bytes()).err().ok_or("accepted")?;
        assert!(matches!(error, ResticError::BadConfig));
        assert!(!text_chain(&error).contains("MARKER"));
    }
    assert_eq!(config_id(format!("{{\"id\":\"{CONFIG_ID}\",\"more\":1}}").as_bytes())?, CONFIG_ID);
    Ok(())
}


#[test]
fn a_hostile_listing_keeps_no_text_in_any_error() -> Result<(), Box<dyn Error>> {
    let marker = "MARKER".repeat(LONG_MARKER_BYTES);
    let raw = RawRun {
        key: CONFIG_ID.to_owned(),
        snapshots: format!("{{\"x\":\"{marker}\"}}").into_bytes(),
    };
    let error = parse_run(&raw, &Limits::default()).err().ok_or("accepted")?;
    assert!(matches!(error, ResticError::Listing(BackupError::Malformed { .. })));
    assert!(!text_chain(&error).contains("MARKER"));
    let broken = RawRun {
        key: CONFIG_ID.to_owned(),
        snapshots: format!("[\"{marker}").into_bytes(),
    };
    let cut = parse_run(&broken, &Limits::default()).err().ok_or("accepted")?;
    assert!(matches!(cut, ResticError::Listing(BackupError::Json(_))));
    assert!(!text_chain(&cut).contains("MARKER"));
    Ok(())
}


fn listing_of(id: &str, snapshots: &str) -> Result<backup_monitor::model::Listing, ResticError> {
    parse_run(
        &RawRun {
            key: id.to_owned(),
            snapshots: snapshots.as_bytes().to_vec(),
        },
        &Limits::default(),
    )
}


#[test]
fn a_changed_config_id_is_one_repository_changed() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "d.yaml")?;
    let previous = listing_of(OTHER_ID, PREVIOUS)?;
    let current = listing_of(CONFIG_ID, PRUNED)?;
    let found = findings("main", Some(&previous), &current, &declarations);
    let changed = found
        .iter()
        .filter(
            |finding| matches!(&finding.kind, FindingKind::RepositoryChanged { previous: old, current: new } if old == OTHER_ID && new == CONFIG_ID),
        )
        .count();
    assert_eq!(changed, 1);
    assert!(!found.iter().any(|finding| matches!(finding.kind, FindingKind::Deleted { .. })));
    Ok(())
}


#[test]
fn the_same_config_id_reports_deletions_and_the_named_floor() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "d.yaml")?;
    let previous = listing_of(CONFIG_ID, PREVIOUS)?;
    let current = listing_of(CONFIG_ID, CURRENT)?;
    let found = findings("main", Some(&previous), &current, &declarations);
    assert!(found.iter().any(|finding| matches!(finding.kind, FindingKind::Deleted { .. })));
    assert!(found
        .iter()
        .any(|finding| finding.repository == "main" && matches!(finding.kind, FindingKind::RetentionBelowFloor { floor: FLOOR, .. })));
    Ok(())
}


#[test]
fn a_first_run_checks_the_floor_by_name_and_by_id() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "d.yaml")?;
    let current = listing_of(CONFIG_ID, CURRENT)?;
    let named = findings("main", None, &current, &declarations);
    assert_eq!(named.len(), 1);
    let by_id = load_declarations(
        &format!("tenant: acme\nrepositories:\n  - repository: {CONFIG_ID}\n    expected_min_snapshots: 100\n"),
        "d.yaml",
    )?;
    assert_eq!(findings(CONFIG_ID, None, &current, &by_id).len(), 1);
    Ok(())
}
