#![cfg(unix)]
use backup_monitor::borg::{
    base_directory, environment, fill, io_failure, parse_run, plan, private_directory, read_capped, run_raw, snapshot_listing, valid_location,
    valid_source, BorgError, MAX_PASSPHRASE_BYTES, MODE_MASK,
};
use backup_monitor::declarations::load_declarations;
use backup_monitor::error::BackupError;
use backup_monitor::model::{BorgSource, Limits};
use backup_monitor::restic::{plan as restic_plan, valid_authority, valid_port, MAX_LOCATION_BYTES};
use core_pg::scope::{tenant_scope, TenantScope};
use net_topology::model::RunFailure;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{create_dir_all, set_permissions, Permissions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;


const REPOSITORY_ID: &str = "41d98df912d10fb87c88abe9ff5fed1138c452f4e8c1ac0ff934aa6662a24e34";


const ARCHIVE_ID: &str = "ebee92e1570e4165d7426074084cca7d99acb4a798606718d9a65fb659d8d087";


const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake-borg.sh");


const SCRIPT_MODE: &str = "755";


const SECRET_MODE: u32 = 0o600;


const GROUP_READABLE_MODE: u32 = 0o640;


const OPEN_MODE: u32 = 0o755;


const GROUP_MODE: u32 = 0o750;


const PRIVATE: u32 = 0o700;


const DIRECTORY_PRIVATE: u32 = 0o40700;


const FILE_PRIVATE: u32 = 0o100700;


const DIRECTORY_GROUP: u32 = 0o40750;


const VARIABLE_COUNT: usize = 7;


const BOTH_INDEX: usize = 2;


const SEEN_RUNS: usize = 2;


const PASSPHRASE: &str = "correct horse battery staple\n";


const PATIENT: Duration = Duration::from_secs(120);


const IMPATIENT: Duration = Duration::from_millis(500);


const LONG_MARKER_BYTES: usize = 5000;


const TINY_CAP: u64 = 10;


const FAILED_CODE: i32 = 2;


const WARNING_CODE: i32 = 1;


const GONE_ATTEMPTS: usize = 100;


const GONE_POLL: Duration = Duration::from_millis(50);


const DECLARATIONS: &str = "tenant: acme\nrepositories:\n  - repository: main\n    expected_min_snapshots: 1\n    borg:\n      location: /srv/borg\n      \
                            passphrase_file: /etc/borg-pw\n  - repository: bad\n    expected_min_snapshots: 1\n    borg:\n      location: -r\n      \
                            passphrase_file: /etc/borg-pw\n  - repository: both\n    expected_min_snapshots: 1\n    borg:\n      location: /srv/borg\n      \
                            passphrase_file: /etc/borg-pw\n    restic:\n      location: /srv/restic\n      password_file: /etc/restic-pw\n  - repository: \
                            plain\n    expected_min_snapshots: 1\n";


struct Setup {
    dir: TempDir,
    program: PathBuf,
    state: PathBuf,
    source: BorgSource,
    tenant: TenantScope,
}


fn setup(mode: &str) -> Result<Setup, Box<dyn Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let program = dir.path().join("borg");
    let installed = Command::new("install").arg("-m").arg(SCRIPT_MODE).arg(SCRIPT).arg(&program).status()?;
    assert!(installed.success());
    std::fs::write(dir.path().join("mode"), mode)?;
    let listing = format!(
        "{{\"repository\":{{\"id\":\"{REPOSITORY_ID}\"}},\"archives\":[{{\"name\":\"srv1-1\",\"id\":\"{ARCHIVE_ID}\",\"time\":\"2026-11-12T13:30:39.000000\"}}]}}"
    );
    std::fs::write(dir.path().join("list.json"), listing)?;
    let passphrase = dir.path().join("passphrase");
    std::fs::write(&passphrase, PASSPHRASE)?;
    set_permissions(&passphrase, Permissions::from_mode(SECRET_MODE))?;
    let state = dir.path().join("state");
    let source = BorgSource {
        location: "/srv/borg".to_owned(),
        passphrase_file: passphrase.display().to_string(),
        hostname_from_name: true,
    };
    Ok(Setup {
        dir,
        program,
        state,
        source,
        tenant: tenant_scope("acme")?,
    })
}


fn run(setup: &Setup) -> Result<Vec<u8>, BorgError> {
    run_raw(&setup.program, &setup.source, &setup.tenant, &setup.state, &Limits::default(), PATIENT)
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


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken"))
    }
}


impl Write for Broken {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[test]
fn locations_follow_the_grammar() -> Result<(), Box<dyn Error>> {
    assert!(valid_location("/srv/borg-repo_1.2+3"));
    assert!(valid_location("ssh://backup@host.example/srv/borg"));
    assert!(valid_location("ssh://backup@host.example:22/srv/borg"));
    assert!(valid_location("ssh://backup@host.example:65535/./srv/borg"));
    let long = format!("/{}", "a".repeat(MAX_LOCATION_BYTES));
    let refused = [
        "-r",
        "repo",
        "ssh://-oProxyCommand=x@host/x",
        "ssh://-o@host/x",
        "ssh://u@-host/x",
        "ssh://u@-host:22/x",
        "ssh://@host/x",
        "ssh://host/x",
        "ssh://u@host",
        "ssh://u@host:/x",
        "ssh://u@host:0/x",
        "ssh://u@host:65536/x",
        "ssh://u@host:123456/x",
        "ssh://u@host:8a/x",
        "ssh://u@host:+80/x",
        "ssh://u:pw@host/x",
        "ssh://u@host/rel/../x",
        "ssh://u@host/a b",
        "ssh://u@host/~/x",
        "ssh://u@ho\u{3164}st/x",
        "sftp://u@host/x",
        "file:///srv/x",
        "/srv/a b",
        "/srv/..",
        "/srv/-x\n",
        &long,
    ];
    refused.iter().for_each(|text| assert!(!valid_location(text), "{text}"));
    Ok(())
}


#[test]
fn ports_run_from_one_to_65535() -> Result<(), Box<dyn Error>> {
    ["1", "22", "65535", "00080"].iter().for_each(|port| assert!(valid_port(port), "{port}"));
    ["", "0", "00000", "65536", "99999", "100000", "-1", "+1", "1 ", "a"]
        .iter()
        .for_each(|port| assert!(!valid_port(port), "{port}"));
    assert!(valid_authority("host:65535"));
    assert!(!valid_authority("host:0"));
    assert!(!valid_authority("host:65536"));
    Ok(())
}


#[test]
fn passphrase_paths_follow_the_grammar() -> Result<(), Box<dyn Error>> {
    let long = format!("/{}", "a".repeat(MAX_LOCATION_BYTES));
    let relative = BorgSource {
        location: "/srv".to_owned(),
        passphrase_file: "relative".to_owned(),
        hostname_from_name: false,
    };
    let overlong = BorgSource {
        location: "/srv".to_owned(),
        passphrase_file: long,
        hostname_from_name: false,
    };
    assert!(!valid_source(&relative));
    assert!(!valid_source(&overlong));
    Ok(())
}


#[test]
fn a_refused_entry_refuses_only_its_repository_and_both_kinds_are_refused() -> Result<(), Box<dyn Error>> {
    let declarations = load_declarations(DECLARATIONS, "d.yaml")?;
    let planned = plan(&declarations);
    assert_eq!(planned.refused, vec![1]);
    assert_eq!(planned.runnable.len(), 1);
    assert_eq!(planned.runnable.first().map(|(name, _)| *name), Some("main"));
    let restic = restic_plan(&declarations);
    assert_eq!(restic.refused, vec![BOTH_INDEX]);
    assert!(restic.runnable.is_empty());
    Ok(())
}


#[test]
fn the_argument_vector_and_environment_are_fixed_and_the_passphrase_travels_on_stdin_only() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    run(&setup)?;
    let args = std::fs::read_to_string(setup.dir.path().join("args"))?;
    assert_eq!(args, "--lock-wait 1 list --json /srv/borg\n");
    let base = setup.state.join("borg").join("acme");
    let environment = std::fs::read_to_string(setup.dir.path().join("env"))?;
    let lines: Vec<&str> = environment
        .lines()
        .filter(|line| !line.starts_with("PWD=") && !line.starts_with("_="))
        .collect();
    let expected = [
        format!("BORG_BASE_DIR={}", base.display()),
        "BORG_PASSPHRASE_FD=0".to_owned(),
        "BORG_RELOCATED_REPO_ACCESS_IS_OK=no".to_owned(),
        "BORG_RSH=/usr/bin/ssh -o BatchMode=yes".to_owned(),
        "BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no".to_owned(),
        format!("HOME={}", base.display()),
        format!("TMPDIR={}", base.display()),
    ];
    assert_eq!(lines, expected.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(std::fs::read_to_string(setup.dir.path().join("stdin"))?, PASSPHRASE);
    assert!(!environment.contains("correct horse") && !args.contains("correct horse"));
    Ok(())
}


#[test]
fn the_environment_lists_no_passphrase_variable() -> Result<(), Box<dyn Error>> {
    let variables = environment("/base");
    assert_eq!(variables.len(), VARIABLE_COUNT);
    assert!(variables
        .iter()
        .all(|(name, _)| name != "BORG_PASSPHRASE" && name != "BORG_PASSCOMMAND" && name != "BORG_NEW_PASSPHRASE"));
    Ok(())
}


#[test]
fn an_ssh_location_is_passed_whole_and_ssh_is_named_in_full() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    setup.source.location = "ssh://backup@host.example:2222/srv/borg".to_owned();
    run(&setup)?;
    let args = std::fs::read_to_string(setup.dir.path().join("args"))?;
    assert_eq!(args, "--lock-wait 1 list --json ssh://backup@host.example:2222/srv/borg\n");
    Ok(())
}


#[test]
fn the_listing_is_keyed_on_the_repository_id_and_reads_the_host_from_the_name() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let listing = snapshot_listing(&setup.program, &setup.source, &setup.tenant, &setup.state, &Limits::default(), PATIENT)?;
    assert_eq!(listing.repository, REPOSITORY_ID);
    assert_eq!(listing.snapshots.len(), 1);
    assert_eq!(listing.snapshots.first().and_then(|snapshot| snapshot.host.as_deref()), Some("srv1"));
    let raw = run(&setup)?;
    let plain = BorgSource {
        hostname_from_name: false,
        ..setup.source.clone()
    };
    let without = parse_run(&raw, &plain, &Limits::default())?;
    assert_eq!(without.snapshots.first().and_then(|snapshot| snapshot.host.as_deref()), None);
    Ok(())
}


#[test]
fn a_refused_declaration_spawns_nothing() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    [
        "-r",
        "ssh://-oProxyCommand=x@host/x",
        "ssh://-u@host/x",
        "ssh://u@-host/x",
        "ssh://u@host:123456/x",
    ]
    .iter()
    .try_for_each(|location| -> Result<(), Box<dyn Error>> {
        setup.source.location = (*location).to_owned();
        assert!(matches!(run(&setup), Err(BorgError::Refused)), "{location}");
        Ok(())
    })?;
    assert_eq!(runs(&setup), 0);
    assert!(!setup.state.exists());
    Ok(())
}


#[test]
fn a_bad_passphrase_file_is_refused_before_any_spawn() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let path = PathBuf::from(&setup.source.passphrase_file);
    let link = setup.dir.path().join("link");
    symlink(&path, &link)?;
    let directory = setup.dir.path().join("directory");
    create_dir_all(&directory)?;
    let big = setup.dir.path().join("big");
    std::fs::write(&big, "x".repeat(LONG_MARKER_BYTES))?;
    set_permissions(&big, Permissions::from_mode(SECRET_MODE))?;
    let mut candidates = vec![link, directory, big, setup.dir.path().join("absent")];
    set_permissions(&path, Permissions::from_mode(GROUP_READABLE_MODE))?;
    candidates.push(path);
    candidates.iter().try_for_each(|file| -> Result<(), Box<dyn Error>> {
        let source = BorgSource {
            passphrase_file: file.display().to_string(),
            ..setup.source.clone()
        };
        let outcome = run_raw(&setup.program, &source, &setup.tenant, &setup.state, &Limits::default(), PATIENT);
        assert!(matches!(outcome, Err(BorgError::PassphraseFile)), "{file:?}");
        Ok(())
    })?;
    assert_eq!(runs(&setup), 0);
    Ok(())
}


#[test]
fn the_passphrase_cap_is_exact() -> Result<(), Box<dyn Error>> {
    let cap = usize::try_from(MAX_PASSPHRASE_BYTES)?;
    let at_cap = vec![b'x'; cap];
    assert_eq!(read_capped(&mut at_cap.as_slice())?.len(), cap);
    let over = vec![b'x'; cap + 1];
    assert!(matches!(read_capped(&mut over.as_slice()), Err(BorgError::PassphraseFile)));
    assert!(matches!(read_capped(&mut Broken), Err(BorgError::PassphraseFile)));
    let setup = setup("ok")?;
    std::fs::write(&setup.source.passphrase_file, &at_cap)?;
    run(&setup)?;
    assert_eq!(std::fs::read(setup.dir.path().join("stdin"))?, at_cap);
    Ok(())
}


#[test]
fn a_failing_pipe_write_is_an_io_error() -> Result<(), Box<dyn Error>> {
    assert!(matches!(fill(&mut Broken, b"x"), Err(BorgError::Io)));
    assert!(matches!(io_failure(std::io::Error::other("x")), BorgError::Io));
    Ok(())
}


#[test]
fn the_base_directory_is_created_private_and_persists_between_runs() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    run(&setup)?;
    let base = setup.state.join("borg").join("acme");
    assert_eq!(std::fs::metadata(&base)?.permissions().mode() & MODE_MASK, PRIVATE);
    assert!(!setup.dir.path().join("seen").exists());
    run(&setup)?;
    run(&setup)?;
    assert_eq!(std::fs::read_to_string(setup.dir.path().join("seen"))?.lines().count(), SEEN_RUNS);
    let environments = std::fs::read_to_string(setup.dir.path().join("env"))?;
    assert!(environments.contains(&format!("BORG_BASE_DIR={}", base.display())));
    Ok(())
}


#[test]
fn another_tenant_gets_another_base_directory() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    run(&setup)?;
    setup.tenant = tenant_scope("globex")?;
    run(&setup)?;
    assert!(setup.state.join("borg").join("globex").join("marker").exists());
    assert!(!setup.dir.path().join("seen").exists());
    Ok(())
}


fn refused_base(setup: &Setup) -> bool {
    matches!(run(setup), Err(BorgError::BaseDir)) && runs(setup) == 0
}


#[test]
fn a_symlinked_or_open_base_directory_is_refused_before_any_spawn() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let parent = setup.state.join("borg");
    create_dir_all(&parent)?;
    let elsewhere = setup.dir.path().join("elsewhere");
    create_dir_all(&elsewhere)?;
    set_permissions(&elsewhere, Permissions::from_mode(PRIVATE))?;
    symlink(&elsewhere, parent.join("acme"))?;
    assert!(refused_base(&setup));
    std::fs::remove_file(parent.join("acme"))?;
    create_dir_all(parent.join("acme"))?;
    set_permissions(parent.join("acme"), Permissions::from_mode(OPEN_MODE))?;
    assert!(refused_base(&setup));
    set_permissions(parent.join("acme"), Permissions::from_mode(GROUP_MODE))?;
    assert!(refused_base(&setup));
    set_permissions(parent.join("acme"), Permissions::from_mode(PRIVATE))?;
    run(&setup)?;
    assert_eq!(runs(&setup), 1);
    Ok(())
}


#[test]
fn a_state_directory_that_cannot_hold_the_base_is_refused() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    let file = setup.dir.path().join("file");
    std::fs::write(&file, "x")?;
    setup.state = file;
    assert!(refused_base(&setup));
    setup.state = PathBuf::from("relative/state");
    assert!(refused_base(&setup));
    Ok(())
}


#[test]
fn a_base_directory_owned_by_someone_else_is_refused() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let mine = base_directory(&setup.state, &setup.tenant, rustix::process::geteuid().as_raw())?;
    assert!(mine.ends_with("borg/acme"));
    let other = rustix::process::geteuid().as_raw().wrapping_add(1);
    assert!(matches!(base_directory(&setup.state, &setup.tenant, other), Err(BorgError::BaseDir)));
    assert!(private_directory(true, DIRECTORY_PRIVATE));
    assert!(!private_directory(false, FILE_PRIVATE));
    assert!(!private_directory(true, DIRECTORY_GROUP));
    Ok(())
}


#[test]
fn a_base_directory_that_is_not_text_is_refused() -> Result<(), Box<dyn Error>> {
    let mut setup = setup("ok")?;
    setup.state = setup.dir.path().join(OsStr::from_bytes(b"state\xff"));
    assert!(refused_base(&setup));
    Ok(())
}


#[test]
fn a_run_past_the_deadline_is_a_timeout() -> Result<(), Box<dyn Error>> {
    let setup = setup("sleep")?;
    let outcome = run_raw(&setup.program, &setup.source, &setup.tenant, &setup.state, &Limits::default(), IMPATIENT);
    assert!(matches!(outcome, Err(BorgError::Timeout)));
    Ok(())
}


#[test]
fn a_grandchild_holding_stdout_is_killed_with_the_group() -> Result<(), Box<dyn Error>> {
    let setup = setup("hold")?;
    let outcome = run_raw(&setup.program, &setup.source, &setup.tenant, &setup.state, &Limits::default(), IMPATIENT);
    assert!(matches!(outcome, Err(BorgError::Timeout)));
    let pid: u32 = std::fs::read_to_string(setup.dir.path().join("grandchild"))?.trim().parse()?;
    let gone = (0..GONE_ATTEMPTS).any(|_| {
        std::thread::sleep(GONE_POLL);
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_or(true, |stat| stat.rsplit_once(") ").is_some_and(|(_, rest)| rest.starts_with('Z')))
    });
    assert!(gone);
    Ok(())
}


#[test]
fn output_over_the_cap_is_oversized() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let limits = Limits {
        max_bytes: TINY_CAP,
        ..Limits::default()
    };
    let outcome = run_raw(&setup.program, &setup.source, &setup.tenant, &setup.state, &limits, PATIENT);
    assert!(matches!(outcome, Err(BorgError::Oversized)));
    Ok(())
}


#[test]
fn every_non_zero_exit_is_failed_and_keeps_no_text() -> Result<(), Box<dyn Error>> {
    let failing = setup("fail")?;
    let error = run(&failing).err().ok_or("no error")?;
    assert!(matches!(error, BorgError::Failed { code: Some(FAILED_CODE) }));
    let text = text_chain(&error);
    assert!(!text.contains("hunter2") && !text.contains("stderr") && !text.contains("/srv/borg") && !text.contains("correct horse"));
    let warning = setup("warn")?;
    assert!(matches!(run(&warning), Err(BorgError::Failed { code: Some(WARNING_CODE) })));
    Ok(())
}


#[test]
fn a_missing_program_is_a_spawn_error() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let outcome = run_raw(
        Path::new("/nonexistent/borg"),
        &setup.source,
        &setup.tenant,
        &setup.state,
        &Limits::default(),
        PATIENT,
    );
    assert!(matches!(outcome, Err(BorgError::Spawn)));
    Ok(())
}


#[test]
fn run_failures_map_to_fixed_errors() -> Result<(), Box<dyn Error>> {
    assert!(matches!(BorgError::from(RunFailure::TimedOut), BorgError::Timeout));
    assert!(matches!(BorgError::from(RunFailure::TooLarge), BorgError::Oversized));
    assert!(matches!(
        BorgError::from(RunFailure::Failed {
            code: Some(FAILED_CODE),
            read: 0
        }),
        BorgError::Failed { code: Some(FAILED_CODE) }
    ));
    assert!(matches!(BorgError::from(RunFailure::Spawn), BorgError::Spawn));
    assert!(matches!(BorgError::from(RunFailure::Io), BorgError::Io));
    assert!(matches!(BorgError::from(RunFailure::Refused), BorgError::Refused));
    assert!(matches!(BorgError::from(RunFailure::Unwaitable), BorgError::Unwaitable));
    Ok(())
}


#[test]
fn a_hostile_listing_keeps_no_text_in_any_error() -> Result<(), Box<dyn Error>> {
    let setup = setup("ok")?;
    let marker = "MARKER".repeat(LONG_MARKER_BYTES);
    let wrong = format!("{{\"x\":\"{marker}\"}}");
    let error = parse_run(wrong.as_bytes(), &setup.source, &Limits::default()).err().ok_or("accepted")?;
    assert!(matches!(error, BorgError::Listing(BackupError::Malformed { .. })));
    assert!(!text_chain(&error).contains("MARKER"));
    let cut = format!("{{\"archives\":[\"{marker}");
    let broken = parse_run(cut.as_bytes(), &setup.source, &Limits::default()).err().ok_or("accepted")?;
    assert!(matches!(broken, BorgError::Listing(BackupError::Json(_))));
    assert!(!text_chain(&broken).contains("MARKER"));
    Ok(())
}
