use crate::support::{append, lines, poll_with, scoped_logging, setup, EXEC, LEN_THREE, LINE_LIMIT, THREE, TWO};
use crate::types::TestResult;
use agent_channel::app::{reload_context, shared_log_audit};
use agent_linux::error::{FimError, SourceError};
use agent_linux::fim::{event_line, fim_line, load_plan, load_with_plan, plan_from_bytes, refusal, MAX_REASON_CHARS};
use agent_linux::model::{FimFile, FimPlan, SourceSettings, MAX_PLANTED_BYTES};
use agent_linux::settings::{fim_state, open_settings_engine, settings_loader};
use agent_linux::trusted::read_trusted_capped;
use agent_linux::types::ReadBytesFn;
use core_audit::log::open_file_log;
use core_config::error::ConfigError;
use core_config::parse::read_bytes_capped;
use core_config::reload::{reload, ReloadOutcome};
use linux_fim::model::FimEvent;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;


const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../linux-fim/roles/linux.yaml");


const ROOT_OPEN: &str = include_str!("../fixtures/fim/root-open.json");


const WRITE_PASSWD: &str = include_str!("../fixtures/fim/write-passwd.json");


const PLANTED: &str = "/root/passwords.txt\t64769\t4708\n/root\t64769\t1692\n";


const ROLE: &str = "server";


const ENTRY_TWO: usize = 2;


const ALL_WRITE: u32 = 0o666;


const POLICY_COUNT: usize = 24;


const DIGEST_CHARS: usize = 64;


const KPROBE_ARGS_OVER: usize = 9;


const TABLE_BYTES_CAP: u64 = 65_536;


const SPARSE_BYTES: u64 = 104_857_600;


const SMALL_LINE: u64 = 300;


const TINY_SPOOL_LINE: usize = 20;


const LONG_KEY_CHARS: usize = 1_000;


const LONG_REASON_FIELD: &str = "version: 1\nroles: []\n";


fn table_bytes() -> std::io::Result<Vec<u8>> {
    fs::read(TABLE)
}


fn plan() -> Result<FimPlan, Box<dyn std::error::Error>> {
    Ok(plan_from_bytes(ROLE, &table_bytes()?, PLANTED.as_bytes())?)
}


fn settings_with(plan: FimPlan) -> SourceSettings {
    SourceSettings {
        fim: Some(Arc::new(plan)),
        ..SourceSettings::default()
    }
}


fn counting_read(path: &Path, max: u64) -> Result<Vec<u8>, ConfigError> {
    let mut calls = path.as_os_str().to_owned();
    calls.push(".calls");
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(PathBuf::from(calls))
        .map_err(|source| ConfigError::Io {
            file: path.display().to_string(),
            source,
        })?;
    writeln!(file, "{max}").map_err(|source| ConfigError::Io {
        file: path.display().to_string(),
        source,
    })?;
    read_bytes_capped(path, max)
}


fn section(dir: &Path, planted: &str) -> Result<FimFile, Box<dyn std::error::Error>> {
    fs::write(dir.join("planted.tsv"), planted)?;
    fs::copy(TABLE, dir.join("roles.yaml"))?;
    Ok(FimFile {
        table: dir.join("roles.yaml"),
        role: ROLE.to_owned(),
        planted: dir.join("planted.tsv"),
    })
}


#[test]
fn the_plan_holds_the_policies_the_planted_identities_and_the_digests() -> TestResult {
    let built = plan()?;
    assert_eq!(built.role, ROLE);
    assert_eq!(built.policies.len(), POLICY_COUNT);
    assert_eq!(built.sets.planted.len(), TWO as usize);
    assert_eq!(built.table_sha256.len(), DIGEST_CHARS);
    let other = plan_from_bytes(ROLE, &table_bytes()?, b"/root/passwords.txt\t64769\t1\n")?;
    assert_eq!(other.table_sha256, built.table_sha256);
    assert_ne!(other.planted_sha256, built.planted_sha256);
    Ok(())
}


#[test]
fn every_refusal_is_named() -> TestResult {
    let table = table_bytes()?;
    assert!(matches!(plan_from_bytes(ROLE, b"\xff", PLANTED.as_bytes()), Err(FimError::TableNotUtf8)));
    assert!(matches!(plan_from_bytes(ROLE, &table, b"\xff"), Err(FimError::PlantedNotUtf8)));
    assert!(matches!(
        plan_from_bytes(ROLE, b"version: 9\nroles: []\n", PLANTED.as_bytes()),
        Err(FimError::Table(_))
    ));
    assert!(matches!(plan_from_bytes("", &table, PLANTED.as_bytes()), Err(FimError::EmptyRole)));
    assert!(matches!(plan_from_bytes("nosuch", &table, PLANTED.as_bytes()), Err(FimError::NoRole)));
    assert!(matches!(plan_from_bytes(ROLE, &table, b"nonsense\n"), Err(FimError::Planted(_))));
    assert!(matches!(
        plan_from_bytes(ROLE, &table, b"/etc/passwd\t64769\t1\n"),
        Err(FimError::Undeclared { entry: 1 })
    ));
    assert!(matches!(
        plan_from_bytes(ROLE, &table, PLANTED.replace("/root\t", "/etc\t").as_bytes()),
        Err(FimError::Undeclared { entry: ENTRY_TWO })
    ));
    assert!(matches!(
        plan_from_bytes(ROLE, &table, format!("{PLANTED}/root/passwords.txt\t64769\t4708\n").as_bytes()),
        Err(FimError::Duplicate { entry: LEN_THREE })
    ));
    Ok(())
}


#[test]
fn a_refusal_names_the_file_and_its_reason_is_cut() -> TestResult {
    let named = refusal(Path::new("/etc/roles.yaml"), &FimError::NoRole);
    assert!(named.to_string().contains("/etc/roles.yaml") && named.to_string().contains("no role"));
    let long_key = "k".repeat(LONG_KEY_CHARS);
    let text = format!("{LONG_REASON_FIELD}x: 1\n{long_key}: 1\n");
    let error = plan_from_bytes(ROLE, text.as_bytes(), PLANTED.as_bytes()).err().ok_or("accepted")?;
    let cut = refusal(Path::new("/t"), &error);
    assert!(matches!(cut, ConfigError::WatchedFile { reason, .. } if reason.chars().count() <= MAX_REASON_CHARS));
    Ok(())
}


#[test]
fn each_file_is_read_once_under_its_own_cap() -> TestResult {
    let dir = tempdir()?;
    let files = section(dir.path(), PLANTED)?;
    let built = load_plan(&files, counting_read)?;
    assert_eq!(built.sets.planted.len(), TWO as usize);
    assert_eq!(fs::read_to_string(dir.path().join("roles.yaml.calls"))?, format!("{TABLE_BYTES_CAP}\n"));
    assert_eq!(
        fs::read_to_string(dir.path().join("planted.tsv.calls"))?,
        format!("{MAX_PLANTED_BYTES}\n")
    );
    Ok(())
}


#[test]
fn the_plan_is_built_from_the_bytes_that_were_read() -> TestResult {
    fn stale(path: &Path, max: u64) -> Result<Vec<u8>, ConfigError> {
        if path.file_name().and_then(|name| name.to_str()) == Some("planted.tsv") {
            Ok(b"/etc/passwd\t64769\t1\n".to_vec())
        } else {
            read_bytes_capped(path, max)
        }
    }
    let dir = tempdir()?;
    let files = section(dir.path(), PLANTED)?;
    assert!(matches!(load_plan(&files, stale), Err(ConfigError::WatchedFile { .. })));
    Ok(())
}


#[test]
fn a_file_that_is_not_a_plain_capped_regular_file_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let files = section(dir.path(), PLANTED)?;
    let production: ReadBytesFn = read_trusted_capped;
    fs::remove_file(&files.planted)?;
    assert!(matches!(load_plan(&files, production), Err(ConfigError::Io { .. })));
    assert!(Command::new("mkfifo").arg(&files.planted).status()?.success());
    assert!(matches!(load_plan(&files, production), Err(ConfigError::WatchedFile { .. })));
    fs::remove_file(&files.planted)?;
    std::os::unix::fs::symlink("/dev/zero", &files.planted)?;
    assert!(matches!(load_plan(&files, production), Err(ConfigError::WatchedFile { .. })));
    fs::remove_file(&files.planted)?;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&files.planted)?
        .set_len(SPARSE_BYTES)?;
    assert!(matches!(load_plan(&files, production), Err(ConfigError::TooLarge { .. })));
    Ok(())
}


#[test]
fn a_settings_file_without_the_section_has_no_plan_and_with_it_the_plan() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("agent-linux.yaml");
    let base = "agent_file: /a\nexport_path: /e\ncursor_file: /c\naudit_file: /l\n";
    fs::write(&path, base)?;
    assert!(load_with_plan(&path, read_trusted_capped)?.settings.fim.is_none());
    let files = section(dir.path(), PLANTED)?;
    let text = format!(
        "{base}fim:\n  table: {}\n  role: server\n  planted: {}\n",
        files.table.display(),
        files.planted.display()
    );
    fs::write(&path, text)?;
    let loaded = load_with_plan(&path, read_trusted_capped)?;
    assert_eq!(loaded.settings.fim.as_ref().map(|plan| plan.role.as_str()), Some(ROLE));
    assert_eq!(loaded.fim, Some(files.clone()));
    assert_eq!(fim_state(&loaded).len(), THREE as usize);
    fs::write(&files.planted, "bad\n")?;
    assert!(load_with_plan(&path, read_trusted_capped).is_err());
    Ok(())
}


#[test]
fn a_line_of_a_fim_policy_is_one_fim_record_instead_of_its_ecs_event() -> TestResult {
    let _log = scoped_logging();
    let mut fixture = setup()?;
    append(&fixture.paths.export, &format!("{ROOT_OPEN}{WRITE_PASSWD}{EXEC}\n"))?;
    let settings = settings_with(plan()?);
    let report = poll_with(&mut fixture, &settings, LINE_LIMIT)?;
    assert_eq!((report.spooled, report.fim), (THREE, TWO));
    let spooled = lines(&fixture.paths.spool)?;
    assert_eq!(spooled.len(), THREE as usize);
    assert!(spooled.iter().filter(|line| line.contains("agent.fim")).count() == TWO as usize);
    assert!(spooled
        .iter()
        .any(|line| line.contains("\"type\":\"honeytoken\"") && line.contains("/root/passwords.txt")));
    assert!(spooled
        .iter()
        .any(|line| line.contains("\"type\":\"write\"") && line.contains("/etc/passwd")));
    assert!(spooled.iter().any(|line| line.contains("/usr/bin/curl") && !line.contains("agent.fim")));
    Ok(())
}


#[test]
fn without_a_plan_the_same_lines_stay_ecs() -> TestResult {
    let _log = scoped_logging();
    let mut fixture = setup()?;
    append(&fixture.paths.export, &format!("{ROOT_OPEN}{WRITE_PASSWD}"))?;
    let report = poll_with(&mut fixture, &SourceSettings::default(), LINE_LIMIT)?;
    assert_eq!(report.fim, 0);
    assert!(!fs::read_to_string(&fixture.paths.spool).is_ok_and(|spooled| spooled.contains("agent.fim")));
    Ok(())
}


#[test]
fn no_event_reaches_token_severity_without_planted_identities() -> TestResult {
    let _log = scoped_logging();
    let mut fixture = setup()?;
    append(&fixture.paths.export, ROOT_OPEN)?;
    let empty = plan_from_bytes(ROLE, &table_bytes()?, b"")?;
    let report = poll_with(&mut fixture, &settings_with(empty), LINE_LIMIT)?;
    assert_eq!(report.fim, 1);
    let spooled = fs::read_to_string(&fixture.paths.spool)?;
    assert!(spooled.contains("\"type\":\"write\"") && spooled.contains("\"mount_ambiguous\":true"));
    assert!(!spooled.contains("\"type\":\"honeytoken\""));
    Ok(())
}


#[test]
fn a_line_over_the_limit_is_counted_not_classified_and_a_long_record_is_counted() -> TestResult {
    let _log = scoped_logging();
    let mut fixture = setup()?;
    append(&fixture.paths.export, WRITE_PASSWD)?;
    let small = SourceSettings {
        max_line_bytes: SMALL_LINE,
        ..settings_with(plan()?)
    };
    let report = poll_with(&mut fixture, &small, LINE_LIMIT)?;
    assert_eq!((report.oversized, report.fim, report.spooled), (1, 0, 0));
    let mut other = setup()?;
    append(&other.paths.export, WRITE_PASSWD)?;
    let other_report = poll_with(&mut other, &settings_with(plan()?), TINY_SPOOL_LINE)?;
    assert_eq!((other_report.oversized, other_report.fim, other_report.spooled), (1, 0, 0));
    Ok(())
}


#[test]
fn a_line_that_is_not_utf8_is_left_to_the_ecs_path() -> TestResult {
    let _log = scoped_logging();
    let mut fixture = setup()?;
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(&fixture.paths.export)?
        .write_all(b"\xff\xfe\n")?;
    let report = poll_with(&mut fixture, &settings_with(plan()?), LINE_LIMIT)?;
    assert_eq!((report.malformed, report.fim), (1, 0));
    assert!(fim_line(b"\xff", LINE_LIMIT as u64, &plan()?).is_none());
    Ok(())
}


#[test]
fn a_line_with_too_many_arguments_is_an_oversized_record() -> TestResult {
    let mut value: serde_json::Value = serde_json::from_str(WRITE_PASSWD)?;
    let args = value
        .pointer_mut("/process_kprobe/args")
        .and_then(|args| args.as_array_mut())
        .ok_or("no args")?;
    let first = args.first().cloned().ok_or("no first arg")?;
    args.resize(KPROBE_ARGS_OVER, first);
    let line = fim_line(value.to_string().as_bytes(), LINE_LIMIT as u64, &plan()?).ok_or("not classified")?;
    assert!(line.contains("\"type\":\"oversized\"") && line.contains("ostyr-fim-server"));
    Ok(())
}


#[test]
fn every_event_kind_has_its_record() -> TestResult {
    let process = "/usr/bin/x".to_owned();
    let events = [
        (
            FimEvent::Write {
                path: "/p".into(),
                process: process.clone(),
                name_match: true,
                mount_ambiguous: false,
                foreign_mount_ns: false,
                dentry_path: None,
            },
            "write",
        ),
        (
            FimEvent::Honeytoken {
                path: "/p".into(),
                process: process.clone(),
            },
            "honeytoken",
        ),
        (
            FimEvent::Link {
                existing: "/a".into(),
                created: "/b".into(),
                process: process.clone(),
                honeytoken: false,
                name_match: false,
                mount_ambiguous: true,
                foreign_mount_ns: false,
                created_dentry: Some("/d".into()),
            },
            "link",
        ),
        (
            FimEvent::Rename {
                source: "/a".into(),
                target: "/b".into(),
                process: process.clone(),
                honeytoken: true,
                mount_ambiguous: false,
                foreign_mount_ns: true,
                source_dentry: None,
                target_dentry: Some("/t".into()),
            },
            "rename",
        ),
        (
            FimEvent::MissingPath {
                policy: "ostyr-fim-server".into(),
                function: "f".into(),
                process,
            },
            "missing_path",
        ),
        (
            FimEvent::Oversized {
                policy: "ostyr-fim-server".into(),
                bytes: ENTRY_TWO,
            },
            "oversized",
        ),
    ];
    events.iter().try_for_each(|(event, expected)| -> TestResult {
        let value: serde_json::Value = serde_json::from_str(&event_line(event))?;
        assert_eq!(value.pointer("/event/kind").and_then(|kind| kind.as_str()), Some("agent.fim"));
        assert_eq!(value.pointer("/agent/fim/type").and_then(|kind| kind.as_str()), Some(*expected));
        Ok(())
    })?;
    Ok(())
}


fn write_agent(path: &Path, fim: &str) -> std::io::Result<()> {
    fs::write(path, format!("agent_file: /a\nexport_path: /e\ncursor_file: /c\naudit_file: /l\n{fim}"))
}


fn fim_text(files: &FimFile) -> String {
    format!(
        "fim:\n  table: {}\n  role: server\n  planted: {}\n",
        files.table.display(),
        files.planted.display()
    )
}


#[test]
fn the_plan_follows_a_reload_and_a_refused_one_keeps_the_old_plan() -> TestResult {
    let dir = tempdir()?;
    let files = section(dir.path(), PLANTED)?;
    let path = dir.path().join("agent-linux.yaml");
    write_agent(&path, &fim_text(&files))?;
    let audit = dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit)?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    let (engine, shared, _sensor, _updates, _osquery, _metrics) = open_settings_engine(path.clone(), shared_log_audit(&log), context)?;
    let first = shared.load().fim.clone().ok_or("no first plan")?;
    assert_eq!(first.sets.planted.len(), TWO as usize);
    assert_eq!(reload(&engine), ReloadOutcome::Unchanged);
    fs::write(&files.planted, "/root/passwords.txt\t64769\t4708\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys == ["agent_linux.fim_planted_sha256"]));
    assert_eq!(shared.load().fim.as_ref().map(|plan| plan.sets.planted.len()), Some(1));
    fs::write(&files.planted, "/etc/passwd\t64769\t4708\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("planted.tsv entry 1")));
    assert_eq!(shared.load().fim.as_ref().map(|plan| plan.sets.planted.len()), Some(1));
    assert!(fs::read_to_string(&audit)?.contains("refused"));
    fs::write(&files.planted, PLANTED)?;
    fs::write(
        &files.table,
        "version: 1\nroles:\n  - name: server\n    honeytokens:\n      - { path: /root/passwords.txt, kind: password_file }\n",
    )?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { keys } if keys.iter().any(|key| key == "agent_linux.fim_table_sha256")));
    write_agent(&path, "")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert!(shared.load().fim.is_none());
    Ok(())
}


#[test]
fn a_bad_plan_stops_the_start_by_name() -> TestResult {
    let dir = tempdir()?;
    let files = section(dir.path(), "/etc/passwd\t64769\t1\n")?;
    let path = dir.path().join("agent-linux.yaml");
    write_agent(&path, &fim_text(&files))?;
    let log = Arc::new(open_file_log(&dir.path().join("audit.log"))?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    let refused = open_settings_engine(path.clone(), shared_log_audit(&log), context)
        .err()
        .ok_or("started")?;
    assert!(matches!(&refused, SourceError::Config(_)) && refused.to_string().contains("planted.tsv entry 1"));
    assert!(refused.to_string().contains(&files.planted.display().to_string()));
    assert!(!refused.to_string().contains("token"));
    fs::write(&files.planted, PLANTED)?;
    fs::write(&files.table, "version: 9\nroles: []\n")?;
    let table_refused = settings_loader(path)().err().ok_or("loaded")?;
    assert!(table_refused.to_string().contains(&files.table.display().to_string()));
    Ok(())
}


#[test]
fn an_input_another_user_can_write_stops_the_start_and_refuses_a_reload_keeping_the_plan() -> TestResult {
    let dir = tempdir()?;
    let files = section(dir.path(), PLANTED)?;
    let path = dir.path().join("agent-linux.yaml");
    write_agent(&path, &fim_text(&files))?;
    let audit = dir.path().join("audit.log");
    let log = Arc::new(open_file_log(&audit)?);
    let context = reload_context(&path, "agent_linux", "tenant", "reload");
    let (engine, shared, _sensor, _updates, _osquery, _metrics) = open_settings_engine(path.clone(), shared_log_audit(&log), context)?;
    fs::write(&files.planted, "/root/passwords.txt\t64769\t4708\n")?;
    fs::set_permissions(&files.planted, std::os::unix::fs::PermissionsExt::from_mode(ALL_WRITE))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { reason } if reason.contains("writable by group or others")));
    assert_eq!(shared.load().fim.as_ref().map(|plan| plan.sets.planted.len()), Some(TWO as usize));
    assert!(fs::read_to_string(&audit)?.contains("refused"));
    let started = open_settings_engine(
        path.clone(),
        shared_log_audit(&log),
        reload_context(&path, "agent_linux", "tenant", "reload"),
    );
    assert!(started.err().ok_or("started")?.to_string().contains(&files.planted.display().to_string()));
    Ok(())
}
