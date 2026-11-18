use crate::types::TestResult;
use agent_linux::error::{OsqueryError, SensorError};
use agent_linux::model::{
    OsqueryEnv, OsquerySettings, DEFAULT_OSQUERY_DEADLINE_SECONDS, DEFAULT_OSQUERY_MEMORY_BYTES, DEFAULT_OSQUERY_TEMP_BYTES,
    DEFAULT_OSQUERY_TEMP_TOTAL_BYTES,
};
use agent_linux::osquery::{
    check_program, check_query, errno_error, has_control, logger_dir_fault, osquery_error_of, prepare_logger_dir, program_fault, query_fault,
    query_spec, row_of, rows_from_output, rows_with_builder, run_query, FIXED_ARGUMENTS, LOGGER_DIR_NAME, MAX_COLUMNS, MAX_QUERY_BYTES, MAX_ROWS,
    MAX_ROW_BYTES, MAX_VALUE_BYTES, NAMESPACE_FILE_NAME, TEMP_DIR_NAME,
};
use agent_linux::types::UpdateFuture;
use serde_json::{json, Value};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};


const OWNER_ONLY_DIR: u32 = 0o700;


const OWNER_ONLY_FILE: u32 = 0o600;


const OPEN_DIR: u32 = 0o777;


const PROGRAM_MODE: u32 = 0o755;


const GROUP_WRITABLE_PROGRAM: u32 = 0o775;


const INVALID_BYTE: u8 = 0xff;


const MARKER: &str = "SECRET-MARKER-9f3a";


const EXIT_CODE: i32 = 2;


const SELF_BIND_CALL: usize = 2;


const MAKE_PRIVATE_CALL: usize = 3;


const CREATE_CALL: usize = 4;


const FIRST_BIND_CALL: usize = 5;


const CREATE_STEP: usize = 2;


const SECOND_BIND_STEP: usize = 4;


const HEAD_WORDS: usize = 3;


const CALL_LOG: &str = "calls.log";


const TOOLS: [&str; 5] = ["prlimit", "unshare", "nsenter", "mount", "umount"];


const OVER_COLUMNS: usize = MAX_COLUMNS + 1;


const REGULAR_FILE_MODE: u32 = 0o100_644;


const DIRECTORY_MODE: u32 = 0o040_755;


const GROUP_WRITABLE_FILE_MODE: u32 = 0o100_664;


const OTHER_USER: u32 = 4_242;


const MODE_BITS: u32 = 0o777;


const REFUSED_ROWS: usize = 8;


const KEPT_ROWS: usize = 4;


fn echo(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let mut row = serde_json::Map::new();
    row.insert("program".to_owned(), Value::String(spec.program.display().to_string()));
    row.insert("tmpdir".to_owned(), Value::String(format!("{:?}", spec.environment)));
    row.insert("deadline".to_owned(), Value::String(deadline.as_secs().to_string()));
    row.insert("max_output".to_owned(), Value::String(spec.max_output.to_string()));
    row.insert("environment".to_owned(), Value::String(format!("{:?}", spec.environment)));
    spec.arguments.iter().enumerate().for_each(|(index, argument)| {
        row.insert(format!("arg{index}"), Value::String(argument.to_string_lossy().into_owned()));
    });
    let body = serde_json::to_vec(&json!([row])).map_err(|_| SensorError::Parse);
    Box::pin(async move { body })
}


fn is_setup(spec: &agent_linux::model::CommandSpec) -> bool {
    spec.max_output != agent_linux::osquery::MAX_OSQUERY_OUTPUT_BYTES
}


fn program_name(spec: &agent_linux::model::CommandSpec) -> String {
    spec.program
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
}


fn log_call(spec: &agent_linux::model::CommandSpec) -> io::Result<()> {
    let directory = spec
        .arguments
        .iter()
        .filter_map(|argument| argument.to_str())
        .map(|argument| argument.trim_start_matches("--mount="))
        .find_map(|argument| argument.find(TEMP_DIR_NAME).and_then(|at| argument.get(..at + TEMP_DIR_NAME.len())));
    let log = directory.map(|path| Path::new(path).join(CALL_LOG));
    let words: Vec<String> = spec.arguments.iter().map(|argument| argument.to_string_lossy().into_owned()).collect();
    let line = format!("{} {}\n", program_name(spec), words.join(" "));
    log.map_or(Ok(()), |path| {
        fs::OpenOptions::new().create(true).append(true).open(path)?.write_all(line.as_bytes())
    })
}


fn recording(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    let logged = log_call(&spec).map_err(SensorError::Io);
    Box::pin(async move { logged.map(|()| b"[]".to_vec()) })
}


fn unshare_fails(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let unshare = program_name(&spec) == "unshare";
    let outcome = recording(spec, deadline);
    if unshare {
        fail(SensorError::Exit(Some(1)))
    } else {
        outcome
    }
}


fn bind_fails(spec: agent_linux::model::CommandSpec, deadline: std::time::Duration) -> UpdateFuture {
    let binds = spec.arguments.iter().any(|argument| argument == "--bind") && spec.arguments.iter().any(|argument| argument == "/tmp");
    let outcome = recording(spec, deadline);
    if binds {
        fail(SensorError::Timeout)
    } else {
        outcome
    }
}


fn umount_fails(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if program_name(&spec) == "umount" {
        fail(SensorError::Exit(Some(EXIT_CODE)))
    } else {
        answer(b"[]".to_vec())
    }
}


fn sqlite_full(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Exit(Some(agent_linux::osquery::SQLITE_FULL_EXIT)))
    }
}


fn answer(body: Vec<u8>) -> UpdateFuture {
    Box::pin(async move { Ok(body) })
}


fn fail(error: SensorError) -> UpdateFuture {
    Box::pin(async move { Err(error) })
}


fn too_many_rows(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        answer(format!("[{}{{}}]", "{},".repeat(MAX_ROWS)).into_bytes())
    }
}


fn exactly_max_rows(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        answer(format!("[{}{{}}]", "{},".repeat(MAX_ROWS - 1)).into_bytes())
    }
}


fn timeout(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Timeout)
    }
}


fn too_large(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::TooLarge(1))
    }
}


fn exit_two(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Exit(Some(EXIT_CODE)))
    }
}


fn killed(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Exit(None))
    }
}


fn no_start(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        fail(SensorError::Io(io::Error::from(io::ErrorKind::NotFound)))
    }
}


fn marked_garbage(spec: agent_linux::model::CommandSpec, _deadline: std::time::Duration) -> UpdateFuture {
    if is_setup(&spec) {
        answer(b"[]".to_vec())
    } else {
        answer(format!("[{{\"a\":\"x\"}}\n {MARKER} \u{1b}[31m").into_bytes())
    }
}


struct Fixture {
    _root: TempDir,
    state: PathBuf,
    settings: OsquerySettings,
}


fn make_dir(path: &Path, mode: u32) -> io::Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}


fn trusted_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}


fn fixture() -> Result<Fixture, Box<dyn Error>> {
    let root = tempdir()?;
    let bin = root.path().join("bin");
    make_dir(&bin, PROGRAM_MODE)?;
    let program = bin.join("osqueryi");
    let tools = TOOLS.map(|name| bin.join(name));
    [&program].into_iter().chain(tools.iter()).try_for_each(|path| {
        fs::write(path, b"")?;
        fs::set_permissions(path, fs::Permissions::from_mode(PROGRAM_MODE))
    })?;
    let state = root.path().join("state");
    make_dir(&state, OWNER_ONLY_DIR)?;
    let settings = OsquerySettings {
        path: program,
        prlimit_path: bin.join("prlimit"),
        unshare_path: bin.join("unshare"),
        nsenter_path: bin.join("nsenter"),
        mount_path: bin.join("mount"),
        umount_path: bin.join("umount"),
        deadline_seconds: DEFAULT_OSQUERY_DEADLINE_SECONDS,
        max_memory_bytes: DEFAULT_OSQUERY_MEMORY_BYTES,
        max_temp_bytes: DEFAULT_OSQUERY_TEMP_BYTES,
        max_temp_total_bytes: DEFAULT_OSQUERY_TEMP_TOTAL_BYTES,
    };
    Ok(Fixture {
        _root: root,
        state,
        settings,
    })
}


fn env_of(fixture: &Fixture, run: agent_linux::types::UpdateRunFn) -> OsqueryEnv {
    OsqueryEnv {
        state_dir: fixture.state.clone(),
        trusted_uid: trusted_uid(),
        run,
    }
}


#[tokio::test]
async fn a_query_runs_with_separate_arguments_and_the_fixed_flags() -> TestResult {
    let fixture = fixture()?;
    let query = "SELECT name, version FROM deb_packages LIMIT 5; -- x";
    let result = run_query(&env_of(&fixture, echo), &fixture.settings, query).await?;
    assert_eq!((result.rows.len(), result.refused_rows), (1, 0));
    let row = result.rows.first().ok_or("no row")?;
    let ns_file = fixture.state.join(TEMP_DIR_NAME).join(NAMESPACE_FILE_NAME);
    let wrapper: [String; WRAPPER_ARGUMENTS] = [
        format!("--mount={}", ns_file.display()),
        "--wd=/tmp".to_owned(),
        "--".to_owned(),
        fixture.settings.prlimit_path.display().to_string(),
        format!("--as={DEFAULT_OSQUERY_MEMORY_BYTES}"),
        format!("--cpu={DEFAULT_OSQUERY_DEADLINE_SECONDS}"),
        format!("--fsize={DEFAULT_OSQUERY_TEMP_BYTES}"),
        "--nofile=256:256".to_owned(),
        "--core=1".to_owned(),
        "--".to_owned(),
        fixture.settings.path.display().to_string(),
    ];
    let first = wrapper.len();
    assert_eq!(row.get("program").cloned(), Some(fixture.settings.nsenter_path.display().to_string()));
    wrapper
        .iter()
        .enumerate()
        .for_each(|(index, flag)| assert_eq!(row.get(&format!("arg{index}")), Some(flag)));
    FIXED_ARGUMENTS
        .iter()
        .enumerate()
        .for_each(|(index, flag)| assert_eq!(row.get(&format!("arg{}", first + index)).map(String::as_str), Some(*flag)));
    let logger = fixture.state.join(LOGGER_DIR_NAME);
    let logger_index = first + FIXED_ARGUMENTS.len();
    let last = logger_index + 1;
    assert_eq!(
        row.get(&format!("arg{logger_index}")).cloned(),
        Some(format!("--logger_path={}", logger.display()))
    );
    assert_eq!(row.get(&format!("arg{last}")).map(String::as_str), Some(query));
    assert!(row.get(&format!("arg{}", last + 1)).is_none());
    assert_eq!(row.get("deadline").cloned(), Some(DEFAULT_OSQUERY_DEADLINE_SECONDS.to_string()));
    assert_eq!(
        row.get("max_output").cloned(),
        Some(agent_linux::osquery::MAX_OSQUERY_OUTPUT_BYTES.to_string())
    );
    let temp = fixture.state.join(TEMP_DIR_NAME);
    assert!(row
        .get("environment")
        .is_some_and(|text| text.contains("LC_ALL") && !text.contains("HOME") && text.contains("(\"TMPDIR\", \"/tmp\")")));
    assert_eq!(fs::metadata(&temp)?.permissions().mode() & MODE_BITS, OWNER_ONLY_DIR);
    assert_eq!(fs::metadata(&logger)?.permissions().mode() & MODE_BITS, OWNER_ONLY_DIR);
    assert!(row.values().any(|value| value == DISABLED_TABLES_FLAG));
    assert!(row.values().any(|value| value == "--disable_extensions"));
    let again = run_query(&env_of(&fixture, echo), &fixture.settings, query).await?;
    assert_eq!(again.rows.len(), 1);
    Ok(())
}


#[test]
fn the_spec_has_no_shell_and_the_query_last() -> TestResult {
    let fixture = fixture()?;
    let spec = query_spec(&fixture.settings, "/n", "/l", "SELECT 1");
    assert_eq!(spec.program, fixture.settings.nsenter_path);
    assert_eq!(spec.arguments.last().and_then(|argument| argument.to_str()), Some("SELECT 1"));
    assert_eq!(spec.accepted_codes, vec![0]);
    Ok(())
}


#[tokio::test]
async fn more_rows_than_the_cap_are_refused_and_the_cap_itself_passes() -> TestResult {
    let fixture = fixture()?;
    let over = run_query(&env_of(&fixture, too_many_rows), &fixture.settings, "SELECT 1").await;
    assert_eq!(over, Err(OsqueryError::TooLarge));
    let at_cap = run_query(&env_of(&fixture, exactly_max_rows), &fixture.settings, "SELECT 1").await?;
    assert_eq!(at_cap.rows.len(), MAX_ROWS);
    Ok(())
}


#[test]
fn one_bad_row_is_refused_alone_and_counted() -> TestResult {
    let wide: serde_json::Map<String, Value> = (0..OVER_COLUMNS).map(|index| (format!("c{index}"), json!("v"))).collect();
    let at_columns: serde_json::Map<String, Value> = (0..MAX_COLUMNS).map(|index| (format!("c{index}"), json!("v"))).collect();
    let big_value = json!({"k": "a".repeat(MAX_VALUE_BYTES + 1)});
    let big_column = json!({"a".repeat(MAX_VALUE_BYTES + 1): "v"});
    let at_value = json!({"k": "a".repeat(MAX_VALUE_BYTES)});
    let escape = json!({"k": "\u{1b}[31mred"});
    let escape_column = json!({"\u{1b}k": "v"});
    let number = json!({"k": 1});
    let not_object = json!("text");
    let huge_row = json!({"k": "a".repeat(MAX_ROW_BYTES)});
    let rows = json!([
        {"name": "ok", "text": "line\nbreak\ttab\r"},
        wide,
        big_value,
        big_column,
        escape,
        escape_column,
        number,
        not_object,
        huge_row,
        at_columns,
        at_value,
        {"name": "last"}
    ]);
    let result = rows_from_output(&serde_json::to_vec(&rows)?)?;
    assert_eq!(result.refused_rows, REFUSED_ROWS);
    assert_eq!(result.rows.len(), KEPT_ROWS);
    assert_eq!(result.rows.first().and_then(|row| row.get("name")).map(String::as_str), Some("ok"));
    assert_eq!(result.rows.last().and_then(|row| row.get("name")).map(String::as_str), Some("last"));
    assert!(rows_from_output(b"[]")?.rows.is_empty());
    assert!(row_of("{}").is_some());
    assert!(has_control("\u{7f}"));
    assert!(!has_control("plain"));
    Ok(())
}


#[tokio::test]
async fn runner_failures_map_to_fixed_variants() -> TestResult {
    let fixture = fixture()?;
    let query = "SELECT 1";
    let run = |function: agent_linux::types::UpdateRunFn| {
        let env = env_of(&fixture, function);
        let settings = fixture.settings.clone();
        async move { run_query(&env, &settings, query).await }
    };
    assert_eq!(run(timeout).await, Err(OsqueryError::Deadline));
    assert_eq!(run(too_large).await, Err(OsqueryError::TooLarge));
    assert_eq!(run(exit_two).await, Err(OsqueryError::Exit(EXIT_CODE)));
    assert_eq!(run(killed).await, Err(OsqueryError::ResourceLimit));
    assert_eq!(run(no_start).await, Err(OsqueryError::Spawn(io::ErrorKind::NotFound)));
    let text = OsqueryError::ResourceLimit.to_string();
    assert!(["memory", "CPU time", "temp file size", "temp space"]
        .iter()
        .all(|limit| text.contains(limit)));
    let utf8 = std::str::from_utf8(&[INVALID_BYTE]).err().ok_or("valid")?;
    assert_eq!(osquery_error_of(SensorError::Utf8(utf8)), OsqueryError::NotJson { line: 0, column: 0 });
    assert_eq!(osquery_error_of(SensorError::Parse), OsqueryError::NotJson { line: 0, column: 0 });
    Ok(())
}


#[tokio::test]
async fn bad_json_gives_a_position_and_no_output_byte() -> TestResult {
    let fixture = fixture()?;
    let error = run_query(&env_of(&fixture, marked_garbage), &fixture.settings, "SELECT 1")
        .await
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, OsqueryError::NotJson { line, column } if line >= 1 && column >= 1));
    let mut texts = vec![error.to_string(), format!("{error:?}")];
    texts.extend(error.source().map(|cause| format!("{cause} {cause:?}")));
    assert!(error.source().is_none());
    assert!(texts.iter().all(|text| !text.contains(MARKER) && !text.contains('\u{1b}')));
    let not_array = rows_from_output(b"{\"a\":\"b\"}");
    assert!(matches!(not_array, Err(OsqueryError::NotJson { .. })));
    Ok(())
}


#[test]
fn queries_are_checked_before_any_run() -> TestResult {
    let long = "a".repeat(MAX_QUERY_BYTES + 1);
    let at_limit = "a".repeat(MAX_QUERY_BYTES);
    for (query, refused) in [
        ("", true),
        ("   \n", true),
        (long.as_str(), true),
        (at_limit.as_str(), false),
        ("SELECT\0 1", true),
        ("--extensions_socket=/tmp/x", true),
        (".shell id", true),
        (" -x", false),
        ("SELECT 1", false),
    ] {
        assert_eq!(check_query(query).is_err(), refused, "{query:.20}");
    }
    assert_eq!(query_fault("SELECT 1"), None);
    Ok(())
}


#[tokio::test]
async fn a_refused_query_never_starts_anything() -> TestResult {
    let fixture = fixture()?;
    let result = run_query(&env_of(&fixture, echo), &fixture.settings, "-x").await;
    assert!(matches!(result, Err(OsqueryError::BadQuery(_))));
    assert!(!fixture.state.join(LOGGER_DIR_NAME).exists());
    Ok(())
}


#[test]
fn the_program_is_judged_through_handles() -> TestResult {
    let fixture = fixture()?;
    let uid = trusted_uid();
    assert_eq!(check_program(&fixture.settings.path, uid), Ok(()));
    assert!(matches!(check_program(Path::new("/"), uid), Err(OsqueryError::Untrusted(_))));
    assert!(matches!(check_program(Path::new("/tmp/.."), uid), Err(OsqueryError::Untrusted(_))));
    assert!(matches!(
        check_program(Path::new("relative/osqueryi"), uid),
        Err(OsqueryError::Untrusted(_))
    ));
    let bin = fixture.settings.path.parent().ok_or("no parent")?;
    assert_eq!(
        check_program(&bin.join("missing"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    );
    assert_eq!(
        check_program(&bin.join("nodir").join("osqueryi"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    );
    let link = bin.join("link");
    symlink(&fixture.settings.path, &link)?;
    assert_eq!(check_program(&link, uid), Ok(()));
    let loop_a = bin.join("loop_a");
    symlink(&loop_a, &loop_a)?;
    assert!(matches!(check_program(&loop_a, uid), Err(OsqueryError::Spawn(_))));
    let sub = bin.join("sub");
    make_dir(&sub, PROGRAM_MODE)?;
    assert_eq!(check_program(&sub, uid), Err(OsqueryError::Untrusted("program is not a regular file")));
    let loose = bin.join("loose");
    fs::write(&loose, b"")?;
    fs::set_permissions(&loose, fs::Permissions::from_mode(GROUP_WRITABLE_PROGRAM))?;
    assert_eq!(
        check_program(&loose, uid),
        Err(OsqueryError::Untrusted("program is writable by group or others"))
    );
    assert!(matches!(check_program(&fixture.settings.path, uid + 1), Err(OsqueryError::Untrusted(_))));
    let planted = fixture.state.join("planted");
    fs::write(&planted, b"")?;
    fs::set_permissions(&planted, fs::Permissions::from_mode(PROGRAM_MODE))?;
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(OPEN_DIR))?;
    let to_open_dir = bin.join("to_open_dir");
    symlink(&planted, &to_open_dir)?;
    assert!(matches!(check_program(&to_open_dir, uid), Err(OsqueryError::Untrusted(_))));
    fs::set_permissions(bin, fs::Permissions::from_mode(OPEN_DIR))?;
    assert!(matches!(check_program(&fixture.settings.path, uid), Err(OsqueryError::Untrusted(_))));
    Ok(())
}


#[test]
fn the_fault_functions_name_each_case() -> TestResult {
    assert_eq!(program_fault(REGULAR_FILE_MODE, 0, 0), None);
    assert!(program_fault(DIRECTORY_MODE, 0, 0).is_some());
    assert!(program_fault(REGULAR_FILE_MODE, OTHER_USER, 0).is_some());
    assert!(program_fault(GROUP_WRITABLE_FILE_MODE, 0, 0).is_some());
    assert_eq!(logger_dir_fault(OWNER_ONLY_DIR, 0, 0), None);
    assert!(logger_dir_fault(OWNER_ONLY_DIR, OTHER_USER, 0).is_some());
    assert!(logger_dir_fault(OPEN_DIR, 0, 0).is_some());
    assert_eq!(errno_error(rustix::io::Errno::NOENT), OsqueryError::Spawn(io::ErrorKind::NotFound));
    Ok(())
}


#[test]
fn the_logger_directory_is_private_and_a_planted_one_is_refused() -> TestResult {
    let fixture = fixture()?;
    let uid = trusted_uid();
    let made = prepare_logger_dir(&fixture.state, uid)?;
    assert_eq!(made, fixture.state.join(LOGGER_DIR_NAME));
    assert_eq!(prepare_logger_dir(&fixture.state, uid)?, made);
    fs::set_permissions(&made, fs::Permissions::from_mode(OPEN_DIR))?;
    assert!(matches!(prepare_logger_dir(&fixture.state, uid), Err(OsqueryError::Untrusted(_))));
    fs::remove_dir(&made)?;
    fs::write(&made, b"")?;
    assert!(matches!(prepare_logger_dir(&fixture.state, uid), Err(OsqueryError::Spawn(_))));
    fs::remove_file(&made)?;
    symlink(&fixture.state, &made)?;
    assert!(matches!(prepare_logger_dir(&fixture.state, uid), Err(OsqueryError::Spawn(_))));
    assert!(matches!(prepare_logger_dir(&fixture.state, uid + 1), Err(OsqueryError::Untrusted(_))));
    assert!(matches!(prepare_logger_dir(Path::new("state"), uid), Err(OsqueryError::Untrusted(_))));
    assert_eq!(
        prepare_logger_dir(&fixture.state.join("missing"), uid),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    );
    Ok(())
}


#[tokio::test]
async fn a_logger_path_that_is_not_utf8_is_refused() -> TestResult {
    let fixture = fixture()?;
    let odd = fixture.state.join(OsStr::from_bytes(&[b'd', INVALID_BYTE]));
    make_dir(&odd, OWNER_ONLY_DIR)?;
    let env = OsqueryEnv {
        state_dir: odd,
        trusted_uid: trusted_uid(),
        run: echo,
    };
    let result = run_query(&env, &fixture.settings, "SELECT 1").await;
    assert_eq!(result, Err(OsqueryError::Untrusted("private directory is not UTF-8")));
    Ok(())
}


#[tokio::test]
async fn an_untrusted_program_stops_the_run_before_the_logger_directory() -> TestResult {
    let fixture = fixture()?;
    let settings = OsquerySettings {
        path: PathBuf::from("relative"),
        ..fixture.settings.clone()
    };
    let result = run_query(&env_of(&fixture, echo), &settings, "SELECT 1").await;
    assert!(matches!(result, Err(OsqueryError::Untrusted(_))));
    assert!(!fixture.state.join(LOGGER_DIR_NAME).exists());
    Ok(())
}


pub fn counting_builder(raw: &str, calls: &mut usize) -> Option<std::collections::BTreeMap<String, String>> {
    *calls += 1;
    row_of(raw)
}


const TWO_ROWS: &[u8] = b"[{\"a\":\"b\"},{\"c\":\"d\"}]";


const TWO_ROWS_COUNT: usize = 2;


#[test]
fn the_row_count_bound_is_applied_before_any_row_is_built() -> TestResult {
    let over: Vec<Value> = (0..=MAX_ROWS).map(|index| json!({"k": index.to_string()})).collect();
    let mut calls = 0;
    let refused = rows_with_builder(&serde_json::to_vec(&over)?, counting_builder, &mut calls);
    assert_eq!(refused, Err(OsqueryError::TooLarge));
    assert_eq!(calls, 0);
    let two = rows_with_builder(TWO_ROWS, counting_builder, &mut calls)?;
    assert_eq!(two.rows.len(), TWO_ROWS_COUNT);
    assert_eq!(calls, TWO_ROWS_COUNT);
    Ok(())
}


const DISABLED_TABLES_FLAG: &str = "--disable_tables=curl,curl_certificate,carves,ec2_instance_metadata,ec2_instance_tags,azure_instance_metadata,azure_instance_tags,ycloud_instance_metadata";


#[tokio::test]
async fn an_untrusted_prlimit_stops_the_run() -> TestResult {
    let fixture = fixture()?;
    let settings = OsquerySettings {
        prlimit_path: PathBuf::from("prlimit"),
        ..fixture.settings.clone()
    };
    let result = run_query(&env_of(&fixture, echo), &settings, "SELECT 1").await;
    assert!(matches!(result, Err(OsqueryError::Untrusted(_))));
    assert!(!fixture.state.join(LOGGER_DIR_NAME).exists());
    Ok(())
}


const WRAPPER_ARGUMENTS: usize = 11;


fn read_calls(fixture: &Fixture) -> io::Result<Vec<String>> {
    let log = fixture.state.join(TEMP_DIR_NAME).join(CALL_LOG);
    Ok(fs::read_to_string(log)?.lines().map(str::to_owned).collect())
}


fn call_names(calls: &[String]) -> Vec<&str> {
    calls.iter().filter_map(|call| call.split(' ').next()).collect()
}


#[tokio::test]
async fn the_namespace_is_prepared_in_order_and_dropped_after_the_run() -> TestResult {
    let fixture = fixture()?;
    let result = run_query(&env_of(&fixture, recording), &fixture.settings, "SELECT 1").await?;
    assert_eq!(result.rows.len(), 0);
    let calls = read_calls(&fixture)?;
    let binds = agent_linux::osquery::present_binds();
    let expected: Vec<&str> = ["umount", "umount", "mount", "mount", "unshare"]
        .into_iter()
        .chain(binds.iter().map(|_| "nsenter"))
        .chain(["nsenter", "umount", "umount"])
        .collect();
    assert_eq!(call_names(&calls), expected);
    let ns_file = fixture.state.join(TEMP_DIR_NAME).join(NAMESPACE_FILE_NAME);
    let temp_dir = fixture.state.join(TEMP_DIR_NAME);
    assert_eq!(calls.first().cloned(), Some(format!("umount {}", ns_file.display())));
    assert_eq!(calls.get(1).cloned(), Some(format!("umount {}", temp_dir.display())));
    assert_eq!(
        calls.get(SELF_BIND_CALL).cloned(),
        Some(format!("mount --bind {0} {0}", temp_dir.display()))
    );
    assert_eq!(
        calls.get(MAKE_PRIVATE_CALL).cloned(),
        Some(format!("mount --make-private {}", temp_dir.display()))
    );
    let size = format!("size={DEFAULT_OSQUERY_TEMP_TOTAL_BYTES},mode=1777,nosuid,nodev");
    let create = calls.get(CREATE_CALL).ok_or("no create")?;
    assert!(create.contains("--mount=") && create.contains("--propagation=private -- ") && create.contains(&size));
    assert!(create.ends_with("tmpfs /tmp"));
    binds.iter().enumerate().try_for_each(|(index, bind)| {
        calls
            .get(index + FIRST_BIND_CALL)
            .filter(|call| call.ends_with(&format!("--bind /tmp {bind}")))
            .map(|_| ())
            .ok_or("no bind")
    })?;
    assert_eq!(fs::metadata(&ns_file)?.permissions().mode() & MODE_BITS, OWNER_ONLY_FILE);
    Ok(())
}


#[tokio::test]
async fn a_failed_step_names_itself_keeps_its_cause_and_still_drops_the_namespace() -> TestResult {
    let fixture = fixture()?;
    let failed = run_query(&env_of(&fixture, unshare_fails), &fixture.settings, "SELECT 1").await;
    assert_eq!(
        failed,
        Err(OsqueryError::Sandbox {
            step: "namespace",
            source: Box::new(OsqueryError::Exit(1)),
        })
    );
    let error = failed.err().ok_or("accepted")?;
    assert!(error.source().is_some_and(|cause| cause.to_string().contains("status 1")));
    assert_eq!(
        call_names(&read_calls(&fixture)?),
        ["umount", "umount", "mount", "mount", "unshare", "umount", "umount"]
    );
    let bind_failed = run_query(&env_of(&fixture, bind_fails), &fixture.settings, "SELECT 1").await;
    assert_eq!(
        bind_failed,
        Err(OsqueryError::Sandbox {
            step: "bind",
            source: Box::new(OsqueryError::Deadline),
        })
    );
    let calls = read_calls(&fixture)?;
    assert_eq!(call_names(&calls).last().copied(), Some("umount"));
    assert!(!call_names(&calls).contains(&"prlimit"));
    Ok(())
}


#[tokio::test]
async fn a_failed_umount_is_logged_not_fatal_and_a_full_tmpfs_is_a_resource_limit() -> TestResult {
    let fixture = fixture()?;
    let passed = run_query(&env_of(&fixture, umount_fails), &fixture.settings, "SELECT 1").await?;
    assert!(passed.rows.is_empty());
    let full = run_query(&env_of(&fixture, sqlite_full), &fixture.settings, "SELECT 1").await;
    assert_eq!(full, Err(OsqueryError::ResourceLimit));
    assert_eq!(osquery_error_of(SensorError::Exit(Some(EXIT_CODE))), OsqueryError::Exit(EXIT_CODE));
    Ok(())
}


#[test]
fn the_setup_chain_uses_separate_arguments_and_the_exact_size() -> TestResult {
    let fixture = fixture()?;
    let steps = agent_linux::osquery::setup_steps(&fixture.settings, "/dir", "/ns", &["/a", "/b"]);
    assert_eq!(
        steps.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        ["self-bind", "make-private", "namespace", "bind", "bind"]
    );
    let (_, create) = steps.get(CREATE_STEP).ok_or("no step")?;
    assert_eq!(create.program, fixture.settings.unshare_path);
    let words: Vec<String> = create.arguments.iter().map(|argument| argument.to_string_lossy().into_owned()).collect();
    let head = ["--mount=/ns", "--propagation=private", "--"].map(str::to_owned);
    assert_eq!(words.get(..HEAD_WORDS), Some(&head[..]));
    assert_eq!(words.get(HEAD_WORDS).map(String::as_str), fixture.settings.mount_path.to_str());
    let tail = [
        "-t".to_owned(),
        "tmpfs".to_owned(),
        "-o".to_owned(),
        format!("size={DEFAULT_OSQUERY_TEMP_TOTAL_BYTES},mode=1777,nosuid,nodev"),
        "tmpfs".to_owned(),
        "/tmp".to_owned(),
    ];
    assert_eq!(words.get(HEAD_WORDS + 1..), Some(&tail[..]));
    let (_, bind) = steps.get(SECOND_BIND_STEP).ok_or("no bind")?;
    assert_eq!(bind.program, fixture.settings.nsenter_path);
    assert_eq!(bind.arguments.last().and_then(|argument| argument.to_str()), Some("/b"));
    assert!(steps
        .iter()
        .all(|(_, spec)| spec.accepted_codes == vec![0] && spec.max_output < agent_linux::osquery::MAX_OSQUERY_OUTPUT_BYTES));
    Ok(())
}


#[tokio::test]
async fn an_untrusted_namespace_tool_stops_the_run_before_any_start() -> TestResult {
    let fixture = fixture()?;
    let base = fixture.settings.clone();
    let tools = [
        OsquerySettings {
            unshare_path: PathBuf::from("unshare"),
            ..base.clone()
        },
        OsquerySettings {
            nsenter_path: PathBuf::from("nsenter"),
            ..base.clone()
        },
        OsquerySettings {
            mount_path: PathBuf::from("mount"),
            ..base.clone()
        },
        OsquerySettings {
            umount_path: PathBuf::from("umount"),
            ..base
        },
    ];
    for settings in &tools {
        let result = run_query(&env_of(&fixture, recording), settings, "SELECT 1").await;
        assert!(matches!(result, Err(OsqueryError::Untrusted(_))));
    }
    assert!(!fixture.state.join(TEMP_DIR_NAME).exists());
    Ok(())
}


#[test]
fn the_namespace_file_is_made_once_and_never_through_a_symlink() -> TestResult {
    let fixture = fixture()?;
    let temp = agent_linux::osquery::prepare_temp_dir(&fixture.state, trusted_uid())?;
    let made = agent_linux::osquery::prepare_namespace_file(&temp)?;
    assert_eq!(agent_linux::osquery::prepare_namespace_file(&temp)?, made);
    fs::remove_file(&made)?;
    symlink(&fixture.state, &made)?;
    assert!(matches!(agent_linux::osquery::prepare_namespace_file(&temp), Err(OsqueryError::Spawn(_))));
    assert!(matches!(
        agent_linux::osquery::prepare_namespace_file(&fixture.state.join("missing")),
        Err(OsqueryError::Spawn(io::ErrorKind::NotFound))
    ));
    Ok(())
}
